package winfsp

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

// FileSystemRef is the reference for the file system,
// with which the callers can operate and manipulate the
// file system, except for destroying it.
type FileSystemRef struct {
	fileSystemOps     *FSP_FILE_SYSTEM_INTERFACE
	fileSystem        *FSP_FILE_SYSTEM
	base              BehaviourBase
	getVolumeInfo     BehaviourGetVolumeInfo
	setVolumeLabel    BehaviourSetVolumeLabel
	getSecurityByName BehaviourGetSecurityByName
	create            BehaviourCreate
	overwrite         BehaviourOverwrite
	cleanup           BehaviourCleanup
	read              BehaviourRead
	write             BehaviourWrite
	flush             BehaviourFlush
	getFileInfo       BehaviourGetFileInfo
	setBasicInfo      BehaviourSetBasicInfo
	setFileSize       BehaviourSetFileSize
	canDelete         BehaviourCanDelete
	rename            BehaviourRename
	getSecurity       BehaviourGetSecurity
	setSecurity       BehaviourSetSecurity
	readDirRaw        BehaviourReadDirectoryRaw
	getDirInfoByName  BehaviourGetDirInfoByName
	deviceIoControl   BehaviourDeviceIoControl
	createEx          BehaviourCreateEx
}

// ntStatusNoRef is returned when user context to inner
// map is not present.
const ntStatusNoRef = windows.STATUS_DEVICE_OFF_LINE

var refMap sync.Map

func loadFileSystemRef(fileSystem uintptr) *FileSystemRef {
	fsp := (*FSP_FILE_SYSTEM)(unsafe.Pointer(fileSystem))
	value, ok := refMap.Load(fsp.UserContext)
	if !ok {
		return nil
	}
	return value.(*FileSystemRef)
}

var syscallNTStatusMap = map[syscall.Errno]windows.NTStatus{
	syscall.Errno(0): windows.STATUS_SUCCESS,

	// Application errors conversion map.
	syscall.ENOENT:  windows.STATUS_OBJECT_NAME_NOT_FOUND,
	syscall.EEXIST:  windows.STATUS_OBJECT_NAME_COLLISION,
	syscall.EPERM:   windows.STATUS_ACCESS_DENIED,
	syscall.ENOTDIR: windows.STATUS_NOT_A_DIRECTORY,
	syscall.EISDIR:  windows.STATUS_FILE_IS_A_DIRECTORY,
	syscall.EINVAL:  windows.STATUS_INVALID_PARAMETER,

	// System errors conversion map.
	syscall.ERROR_ACCESS_DENIED: windows.STATUS_ACCESS_DENIED,
	//syscall.ERROR_FILE_NOT_FOUND:  windows.STATUS_OBJECT_NAME_NOT_FOUND,
	//syscall.ERROR_PATH_NOT_FOUND:  windows.STATUS_OBJECT_NAME_NOT_FOUND,
	syscall.ERROR_NOT_FOUND:       windows.STATUS_OBJECT_NAME_NOT_FOUND,
	syscall.ERROR_FILE_EXISTS:     windows.STATUS_OBJECT_NAME_COLLISION,
	syscall.ERROR_ALREADY_EXISTS:  windows.STATUS_OBJECT_NAME_COLLISION,
	syscall.ERROR_BUFFER_OVERFLOW: windows.STATUS_BUFFER_OVERFLOW,
	syscall.ERROR_DIR_NOT_EMPTY:   windows.STATUS_DIRECTORY_NOT_EMPTY,
}

func convertNTStatus(err error) windows.NTStatus {
	if err == nil {
		return windows.STATUS_SUCCESS
	}
	var status windows.NTStatus
	if errors.As(err, &status) {
		return status
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if status, ok := syscallNTStatusMap[errno]; ok {
			return status
		}
	}
	if errors.Is(err, io.EOF) {
		return windows.STATUS_END_OF_FILE
	}
	if errors.Is(err, os.ErrExist) {
		return windows.STATUS_OBJECT_NAME_COLLISION
	}
	if errors.Is(err, os.ErrNotExist) {
		return windows.STATUS_OBJECT_NAME_NOT_FOUND
	}
	if errors.Is(err, os.ErrPermission) {
		return windows.STATUS_ACCESS_DENIED
	}
	return windows.STATUS_INTERNAL_ERROR
}

func utf16PtrToString(ptr uintptr) string {
	utf16Ptr := (*uint16)(unsafe.Pointer(ptr))
	return windows.UTF16PtrToString(utf16Ptr)
}

func enforceBytePtr(ptr uintptr, size int) []byte {
	slice := &reflect.SliceHeader{
		Data: ptr,
		Len:  size,
		Cap:  size,
	}
	return *(*[]byte)(unsafe.Pointer(slice))
}

// FileSystem is the created object of WinFSP's filesystem.
//
// Most behaviour of the file system are defined for the
// FileSystemRef object, except for the resource management
// ones. The FileSystem object will be recycled automatically
// when there's no reference to it.
type FileSystem struct {
	FileSystemRef
}

// BehaviourBase defines the mandatory methods.
//
// Other methods might be implemented and will be checked
// upon mounting the filesystem.
type BehaviourBase interface {
	// Open the file specified by name.
	Open(
		fs *FileSystemRef, name string,
		createOptions, grantedAccess uint32,
		info *FSP_FSCTL_FILE_INFO,
	) (uintptr, error)

	// Close a open file handle.
	Close(fs *FileSystemRef, file uintptr)
}

func delegateOpen(
	fileSystem, fileName uintptr,
	createOptions, grantedAccess uint32,
	file *uintptr, fileInfoAddr uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	result, err := ref.base.Open(
		ref, utf16PtrToString(fileName),
		createOptions, grantedAccess,
		(*FSP_FSCTL_FILE_INFO)(
			unsafe.Pointer(fileInfoAddr)),
	)
	if err != nil {
		return convertNTStatus(err)
	}
	*file = result
	return windows.STATUS_SUCCESS
}

var go_delegateOpen = syscall.NewCallbackCDecl(func(
	fileSystem, fileName uintptr,
	createOptions, grantedAccess uint32,
	file *uintptr, fileInfoAddr uintptr,
) uintptr {
	return uintptr(delegateOpen(
		fileSystem, fileName,
		createOptions, grantedAccess,
		file, fileInfoAddr,
	))
})

func delegateClose(fileSystem, file uintptr) {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return
	}
	ref.base.Close(ref, file)
}

var go_delegateClose = syscall.NewCallbackCDecl(func(
	fileSystem, file uintptr,
) uintptr {
	delegateClose(fileSystem, file)
	return uintptr(windows.STATUS_SUCCESS)
})

// BehaviourGetVolumeInfo retrieves volume info.
type BehaviourGetVolumeInfo interface {
	GetVolumeInfo(
		fs *FileSystemRef, info *FSP_FSCTL_VOLUME_INFO,
	) error
}

func delegateGetVolumeInfo(
	fileSystem, volumeInfoAddr uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	return convertNTStatus(ref.getVolumeInfo.GetVolumeInfo(
		ref, (*FSP_FSCTL_VOLUME_INFO)(
			unsafe.Pointer(volumeInfoAddr)),
	))
}

var go_delegateGetVolumeInfo = syscall.NewCallbackCDecl(func(
	fileSystem, volumeInfoAddr uintptr,
) uintptr {
	return uintptr(delegateGetVolumeInfo(
		fileSystem, volumeInfoAddr,
	))
})

// BehaviourSetVolumeLabel sets volume label.
type BehaviourSetVolumeLabel interface {
	SetVolumeLabel(
		fs *FileSystemRef, label string,
		info *FSP_FSCTL_VOLUME_INFO,
	) error
}

func delegateSetVolumeLabel(
	fileSystem, labelAddr, volumeInfoAddr uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	return convertNTStatus(ref.setVolumeLabel.SetVolumeLabel(
		ref, utf16PtrToString(labelAddr),
		(*FSP_FSCTL_VOLUME_INFO)(
			unsafe.Pointer(volumeInfoAddr)),
	))
}

var go_delegateSetVolumeLabel = syscall.NewCallbackCDecl(func(
	fileSystem, labelAddr, volumeInfoAddr uintptr,
) uintptr {
	return uintptr(delegateSetVolumeLabel(
		fileSystem, labelAddr, volumeInfoAddr,
	))
})

// GetSecurityByNameFlags indicates the content that the
// caller cares about. The callee can return null value on
// the item that is not interested in.
type GetSecurityByNameFlags uint8

const (
	GetExistenceOnly = GetSecurityByNameFlags(iota)
	GetAttributesByName
	GetSecurityByName
	GetAttributesSecurity
)

// BehaviourGetSecurityByName retrieves file attributes and
// security descriptor by file name.
//
// The file attribute can also be a reparse point index when
// windows.STATUS_REPARSE is returned.
type BehaviourGetSecurityByName interface {
	GetSecurityByName(
		fs *FileSystemRef, name string,
		flags GetSecurityByNameFlags,
	) (uint32, *windows.SECURITY_DESCRIPTOR, error)
}

func delegateGetSecurityByName(
	fileSystem, fileName, attributesAddr uintptr,
	securityDescAddr, securityDescSizeAddr uintptr,
) windows.NTStatus {
	flags := GetExistenceOnly
	attributes := (*uint32)(unsafe.Pointer(attributesAddr))
	if attributes != nil {
		flags |= GetAttributesByName
		*attributes = 0
	}
	size := (*uintptr)(unsafe.Pointer(securityDescSizeAddr))
	var bufferSize int
	if size != nil {
		flags |= GetSecurityByName
		bufferSize = int(*size)
		*size = 0
	}
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	attr, sd, err := ref.getSecurityByName.GetSecurityByName(
		ref, utf16PtrToString(fileName), flags)
	if err != nil {
		return convertNTStatus(err)
	}
	if attributes != nil {
		*attributes = attr
	}
	if size != nil {
		length := int(sd.Length())
		*size = uintptr(length)
		source := enforceBytePtr(uintptr(unsafe.Pointer(sd)), length)
		target := enforceBytePtr(securityDescAddr, bufferSize)
		if copy(target, source) < length {
			return windows.STATUS_BUFFER_OVERFLOW
		}
	}
	return windows.STATUS_SUCCESS
}

var go_delegateGetSecurityByName = syscall.NewCallbackCDecl(func(
	fileSystem, fileName, attributesAddr uintptr,
	securityDescAddr, securityDescSizeAddr uintptr,
) uintptr {
	return uintptr(delegateGetSecurityByName(
		fileSystem, fileName, attributesAddr,
		securityDescAddr, securityDescSizeAddr,
	))
})

// BehaviourCreate creates a new file or directory.
type BehaviourCreate interface {
	Create(
		fs *FileSystemRef, name string,
		createOptions, grantedAccess, fileAttributes uint32,
		securityDescriptor *windows.SECURITY_DESCRIPTOR,
		allocationSize uint64, info *FSP_FSCTL_FILE_INFO,
	) (uintptr, error)
}

func delegateCreate(
	fileSystem, fileName uintptr,
	createOptions, grantedAccess, fileAttributes uint32,
	securityDescriptor uintptr, allocationSize uint64,
	file *uintptr, fileInfoAddr uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	result, err := ref.create.Create(
		ref, utf16PtrToString(fileName),
		createOptions, grantedAccess, fileAttributes,
		(*windows.SECURITY_DESCRIPTOR)(
			unsafe.Pointer(securityDescriptor)),
		allocationSize, (*FSP_FSCTL_FILE_INFO)(
			unsafe.Pointer(fileInfoAddr)),
	)
	if err != nil {
		return convertNTStatus(err)
	}
	*file = result
	return windows.STATUS_SUCCESS
}

var go_delegateCreate = syscall.NewCallbackCDecl(func(
	fileSystem, fileName uintptr,
	createOptions, grantedAccess, fileAttributes uint32,
	securityDescriptor uintptr, allocationSize uint64,
	file *uintptr, fileInfoAddr uintptr,
) uintptr {
	return uintptr(delegateCreate(
		fileSystem, fileName,
		createOptions, grantedAccess, fileAttributes,
		securityDescriptor, allocationSize,
		file, fileInfoAddr,
	))
})

// BehaviourOverwrite overwrites a file's attribute.
type BehaviourOverwrite interface {
	Overwrite(
		fs *FileSystemRef, file uintptr,
		attributes uint32, replaceAttributes bool,
		allocationSize uint64,
		info *FSP_FSCTL_FILE_INFO,
	) error
}

func delegateOverwrite(
	fileSystem, file uintptr,
	attributes uint32, replaceAttributes uint8,
	allocationSize uint64, fileInfoAddr uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	return convertNTStatus(ref.overwrite.Overwrite(
		ref, file, attributes, replaceAttributes != 0,
		allocationSize, (*FSP_FSCTL_FILE_INFO)(
			unsafe.Pointer(fileInfoAddr)),
	))
}

var go_delegateOverwrite = syscall.NewCallbackCDecl(func(
	fileSystem, file uintptr,
	attributes uint32, replaceAttributes uint8,
	allocationSize uint64, fileInfoAddr uintptr,
) uintptr {
	return uintptr(delegateOverwrite(
		fileSystem, file,
		attributes, replaceAttributes,
		allocationSize, fileInfoAddr,
	))
})

// BehaviourCleanup performs the cleanup behaviour.
type BehaviourCleanup interface {
	Cleanup(
		fs *FileSystemRef, file uintptr, name string,
		cleanupFlags uint32,
	)
}

func delegateCleanup(
	fileSystem, fileContext, filename uintptr,
	cleanupFlags uint32,
) {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return
	}
	ref.cleanup.Cleanup(
		ref, fileContext, utf16PtrToString(filename),
		cleanupFlags,
	)
}

var go_delegateCleanup = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext, filename uintptr,
	cleanupFlags uint32,
) uintptr {
	delegateCleanup(
		fileSystem, fileContext, filename,
		cleanupFlags,
	)
	return uintptr(windows.STATUS_SUCCESS)
})

// BehaviourRead read an open file.
type BehaviourRead interface {
	Read(
		fs *FileSystemRef, file uintptr,
		buf []byte, offset uint64,
	) (int, error)
}

func delegateRead(
	fileSystem, fileContext, buffer uintptr,
	offset uint64, length uint32, bytesRead *uint32,
) windows.NTStatus {
	*bytesRead = 0
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	n, err := ref.read.Read(ref, fileContext,
		enforceBytePtr(buffer, int(length)), offset)
	*bytesRead = uint32(n)
	// XXX: this is required otherwise windows kernel render
	// it as nothing read from the file instead.
	if n > 0 && err == io.EOF {
		err = nil
	}
	return convertNTStatus(err)
}

var go_delegateRead = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext, buffer uintptr,
	offset uint64, length uint32, bytesRead *uint32,
) uintptr {
	return uintptr(delegateRead(
		fileSystem, fileContext, buffer,
		offset, length, bytesRead,
	))
})

// BehaviourWrite writes an open file.
type BehaviourWrite interface {
	Write(
		fs *FileSystemRef, file uintptr,
		buf []byte, offset uint64,
		writeToEndOfFile, constrainedIo bool,
		info *FSP_FSCTL_FILE_INFO,
	) (int, error)
}

func delegateWrite(
	fileSystem, fileContext, buffer uintptr,
	offset uint64, length uint32,
	writeToEndOfFile, constrainedIo uint8,
	bytesWritten *uint32, fileInfoAddr uintptr,
) windows.NTStatus {
	*bytesWritten = 0
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	n, err := ref.write.Write(ref, fileContext,
		enforceBytePtr(buffer, int(length)), offset,
		writeToEndOfFile != 0, constrainedIo != 0,
		(*FSP_FSCTL_FILE_INFO)(
			unsafe.Pointer(fileInfoAddr)),
	)
	*bytesWritten = uint32(n)
	return convertNTStatus(err)
}

var go_delegateWrite = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext, buffer uintptr,
	offset uint64, length uint32,
	writeToEndOfFile, constrainedIo uint8,
	bytesWritten *uint32, fileInfoAddr uintptr,
) uintptr {
	return uintptr(delegateWrite(
		fileSystem, fileContext, buffer,
		offset, length,
		writeToEndOfFile, constrainedIo,
		bytesWritten, fileInfoAddr,
	))
})

// BehaviourFlush flushes a file or volume.
//
// When file is not NULL, the specific file will be flushed,
// otherwise the whole volume will be flushed.
type BehaviourFlush interface {
	Flush(
		fs *FileSystemRef, file uintptr,
		info *FSP_FSCTL_FILE_INFO,
	) error
}

func delegateFlush(
	fileSystem, fileContext, infoAddr uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	return convertNTStatus(ref.flush.Flush(
		ref, fileContext, (*FSP_FSCTL_FILE_INFO)(
			unsafe.Pointer(infoAddr)),
	))
}

var go_delegateFlush = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext, infoAddr uintptr,
) uintptr {
	return uintptr(delegateFlush(
		fileSystem, fileContext, infoAddr,
	))
})

// BehaviourGetFileInfo retrieves stat of file or directory.
type BehaviourGetFileInfo interface {
	GetFileInfo(
		fs *FileSystemRef, file uintptr,
		info *FSP_FSCTL_FILE_INFO,
	) error
}

func delegateGetFileInfo(
	fileSystem, fileContext, infoAddr uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	return convertNTStatus(ref.getFileInfo.GetFileInfo(
		ref, fileContext, (*FSP_FSCTL_FILE_INFO)(
			unsafe.Pointer(infoAddr)),
	))
}

var go_delegateGetFileInfo = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext, infoAddr uintptr,
) uintptr {
	return uintptr(delegateGetFileInfo(
		fileSystem, fileContext, infoAddr,
	))
})

// SetBasicInfoFlags specifies a set of modified values
// in the SetBasicInfoFlags call.
type SetBasicInfoFlags uint32

const (
	SetBasicInfoAttributes = SetBasicInfoFlags(1 << iota)
	SetBasicInfoCreationTime
	SetBasicInfoLastAccessTime
	SetBasicInfoLastWriteTime
	SetBasicInfoChangeTime
)

// BehaviourSetBasicInfo sets stat of file or directory.
type BehaviourSetBasicInfo interface {
	SetBasicInfo(
		fs *FileSystemRef, file uintptr,
		flags SetBasicInfoFlags, attributes uint32,
		creationTime, lastAccessTime, lastWriteTime, changeTime uint64,
		fileInfo *FSP_FSCTL_FILE_INFO,
	) error
}

func delegateSetBasicInfo(
	fileSystem, fileContext uintptr,
	attributes uint32,
	creationTime, lastAccessTime, lastWriteTime, changeTime uint64,
	fileInfoAddr uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	var flags SetBasicInfoFlags
	if attributes != windows.INVALID_FILE_ATTRIBUTES {
		flags |= SetBasicInfoAttributes
	}
	if creationTime != 0 {
		flags |= SetBasicInfoCreationTime
	}
	if lastAccessTime != 0 {
		flags |= SetBasicInfoLastAccessTime
	}
	if lastWriteTime != 0 {
		flags |= SetBasicInfoLastAccessTime
	}
	if changeTime != 0 {
		flags |= SetBasicInfoChangeTime
	}
	return convertNTStatus(ref.setBasicInfo.SetBasicInfo(
		ref, fileContext, flags, attributes,
		creationTime, lastAccessTime, lastWriteTime, changeTime,
		(*FSP_FSCTL_FILE_INFO)(unsafe.Pointer(fileInfoAddr)),
	))
}

var go_delegateSetBasicInfo = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext uintptr,
	attributes uint32,
	creationTime, lastAccessTime, lastWriteTime, changeTime uint64,
	fileInfoAddr uintptr,
) uintptr {
	return uintptr(delegateSetBasicInfo(
		fileSystem, fileContext, attributes,
		creationTime, lastAccessTime, lastWriteTime, changeTime,
		fileInfoAddr,
	))
})

// BehaviourSetFileSize sets file's size or allocation size.
type BehaviourSetFileSize interface {
	SetFileSize(
		fs *FileSystemRef, file uintptr,
		newSize uint64, setAllocationSize bool,
		fileInfo *FSP_FSCTL_FILE_INFO,
	) error
}

func delegateSetFileSize(
	fileSystem, fileContext uintptr,
	newSize uint64, setAllocationSize uint8,
	fileInfoAddr uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	return convertNTStatus(ref.setFileSize.SetFileSize(
		ref, fileContext, newSize, setAllocationSize != 0,
		(*FSP_FSCTL_FILE_INFO)(unsafe.Pointer(fileInfoAddr)),
	))
}

var go_delegateSetFileSize = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext uintptr,
	newSize uint64, setAllocationSize uint8,
	fileInfoAddr uintptr,
) uintptr {
	return uintptr(delegateSetFileSize(
		fileSystem, fileContext,
		newSize, setAllocationSize,
		fileInfoAddr,
	))
})

// BehaviourCanDelete detects whether the file can be deleted.
type BehaviourCanDelete interface {
	CanDelete(
		fs *FileSystemRef, file uintptr, name string,
	) error
}

func delegateCanDelete(
	fileSystem, fileContext, filename uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	return convertNTStatus(ref.canDelete.CanDelete(
		ref, fileContext, utf16PtrToString(filename),
	))
}

var go_delegateCanDelete = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext, filename uintptr,
) uintptr {
	return uintptr(delegateCanDelete(
		fileSystem, fileContext, filename,
	))
})

// BehaviourRename renames a file or directory.
type BehaviourRename interface {
	Rename(
		fs *FileSystemRef, file uintptr,
		source, target string, replaceIfExist bool,
	) error
}

func delegateRename(
	fileSystem, fileContext uintptr,
	source, target uintptr, replaceIfExists uint8,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	return convertNTStatus(ref.rename.Rename(
		ref, fileContext,
		utf16PtrToString(source), utf16PtrToString(target),
		replaceIfExists != 0,
	))
}

var go_delegateRename = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext uintptr,
	source, target uintptr, replaceIfExists uint8,
) uintptr {
	return uintptr(delegateRename(
		fileSystem, fileContext,
		source, target, replaceIfExists,
	))
})

// BehaviourGetSecurity retrieves security descriptor by file.
type BehaviourGetSecurity interface {
	GetSecurity(
		fs *FileSystemRef, file uintptr,
	) (*windows.SECURITY_DESCRIPTOR, error)
}

func delegateGetSecurity(
	fileSystem, fileContext uintptr,
	securityDescAddr, securityDescSizeAddr uintptr,
) windows.NTStatus {
	size := (*uintptr)(unsafe.Pointer(securityDescSizeAddr))
	var bufferSize int
	if size != nil {
		bufferSize = int(*size)
		*size = 0
	}
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	sd, err := ref.getSecurity.GetSecurity(ref, fileContext)
	if err != nil {
		return convertNTStatus(err)
	}
	length := int(sd.Length())
	*size = uintptr(length)
	// XXX: though the API document says so, I haven't seen
	// under any circumstances will the security descriptor's
	// buffer address be NULL.
	if securityDescAddr != 0 {
		source := enforceBytePtr(uintptr(unsafe.Pointer(sd)), length)
		target := enforceBytePtr(securityDescAddr, bufferSize)
		if copy(target, source) < length {
			return windows.STATUS_BUFFER_OVERFLOW
		}
	}
	return windows.STATUS_SUCCESS
}

var go_delegateGetSecurity = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext uintptr,
	securityDescAddr, securityDescSizeAddr uintptr,
) uintptr {
	return uintptr(delegateGetSecurity(
		fileSystem, fileContext,
		securityDescAddr, securityDescSizeAddr,
	))
})

// BehaviourSetSecurity sets security descriptor by file.
type BehaviourSetSecurity interface {
	SetSecurity(
		fs *FileSystemRef, file uintptr,
		info windows.SECURITY_INFORMATION,
		desc *windows.SECURITY_DESCRIPTOR,
	) error
}

func delegateSetSecurity(
	fileSystem, fileContext uintptr,
	info windows.SECURITY_INFORMATION, securityDescSizeAddr uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	return convertNTStatus(ref.setSecurity.SetSecurity(
		ref, fileContext, info,
		(*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(
			securityDescSizeAddr))))
}

var go_delegateSetSecurity = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext uintptr,
	info windows.SECURITY_INFORMATION, securityDescSizeAddr uintptr,
) uintptr {
	return uintptr(delegateSetSecurity(
		fileSystem, fileContext,
		info, securityDescSizeAddr,
	))
})

var (
	deleteDirectoryBuffer  *syscall.Proc
	acquireDirectoryBuffer *syscall.Proc
	releaseDirectoryBuffer *syscall.Proc
	readDirectoryBuffer    *syscall.Proc
	fillDirectoryBuffer    *syscall.Proc
)

// DirBuffer is the directory buffer block which can be
// operated WinFSP's directory info API.
//
// To fill content into the buffer, one should try to acquire
// a DirBufferFiller, which is only acquired when there's no
// remaining content, or the user tells it to flush and reset.
type DirBuffer struct {
	ptr uintptr
}

// Delete the directory buffer.
func (buf *DirBuffer) Delete() {
	_, _, _ = deleteDirectoryBuffer.Call(
		uintptr(unsafe.Pointer(&buf.ptr)))
}

// ReadDirectory fills the read content into the buffer when
// there's no content remaining.
func (buf *DirBuffer) ReadDirectory(
	marker *uint16, buffer []byte,
) int {
	var bytesTransferred uint32
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&buffer))
	_, _, _ = readDirectoryBuffer.Call(
		uintptr(unsafe.Pointer(&buf.ptr)),
		uintptr(unsafe.Pointer(marker)),
		slice.Data, uintptr(slice.Len),
		uintptr(unsafe.Pointer(&bytesTransferred)),
	)
	return int(bytesTransferred)
}

// DirBufferFiller is the acquired filler of file system.
type DirBufferFiller struct {
	buf *DirBuffer
}

// Acquire the directory buffer filler when there has no
// content buffered, or it tells to reset the buffer.
//
// Unlike other interface, the acquisition may fail and
// the filler might be nil this case. The caller must
// judge whether there is error or there's no need to
// acquire the directory buffer yet.
func (buf *DirBuffer) Acquire(reset bool) (*DirBufferFiller, error) {
	var resetVal uintptr
	if reset {
		resetVal = uintptr(1)
	}
	var status windows.NTStatus
	acquireOk, _, _ := acquireDirectoryBuffer.Call(
		uintptr(unsafe.Pointer(&buf.ptr)), resetVal,
		uintptr(unsafe.Pointer(&status)),
	)
	var err error
	if status != windows.STATUS_SUCCESS {
		err = status
	}
	// BUG: microsoft's calling convention sets AL to 1
	// when the result is BOOLEAN, so we must only look
	// at the lowest bit of the digits then.
	if (uint8(acquireOk) != 1) || err != nil {
		return nil, err
	}
	return &DirBufferFiller{buf: buf}, nil
}

// Fill a directory entry into the directory filler.
//
// The iteration might also be stopped when the caller
// returns false, in thise case we should also terminate
// the iteration and copy the content out to the handler.
func (b *DirBufferFiller) Fill(
	name string, fileInfo *FSP_FSCTL_FILE_INFO,
) (bool, error) {
	utf16, err := windows.UTF16FromString(name)
	if err != nil {
		return false, err
	}
	if len(utf16) > 0 && utf16[len(utf16)-1] == 0 {
		// Prune the trailing NUL, since it is not need
		// while copying to the directory buffer.
		utf16 = utf16[:len(utf16)-1]
	}
	length := int(unsafe.Sizeof(FSP_FSCTL_DIR_INFO{}) +
		uintptr(len(utf16))*SIZEOF_WCHAR)
	alignedBuffer := make([]uint64, (length+7)/8)
	alignedAddr := uintptr(unsafe.Pointer(&alignedBuffer[0]))
	dirInfo := (*FSP_FSCTL_DIR_INFO)(unsafe.Pointer(alignedAddr))
	dirInfo.Size = uint16(length)
	if fileInfo != nil {
		dirInfo.FileInfo = *fileInfo
	}
	target := *((*[]uint16)(unsafe.Pointer(&reflect.SliceHeader{
		Data: alignedAddr + unsafe.Sizeof(FSP_FSCTL_DIR_INFO{}),
		Len:  len(utf16),
		Cap:  len(utf16),
	})))
	copy(target, utf16)
	var status windows.NTStatus
	copyOk, _, _ := fillDirectoryBuffer.Call(
		uintptr(unsafe.Pointer(&b.buf.ptr)), alignedAddr,
		uintptr(unsafe.Pointer(&status)),
	)
	if status != windows.STATUS_SUCCESS {
		err = status
	}
	runtime.KeepAlive(alignedBuffer)
	// BUG: same bug as the acquire counterpart here.
	return uint8(copyOk) != 0, err
}

// Release the directory buffer filler.
func (b *DirBufferFiller) Release() {
	_, _, _ = releaseDirectoryBuffer.Call(
		uintptr(unsafe.Pointer(&b.buf.ptr)))
}

// BehaviourReadDirectoryRaw is the raw interface of read
// directory. Under most circumstances, the caller should
// implement BehaviourReadDirectory interface instead.
//
// For performance issue, the pattern and marker are not
// translated into go string.
type BehaviourReadDirectoryRaw interface {
	ReadDirectoryRaw(
		fs *FileSystemRef, file uintptr,
		pattern, marker *uint16, buf []byte,
	) (int, error)
}

func delegateReadDirectory(
	fileSystem, fileContext uintptr,
	pattern, marker *uint16,
	buf uintptr, length uint32, numRead *uint32,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	n, err := ref.readDirRaw.ReadDirectoryRaw(
		ref, fileContext, pattern, marker,
		enforceBytePtr(buf, int(length)))
	*numRead = uint32(n)
	return convertNTStatus(err)
}

var go_delegateReadDirectory = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext uintptr,
	pattern, marker *uint16,
	buf uintptr, length uint32, numRead *uint32,
) uintptr {
	return uintptr(delegateReadDirectory(
		fileSystem, fileContext,
		pattern, marker,
		buf, length, numRead,
	))
})

// BehaviourReadDirectory is the delegated interface which
// requires a translation from file descriptor and its
// dedicated directory buffer, alongside with occasionally
// called read directory call.
//
// The directory buffer allocated by the file system must be
// destroyed manually when the BehaviourBase.Close method
// has been called.
type BehaviourReadDirectory interface {
	GetOrNewDirBuffer(
		fileSystem *FileSystemRef, file uintptr,
	) (*DirBuffer, error)

	ReadDirectory(
		fs *FileSystemRef, file uintptr, pattern string,
		fill func(string, *FSP_FSCTL_FILE_INFO) (bool, error),
	) error
}

type behaviourReadDirectoryDelegate struct {
	readDir BehaviourReadDirectory
}

func (d *behaviourReadDirectoryDelegate) ReadDirectoryRaw(
	fs *FileSystemRef, file uintptr,
	pattern, marker *uint16, buf []byte,
) (int, error) {
	// XXX: This is literally identital to the WinFsp-Tutorial.
	// https://github.com/winfsp/winfsp/wiki/WinFsp-Tutorial#readdirectory
	dirBuf, err := d.readDir.GetOrNewDirBuffer(fs, file)
	if err != nil {
		return 0, err
	}
	filler, err := dirBuf.Acquire(marker == nil)
	if err != nil {
		return 0, err
	}
	if filler != nil {
		if err := func() error {
			defer filler.Release()
			var readPattern string
			if pattern != nil {
				readPattern = windows.UTF16PtrToString(pattern)
			}
			return d.readDir.ReadDirectory(
				fs, file, readPattern, filler.Fill)
		}(); err != nil {
			return 0, err
		}
	}
	return dirBuf.ReadDirectory(marker, buf), nil
}

// BehaviourGetDirInfoByName get directory information for a
// file or directory within a parent directory.
type BehaviourGetDirInfoByName interface {
	GetDirInfoByName(
		fs *FileSystemRef, parentDirFile uintptr,
		name string, dirInfo *FSP_FSCTL_DIR_INFO,
	) error
}

func delegateGetDirInfoByName(
	fileSystem, parentDirFile uintptr,
	fileName, dirInfoAddr uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	return convertNTStatus(ref.getDirInfoByName.GetDirInfoByName(
		ref, parentDirFile, utf16PtrToString(fileName),
		(*FSP_FSCTL_DIR_INFO)(unsafe.Pointer(dirInfoAddr)),
	))
}

var go_delegateGetDirInfoByName = syscall.NewCallbackCDecl(func(
	fileSystem, parentDirFile uintptr,
	fileName, dirInfoAddr uintptr,
) uintptr {
	return uintptr(delegateGetDirInfoByName(
		fileSystem, parentDirFile,
		fileName, dirInfoAddr,
	))
})

// BehaviourDeviceIoControl processes control code.
type BehaviourDeviceIoControl interface {
	DeviceIoControl(
		fs *FileSystemRef, file uintptr,
		code uint32, data []byte,
	) ([]byte, error)
}

func delegateDeviceIoControl(
	fileSystem, fileContext uintptr, controlCode uint32,
	inputBuffer uintptr, inputBufferLength uint32,
	outputBuffer uintptr, outputBufferLength uint32,
	bytesWritten *uint32,
) windows.NTStatus {
	*bytesWritten = 0
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	input := enforceBytePtr(inputBuffer, int(inputBufferLength))
	result, err := ref.deviceIoControl.DeviceIoControl(
		ref, fileContext, controlCode, input,
	)
	if err != nil {
		return convertNTStatus(err)
	}
	output := enforceBytePtr(outputBuffer, int(outputBufferLength))
	copied := copy(output, result)
	*bytesWritten = uint32(copied)
	if copied < len(output) {
		return windows.STATUS_BUFFER_OVERFLOW
	}
	return windows.STATUS_SUCCESS
}

var go_delegateDeviceIoControl = syscall.NewCallbackCDecl(func(
	fileSystem, fileContext uintptr, controlCode uint32,
	inputBuffer uintptr, inputBufferLength uint32,
	outputBuffer uintptr, outputBufferLength uint32,
	bytesWritten *uint32,
) uintptr {
	return uintptr(delegateDeviceIoControl(
		fileSystem, fileContext, controlCode,
		inputBuffer, inputBufferLength,
		outputBuffer, outputBufferLength,
		bytesWritten,
	))
})

// BehaviourCreateEx creates file with extended attributes.
//
// Please notice this interface conflicts with BehaviourCreate
// and is prioritized over it.
type BehaviourCreateEx interface {
	CreateExWithExtendedAttribute(
		fs *FileSystemRef, name string,
		createOptions, grantedAccess, fileAttributes uint32,
		securityDescriptor *windows.SECURITY_DESCRIPTOR,
		extendedAttribute *FILE_FULL_EA_INFORMATION,
		allocationSize uint64, info *FSP_FSCTL_FILE_INFO,
	) (uintptr, error)

	CreateExWithReparsePointData(
		fs *FileSystemRef, name string,
		createOptions, grantedAccess, fileAttributes uint32,
		securityDescriptor *windows.SECURITY_DESCRIPTOR,
		extendedAttribute *REPARSE_DATA_BUFFER_GENERIC,
		allocationSize uint64, info *FSP_FSCTL_FILE_INFO,
	) (uintptr, error)
}

func delegateCreateEx(
	fileSystem, fileName uintptr,
	createOptions, grantedAccess, fileAttributes uint32,
	securityDescriptor uintptr, allocationSize uint64,
	extraBuffer uintptr, extraLength uint32, isReparse uint8,
	file *uintptr, fileInfoAddr uintptr,
) windows.NTStatus {
	ref := loadFileSystemRef(fileSystem)
	if ref == nil {
		return ntStatusNoRef
	}
	result, err := func() (uintptr, error) {
		if isReparse != 0 {
			return ref.createEx.CreateExWithReparsePointData(
				ref, utf16PtrToString(fileName),
				createOptions, grantedAccess, fileAttributes,
				(*windows.SECURITY_DESCRIPTOR)(
					unsafe.Pointer(securityDescriptor)),
				(*REPARSE_DATA_BUFFER_GENERIC)(
					unsafe.Pointer(extraBuffer)),
				allocationSize, (*FSP_FSCTL_FILE_INFO)(
					unsafe.Pointer(fileInfoAddr)),
			)
		} else {
			return ref.createEx.CreateExWithExtendedAttribute(
				ref, utf16PtrToString(fileName),
				createOptions, grantedAccess, fileAttributes,
				(*windows.SECURITY_DESCRIPTOR)(
					unsafe.Pointer(securityDescriptor)),
				(*FILE_FULL_EA_INFORMATION)(
					unsafe.Pointer(extraBuffer)),
				allocationSize, (*FSP_FSCTL_FILE_INFO)(
					unsafe.Pointer(fileInfoAddr)),
			)
		}
	}()
	if err != nil {
		return convertNTStatus(err)
	}
	*file = result
	return windows.STATUS_SUCCESS
}

var go_delegateCreateEx = syscall.NewCallbackCDecl(func(
	fileSystem, fileName uintptr,
	createOptions, grantedAccess, fileAttributes uint32,
	securityDescriptor uintptr, allocationSize uint64,
	extraBuffer uintptr, extraLength uint32, isReparse uint8,
	file *uintptr, fileInfoAddr uintptr,
) uintptr {
	return uintptr(delegateCreateEx(
		fileSystem, fileName,
		createOptions, grantedAccess, fileAttributes,
		securityDescriptor, allocationSize,
		extraBuffer, extraLength, isReparse,
		file, fileInfoAddr,
	))
})

type option struct {
	caseSensitive  bool
	volumePrefix   string
	fileSystemName string
	passPattern    bool
	creationTime   time.Time
}

func newOption() *option {
	return &option{
		caseSensitive:  false,
		volumePrefix:   "",
		fileSystemName: "WinFSP",
		creationTime:   time.Now(),
	}
}

// Option is the options that could be passed to mount.
type Option func(*option)

// CaseSensitive is used to indicate whether the underlying
// file system can be distinguied case sensitively.
//
// This value should be set depending on your filesystem's
// implementation. On windows, it is very likely that the
// filesystem is case insensitive, so we set this value to
// false by default.
func CaseSensitive(value bool) Option {
	return func(o *option) {
		o.caseSensitive = value
	}
}

// VolumePrefix sets the volume prefix on mounting.
//
// Specifying volume prefix will turn the filesystem into
// a network device instead of the disk one.
func VolumePrefix(value string) Option {
	return func(o *option) {
		o.volumePrefix = value
	}
}

// FileSystemName sets the file system's type for display.
func FileSystemName(value string) Option {
	return func(o *option) {
		o.fileSystemName = value
	}
}

// CreationTime sets the volume creation time explicitly,
// instead of using the timestamp of calling mount.
func CreationTime(value time.Time) Option {
	return func(o *option) {
		o.creationTime = value
	}
}

// PassPattern specifies whether the pattern for read
// directory should be passed.
func PassPattern(value bool) Option {
	return func(o *option) {
		o.passPattern = value
	}
}

// Options is used to aggregate a bundle of options.
func Options(opts ...Option) Option {
	return func(o *option) {
		for _, opt := range opts {
			opt(o)
		}
	}
}

const (
	fspNetDeviceName  = "WinFSP.Net"
	fspDiskDeviceName = "WinFSP.Disk"
)

var (
	fileSystemCreate *syscall.Proc
	fileSystemDelete *syscall.Proc
	setMountPoint    *syscall.Proc
	startDispatcher  *syscall.Proc
	stopDispatcher   *syscall.Proc
)

// Mount attempts to mount a file system to specified mount
// point, returning the handle to the real filesystem.
func Mount(
	fs BehaviourBase, mountpoint string, opts ...Option,
) (*FileSystem, error) {
	if fs == nil {
		return nil, errors.New("invalid nil fs parameter")
	}
	if err := tryLoadWinFSP(); err != nil {
		return nil, err
	}
	option := newOption()
	Options(opts...)(option)
	created := false

	// Place the reference map right now.
	result := &FileSystem{}
	fileSystemRef := &result.FileSystemRef
	fileSystemAddr := uintptr(unsafe.Pointer(fileSystemRef))
	_, loaded := refMap.LoadOrStore(fileSystemAddr, fileSystemRef)
	if loaded {
		return nil, errors.New("out of memory")
	}
	defer func() {
		if !created {
			refMap.Delete(fileSystemAddr)
		}
	}()
	attributes := uint32(0)
	if option.caseSensitive {
		attributes |= FspFSAttributeCaseSensitive
	}
	attributes |= FspFSAttributeCasePreservedNames
	attributes |= FspFSAttributeUnicodeOnDisk
	attributes |= FspFSAttributePersistentAcls
	attributes |= FspFSAttributeFlushAndPurgeOnCleanup
	if option.passPattern {
		attributes |= FspFSAttributePassQueryDirectoryPattern
	}
	attributes |= FspFSAttributeUmFileContextIsUserContext2

	// Intepret the behaviours to convert interface.
	//
	// XXX: we will also need to store the fileSystemOps into
	// the fileSystemRef, since the FspFileSystemCreate will
	// create reference to this object, which might be GC-ed
	// and reused by the golang's runtime.
	fileSystemOps := &FSP_FILE_SYSTEM_INTERFACE{}
	fileSystemRef.base = fs
	fileSystemRef.fileSystemOps = fileSystemOps
	fileSystemOps.Open = go_delegateOpen
	fileSystemOps.Close = go_delegateClose
	if inner, ok := fs.(BehaviourGetVolumeInfo); ok {
		fileSystemRef.getVolumeInfo = inner
		fileSystemOps.GetVolumeInfo = go_delegateGetVolumeInfo
	}
	if inner, ok := fs.(BehaviourSetVolumeLabel); ok {
		fileSystemRef.setVolumeLabel = inner
		fileSystemOps.SetVolumeLabel = go_delegateSetVolumeLabel
	}
	if inner, ok := fs.(BehaviourGetSecurityByName); ok {
		fileSystemRef.getSecurityByName = inner
		fileSystemOps.GetSecurityByName = go_delegateGetSecurityByName
	}
	if inner, ok := fs.(BehaviourCreateEx); ok {
		fileSystemRef.createEx = inner
		fileSystemOps.CreateEx = go_delegateCreateEx
	} else if inner, ok := fs.(BehaviourCreate); ok {
		fileSystemRef.create = inner
		fileSystemOps.Create = go_delegateCreate
	}
	if inner, ok := fs.(BehaviourOverwrite); ok {
		fileSystemRef.overwrite = inner
		fileSystemOps.Overwrite = go_delegateOverwrite
	}
	if inner, ok := fs.(BehaviourCleanup); ok {
		fileSystemRef.cleanup = inner
		fileSystemOps.Cleanup = go_delegateCleanup
	}
	if inner, ok := fs.(BehaviourRead); ok {
		fileSystemRef.read = inner
		fileSystemOps.Read = go_delegateRead
	}
	if inner, ok := fs.(BehaviourWrite); ok {
		fileSystemRef.write = inner
		fileSystemOps.Write = go_delegateWrite
	}
	if inner, ok := fs.(BehaviourFlush); ok {
		fileSystemRef.flush = inner
		fileSystemOps.Flush = go_delegateFlush
	}
	if inner, ok := fs.(BehaviourGetFileInfo); ok {
		fileSystemRef.getFileInfo = inner
		fileSystemOps.GetFileInfo = go_delegateGetFileInfo
	}
	if inner, ok := fs.(BehaviourSetFileSize); ok {
		fileSystemRef.setFileSize = inner
		fileSystemOps.SetFileSize = go_delegateSetFileSize
	}
	if inner, ok := fs.(BehaviourCanDelete); ok {
		fileSystemRef.canDelete = inner
		fileSystemOps.CanDelete = go_delegateCanDelete
	}
	if inner, ok := fs.(BehaviourRename); ok {
		fileSystemRef.rename = inner
		fileSystemOps.Rename = go_delegateRename
	}
	if inner, ok := fs.(BehaviourGetSecurity); ok {
		fileSystemRef.getSecurity = inner
		fileSystemOps.GetSecurity = go_delegateGetSecurity
	}
	if inner, ok := fs.(BehaviourSetSecurity); ok {
		fileSystemRef.setSecurity = inner
		fileSystemOps.SetSecurity = go_delegateSetSecurity
	}
	if inner, ok := fs.(BehaviourReadDirectoryRaw); ok {
		fileSystemRef.readDirRaw = inner
		fileSystemOps.ReadDirectory = go_delegateReadDirectory
	} else if inner, ok := fs.(BehaviourReadDirectory); ok {
		fileSystemRef.readDirRaw = &behaviourReadDirectoryDelegate{
			readDir: inner,
		}
		fileSystemOps.ReadDirectory = go_delegateReadDirectory
	}
	if inner, ok := fs.(BehaviourGetDirInfoByName); ok {
		fileSystemRef.getDirInfoByName = inner
		fileSystemOps.GetDirInfoByName = go_delegateGetDirInfoByName
	}
	if inner, ok := fs.(BehaviourDeviceIoControl); ok {
		fileSystemRef.deviceIoControl = inner
		fileSystemOps.Control = go_delegateDeviceIoControl
	}

	// Convert the file system names into their wchar types.
	convertError := func(err error, content string) error {
		return errors.Wrapf(err, "string %q convert utf16", content)
	}
	utf16Prefix, err := windows.UTF16FromString(option.volumePrefix)
	if err != nil {
		return nil, convertError(err, option.volumePrefix)
	}
	utf16Name, err := windows.UTF16FromString(option.fileSystemName)
	if err != nil {
		return nil, convertError(err, option.fileSystemName)
	}
	utf16MountPoint, err := windows.UTF16PtrFromString(mountpoint)
	if err != nil {
		return nil, convertError(err, mountpoint)
	}
	driverName := fspDiskDeviceName
	if option.volumePrefix != "" {
		driverName = fspNetDeviceName
	}
	utf16Driver, err := windows.UTF16PtrFromString(driverName)
	if err != nil {
		return nil, convertError(err, driverName)
	}

	// Convert and file the volume parameters for mounting.
	volumeParams := &FSP_FSCTL_VOLUME_PARAMS_V1{}
	sizeOfVolumeParamsV1 := uint16(unsafe.Sizeof(
		FSP_FSCTL_VOLUME_PARAMS_V1{}))
	volumeParams.SizeOfVolumeParamsV1 = sizeOfVolumeParamsV1
	volumeParams.SectorSize = 1
	volumeParams.SectorsPerAllocationUnit = 4096
	nowFiletime := syscall.NsecToFiletime(
		option.creationTime.UnixNano())
	volumeParams.VolumeCreationTime =
		*(*uint64)(unsafe.Pointer(&nowFiletime))
	volumeParams.FileSystemAttribute = attributes
	copy(volumeParams.Prefix[:], utf16Prefix)
	copy(volumeParams.FileSystemName[:], utf16Name)

	// Attempt to create the file system now.
	createResult, _, err := fileSystemCreate.Call(
		uintptr(unsafe.Pointer(utf16Driver)),
		uintptr(unsafe.Pointer(volumeParams)),
		uintptr(unsafe.Pointer(fileSystemOps)),
		uintptr(unsafe.Pointer(&result.fileSystem)),
	)
	runtime.KeepAlive(utf16Driver)
	createStatus := windows.NTStatus(createResult)
	if err == syscall.Errno(0) {
		err = nil
	}
	if err == nil && createStatus != windows.STATUS_SUCCESS {
		err = createStatus
	}
	if err != nil && err != windows.STATUS_SUCCESS {
		return nil, errors.Wrap(err, "create file system")
	}
	defer func() {
		if !created {
			_, _, _ = fileSystemDelete.Call(
				uintptr(unsafe.Pointer(result.fileSystem)))
		}
	}()
	result.fileSystem.UserContext = fileSystemAddr

	// Attempt to mount the file system at mount point.
	mountResult, _, err := setMountPoint.Call(
		uintptr(unsafe.Pointer(result.fileSystem)),
		uintptr(unsafe.Pointer(utf16MountPoint)),
	)
	runtime.KeepAlive(utf16MountPoint)
	mountStatus := windows.NTStatus(mountResult)
	if err == syscall.Errno(0) {
		err = nil
	}
	if err == nil && mountStatus != windows.STATUS_SUCCESS {
		err = mountStatus
	}
	if err != nil && err != windows.STATUS_SUCCESS {
		return nil, errors.Wrap(err, "mount file system")
	}

	// Attempt to start the file system dispatcher.
	startResult, _, err := startDispatcher.Call(
		uintptr(unsafe.Pointer(result.fileSystem)), uintptr(0),
	)
	startStatus := windows.NTStatus(startResult)
	if err == syscall.Errno(0) {
		err = nil
	}
	if err == nil && startStatus != windows.STATUS_SUCCESS {
		err = startStatus
	}
	if err != nil && err != windows.STATUS_SUCCESS {
		return nil, errors.Wrap(err, "start dispatcher")
	}
	defer func() {
		if !created {
			_, _, _ = stopDispatcher.Call(
				uintptr(unsafe.Pointer(result.fileSystem)))
		}
	}()
	created = true
	return result, nil
}

// Unmount destroy the created file system.
func (f *FileSystem) Unmount() {
	fileSystem := uintptr(unsafe.Pointer(f.fileSystem))
	_, _, _ = stopDispatcher.Call(fileSystem)
	_, _, _ = fileSystemDelete.Call(fileSystem)
}

// loadWinFSPDLL attempts to locate and load the DLL, the
// library handle will be available from now on.
func loadWinFSPDLL() (*syscall.DLL, error) {
	dllName := ""
	switch runtime.GOARCH {
	case "arm64":
		dllName = "winfsp-a64.dll"
	case "amd64":
		dllName = "winfsp-x64.dll"
	case "386":
		dllName = "winfsp-x86.dll"
	}
	if dllName == "" {
		// Current platform does not have winfsp shipped
		// with it, and we can only report the error.
		return nil, errors.Errorf(
			"winfsp unsupported arch %q", runtime.GOARCH)
	}
	dll, _ := syscall.LoadDLL(dllName)
	if dll != nil {
		return dll, nil
	}

	// Well, we must lookup the registry to find our
	// winFSP installation now.
	findInstallError := func(err error) error {
		return errors.Wrapf(err, "winfsp find installation")
	}
	var keyReg syscall.Handle // HKLM\\Software\\WinFSP
	keyName, err := syscall.UTF16PtrFromString("Software\\WinFsp")
	if err != nil {
		return nil, findInstallError(err)
	}
	if err := syscall.RegOpenKeyEx(
		syscall.HKEY_LOCAL_MACHINE, keyName, 0,
		syscall.KEY_READ|syscall.KEY_WOW64_32KEY, &keyReg,
	); err != nil {
		return nil, findInstallError(err)
	}
	defer syscall.RegCloseKey(keyReg)
	valueName, err := syscall.UTF16PtrFromString("InstallDir")
	if err != nil {
		return nil, findInstallError(err)
	}
	var pathBuf [syscall.MAX_PATH]uint16
	var valueType, valueSize uint32
	valueSize = uint32(len(pathBuf)) * SIZEOF_WCHAR
	if err := syscall.RegQueryValueEx(
		keyReg, valueName, nil, &valueType,
		(*byte)(unsafe.Pointer(&pathBuf)), &valueSize,
	); err != nil {
		return nil, findInstallError(err)
	}
	if valueType != syscall.REG_SZ {
		return nil, findInstallError(syscall.ERROR_MOD_NOT_FOUND)
	}
	path := pathBuf[:int(valueSize/SIZEOF_WCHAR)]
	if len(path) > 0 && path[len(path)-1] == 0 {
		path = path[:len(path)-1]
	}
	installPath := syscall.UTF16ToString(path)

	// Attempt to load the DLL that we have found.
	return syscall.LoadDLL(filepath.Join(
		installPath, "bin", dllName))
}

var (
	winFSPDLL *syscall.DLL
)

func findProc(name string, target **syscall.Proc) error {
	proc, err := winFSPDLL.FindProc(name)
	if err != nil {
		return errors.Wrapf(err,
			"winfsp cannot find proc %q", name)
	}
	*target = proc
	return nil
}

func loadProcs(procs map[string]**syscall.Proc) error {
	for name, proc := range procs {
		if err := findProc(name, proc); err != nil {
			return err
		}
	}
	return nil
}

func initWinFSP() error {
	dll, err := loadWinFSPDLL()
	if err != nil {
		return err
	}
	winFSPDLL = dll
	return loadProcs(map[string]**syscall.Proc{
		"FspFileSystemDeleteDirectoryBuffer":  &deleteDirectoryBuffer,
		"FspFileSystemAcquireDirectoryBuffer": &acquireDirectoryBuffer,
		"FspFileSystemReleaseDirectoryBuffer": &releaseDirectoryBuffer,
		"FspFileSystemReadDirectoryBuffer":    &readDirectoryBuffer,
		"FspFileSystemFillDirectoryBuffer":    &fillDirectoryBuffer,
		"FspFileSystemCreate":                 &fileSystemCreate,
		"FspFileSystemDelete":                 &fileSystemDelete,
		"FspFileSystemSetMountPoint":          &setMountPoint,
		"FspFileSystemStartDispatcher":        &startDispatcher,
		"FspFileSystemStopDispatcher":         &stopDispatcher,
	})
}

var (
	tryLoadOnce sync.Once
	tryLoadErr  error
)

// tryLoadWinFSP attempts to load the WinFSP DLL, the work
// is done once and error will be persistent.
func tryLoadWinFSP() error {
	tryLoadOnce.Do(func() {
		tryLoadErr = initWinFSP()
	})
	return tryLoadErr
}
