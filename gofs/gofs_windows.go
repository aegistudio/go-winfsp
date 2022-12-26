package gofs

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"

	"github.com/aegistudio/go-winfsp"
	"github.com/aegistudio/go-winfsp/filetime"
	"github.com/aegistudio/go-winfsp/pathlock"
	"github.com/aegistudio/go-winfsp/procsd"
)

type File interface {
	io.ReadWriteCloser
	io.ReaderAt
	io.WriterAt
	io.Seeker

	Readdir(count int) ([]os.FileInfo, error)
	Stat() (os.FileInfo, error)
	Sync() error
	Truncate(size int64) error
}

type FileSystem interface {
	OpenFile(name string, flag int, perm os.FileMode) (File, error)
	Mkdir(name string, perm os.FileMode) error
	Stat(name string) (os.FileInfo, error)
	Rename(source, target string) error
	Remove(name string) error
}

type fileHandle struct {
	lock  *pathlock.Lock
	dir   winfsp.DirBuffer
	file  File
	flags int
	mtx   sync.RWMutex

	evaluatedIndex uint64
}

type fileSystem struct {
	inner   FileSystem
	handles sync.Map
	locker  pathlock.PathLocker

	labelLen int
	label    [32]uint16
}

func (handle *fileHandle) reopenFile(fs *fileSystem) (File, error) {
	return fs.inner.OpenFile(
		handle.lock.FilePath(), handle.flags, os.FileMode(0))
}

func attributesFromFileMode(mode os.FileMode) uint32 {
	var attributes uint32
	if mode.IsDir() {
		attributes |= windows.FILE_ATTRIBUTE_DIRECTORY
	}
	if (uint32(mode.Perm()) & 0200) == 0 {
		attributes |= windows.FILE_ATTRIBUTE_READONLY
	}
	if attributes == 0 {
		attributes = windows.FILE_ATTRIBUTE_NORMAL
	}
	return attributes
}

func (fs *fileSystem) GetSecurityByName(
	ref *winfsp.FileSystemRef, name string,
	flags winfsp.GetSecurityByNameFlags,
) (uint32, *windows.SECURITY_DESCRIPTOR, error) {
	info, err := fs.inner.Stat(name)
	if err != nil || flags == winfsp.GetExistenceOnly {
		return 0, nil, err
	}
	attributes := attributesFromFileMode(info.Mode())
	var sd *windows.SECURITY_DESCRIPTOR
	if (flags & winfsp.GetSecurityByName) != 0 {
		// XXX: this is a mock up, the file is considered to
		// be owned by current process, so it is okay to
		// return the security descriptor of the process.
		sd, err = procsd.Load()
	}
	return attributes, sd, err
}

var _ winfsp.BehaviourGetSecurityByName = (*fileSystem)(nil)

func evaluateIndexNumber(p string) uint64 {
	// XXX: we evaluate the index number for a file by hashing,
	// so each file is identified by its path. Since we will not
	// support open by file ID in this scenario, it is okay to
	// simply map a path to its hash value.
	//
	// And we caches the index number right at file creation,
	// the index number will only be available while stating an
	// open file, not on reading directories.
	data := sha256.Sum256([]byte(p))
	a := binary.BigEndian.Uint64(data[0:8])
	b := binary.BigEndian.Uint64(data[8:16])
	c := binary.BigEndian.Uint64(data[16:24])
	d := binary.BigEndian.Uint64(data[24:32])
	return a ^ b ^ c ^ d
}

func fileInfoFromStat(
	target *winfsp.FSP_FSCTL_FILE_INFO, source os.FileInfo,
	evaluatedIndexNumber uint64,
) {
	target.FileAttributes = attributesFromFileMode(source.Mode())
	target.ReparseTag = 0
	target.FileSize = uint64(source.Size())
	target.AllocationSize = ((target.FileSize + 4095) / 4096) * 4096
	target.CreationTime = filetime.Timestamp(source.ModTime())
	target.LastAccessTime = target.CreationTime
	target.LastWriteTime = target.CreationTime
	target.ChangeTime = target.LastWriteTime
	target.IndexNumber = evaluatedIndexNumber
	target.HardLinks = 0
	target.EaSize = 0

	// We can extract more data from it if it is find data from
	// windows, which is the one from golang's standard library.
	sys := source.Sys()
	if sys == nil {
		return
	}
	findData, ok := sys.(*syscall.Win32FileAttributeData)
	if !ok {
		return
	}
	target.CreationTime = filetime.Filetime(findData.CreationTime)
	target.LastAccessTime = filetime.Filetime(findData.LastAccessTime)
	target.LastWriteTime = filetime.Filetime(findData.LastWriteTime)
	target.ChangeTime = target.LastWriteTime
}

const (
	// unsupportedCreateOptions are the options that are not
	// supported by the file system driver.
	//
	// There're many of them, but it is good to eliminate
	// behaviours that might violates the intention of the
	// caller processes and maintain the integrity of the
	// inner file system.
	unsupportedCreateOptions = windows.FILE_WRITE_THROUGH |
		windows.FILE_CREATE_TREE_CONNECTION |
		windows.FILE_NO_EA_KNOWLEDGE |
		windows.FILE_OPEN_BY_FILE_ID |
		windows.FILE_RESERVE_OPFILTER |
		windows.FILE_OPEN_REQUIRING_OPLOCK |
		windows.FILE_COMPLETE_IF_OPLOCKED |
		windows.FILE_OPEN_NO_RECALL

	// bothDirectoryFlags are the flags of directory or-ing
	// the non directory flags. If both flags are set, this
	// is obsolutely an invalid flag, you know.
	bothDirectoryFlags = windows.FILE_DIRECTORY_FILE |
		windows.FILE_NON_DIRECTORY_FILE
)

func (fs *fileSystem) openFile(
	ref *winfsp.FileSystemRef, name string,
	createOptions, grantedAccess uint32, mode os.FileMode,
	info *winfsp.FSP_FSCTL_FILE_INFO,
) (uintptr, error) {
	if createOptions&unsupportedCreateOptions != 0 {
		return 0, windows.STATUS_INVALID_PARAMETER
	}
	if createOptions&bothDirectoryFlags == bothDirectoryFlags {
		return 0, windows.STATUS_INVALID_PARAMETER
	}

	// Determine the current access flag for writer here.
	flags := 0
	accessFlags := 0
	readAccess := grantedAccess & windows.FILE_READ_DATA
	writeAccess := grantedAccess &
		(windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA)
	switch {
	case readAccess == 0 && writeAccess == 0:
	case readAccess != 0 && writeAccess == 0:
		accessFlags = os.O_RDONLY
	case readAccess == 0 && writeAccess != 0:
		accessFlags = os.O_WRONLY
	case readAccess != 0 && writeAccess != 0:
		accessFlags = os.O_RDWR
	}
	if writeAccess == windows.FILE_APPEND_DATA {
		flags |= os.O_APPEND
	}

	// Determine the creation mode for writer here.
	//
	// TODO: I've not studied the dispositions here carefully
	// so the actual behaviour might be bizarre, and it would
	// be helpful of you to correct them.
	disposition := (createOptions >> 24) & 0x0ff
	switch disposition {
	case windows.FILE_SUPERSEDE:
		// XXX: FILE_SUPERSEDE means to remove the file on disk
		// and then replace it by our file, we don't support
		// removing file while there's open file handles. But
		// it can still be open when it is the only one to open
		// the specified file.
		flags |= os.O_CREATE | os.O_TRUNC
	case windows.FILE_CREATE:
		flags |= os.O_CREATE | os.O_EXCL
	case windows.FILE_OPEN:
	case windows.FILE_OPEN_IF:
		flags |= os.O_CREATE
	case windows.FILE_OVERWRITE:
		flags |= os.O_TRUNC
	case windows.FILE_OVERWRITE_IF:
		flags |= os.O_CREATE | os.O_TRUNC
	default:
		return 0, windows.STATUS_INVALID_PARAMETER
	}

	// Lock the file with desired mode.
	lockFunc := fs.locker.RLock
	if (createOptions&windows.FILE_DELETE_ON_CLOSE != 0) ||
		(grantedAccess&windows.DELETE != 0) ||
		(disposition == windows.FILE_SUPERSEDE) {
		lockFunc = fs.locker.Lock
	}
	lock := lockFunc(name)
	if lock == nil {
		return 0, windows.STATUS_SHARING_VIOLATION
	}
	created := false
	defer func() {
		if !created {
			lock.Unlock()
		}
	}()

	// Attempt to allocate the file handle.
	handle := &fileHandle{
		lock: lock,
	}
	handleAddr := uintptr(unsafe.Pointer(handle))
	_, loaded := fs.handles.LoadOrStore(handleAddr, handle)
	if loaded {
		return 0, windows.ERROR_NOT_ENOUGH_MEMORY
	}
	defer func() {
		if !created {
			fs.handles.Delete(handleAddr)
		}
	}()

	// Normalize the path to ensure identity of operation.
	name = lock.FilePath()

	// See if we are asked to create directories here.
	if (createOptions&windows.FILE_DIRECTORY_FILE != 0) &&
		(flags&os.O_CREATE != 0) {
		if flags&os.O_TRUNC != 0 {
			return 0, windows.STATUS_INVALID_PARAMETER
		}
		mode |= os.FileMode(0111)
		if err := fs.inner.Mkdir(name, mode); err != nil {
			if os.IsExist(err) ||
				errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
				err = windows.STATUS_OBJECT_NAME_COLLISION
				if flags&os.O_EXCL == 0 {
					err = nil
				}
			}
			if err != nil {
				return 0, err
			}
		}

		// Clear the flags since the create directory has
		// already been handled properly above.
		flags = 0
		mode = os.FileMode(0)
		accessFlags = os.O_RDONLY
	}

	// Attempt to open the file in the underlying file system.
	dirCheckErr := windows.STATUS_NOT_A_DIRECTORY
	file, err := fs.inner.OpenFile(name, accessFlags|flags, mode)
	if err != nil {
		// We will only try again if it complains about opening a
		// directory file failed, but we should be able to open the
		// directory with POSIX compatible flags.
		//
		// We will perform extra check to ensure we have really
		// opened a directory rather than been entangled in some
		// TOCTOU scenario.
		//
		// XXX: The O_RDONLY, O_WRONLY and O_APPEND flags (or their
		// preimages FILE_LIST_DIRECTORY, FILE_ADD_FILE and
		// FILE_ADD_SUBDIRECTORY) are not mandatory. All these
		// operations are retranslated into POSIX style operations.
		if (createOptions&bothDirectoryFlags !=
			windows.FILE_NON_DIRECTORY_FILE) &&
			(errors.Is(err, syscall.EISDIR) ||
				errors.Is(err, windows.STATUS_FILE_IS_A_DIRECTORY) ||
				errors.Is(err, windows.ERROR_DIRECTORY)) {
			accessFlags = os.O_RDONLY
			flags = 0
			file, err = fs.inner.OpenFile(name, accessFlags|flags, mode)
			createOptions |= windows.FILE_DIRECTORY_FILE
			dirCheckErr = windows.STATUS_OBJECT_NAME_NOT_FOUND
		}
		if err != nil {
			return 0, err
		}
	}
	defer func() {
		if !created {
			_ = file.Close()
		}
	}()
	handle.file = file
	handle.flags = accessFlags | (flags & os.O_APPEND)

	// Judge whether this is the stuff we would like to open.
	fileInfo, err := file.Stat()
	if err != nil {
		return 0, err
	}
	switch createOptions & bothDirectoryFlags {
	case windows.FILE_DIRECTORY_FILE:
		if !fileInfo.IsDir() {
			return 0, dirCheckErr
		}
	case windows.FILE_NON_DIRECTORY_FILE:
		if fileInfo.IsDir() {
			return 0, windows.STATUS_FILE_IS_A_DIRECTORY
		}
	default:
	}

	// Downgrade the lock to reader lock if it is the file
	// to supersede, and other processes can access it with
	// such flag from now on.
	if disposition == windows.FILE_SUPERSEDE {
		lock.Downgrade()
	}

	// Evaluate the file index for the file and cache it.
	handle.evaluatedIndex = evaluateIndexNumber(lock.Path())

	// Copy the status out to the file information block.
	fileInfoFromStat(info, fileInfo, handle.evaluatedIndex)

	// Finish opening the file and return to the caller.
	created = true
	return handleAddr, nil
}

func (fs *fileSystem) Create(
	ref *winfsp.FileSystemRef, name string,
	createOptions, grantedAccess, fileAttributes uint32,
	securityDescriptor *windows.SECURITY_DESCRIPTOR,
	allocationSize uint64, info *winfsp.FSP_FSCTL_FILE_INFO,
) (uintptr, error) {
	fileMode := os.FileMode(0444)
	if fileAttributes&windows.FILE_ATTRIBUTE_READONLY == 0 {
		fileMode |= os.FileMode(0666)
	}
	if fileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		fileMode |= os.FileMode(0111)
	}
	return fs.openFile(
		ref, name, createOptions, grantedAccess,
		fileMode, info,
	)
}

var _ winfsp.BehaviourCreate = (*fileSystem)(nil)

func (fs *fileSystem) Open(
	ref *winfsp.FileSystemRef, name string,
	createOptions, grantedAccess uint32,
	info *winfsp.FSP_FSCTL_FILE_INFO,
) (uintptr, error) {
	return fs.openFile(
		ref, name, createOptions, grantedAccess,
		os.FileMode(0), info,
	)
}

func (fs *fileSystem) load(file uintptr) (*fileHandle, error) {
	obj, ok := fs.handles.Load(file)
	if !ok {
		return nil, windows.STATUS_INVALID_HANDLE
	}
	return obj.(*fileHandle), nil
}

func (fs *fileSystem) Close(
	ref *winfsp.FileSystemRef, file uintptr,
) {
	object, ok := fs.handles.LoadAndDelete(file)
	if !ok {
		return
	}
	fileHandle := object.(*fileHandle)
	fileHandle.mtx.Lock()
	defer fileHandle.mtx.Unlock()
	defer fileHandle.lock.Unlock()
	defer fileHandle.dir.Delete()
	if fileHandle.file != nil {
		_ = fileHandle.file.Close()
		fileHandle.file = nil
	}
}

func (handle *fileHandle) lockChecked() error {
	handle.mtx.RLock()
	valid := false
	defer func() {
		if !valid {
			handle.mtx.RUnlock()
		}
	}()
	if handle.file == nil {
		return windows.STATUS_INVALID_HANDLE
	}
	valid = true
	return nil
}

func (handle *fileHandle) unlockChecked() {
	handle.mtx.RUnlock()
}

var _ winfsp.BehaviourBase = (*fileSystem)(nil)

func (fs *fileSystem) Overwrite(
	ref *winfsp.FileSystemRef, file uintptr,
	attributes uint32, replaceAttributes bool,
	allocationSize uint64,
	info *winfsp.FSP_FSCTL_FILE_INFO,
) error {
	handle, err := fs.load(file)
	if err != nil {
		return err
	}
	if err := handle.lockChecked(); err != nil {
		return err
	}
	defer handle.unlockChecked()
	if err := handle.file.Truncate(0); err != nil {
		return err
	}
	// TODO: support chmod operation in the future.
	//
	// It might seems like we are just ignoring the attribute
	// update but we might support them in the future.
	fileInfo, err := handle.file.Stat()
	if err != nil {
		return err
	}
	fileInfoFromStat(info, fileInfo, handle.evaluatedIndex)
	return nil
}

var _ winfsp.BehaviourOverwrite = (*fileSystem)(nil)

func (fs *fileSystem) GetOrNewDirBuffer(
	ref *winfsp.FileSystemRef, file uintptr,
) (*winfsp.DirBuffer, error) {
	fileHandle, err := fs.load(file)
	if err != nil {
		return nil, err
	}
	return &fileHandle.dir, nil
}

func (fs *fileSystem) ReadDirectory(
	ref *winfsp.FileSystemRef, file uintptr, pattern string,
	fill func(string, *winfsp.FSP_FSCTL_FILE_INFO) (bool, error),
) error {
	handle, err := fs.load(file)
	if err != nil {
		return err
	}
	if err := handle.lockChecked(); err != nil {
		return err
	}
	defer handle.unlockChecked()
	f, err := handle.reopenFile(fs)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fileInfos, err := f.Readdir(-1)
	if err != nil {
		return err
	}
	for _, fileInfo := range fileInfos {
		var info winfsp.FSP_FSCTL_FILE_INFO
		fileInfoFromStat(&info, fileInfo, 0)
		ok, err := fill(fileInfo.Name(), &info)
		if err != nil || !ok {
			return err
		}
	}
	return nil
}

var _ winfsp.BehaviourReadDirectory = (*fileSystem)(nil)

func (fs *fileSystem) GetFileInfo(
	ref *winfsp.FileSystemRef, file uintptr,
	info *winfsp.FSP_FSCTL_FILE_INFO,
) error {
	handle, err := fs.load(file)
	if err != nil {
		return err
	}
	if err := handle.lockChecked(); err != nil {
		return err
	}
	defer handle.unlockChecked()
	fileInfo, err := handle.file.Stat()
	if err != nil {
		return err
	}
	fileInfoFromStat(info, fileInfo, handle.evaluatedIndex)
	return nil
}

var _ winfsp.BehaviourGetFileInfo = (*fileSystem)(nil)

func (fs *fileSystem) GetSecurity(
	ref *winfsp.FileSystemRef, file uintptr,
) (*windows.SECURITY_DESCRIPTOR, error) {
	_, err := fs.load(file)
	if err != nil {
		return nil, err
	}
	return procsd.Load()
}

var _ winfsp.BehaviourGetSecurity = (*fileSystem)(nil)

func (fs *fileSystem) GetVolumeInfo(
	ref *winfsp.FileSystemRef, info *winfsp.FSP_FSCTL_VOLUME_INFO,
) error {
	// TODO: support file system remaining size query.
	info.TotalSize = 8 * 1024 * 1024 * 1024 * 1024 // 8TB
	info.FreeSize = info.TotalSize
	length := fs.labelLen
	info.VolumeLabelLength = 2 * uint16(copy(
		info.VolumeLabel[:length], fs.label[:length]))
	return nil
}

var _ winfsp.BehaviourGetVolumeInfo = (*fileSystem)(nil)

func (fs *fileSystem) SetVolumeLabel(
	ref *winfsp.FileSystemRef, label string,
	info *winfsp.FSP_FSCTL_VOLUME_INFO,
) error {
	utf16, err := windows.UTF16FromString(label)
	if err != nil {
		return err
	}
	fs.labelLen = copy(fs.label[:], utf16)
	return fs.GetVolumeInfo(ref, info)
}

var _ winfsp.BehaviourSetVolumeLabel = (*fileSystem)(nil)

func (fs *fileSystem) SetBasicInfo(
	ref *winfsp.FileSystemRef, file uintptr,
	flags winfsp.SetBasicInfoFlags, attribute uint32,
	creationTime, lastAccessTime, lastWriteTime, changeTime uint64,
	info *winfsp.FSP_FSCTL_FILE_INFO,
) error {
	handle, err := fs.load(file)
	if err != nil {
		return err
	}
	if err := handle.lockChecked(); err != nil {
		return err
	}
	defer handle.unlockChecked()
	fileInfo, err := handle.file.Stat()
	if err != nil {
		return err
	}
	fileInfoFromStat(info, fileInfo, handle.evaluatedIndex)
	return windows.STATUS_ACCESS_DENIED
}

var _ winfsp.BehaviourSetBasicInfo = (*fileSystem)(nil)

// FileTruncateEx is the truncate interface related to Windows
// style opertations. Without this interface, we will be
// imitating the set allocation size behaviour of file, making
// it behaves stragely under certain racing circumstances.
type FileTruncateEx interface {
	File

	// Shrink means it will not expand the file size if a size
	// greater than the file size is passed.
	Shrink(newSize int64) error
}

type fileMimicTruncate struct {
	File
}

func (f *fileMimicTruncate) Shrink(newSize int64) error {
	fileInfo, err := f.Stat()
	if err != nil {
		return err
	}
	if fileInfo.Size() > newSize {
		return f.Truncate(newSize)
	}
	return nil
}

func (fs *fileSystem) SetFileSize(
	ref *winfsp.FileSystemRef, file uintptr,
	newSize uint64, setAllocationSize bool,
	info *winfsp.FSP_FSCTL_FILE_INFO,
) error {
	handle, err := fs.load(file)
	if err != nil {
		return err
	}
	if err := handle.lockChecked(); err != nil {
		return err
	}
	defer handle.unlockChecked()
	size := int64(newSize)
	if setAllocationSize {
		var shrinker FileTruncateEx
		if obj, ok := handle.file.(FileTruncateEx); ok {
			shrinker = obj
		} else {
			shrinker = &fileMimicTruncate{
				File: handle.file,
			}
		}
		if err := shrinker.Shrink(size); err != nil {
			return err
		}
	} else {
		if err := handle.file.Truncate(size); err != nil {
			return err
		}
	}
	fileInfo, err := handle.file.Stat()
	if err != nil {
		return err
	}
	fileInfoFromStat(info, fileInfo, handle.evaluatedIndex)
	return nil
}

var _ winfsp.BehaviourSetFileSize = (*fileSystem)(nil)

func (fs *fileSystem) Read(
	ref *winfsp.FileSystemRef, file uintptr,
	buf []byte, offset uint64,
) (int, error) {
	handle, err := fs.load(file)
	if err != nil {
		return 0, err
	}
	if err := handle.lockChecked(); err != nil {
		return 0, err
	}
	defer handle.unlockChecked()
	// No matter random access or append only file handle
	// on windows should support random read.
	return handle.file.ReadAt(buf, int64(offset))
}

var _ winfsp.BehaviourRead = (*fileSystem)(nil)

// FileWriteEx is the write interface related to Windows style
// writing. Without this interface, we will be imitating the
// write behaviour of file, making it behaves strangely under
// certain racing circumstances.
type FileWriteEx interface {
	File

	// Append means the data will always be written to the
	// tail of the file, regardless of the file's current
	// open mode.
	Append([]byte) (int, error)

	// ConstrainedWriteAt means the data will be written at
	// specified offset and the data within the file's size
	// range will be copied out.
	ConstrainedWriteAt([]byte, int64) (int, error)
}

type fileMimicWrite struct {
	File
	flags int
}

func (f *fileMimicWrite) Append(b []byte) (int, error) {
	if f.flags&os.O_APPEND != 0 {
		return f.Write(b)
	} else {
		// BUG: since we imitates the append behaviour
		// by fetching the file size first and then
		// appending to it, two concurrent append
		// operations will overlaps with each other.
		fileInfo, err := f.Stat()
		if err != nil {
			return 0, err
		}
		return f.WriteAt(b, fileInfo.Size())
	}
}

func (f *fileMimicWrite) ConstrainedWriteAt(
	b []byte, offset int64,
) (int, error) {
	// BUG: this is also a buggy part when two
	// concurrent write operation happens. You
	// might expect the reordering of constrained
	// write operation and an boundary extending
	// operation.
	fileInfo, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := fileInfo.Size()
	if offset >= size {
		return 0, nil
	} else if offset+int64(len(b)) >= size {
		b = b[:len(b)+int(size-offset)]
	}
	return f.WriteAt(b, offset)
}

func (fs *fileSystem) Write(
	ref *winfsp.FileSystemRef, file uintptr,
	b []byte, offset uint64,
	writeToEndOfFile, constrainedIo bool,
	info *winfsp.FSP_FSCTL_FILE_INFO,
) (int, error) {
	handle, err := fs.load(file)
	if err != nil {
		return 0, err
	}
	if (handle.flags&os.O_APPEND != 0) && !writeToEndOfFile {
		// You may not write to an append-only file.
		return 0, windows.STATUS_ACCESS_DENIED
	}
	if err := handle.lockChecked(); err != nil {
		return 0, err
	}
	defer handle.unlockChecked()
	var writer FileWriteEx
	if obj, ok := handle.file.(FileWriteEx); ok {
		writer = obj
	} else {
		writer = &fileMimicWrite{
			File:  handle.file,
			flags: handle.flags,
		}
	}
	var n int
	if writeToEndOfFile && constrainedIo {
		// Nothing to do here.
	} else if writeToEndOfFile {
		n, err = writer.Append(b)
	} else if constrainedIo {
		n, err = writer.ConstrainedWriteAt(b, int64(offset))
	} else {
		n, err = handle.file.WriteAt(b, int64(offset))
	}
	fileInfo, statErr := handle.file.Stat()
	if statErr != nil && err == nil {
		err = statErr
	}
	if fileInfo != nil {
		// XXX: since the driver code just take the information
		// field for notification and display purpose, so only
		// the lastly updated information is required.
		fileInfoFromStat(info, fileInfo, handle.evaluatedIndex)
	}
	return n, err
}

var _ winfsp.BehaviourWrite = (*fileSystem)(nil)

func (fs *fileSystem) Flush(
	ref *winfsp.FileSystemRef, file uintptr,
	info *winfsp.FSP_FSCTL_FILE_INFO,
) error {
	if file == 0 {
		// Flush the whole filesystem, not a single file.
		return nil
	}
	handle, err := fs.load(file)
	if err != nil {
		return err
	}
	if err := handle.lockChecked(); err != nil {
		return err
	}
	defer handle.unlockChecked()
	if err := handle.file.Sync(); err != nil {
		return err
	}
	fileInfo, err := handle.file.Stat()
	if err != nil {
		return err
	}
	fileInfoFromStat(info, fileInfo, handle.evaluatedIndex)
	return nil
}

var _ winfsp.BehaviourFlush = (*fileSystem)(nil)

func (fs *fileSystem) CanDelete(
	ref *winfsp.FileSystemRef, file uintptr,
	name string,
) error {
	handle, err := fs.load(file)
	if err != nil {
		return err
	}
	if err := handle.lockChecked(); err != nil {
		return err
	}
	defer handle.unlockChecked()
	if !handle.lock.IsWrite() {
		return windows.STATUS_ACCESS_DENIED
	}
	fileInfo, err := handle.file.Stat()
	if err != nil {
		return err
	}
	if !fileInfo.IsDir() {
		return nil
	}
	f, err := handle.reopenFile(fs)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fileInfos, err := f.Readdir(-1)
	if err != nil {
		return err
	}
	if len(fileInfos) > 0 {
		return windows.STATUS_DIRECTORY_NOT_EMPTY
	}
	return nil
}

var _ winfsp.BehaviourCanDelete = (*fileSystem)(nil)

func (fs *fileSystem) Cleanup(
	ref *winfsp.FileSystemRef, file uintptr,
	name string, cleanupFlags uint32,
) {
	handle, err := fs.load(file)
	if err != nil {
		return
	}
	if cleanupFlags&winfsp.FspCleanupDelete == 0 {
		return
	}
	if !handle.lock.IsWrite() {
		return
	}
	handle.mtx.Lock()
	defer handle.mtx.Unlock()
	if handle.file == nil {
		return
	}
	_ = handle.file.Close()
	handle.file = nil
	_ = fs.inner.Remove(handle.lock.FilePath())
}

var _ winfsp.BehaviourCleanup = (*fileSystem)(nil)

func (fs *fileSystem) Rename(
	ref *winfsp.FileSystemRef, file uintptr,
	source, target string, replaceIfExist bool,
) error {
	handle, err := fs.load(file)
	if err != nil {
		return err
	}
	if !handle.lock.IsWrite() {
		return windows.STATUS_ACCESS_DENIED
	}
	handle.mtx.Lock()
	defer handle.mtx.Unlock()
	if handle.file == nil {
		return windows.STATUS_INVALID_HANDLE
	}

	// Try to grab the target path's lock. And upon exit
	// either the source or the target lock will be released.
	newLock := fs.locker.Lock(target)
	if newLock == nil {
		return windows.STATUS_SHARING_VIOLATION
	}
	target = newLock.FilePath()
	defer func() { newLock.Unlock() }()

	// Check for the rename precondition so that we could
	// avoid performing sophiscated operations.
	if !replaceIfExist {
		fileInfo, err := fs.inner.Stat(target)
		if err != nil && !os.IsNotExist(err) &&
			!errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
			return err
		}
		if fileInfo != nil {
			return windows.STATUS_OBJECT_NAME_COLLISION
		}
	}

	// After exit, the remaining file will be reopened and
	// seek to its orignal offset, so that we can continue
	// our operations.
	fileInfo, err := handle.file.Stat()
	if err != nil {
		return err
	}
	var pos *int64
	if fileInfo.Mode().IsRegular() {
		value, err := handle.file.Seek(0, os.SEEK_CUR)
		if err != nil {
			return err
		}
		pos = new(int64)
		*pos = value
	}
	_ = handle.file.Close()
	handle.file = nil
	defer func() {
		f, err := handle.reopenFile(fs)
		if err != nil {
			return
		}
		defer func() {
			if f != nil {
				_ = f.Close()
			}
		}()
		if pos != nil {
			if _, err := f.Seek(*pos, os.SEEK_SET); err != nil {
				return
			}
		}
		handle.file, f = f, nil
	}()

	// Attempt to perform the rename operation now.
	source = handle.lock.FilePath()
	if err := fs.inner.Rename(source, target); err != nil {
		return err
	}
	handle.lock, newLock = newLock, handle.lock
	return nil
}

var _ winfsp.BehaviourRename = (*fileSystem)(nil)

func New(fs FileSystem) winfsp.BehaviourBase {
	return &fileSystem{
		inner: fs,
	}
}
