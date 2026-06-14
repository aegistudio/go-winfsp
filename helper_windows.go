package winfsp

import (
	"runtime"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

// Well, for this file, a function exported by WinFSP
// DLL is not qualified to be placed here unless it has
// been marked as "helper" in the
// "winfsp/winfsp.h" header file.
const ()

// PosixMapSecurityDescriptorToPermissions
var posixMapSecurityDescriptorToPermissions dllProc

func init() {
	registerProc(
		"FspPosixMapSecurityDescriptorToPermissions",
		&posixMapSecurityDescriptorToPermissions,
	)
}

// PosixMapSecurityDescriptorToPermissions maps a Windows security descriptor to POSIX permissions.
//
// Will load WinFSP DLL if it has not been loaded, and **panic** if it
// fails to load. If you don't want to panic, you should consider calling
// `LoadWinFSP` or `LoadWinFSPWithDLL` and avoid calling this function
// if it fails to load.
func PosixMapSecurityDescriptorToPermissions(
	securityDescriptor *windows.SECURITY_DESCRIPTOR,
) (uid, gid, mode uint32, err error) {
	err = posixMapSecurityDescriptorToPermissions.CallStatus(
		uintptr(unsafe.Pointer(securityDescriptor)),
		uintptr(unsafe.Pointer(&uid)),
		uintptr(unsafe.Pointer(&gid)),
		uintptr(unsafe.Pointer(&mode)),
	)
	runtime.KeepAlive(securityDescriptor)
	if err != nil {
		return 0, 0, 0, errors.Wrap(err, "FspPosixMapSecurityDescriptorToPermissions")
	}

	return uid, gid, mode, nil
}

var posixMapSidToUid dllProc

func init() {
	registerProc("FspPosixMapSidToUid", &posixMapSidToUid)
}

// PosixMapSidToUid maps a Windows SID to a POSIX UID.
//
// Will load WinFSP DLL if it has not been loaded, and **panic** if it
// fails to load. If you don't want to panic, you should consider calling
// `LoadWinFSP` or `LoadWinFSPWithDLL` and avoid calling this function
// if it fails to load.
func PosixMapSidToUid(sid *windows.SID) (uint32, error) {
	var uid uint32
	err := posixMapSidToUid.CallStatus(
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&uid)),
	)
	runtime.KeepAlive(sid)
	if err != nil {
		return 0, errors.Wrap(err, "FspPosixMapSidToUid")
	}
	return uid, nil
}

var posixMapUidToSid dllProc

func init() {
	registerProc("FspPosixMapUidToSid", &posixMapUidToSid)
}

var deleteSid dllProc

func init() {
	registerProc("FspDeleteSid", &deleteSid)
}

// PosixMapUidToSid maps a POSIX UID to a Windows SID.
//
// Will load WinFSP DLL if it has not been loaded, and **panic** if it
// fails to load. If you don't want to panic, you should consider calling
// `LoadWinFSP` or `LoadWinFSPWithDLL` and avoid calling this function
// if it fails to load.
func PosixMapUidToSid(uid uint32) (*windows.SID, error) {
	var sid *windows.SID
	err := posixMapUidToSid.CallStatus(
		uintptr(uid),
		uintptr(unsafe.Pointer(&sid)),
	)
	if err != nil {
		return nil, errors.Wrap(err, "FspPosixMapUidToSid")
	}

	// The SID is owned by WinFSP's allocator, so it can't just be returned (it
	// would leak) nor freed with LocalFree/GC.
	defer func() {
		deleteSid.Call(
			uintptr(unsafe.Pointer(sid)),
			posixMapUidToSid.proc.Addr(),
		)
		runtime.KeepAlive(sid)
	}()

	// Return a Go-managed copy.
	return sid.Copy()
}

var setSecurityDescriptor dllProc

func init() {
	registerProc("FspSetSecurityDescriptor", &setSecurityDescriptor)
}

// SetSecurityDescriptor modifies a security descriptor.
//
// This is a helper for implementing the SetSecurity operation.
// It modifies an input security descriptor based on the provided
// security information and modification descriptor.
//
// The windows.SECURITY_DESCRIPTOR returned by this function must be
// manually freed by invoking DeleteSecurityDescriptor.
//
// Will load WinFSP DLL if it has not been loaded, and **panic** if it
// fails to load. If you don't want to panic, you should consider calling
// `LoadWinFSP` or `LoadWinFSPWithDLL` and avoid calling this function
// if it fails to load.
func SetSecurityDescriptor(
	inputDescriptor *windows.SECURITY_DESCRIPTOR,
	securityInformation windows.SECURITY_INFORMATION,
	modificationDescriptor *windows.SECURITY_DESCRIPTOR,
) (*windows.SECURITY_DESCRIPTOR, error) {
	var outputDescriptor *windows.SECURITY_DESCRIPTOR
	err := setSecurityDescriptor.CallStatus(
		uintptr(unsafe.Pointer(inputDescriptor)),
		uintptr(securityInformation),
		uintptr(unsafe.Pointer(modificationDescriptor)),
		uintptr(unsafe.Pointer(&outputDescriptor)),
	)
	runtime.KeepAlive(inputDescriptor)
	runtime.KeepAlive(modificationDescriptor)
	if err != nil {
		return nil, errors.Wrap(err, "FspSetSecurityDescriptor")
	}
	return outputDescriptor, nil
}

var deleteSecurityDescriptor dllProc

func init() {
	registerProc("FspDeleteSecurityDescriptor", &deleteSecurityDescriptor)
}

// DeleteSecurityDescriptor deletes a security descriptor.
//
// This is a helper for cleaning up security descriptors created
// by SetSecurityDescriptor.
//
// Will load WinFSP DLL if it has not been loaded, and **panic** if it
// fails to load. If you don't want to panic, you should consider calling
// `LoadWinFSP` or `LoadWinFSPWithDLL` and avoid calling this function
// if it fails to load.
func DeleteSecurityDescriptor(securityDescriptor *windows.SECURITY_DESCRIPTOR) error {
	// Since we will be referring to setSecurityDescriptor.proc
	// later, which must be initialized.
	setSecurityDescriptor.EnsureInitialized()

	// Pass a function pointer to indicate this was created by FspSetSecurityDescriptor
	// The C API expects this to match the function that created the descriptor
	_, err := deleteSecurityDescriptor.Call(
		uintptr(unsafe.Pointer(securityDescriptor)),
		uintptr(unsafe.Pointer(setSecurityDescriptor.proc)),
	)
	runtime.KeepAlive(securityDescriptor)
	if err != nil {
		return errors.Wrap(err, "FspDeleteSecurityDescriptor")
	}
	return nil
}

var debugLogSetHandle dllProc

func init() {
	registerProc("FspDebugLogSetHandle", &debugLogSetHandle)
}

// DebugLogSetHandle sets the debug log handle for WinFSP debugging output.
//
// This function sets the handle where debug messages will be written when debug
// logging is enabled. The handle should be a valid Windows file handle.
//
// Will load WinFSP DLL if it has not been loaded, and **panic** if it
// fails to load. If you don't want to panic, you should consider calling
// `LoadWinFSP` or `LoadWinFSPWithDLL` and avoid calling this function
// if it fails to load.
func DebugLogSetHandle(handle syscall.Handle) error {
	_, err := debugLogSetHandle.Call(uintptr(handle))
	if err != nil {
		return errors.Wrap(err, "FspDebugLogSetHandle")
	}
	return nil
}

var fileSystemOperationProcessId dllProc

func init() {
	registerProc("FspFileSystemOperationProcessIdF", &fileSystemOperationProcessId)
}

// FileSystemOperationProcessId gets the originating process ID.
//
// Valid only during Create, Open and Rename requests when the target exists.
// This function can only be called from within a file system operation handler.
//
// Will load WinFSP DLL if it has not been loaded, and **panic** if it
// fails to load. If you don't want to panic, you should consider calling
// `LoadWinFSP` or `LoadWinFSPWithDLL` and avoid calling this function
// if it fails to load.
func FileSystemOperationProcessId() uint32 {
	result, _ := fileSystemOperationProcessId.Call()
	return uint32(result)
}

var fileSystemFindReparsePoint dllProc

func init() {
	registerProc("FspFileSystemFindReparsePoint", &fileSystemFindReparsePoint)
}

// FindReparsePoint delegates the operation (most likely
// GetSecurityByName) to the underlying
// BehaviourGetReparsePointByName.GetReparsePointByName.
func (fileSystem *FileSystemRef) FindReparsePoint(
	fileName string,
) (bool, uint32, error) {
	utf16FileName, err := windows.UTF16PtrFromString(fileName)
	if err != nil {
		return false, 0, errors.Wrap(err, "convert filename to UTF16")
	}

	var reparsePointIndex uint32

	result, err := fileSystemFindReparsePoint.Call(
		uintptr(unsafe.Pointer(fileSystem.fileSystem)), // FileSystem
		go_delegateGetReparsePointByName,               // GetReparsePointByName callback
		uintptr(0),                                     // Context (unused)
		uintptr(unsafe.Pointer(utf16FileName)),         // FileName
		uintptr(unsafe.Pointer(&reparsePointIndex)),    // PReparsePointIndex
	)
	runtime.KeepAlive(fileSystem.fileSystem)
	runtime.KeepAlive(utf16FileName)

	if err != nil {
		return false, 0, errors.Wrap(err, "FspFileSystemFindReparsePoint")
	}
	return byte(result) != 0, reparsePointIndex, nil
}

// FileSystemFindReparsePoint delegates the operation (most
// likely GetSecurityByName) to the underlying
// BehaviourGetReparsePointByName.GetReparsePointByName.
//
// Will load WinFSP DLL if it has not been loaded, and **panic** if it
// fails to load. If you don't want to panic, you should consider calling
// `LoadWinFSP` or `LoadWinFSPWithDLL` and avoid calling this function
// if it fails to load.
//
// Deprecated: Use FileSystemRef.FindReparsePoint. Will be
// removed in the later versions.
func FileSystemFindReparsePoint(
	fileSystem *FileSystemRef, fileName string,
) (bool, uint32, error) {
	return fileSystem.FindReparsePoint(fileName)
}
