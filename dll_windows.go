package winfsp

import (
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

// BinPath returns the path to the bin folder where WinFSP is
// installed.
func BinPath() (string, error) {
	// Well, we must lookup the registry to find our
	// winFSP installation now.
	findInstallError := func(err error) error {
		return errors.Wrapf(err, "winfsp find installation")
	}
	var keyReg syscall.Handle // HKLM\\Software\\WinFSP
	keyName, err := syscall.UTF16PtrFromString("Software\\WinFsp")
	if err != nil {
		return "", findInstallError(err)
	}
	if err := syscall.RegOpenKeyEx(
		syscall.HKEY_LOCAL_MACHINE, keyName, 0,
		syscall.KEY_READ|syscall.KEY_WOW64_32KEY, &keyReg,
	); err != nil {
		return "", findInstallError(err)
	}
	defer syscall.RegCloseKey(keyReg)
	valueName, err := syscall.UTF16PtrFromString("InstallDir")
	if err != nil {
		return "", findInstallError(err)
	}
	var pathBuf [syscall.MAX_PATH]uint16
	var valueType, valueSize uint32
	valueSize = uint32(len(pathBuf)) * SIZEOF_WCHAR
	if err := syscall.RegQueryValueEx(
		keyReg, valueName, nil, &valueType,
		(*byte)(unsafe.Pointer(&pathBuf)), &valueSize,
	); err != nil {
		return "", findInstallError(err)
	}
	if valueType != syscall.REG_SZ {
		return "", findInstallError(syscall.ERROR_MOD_NOT_FOUND)
	}
	path := pathBuf[:int(valueSize/SIZEOF_WCHAR)]
	if len(path) > 0 && path[len(path)-1] == 0 {
		path = path[:len(path)-1]
	}
	return filepath.Join(syscall.UTF16ToString(path), "bin"), nil
}

func loadSignedDLL(dllPath string) (*syscall.DLL, error) {
	var err error
	absDLLPath, err := filepath.Abs(dllPath)
	if err != nil {
		return nil, errors.Wrapf(err, "resolve path %q", dllPath)
	}
	dllPath = absDLLPath

	u16Path, err := syscall.UTF16PtrFromString(dllPath)
	if err != nil {
		return nil, errors.Wrapf(err, "encode path %q", dllPath)
	}

	fh, err := windows.CreateFile(
		u16Path,
		windows.FILE_GENERIC_READ,
		// Forbid other process from WRITE|DELETE.
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_NON_DIRECTORY_FILE,
		windows.Handle(0),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "open file %q", dllPath)
	}
	defer windows.CloseHandle(fh)

	var winTrustFileInfo windows.WinTrustFileInfo
	winTrustFileInfo.Size = uint32(unsafe.Sizeof(winTrustFileInfo))
	winTrustFileInfo.File = fh
	winTrustFileInfo.KnownSubject = nil

	var winTrustData windows.WinTrustData
	winTrustData.Size = uint32(unsafe.Sizeof(winTrustData))
	winTrustData.PolicyCallbackData = uintptr(0)
	winTrustData.SIPClientData = uintptr(0)
	winTrustData.UIChoice = windows.WTD_UI_NONE
	winTrustData.RevocationChecks = windows.WTD_REVOKE_WHOLECHAIN
	winTrustData.StateAction = windows.WTD_STATEACTION_VERIFY
	winTrustData.StateData = windows.Handle(0)
	winTrustData.URLReference = nil
	winTrustData.UIContext = 0

	winTrustData.FileOrCatalogOrBlobOrSgnrOrCert = unsafe.Pointer(&winTrustFileInfo)
	winTrustData.UnionChoice = windows.WTD_CHOICE_FILE

	err = windows.WinVerifyTrustEx(
		windows.InvalidHWND,
		&windows.WINTRUST_ACTION_GENERIC_VERIFY_V2,
		&winTrustData,
	)
	defer func() {
		winTrustData.StateAction = windows.WTD_STATEACTION_CLOSE
		_ = windows.WinVerifyTrustEx(
			windows.InvalidHWND,
			&windows.WINTRUST_ACTION_GENERIC_VERIFY_V2,
			&winTrustData,
		)
	}()
	if err != nil {
		return nil, errors.Wrapf(err, "verify signature %q", dllPath)
	}

	// XXX: the dependency DLLs of WinFSP is still prone to
	// DLL hijacking, but protecting WinFSP DLL directory
	// is now the responsibility of user.
	hdll, err := windows.LoadLibraryEx(
		dllPath, windows.Handle(0),
		windows.LOAD_LIBRARY_SEARCH_SYSTEM32|windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "load library %q", dllPath)
	}
	return &syscall.DLL{
		Name:   dllPath,
		Handle: syscall.Handle(hdll),
	}, nil
}

// loadWinFSPDLL attempts to locate and load the DLL, the
// library handle will be available from now on.
func loadWinFSPDLL() (*syscall.DLL, error) {
	if winFSPDLL != nil {
		return winFSPDLL, nil
	}
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

	installPath, err := BinPath()
	if err != nil {
		return nil, err
	}
	return loadSignedDLL(filepath.Join(installPath, dllName))
}

// dllProc is a wrapper around a syscall.Proc with more conventional error
// return values. See dllProc.Call below for details.
type dllProc struct {
	proc *syscall.Proc
}

// ntStatusPtr is a sentinel value used by dllProc.Call to indicate an argument
// that should be a pointer to an NTstatus out variable.
var ntStatusPtrTarget windows.NTStatus
var ntStatusPtr = uintptr(unsafe.Pointer(&ntStatusPtrTarget))

// newHeapNTStatus returns a heap-allocated NTStatus. It is deliberately a
// separate, non-inlinable function: returning the pointer is what forces the
// allocation onto the heap. Writing "new(windows.NTStatus)" directly inside
// Call leaves it on the stack -- escape analysis reports "does not escape",
// because converting the address to uintptr hides it from the analysis, and
// runtime.KeepAlive does not change that. Verified with -gcflags='-m -m'.
//
//go:noinline
func newHeapNTStatus() *windows.NTStatus {
	return new(windows.NTStatus)
}

// EnsureInitialized ensure this dllProc to be initialized.
func (p dllProc) EnsureInitialized() {
	if err := tryLoadWinFSP(); err != nil {
		panic(fmt.Sprintf(`
WinFSP DLL load failed: %v

If you don't want to panic, you should consider calling
LoadWinFSP or LoadWinFSPWithDLL manually and handle the
load error there.
`, err))
	}
	// This is actually an assertion error, since it
	// must have been registered by registerProc, then
	// tryLoadWinFSP will load it.
	if p.proc == nil {
		panic("dllProc not registered for initialization")
	}
}

// Call is like syscall.Proc.Call but instead of always returning a non-nil error interface
// value (even on success), this Call wrapper returns a nil error on success. It also
// only returns one non-error result parameter, instead of two, as no callers require
// more than one result value.
//
// Additionally, if an arg is the sentinel value ntStatusPtr, it will be replaced
// with a pointer to a local NTStatus variable to capture the NTStatus return
// and return it as an error if it's not STATUS_SUCCESS.
//
// When the error is non-nil, it's always of type syscall.Errno, like
// syscall.Proc.Call.
//
//go:uintptrescapes
func (p dllProc) Call(args ...uintptr) (uintptr, error) {
	p.EnsureInitialized()
	// The //go:uintptrescapes above covers the caller-supplied uintptr
	// arguments, but NOT this local: the pragma forces the pointees of the
	// function's uintptr PARAMETERS onto the heap, and ntStatus is a local of
	// this function. Its address is laundered into a []uintptr on the line
	// below, which is invisible to the runtime's pointer maps, so if the
	// goroutine stack moves between that assignment and the DLL's write, the
	// DLL writes an NTSTATUS into a freed stack segment. Allocating it on the
	// heap closes that window -- heap objects do not move under Go's
	// non-moving collector.
	ntStatus := newHeapNTStatus()
	statusIdx := slices.Index(args, ntStatusPtr)
	if statusIdx != -1 {
		args[statusIdx] = uintptr(unsafe.Pointer(ntStatus))
	}
	res1, _, err := p.proc.Call(args...)
	runtime.KeepAlive(ntStatus)
	if err == syscall.Errno(0) {
		err = nil
	}
	if err == nil && statusIdx != -1 && *ntStatus != windows.STATUS_SUCCESS {
		err = *ntStatus
	}
	return res1, err
}

// CallStatus is like syscall.Proc.Call1 but is used for procedures that return a
// NTSTATUS status code in the first return value, which if non-STATUS_SUCCESS,
// is returned as an error.
//
//go:uintptrescapes
func (p dllProc) CallStatus(args ...uintptr) error {
	res1, err := p.Call(args...)
	if err != nil {
		return err
	}
	if res1 != uintptr(windows.STATUS_SUCCESS) {
		return windows.NTStatus(res1)
	}
	return nil
}

var winFSPDLL *syscall.DLL

func findProc(name string, target *dllProc) error {
	proc, err := winFSPDLL.FindProc(name)
	if err != nil {
		return errors.Wrapf(err,
			"winfsp cannot find proc %q", name)
	}
	*target = dllProc{proc: proc}
	return nil
}

type dllProcRegistryItem struct {
	name   string
	target *dllProc
}

var dllProcRegistry []dllProcRegistryItem

// registerProc registers a dllProc to be resolved
// upon loading winFSPDLL.
//
// Must only be called from a init() function.
func registerProc(name string, target *dllProc) {
	dllProcRegistry = append(dllProcRegistry, dllProcRegistryItem{
		name:   name,
		target: target,
	})
}

func initWinFSP() error {
	dll, err := loadWinFSPDLL()
	if err != nil {
		return err
	}
	winFSPDLL = dll
	for _, item := range dllProcRegistry {
		if err := findProc(item.name, item.target); err != nil {
			return err
		}
	}
	return nil
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

// LoadWinFSPWithDLL will try to resolve the symbols with
// the DLL provided, the work is done once and the error
// will be persistent.
//
// If the default WinFSP loading process does not work
// for you, then explicitly specifying one is the only
// choice. But you have to take your own risk now.
func LoadWinFSPWithDLL(dll *syscall.DLL) error {
	winFSPDLL = dll
	return tryLoadWinFSP()
}

// LoadWinFSP will load the WinFSP DLL and resolve its
// symbolds immediately.
func LoadWinFSP() error {
	return LoadWinFSPWithDLL(nil)
}
