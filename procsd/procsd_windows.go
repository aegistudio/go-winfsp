package procsd

import (
	"sync"

	"golang.org/x/sys/windows"
)

const infoMask = windows.OWNER_SECURITY_INFORMATION |
	windows.GROUP_SECURITY_INFORMATION |
	windows.DACL_SECURITY_INFORMATION

var (
	once sync.Once
	sd   *windows.SECURITY_DESCRIPTOR
	err  error
)

func load() (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.GetSecurityInfo(
		windows.CurrentProcess(),
		windows.SE_KERNEL_OBJECT, infoMask,
	)
}

func Load() (*windows.SECURITY_DESCRIPTOR, error) {
	once.Do(func() {
		sd, err = load()
	})
	return sd, err
}
