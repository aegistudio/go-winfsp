package filetime

import (
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var pool = &sync.Pool{
	New: func() interface{} {
		return &syscall.Filetime{}
	},
}

func uint64FromFiletime(filetime *syscall.Filetime) uint64 {
	result := *(*uint64)(unsafe.Pointer(filetime))
	return result
}

func Timestamp(t time.Time) uint64 {
	filetime := pool.Get().(*syscall.Filetime)
	defer pool.Put(filetime)
	*filetime = syscall.NsecToFiletime(t.UnixNano())
	return uint64FromFiletime(filetime)
}

func Filetime(t syscall.Filetime) uint64 {
	return uint64FromFiletime(&t)
}
