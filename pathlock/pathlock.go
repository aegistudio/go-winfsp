// Package pathlock offers a simple helper for locking a path
// and performing sharing and accesibility checks.
//
// Normally, this is for removing or renaming a Windows file
// or directory versus read, write and access check operations
// over them. Normally there might be multiple readers, writers
// and access checkers while just single remover or renamer.
package pathlock

import (
	"path"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
)

// pool for integers in the path locker.
var pool = &sync.Pool{
	New: func() interface{} {
		return new(uintptr)
	},
}

// PathLocker is the locker center of a path namespace.
//
// The callers locks the path with reader lock when reading,
// writing and access checking a file, while locks the path
// with writer lock when removing or renaming the file.
//
// The locking process is nonblocking, it releases and returns
// immediately when it fails to lock the path.
type PathLocker struct {
	m sync.Map
}

// readUnlock performs the unlock operation on specified path.
//
// This operation assumes the read lock operation has completed
// successfully, or it will just panic because the integrity of
// the locker has broken.
func (l *PathLocker) readUnlock(p string) {
	obj, _ := l.m.Load(p)
	if atomic.AddUintptr(obj.(*uintptr), ^uintptr(0)) == 1 {
		old, _ := l.m.LoadAndDelete(p)
		pool.Put(old.(*uintptr))
	}
}

// readLock performs the read lock operation on certain path.
//
// The lock operation fails when there's already a writer lock
// on the specified path, or it reaches the upper limit of the
// integer's pointer.
func (l *PathLocker) readLock(p string) bool {
	for {
		newer := pool.Get().(*uintptr)
		atomic.StoreUintptr(newer, 2)
		obj, loaded := l.m.LoadOrStore(p, newer)
		if !loaded {
			// We are the one to put the object which has a
			// lock counter on it already.
			return true
		}
		pool.Put(newer)
		// TODO: we don't need to reacquire the lock every
		// time we fail to increment the pointer, find a way
		// to judge whether the pointer is valid.
		ptr := obj.(*uintptr)
		before := atomic.LoadUintptr(ptr)
		if before == 0 {
			// Writer lock already held, we must return with
			// failure condition here.
			return false
		}
		if before == 1 {
			// The reader lock has dropped its last reference
			// counter, and we will wait for it.
			runtime.Gosched()
			continue
		}
		after := before + 1
		if after == 0 {
			// Too many locks here, why can't you have a cup
			// of coffee instead of acquiring a lock.
			return false
		}
		if atomic.CompareAndSwapUintptr(ptr, before, after) {
			return true
		}
		runtime.Gosched()
	}
}

// writeUnlock performs a unlock operation on a single path.
func (l *PathLocker) writeUnlock(p string) {
	// The object is loaded and deleted from the map directly
	// so we don't have to decrement its counter.
	obj, _ := l.m.LoadAndDelete(p)
	pool.Put(obj.(*uintptr))
}

// writeLock performs a lock operation on a single path.
func (l *PathLocker) writeLock(p string) bool {
	for {
		newer := pool.Get().(*uintptr)
		atomic.StoreUintptr(newer, 0)
		obj, loaded := l.m.LoadOrStore(p, newer)
		if !loaded {
			// We have simply locked it here now.
			return true
		}
		pool.Put(newer)
		before := atomic.LoadUintptr(obj.(*uintptr))
		if before == 0 || before > 1 {
			// If there's any reader locks or writer locks
			// prior to this operation, it must fail.
			return false
		}
		// So before is the empty counter, all we need to
		// do is to wait for next cycle here.
		runtime.Gosched()
	}
}

// readUnlockRecursive is the lock operation to perform locking
// of the specified path.
func (l *PathLocker) readUnlockRecursive(p string) {
	if p == "" || p == "." || p == "/" {
		return
	}
	l.readUnlock(p)
	parent := path.Dir(p)
	l.readUnlockRecursive(parent)
}

// readLockRecursive is the lock operation to perform locking
// of the specified path.
func (l *PathLocker) readLockRecursive(p string) bool {
	if p == "" || p == "." || p == "/" {
		return true
	}
	parent := path.Dir(p)
	if !l.readLockRecursive(parent) {
		return false
	}
	locked := false
	defer func() {
		if !locked {
			l.readUnlockRecursive(parent)
		}
	}()
	locked = l.readLock(p)
	return locked
}

// Lock is the reference object held to release the lock.
type Lock struct {
	locker *PathLocker
	path   string
	write  bool
	free   sync.Once
}

func (l *PathLocker) newLock(path string, write bool) *Lock {
	result := &Lock{
		locker: l,
		path:   path,
		write:  write,
	}
	runtime.SetFinalizer(result, func(l *Lock) {
		l.Unlock()
	})
	return result
}

func (l *Lock) Path() string {
	return l.path
}

func (l *Lock) FilePath() string {
	return filepath.FromSlash(l.Path())
}

func (l *PathLocker) writerDowngrade(path string) {
	// XXX: when it is the writer lock, we are the only one
	// allowed to write the value corresponding to path. So
	// we just need to store the reader counter to it.
	ptr, _ := l.m.Load(path)
	atomic.StoreUintptr(ptr.(*uintptr), 2)
}

func (l *Lock) IsWrite() bool {
	return l.write
}

func (l *Lock) Downgrade() {
	if !l.write {
		return
	}
	l.locker.writerDowngrade(l.path)
	l.write = false
}

func (l *Lock) Unlock() {
	runtime.SetFinalizer(l, nil)
	l.free.Do(func() {
		if l.write {
			l.locker.writeUnlock(l.path)
			l.locker.readUnlockRecursive(path.Dir(l.path))
		} else {
			l.locker.readUnlockRecursive(l.path)
		}
	})
}

func (l *PathLocker) readLockCleanPath(p string) *Lock {
	if l.readLockRecursive(p) {
		return l.newLock(p, false)
	}
	return nil
}

func (l *PathLocker) writeLockCleanPath(p string) *Lock {
	if p == "" || p == "/" || p == "." {
		// You may not write lock the root file system.
		return nil
	}
	parent := path.Dir(p)
	if !l.readLockRecursive(parent) {
		return nil
	}
	locked := false
	defer func() {
		if !locked {
			l.readUnlockRecursive(parent)
		}
	}()
	if !l.writeLock(p) {
		return nil
	}
	defer func() {
		if !locked {
			l.writeUnlock(p)
		}
	}()
	result := l.newLock(p, true)
	locked = true
	return result
}

func cleanSlashPath(p string) string {
	return path.Clean(path.Join("/", p))
}

func cleanFilePath(p string) string {
	p = p[len(filepath.VolumeName(p)):]
	p = filepath.ToSlash(p)
	return cleanSlashPath(p)
}

// RLock attempt to perform the reader lock on the path.
func (l *PathLocker) RLock(p string) *Lock {
	return l.readLockCleanPath(cleanFilePath(p))
}

// Lock attempts to perform the writer lock on the path.
func (l *PathLocker) Lock(p string) *Lock {
	return l.writeLockCleanPath(cleanFilePath(p))
}

// RLockPath attempts to perform the reader lock on the
// slash separated path.
func (l *PathLocker) RLockPath(p string) *Lock {
	return l.readLockCleanPath(cleanSlashPath(p))
}

// LockPath attempts to perform the reader lock on the
// slash separated path.
func (l *PathLocker) LockPath(p string) *Lock {
	return l.writeLockCleanPath(cleanSlashPath(p))
}
