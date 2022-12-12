package pathlock

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func assertEmpty(assert *assert.Assertions, locker *PathLocker) {
	locker.m.Range(func(k, v interface{}) bool {
		_ = assert.Failf(
			"invalid remaining entry %q = %d",
			k.(string), *v.(*uintptr),
		)
		return true
	})
}

func TestRootDir(t *testing.T) {
	assert := assert.New(t)
	locker := &PathLocker{}
	defer assertEmpty(assert, locker)
	assert.NotNil(locker.RLockPath(""))
	assert.NotNil(locker.RLockPath("."))
	assert.NotNil(locker.RLockPath("/"))
	assert.Nil(locker.LockPath(""))
	assert.Nil(locker.LockPath("."))
	assert.Nil(locker.LockPath("/"))
}

func TestReadWriteLock(t *testing.T) {
	assert := assert.New(t)
	locker := &PathLocker{}
	defer assertEmpty(assert, locker)

	lockPathABC := locker.RLockPath("/a/b/c")
	assert.NotNil(lockPathABC)
	defer lockPathABC.Unlock()

	// You can obtain any amount of read lock.
	lockPathABC2 := locker.RLockPath("/a/b/c/")
	assert.NotNil(lockPathABC2)
	defer lockPathABC2.Unlock()

	// Its parent path cannot be write locked.
	assert.Nil(locker.LockPath("/a/b/c"))
	assert.Nil(locker.LockPath("a/b/c"))
	assert.Nil(locker.LockPath("./a/b/c"))
	assert.Nil(locker.LockPath("/a/b"))
	assert.Nil(locker.LockPath("a/b"))
	assert.Nil(locker.LockPath("./a/b"))
	assert.Nil(locker.LockPath("/a"))
	assert.Nil(locker.LockPath("a"))
	assert.Nil(locker.LockPath("./a"))

	// Its child path can be locked however.
	lockPathABCD := locker.LockPath("/a/b/c/d")
	assert.NotNil(lockPathABCD)
	defer lockPathABCD.Unlock()

	// Other paths can be locked however.
	lockPathAC := locker.LockPath("./a/b/c/../../c/")
	assert.NotNil(lockPathAC)
	defer lockPathAC.Unlock()

	// And you can't obtain more lock of it, writer
	// lock is exclusive here.
	assert.Nil(locker.LockPath("a/c"))
	assert.Nil(locker.LockPath("a/c/"))
	assert.Nil(locker.LockPath("./a/c"))
	assert.Nil(locker.LockPath("/a/c"))
	assert.Nil(locker.RLockPath("a/c"))
	assert.Nil(locker.RLockPath("/a/c"))
	assert.Nil(locker.RLockPath("./a/c"))
	assert.Nil(locker.RLockPath("/a/c/d"))
	assert.Nil(locker.RLockPath("./a/c/d"))
	assert.Nil(locker.RLockPath("//a/c/d"))
}
