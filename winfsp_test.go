//go:build windows

package winfsp_test

import (
	"bytes"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/winfsp/go-winfsp"
	"github.com/winfsp/go-winfsp/gofs"
)

const helloWorld = "Hello, World!\n"

func TestMount(t *testing.T) {
	testFS := newTestFS()
	testFS.addTestFile(`\reg-size-123`, bytes.Repeat([]byte{'a'}, 123))
	testFS.addTestFile(`\reg-size-456`, bytes.Repeat([]byte{'a'}, 456))
	testFS.addTestFile(`\hello.txt`, []byte(helloWorld))

	bb := gofs.New(testFS)
	fspFS, err := winfsp.Mount(bb, "T:")
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	defer fspFS.Unmount()

	wantDir(t, `T:\`)
	wantDirContents(t, `T:\`, WantDir{
		"reg-size-123": regular(123),
		"reg-size-456": regular(456),
		"hello.txt":    regular(int64(len(helloWorld))),
	})

	wantRegSize(t, `T:\reg-size-123`, 123)
	wantRegSize(t, `T:\reg-size-456`, 456)
	wantNotExist(t, `T:\not-exist-file`)
	wantFileContents(t, `T:\hello.txt`, helloWorld)

	// Test that that os.File.Close calls make it to the kernel and back to us,
	// and that our testFS accounts for the open FD count correctly.
	t.Run("Close", func(t *testing.T) {
		// Wait for previous operations' close events to be processed
		// (apparently os.File.Close is returning before userspace WinFSP calls
		// handle the Close?)
		for range 20 {
			if testFS.openFiles.Load() == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		testFS.wantOpenFiles(t, 0)
		f, err := os.Open(`T:\reg-size-123`)
		if err != nil {
			t.Fatalf("Open reg-size-123: %v", err)
		}
		testFS.wantOpenFiles(t, 1)

		ch := make(chan any, 1)
		testFS.setSubscriber(ch)
		defer testFS.setSubscriber(nil)

		f.Close()
		select {
		case ev := <-ch:
			_, ok := ev.(regularFileClosedEvent)
			if !ok {
				t.Errorf("got event of type %T; want regularFileClosedEvent", ev)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("timed out waiting for regularFileClosedEvent")
		}
		testFS.wantOpenFiles(t, 0)

		f.Close()
		testFS.wantOpenFiles(t, 0)
	})

	t.Run("CreateFile", func(t *testing.T) {
		wantNotExist(t, `T:\newfile.txt`)
		if err := os.WriteFile(`T:\newfile.txt`, []byte(helloWorld), 0o644); err != nil {
			t.Fatalf("WriteFile newfile.txt: %v", err)
		}
		wantFileContents(t, `T:\newfile.txt`, helloWorld)
	})

	t.Run("RemoveFile", func(t *testing.T) {
		//t.Skip("TODO: make this test pass") // os.Remove is failing with access denied

		const path = `T:\to-delete.txt`
		wantNotExist(t, path)
		if err := os.WriteFile(path, []byte(helloWorld), 0o666); err != nil {
			t.Fatal(err)
		}
		wantFileContents(t, path, helloWorld)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		wantNotExist(t, path)
	})
}

type dirEntMatcher func(t testing.TB, name string, de os.DirEntry)

type WantDir map[string]dirEntMatcher

func wantDir(t testing.TB, path string) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Errorf("Lstat(%q): %v", path, err)
		return
	}
	if !fi.IsDir() {
		t.Errorf("Lstat(%q): not a dir; got %v", path, fi.Mode())
	}
}

func wantDirContents(t testing.TB, path string, want WantDir) {
	t.Helper()
	ents, err := os.ReadDir(path)
	if err != nil {
		t.Errorf("ReadDir(%q): %v", path, err)
		return
	}
	missing := maps.Clone(want)
	for _, de := range ents {
		delete(missing, de.Name())
		m, ok := want[de.Name()]
		if !ok {
			t.Errorf("ReadDir(%q): unexpected directory entry %q", path, de.Name())
			continue
		}
		m(t, de.Name(), de)
	}
	if len(missing) > 0 {
		for name := range missing {
			t.Errorf("ReadDir(%q): missing expected directory entry %q", path, name)
		}
	}
}

func wantRegSize(t testing.TB, path string, size int64) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Errorf("Lstat(%q): %v", path, err)
		return
	}
	if !fi.Mode().IsRegular() {
		t.Errorf("Lstat(%q): not a regular file; got %+v", path, fi)
		return
	}
	if fi.Size() != size {
		t.Errorf("Lstat(%q) regular file size = %d; want %d", path, fi.Size(), size)
	}
}

func wantNotExist(t testing.TB, path string) {
	t.Helper()
	fi, err := os.Lstat(path)
	if !os.IsNotExist(err) {
		t.Errorf("Lstat(%q): got (%v, err %v); want not exist", path, fi, err)
	}
}

func wantFileContents(t testing.TB, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("ReadFile(%q): %v", path, err)
		return
	}
	if string(got) != want {
		t.Errorf("ReadFile(%q) = %q; want %q", path, got, want)
	}
}

func regular(size int64) dirEntMatcher {
	return func(t testing.TB, name string, de os.DirEntry) {
		t.Helper()
		fi, err := de.Info()
		if err != nil {
			t.Errorf("DirEntry.Info() for %q: %v", name, err)
		}
		if !fi.Mode().IsRegular() {
			t.Errorf("DirEntry.Info() for %q: not a regular file; got %+v", name, fi)
			return
		}
		if fi.Size() != size {
			t.Errorf("DirEntry.Info() for %q regular file size = %d; want %d", name, fi.Size(), size)
		}
	}
}

func newTestFS() *testFS {
	return &testFS{
		files: map[string][]byte{},
	}
}

type testFS struct {
	openFiles atomic.Int64

	mu    sync.Mutex
	files map[string][]byte // nil values are directories, else regular file contents
	sub   chan<- any        // if non-nil, subscriber of events
}

func (fs *testFS) setSubscriber(sub chan<- any) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.sub = sub
}

func (fs *testFS) sendEvent(event any) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.sub != nil {
		select {
		case fs.sub <- event:
		default:
		}
	}
}

func (fs *testFS) addTestFile(path string, contents []byte) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.files[path] = contents
}

func (fs *testFS) wantOpenFiles(t testing.TB, want int64) {
	t.Helper()
	got := fs.openFiles.Load()
	if got != want {
		t.Errorf("open files = %d; want %d", got, want)
	}
}

func (fs *testFS) OpenFile(name string, flag int, perm os.FileMode) (gofs.File, error) {
	if name == "" {
		panic("invalid")
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	fsf, ok := fs.files[name]
	if ok && fsf != nil {
		return fs.newFWPFileFromContents(filepath.Base(name), fsf), nil
	}
	d := &testDir{
		fi: newDirFileInfo(filepath.Base(name)),
	}
	for sub, subv := range fs.files {
		if filepath.Dir(sub) == name {
			if subv == nil {
				d.ents = append(d.ents, newDirFileInfo(filepath.Base(sub)))
			} else {
				d.ents = append(d.ents, newRegFileInfo(filepath.Base(sub), int64(len(subv))))
			}
		}
	}
	if len(d.ents) > 0 || ok || name == `\` {
		return d, nil
	}

	if flag&os.O_CREATE == 0 {
		return nil, os.ErrNotExist
	}

	return &writingFile{
		fs:   fs,
		name: name,
		perm: perm,
	}, nil
}

func (fs *testFS) Stat(name string) (os.FileInfo, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if name == `\` {
		return newDirFileInfo(""), nil
	}

	fsf, ok := fs.files[name]
	if ok {
		if fsf == nil {
			return newDirFileInfo(filepath.Base(name)), nil
		}
		return newRegFileInfo(filepath.Base(name), int64(len(fsf))), nil
	}

	// is there a regular file that has this directory?
	for fpath := range fs.files {
		if filepath.Dir(fpath) == name {
			return newDirFileInfo(filepath.Base(name)), nil
		}
	}

	return nil, os.ErrNotExist
}

func (fs *testFS) Mkdir(name string, perm os.FileMode) error {
	return os.ErrPermission
}

func (fs *testFS) Rename(source, target string) error {
	return os.ErrPermission
}

func (fs *testFS) Remove(name string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	_, ok := fs.files[name]
	if !ok {
		return os.ErrNotExist
	}
	delete(fs.files, name)
	return nil
}

func newRegFileInfo(baseName string, size int64) os.FileInfo {
	return testRegFileInfo{baseName: baseName, size: size}
}

type testRegFileInfo struct {
	baseName string
	size     int64
}

func (fi testRegFileInfo) Name() string      { return fi.baseName }
func (fi testRegFileInfo) Size() int64       { return fi.size }
func (fi testRegFileInfo) Mode() os.FileMode { return 0o444 }
func (fi testRegFileInfo) ModTime() time.Time {
	return fakeTime
}
func (fi testRegFileInfo) IsDir() bool      { return false }
func (fi testRegFileInfo) Sys() interface{} { return nil }

func newDirFileInfo(name string) os.FileInfo {
	return testDirFileInfo{baseName: name}
}

type testDirFileInfo struct {
	baseName string
}

var fakeTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

func (fi testDirFileInfo) Name() string      { return fi.baseName }
func (fi testDirFileInfo) Size() int64       { return 0 }
func (fi testDirFileInfo) Mode() os.FileMode { return 0o777 | os.ModeDir }
func (fi testDirFileInfo) ModTime() time.Time {
	return fakeTime
}
func (fi testDirFileInfo) IsDir() bool      { return true }
func (fi testDirFileInfo) Sys() interface{} { return nil }

type testDir struct {
	fi os.FileInfo // for Stat, must be non-nil

	gofs.File // embedded to panic to unimplemented methods
	ents      []os.FileInfo
}

func (d *testDir) Readdir(n int) ([]os.FileInfo, error) {
	if n != -1 {
		panic("unexpected readdir argument")
	}
	return d.ents, nil
}

func (d *testDir) Close() error { return nil }

func (d *testDir) Stat() (os.FileInfo, error) {
	return d.fi, nil
}

func (fs *testFS) newFWPFileFromContents(baseName string, contents []byte) gofs.File {
	fs.openFiles.Add(1)
	return &winFSPRegularFile{
		fs:       fs,
		contents: contents,
		fi:       newRegFileInfo(baseName, int64(len(contents))),
	}
}

type winFSPRegularFile struct {
	fs        *testFS
	closeOnce sync.Once
	fi        os.FileInfo
	contents  []byte
}

func (f *winFSPRegularFile) Close() error {
	f.closeOnce.Do(func() {
		f.fs.openFiles.Add(-1)
		f.fs.sendEvent(regularFileClosedEvent{})
	})
	return nil
}

type regularFileClosedEvent struct{}

func (f *winFSPRegularFile) Sync() error               { return nil }
func (f *winFSPRegularFile) Truncate(size int64) error { return os.ErrPermission }
func (f *winFSPRegularFile) Write(p []byte) (n int, err error) {
	return 0, os.ErrPermission
}
func (f *winFSPRegularFile) WriteAt(p []byte, off int64) (n int, err error) {
	return 0, os.ErrPermission
}

func (f *winFSPRegularFile) Readdir(count int) (ents []os.FileInfo, err error) {
	return nil, nil
}

func (f *winFSPRegularFile) Read(p []byte) (n int, err error) {
	panic("unused") // winfsp uses ReadAt only
}

func (f *winFSPRegularFile) ReadAt(p []byte, off int64) (n int, err error) {
	n = copy(p, f.contents[min(off, int64(len(f.contents))):])
	if n == 0 && len(p) > 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (f *winFSPRegularFile) Seek(offset int64, whence int) (int64, error) {
	panic("unused") // winfsp only uses Seek for Renames; not needed in tests yet
}

func (f *winFSPRegularFile) Stat() (os.FileInfo, error) {
	return f.fi, nil
}

type writingFile struct {
	gofs.File
	fs   *testFS
	name string
	perm os.FileMode

	closeOnce sync.Once

	buf []byte
}

func (f *writingFile) Write(p []byte) (n int, err error) {
	f.buf = append(f.buf, p...)
	return len(p), nil
}

func (f *writingFile) ReadAt(p []byte, off int64) (n int, err error) {
	n = copy(p, f.buf[min(off, int64(len(f.buf))):])
	if n == 0 && len(p) > 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (f *writingFile) WriteAt(p []byte, off int64) (n int, err error) {
	newSize := int(off) + len(p)
	if newSize > len(f.buf) {
		newBuf := make([]byte, newSize)
		copy(newBuf, f.buf)
		f.buf = newBuf
	}
	copy(f.buf[off:], p)
	return len(p), nil
}

func (f *writingFile) Close() error {
	f.closeOnce.Do(func() {
		f.fs.mu.Lock()
		defer f.fs.mu.Unlock()
		f.fs.files[f.name] = bytes.Clone(f.buf)
	})
	return nil
}

func (f *writingFile) Stat() (os.FileInfo, error) {
	return testRegFileInfo{
		baseName: filepath.Base(f.name),
		size:     int64(len(f.buf)),
	}, nil
}
