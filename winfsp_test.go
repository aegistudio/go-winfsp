//go:build windows

package winfsp_test

import (
	"bytes"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/winfsp/go-winfsp"
	"github.com/winfsp/go-winfsp/gofs"
)

func TestMount(t *testing.T) {
	bb := gofs.New(&testFS{})
	fs, err := winfsp.Mount(bb, "T:")
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	defer fs.Unmount()

	fi, err := os.Stat(`T:\reg-size-123`)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got, want := fi.Size(), int64(123); got != want {
		t.Errorf("file size = %v; want %v", got, want)
	}
}

type testFS struct{}

func (fs *testFS) OpenFile(name string, flag int, perm os.FileMode) (gofs.File, error) {
	if name == `\` {
		return &testDir{
			fi: newDirFileInfo(""),
			ents: []os.FileInfo{
				newRegFileInfo("reg-size-123", 123),
			},
		}, nil
	}
	if size, ok := strings.CutPrefix(name, `\reg-size-`); ok {
		n, err := strconv.ParseInt(size, 10, 64)
		if err != nil {
			return nil, err
		}
		if n > 10<<20 {
			return nil, os.ErrInvalid
		}
		return newFWPFileFromContents(filepath.Base(name), bytes.Repeat([]byte{'a'}, int(n))), nil
	}
	log.Printf("OpenFile(%q) not found", name)
	return nil, os.ErrNotExist
}

func (fs *testFS) Stat(name string) (os.FileInfo, error) {
	if name == `\` {
		return newDirFileInfo(""), nil
	}
	if size, ok := strings.CutPrefix(name, `\reg-size-`); ok {
		n, err := strconv.ParseInt(size, 10, 64)
		if err != nil {
			return nil, err
		}
		return newRegFileInfo(filepath.Base(name), n), nil
	}
	log.Printf("Stat(%q) not found", name)
	return nil, os.ErrPermission
}

func (fs *testFS) Mkdir(name string, perm os.FileMode) error {
	return os.ErrPermission
}

func (fs *testFS) Rename(source, target string) error {
	return os.ErrPermission
}

func (fs *testFS) Remove(name string) error {
	return os.ErrPermission
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
func (fi testDirFileInfo) Mode() os.FileMode { return 0o555 }
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
	// TODO: care about n?
	return d.ents, nil
}

func (d *testDir) Close() error { return nil }

func (d *testDir) Stat() (os.FileInfo, error) {
	return d.fi, nil
}

func newFWPFileFromContents(baseName string, contents []byte) gofs.File {
	return &winFSPRegularFile{
		contents: contents,
		fi:       newRegFileInfo(baseName, int64(len(contents))),
	}
}

type winFSPRegularFile struct {
	fi       os.FileInfo
	contents []byte
}

func (f *winFSPRegularFile) Close() error { return nil }

func (f *winFSPRegularFile) Sync() error               { return nil }
func (f *winFSPRegularFile) Truncate(size int64) error { return os.ErrPermission }
func (f *winFSPRegularFile) Write(p []byte) (n int, err error) {
	return 0, os.ErrPermission
}
func (f *winFSPRegularFile) WriteAt(p []byte, off int64) (n int, err error) {
	return 0, os.ErrPermission
}

func (f *winFSPRegularFile) Readdir(count int) (ents []os.FileInfo, err error) {
	return nil, os.ErrInvalid
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
