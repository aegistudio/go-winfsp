// Package gofs aims at providing a simple but working
// Golang file system implementation for WinFSP.
//
// The file system supports only file and directory, both
// of them can be opened by OpenFile operation, returning
// a file interface. The File interface should supports
// only read, write (append or random), close, seek, sync,
// readdir, truncate and stat operations.
//
// On the filesystem level, it supports Name, Stat,
// OpenFile, Mkdir, Remove and Rename operations.
// Rename operation must not select to replace the target
// file or not. Both Remove and Rename operations will
// never be called when there's open file under it.
//
// This makes it works even if the underlying file system
// is backed by a Window's native directory through the
// language interfaces by Golang.
package gofs
