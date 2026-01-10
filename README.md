# go-winfsp

This is a [Go](https://golang.org) binding for the native [WinFSP](https://github.com/winfsp/winfsp)
API, which lets you implement a Windows native filesystem
based on the WinFSP framework.

There's also another Go binding for WinFSP named
[cgofuse](https://github.com/winfsp/cgofuse), which is based
on WinFSP's FUSE compatibility layer API instead of the native
one. However, I've found it problematic when implementing a
filesystem backed by a Windows native filesystem, due to
the semantic differences between POSIX style file API and Windows'
file API. This is the major motivation for writing this package.

The go-winfsp binding should offer a Windows-specific but
seamless API to implement a filesystem. However, callers
need not worry about adapting to different platform's API,
since the API also provides a Go standard library style
interface for describing a filesystem, and the adaption
should be a breeze.
