# go-winfsp

This is a Golang binding for the native [WinFSP](https://github.com/winfsp/winfsp)
API, with which you can implement a Windows native filesystem
based on the WinFSP's framework.

There's also another Golang binding of WinFSP named
[cgofuse](https://github.com/winfsp/cgofuse), which is based
on WinFSP's FUSE compatible layer API instead of the native
one. However I've found it problematic when implementing a
filesystem backed by a Window's native filesystem, due to
the semantic difference of POSIX style file API and Window's
file API. This is the major motive I write this binding.

The go-winfsp binding should offers a Windows dedicated but
seamless API to implement a filesystem. However, the caller
need not to worry about adapting to different platform's API,
since the API also provides a Golang standard library style
interface for describing a filesystem, and the adaption job
should be just like a breeze.
