// Package winfsp is the native binding API for WinFSP.
//
// Its API definition conforms to the descriptions in
// https://github.com/winfsp/winfsp/wiki/WinFsp-API-winfsp.h,
// while we invoke the API in a DLLProc+NonCGO manner.
//
// The API interfaces are only usable on windows, since
// they refers to the native API on winfsp.dll.
package winfsp
