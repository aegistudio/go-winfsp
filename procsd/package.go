// Package procsd is the helper package for retrieving
// process security descriptor under windows.
//
// Since the whole security descriptor will be loaded
// into the memory, and it is very unlikely that the
// process updates its privilege while running, we will
// only load it once.
package procsd
