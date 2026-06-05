//go:build linux

package testkit

import "syscall"

// forkSyscall invokes clone(SIGCHLD) directly: equivalent to fork(2) but
// without the libc/Go-runtime wrappers that assume a fully cloned address
// space.
func forkSyscall() (uintptr, uintptr, syscall.Errno) {
	return syscall.RawSyscall(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0)
}
