//go:build darwin

package testkit

import "syscall"

// forkSyscall invokes BSD fork(2) directly. darwin's libsystem fork has extra
// pthread bookkeeping the Go runtime cannot safely participate in; the raw
// syscall + immediate exit in the child sidesteps it.
func forkSyscall() (uintptr, uintptr, syscall.Errno) {
	return syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
}
