//go:build linux || darwin

package testkit

import (
	"fmt"
	"syscall"
)

// runForkProbe attempts to create a child process via a bare fork-style
// syscall (no exec). The forked child immediately exits; the parent reaps it
// and records "fork":true on success. Distinguishing fork-without-exec from
// exec lets the harness tell apart no-new-exec (gVisor, Seatbelt) from
// no-new-process (AppContainer).
//
// A bare fork in a multithreaded Go runtime is inherently fragile: only the
// caller thread is cloned and the child's runtime state is inconsistent. The
// child must do nothing except an exit syscall.
func runForkProbe(report *ClientReport) {
	pid, _, errno := forkSyscall()
	if errno != 0 {
		report.AddCheck("fork", false, fmt.Errorf("fork: %w", errno))
		return
	}
	if pid == 0 {
		// Child: jump straight into an exit syscall. No Go runtime work.
		syscall.Exit(0)
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(int(pid), &ws, 0, nil); err != nil {
		report.AddCheck("fork", false, fmt.Errorf("wait fork child: %w", err))
		return
	}
	report.AddCheck("fork", true, nil)
}
