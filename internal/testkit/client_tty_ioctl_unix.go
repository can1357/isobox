//go:build darwin || linux

package testkit

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const ttyIoctlProbeEnv = "ISOBOX_TESTKIT_TIOCSTI_MARKER"

func runTTYIoctlProbe(report *ClientReport) {
	marker := []byte(os.Getenv(ttyIoctlProbeEnv))
	if len(marker) == 0 {
		report.Unsupported = ttyIoctlProbeEnv + " must be set by a host-side isolated pty harness; refusing to inject bytes into the process stdin"
		return
	}
	if len(marker) > 16 {
		report.AddCheck("tiocsti", false, fmt.Errorf("%s is too long for tty ioctl probe", ttyIoctlProbeEnv))
		return
	}

	fd := int(os.Stdin.Fd())
	for _, b := range marker {
		if err := ioctlTIOCSTI(fd, b); err != nil {
			report.AddCheck("tiocsti", false, err)
			report.AddEvidence("stdin.fd", fmt.Sprint(fd))
			return
		}
	}
	report.AddCheck("tiocsti", true, nil)
	report.AddEvidence("stdin.fd", fmt.Sprint(fd))
	report.AddEvidence("marker.bytes", fmt.Sprint(len(marker)))
}

func ioctlTIOCSTI(fd int, b byte) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(tiocstiRequest), uintptr(unsafe.Pointer(&b)))
	if errno != 0 {
		return errno
	}
	return nil
}
