//go:build darwin || linux

package testkit

import (
	"errors"
	"os"
	"testing"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func TestTTYIoctlProbeRequiresIsolatedHarnessMarker(t *testing.T) {
	t.Setenv(ttyIoctlProbeEnv, "")
	report, err := RunClientProbe(ClientConfig{Probe: ProbeTTYIoctl})
	if err != nil {
		t.Fatal(err)
	}
	if report.Unsupported == "" {
		t.Fatalf("tty ioctl probe should refuse to run without isolated harness marker: %#v", report)
	}
}

func TestTTYIoctlProbeUsesOnlyProvidedStdinPTY(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()

	oldStdin := os.Stdin
	os.Stdin = slave
	defer func() { os.Stdin = oldStdin }()

	marker := "i\n"
	t.Setenv(ttyIoctlProbeEnv, marker)
	report, err := RunClientProbe(ClientConfig{Probe: ProbeTTYIoctl})
	if err != nil {
		t.Fatal(err)
	}
	check, ok := report.Checks["tiocsti"]
	if !ok {
		t.Fatalf("tiocsti check missing: %#v", report)
	}
	if !check.Success {
		return
	}

	if err := unix.SetNonblock(int(slave.Fd()), true); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(marker))
	n, err := slave.Read(buf)
	if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatal(err)
	}
	if n > 0 && string(buf[:n]) != marker[:n] {
		t.Fatalf("injected bytes landed somewhere unexpected: got %q want prefix of %q", string(buf[:n]), marker)
	}
}
