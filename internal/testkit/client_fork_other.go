//go:build !linux && !darwin

package testkit

import (
	"errors"
	"os"
)

// runForkProbe on platforms without a fork syscall (Windows) exercises the
// host's "create child process" primitive instead — on Windows this is
// CreateProcess, the very call PROCESS_CREATION_CHILD_PROCESS_RESTRICTED
// blocks. The child runs the noop probe and exits.
func runForkProbe(report *ClientReport) {
	self, err := os.Executable()
	if err != nil {
		report.AddCheck("fork", false, err)
		return
	}
	attr := &os.ProcAttr{Files: []*os.File{nil, nil, nil}}
	proc, err := os.StartProcess(self, []string{self, "--probe", string(ProbeNoop)}, attr)
	if err != nil {
		report.AddCheck("fork", false, err)
		return
	}
	state, err := proc.Wait()
	if err != nil {
		report.AddCheck("fork", false, err)
		return
	}
	if !state.Success() {
		report.AddCheck("fork", false, errors.New("fork child reported failure"))
		return
	}
	report.AddCheck("fork", true, nil)
}
