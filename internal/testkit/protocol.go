package testkit

// Probe names the operation group executed by isobox-testkit-client.
type Probe string

const (
	ProbeNoop       Probe = "noop"
	ProbeFSRead     Probe = "fs-read"
	ProbeFSWrite    Probe = "fs-write"
	ProbeNetwork    Probe = "network"
	ProbeExec       Probe = "exec"
	ProbeIPC        Probe = "ipc"
	ProbeMach       Probe = "mach"
	ProbeKernelInfo Probe = "kernel-info"
	ProbeTTYIoctl   Probe = "tty-ioctl"
)

// CheckResult records whether one client-side operation succeeded. Host-side
// expectations decide whether success is good or bad for a capability case.
type CheckResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// ClientReport is the JSON protocol emitted by isobox-testkit-client.
type ClientReport struct {
	Probe       Probe                  `json:"probe"`
	Checks      map[string]CheckResult `json:"checks,omitempty"`
	Evidence    map[string]string      `json:"evidence,omitempty"`
	Unsupported string                 `json:"unsupported,omitempty"`
}

// AddCheck appends an operation result to the report.
func (r *ClientReport) AddCheck(name string, success bool, err error) {
	if r.Checks == nil {
		r.Checks = make(map[string]CheckResult)
	}
	result := CheckResult{Success: success}
	if err != nil {
		result.Error = err.Error()
	}
	r.Checks[name] = result
}

// AddEvidence appends non-pass/fail diagnostic evidence to the report.
func (r *ClientReport) AddEvidence(name, value string) {
	if r.Evidence == nil {
		r.Evidence = make(map[string]string)
	}
	r.Evidence[name] = value
}

// CaseStatus is the host-side result status for one capability case.
type CaseStatus string

const (
	CasePass CaseStatus = "pass"
	CaseFail CaseStatus = "fail"
	CaseSkip CaseStatus = "skip"
)

// CaseReport is emitted by isobox-testkit-host for one capability case.
type CaseReport struct {
	Capability string            `json:"capability"`
	Case       string            `json:"case"`
	Status     CaseStatus        `json:"status"`
	Details    string            `json:"details,omitempty"`
	Checks     map[string]bool   `json:"checks,omitempty"`
	Evidence   map[string]string `json:"evidence,omitempty"`
}
