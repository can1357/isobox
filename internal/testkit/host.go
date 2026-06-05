package testkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/can1357/isobox"
)

// HostOptions configures a host-side testkit run.
type HostOptions struct {
	ClientPath  string
	Backend     string
	Caps        []string
	Timeout     time.Duration
	Keep        bool
	ConnectAddr string
	MachService string
}

// RunHost executes the selected capability cases and returns one report per case.
func RunHost(ctx context.Context, opts HostOptions) ([]CaseReport, error) {
	if opts.ClientPath == "" {
		return nil, errors.New("testkit: --client is required")
	}
	client, err := filepath.Abs(opts.ClientPath)
	if err != nil {
		return nil, fmt.Errorf("testkit: resolving client path: %w", err)
	}
	if st, err := os.Stat(client); err != nil {
		return nil, fmt.Errorf("testkit: client not usable: %w", err)
	} else if st.IsDir() {
		return nil, fmt.Errorf("testkit: client path is a directory: %s", client)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.MachService == "" {
		opts.MachService = "com.apple.coreservices.launchservicesd"
	}

	runner, err := newRunner(opts.Backend)
	if err != nil {
		return nil, err
	}

	root, err := os.MkdirTemp("", "isobox-testkit-host-*")
	if err != nil {
		return nil, fmt.Errorf("testkit: creating fixture dir: %w", err)
	}
	if !opts.Keep {
		defer os.RemoveAll(root)
	}

	selected, err := selectedCapabilities(opts.Caps, runner.Capabilities())
	if err != nil {
		return nil, err
	}
	reports := make([]CaseReport, 0, len(selected))
	for _, cap := range selected {
		if !runner.Capabilities().Has(cap) {
			reports = append(reports, CaseReport{
				Capability: string(cap),
				Case:       string(cap),
				Status:     CaseSkip,
				Details:    fmt.Sprintf("backend %s does not advertise %s", runner.Backend(), cap),
			})
			continue
		}
		report := runCapabilityCase(ctx, runner, client, root, cap, opts)
		if opts.Keep {
			if report.Evidence == nil {
				report.Evidence = make(map[string]string)
			}
			report.Evidence["fixture_dir"] = root
		}
		reports = append(reports, report)
	}
	return reports, nil
}

func newRunner(name string) (*isobox.Runner, error) {
	if name == "" {
		return isobox.New()
	}
	return isobox.NewBackend(isobox.Backend(name))
}

func selectedCapabilities(names []string, backend isobox.CapabilitySet) ([]isobox.Capability, error) {
	if len(names) == 0 {
		return backend.List(), nil
	}
	known := isobox.Union()
	out := make([]isobox.Capability, 0, len(names))
	seen := make(map[isobox.Capability]struct{}, len(names))
	for _, raw := range names {
		for _, part := range strings.Split(raw, ",") {
			name := strings.TrimSpace(part)
			if name == "" {
				continue
			}
			cap := isobox.Capability(name)
			if !known.Has(cap) {
				return nil, fmt.Errorf("testkit: unknown capability %q", name)
			}
			if _, ok := seen[cap]; ok {
				continue
			}
			seen[cap] = struct{}{}
			out = append(out, cap)
		}
	}
	return out, nil
}

func runCapabilityCase(ctx context.Context, runner *isobox.Runner, client, root string, cap isobox.Capability, opts HostOptions) CaseReport {
	r := CaseReport{Capability: string(cap), Case: string(cap)}
	caseDir := filepath.Join(root, safeName(string(cap)))
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		return fail(r, fmt.Sprintf("creating case dir: %v", err), nil, nil)
	}
	switch cap {
	case isobox.CapFSReadHost:
		return caseFSReadHost(ctx, runner, client, caseDir, opts.Timeout)
	case isobox.CapFSReadScope:
		return caseFSReadScope(ctx, runner, client, caseDir, opts.Timeout)
	case isobox.CapFSWriteDeny:
		return caseFSWriteDeny(ctx, runner, client, caseDir, opts.Timeout)
	case isobox.CapFSWriteScope:
		return caseFSWriteScope(ctx, runner, client, caseDir, opts.Timeout)
	case isobox.CapFSWriteEphemeral:
		return caseFSWriteEphemeral(ctx, runner, client, caseDir, opts.Timeout)
	case isobox.CapNetEnable:
		return caseNetEnable(ctx, runner, client, opts)
	case isobox.CapNetOutbound:
		return caseNetOutbound(ctx, runner, client, opts)
	case isobox.CapNetDisable:
		return caseNetDisable(ctx, runner, client, opts)
	case isobox.CapProcNoExec:
		return caseNoExec(ctx, runner, client, opts.Timeout)
	case isobox.CapIPCRestrict:
		return caseIPCRestrict(ctx, runner, client, caseDir, opts)
	case isobox.CapMachRestrict:
		return caseMachRestrict(ctx, runner, client, opts)
	case isobox.CapKernelIsolation:
		return caseKernelIsolation(ctx, runner, client, opts.Timeout)
	default:
		r.Status = CaseSkip
		r.Details = "no host case implemented"
		return r
	}
}

func caseFSReadHost(ctx context.Context, runner *isobox.Runner, client, dir string, timeout time.Duration) CaseReport {
	path := filepath.Join(dir, "host-read.txt")
	if err := os.WriteFile(path, []byte("read-host"), 0o644); err != nil {
		return setupFail(isobox.CapFSReadHost, err)
	}
	return expectClient(ctx, runner, timeout, isobox.Spec{Args: []string{client, "--probe", string(ProbeFSRead), "--allowed", path}}, isobox.CapFSReadHost, map[string]bool{"allowed": true}, nil)
}

func caseFSReadScope(ctx context.Context, runner *isobox.Runner, client, dir string, timeout time.Duration) CaseReport {
	allowedRoot := filepath.Join(dir, "allowed")
	deniedRoot := filepath.Join(filepath.Dir(dir), safeName("fs.read.scope.denied"))
	if err := os.MkdirAll(allowedRoot, 0o755); err != nil {
		return setupFail(isobox.CapFSReadScope, err)
	}
	if err := os.MkdirAll(deniedRoot, 0o755); err != nil {
		return setupFail(isobox.CapFSReadScope, err)
	}
	allowed := filepath.Join(allowedRoot, "allowed-read.txt")
	denied := filepath.Join(deniedRoot, "denied-read.txt")
	if err := os.WriteFile(allowed, []byte("allowed"), 0o644); err != nil {
		return setupFail(isobox.CapFSReadScope, err)
	}
	if err := os.WriteFile(denied, []byte("denied"), 0o644); err != nil {
		return setupFail(isobox.CapFSReadScope, err)
	}
	allowlist := []string{dir, filepath.Dir(client)}
	allowedSpec := isobox.Spec{Args: []string{client, "--probe", string(ProbeFSRead), "--allowed", allowed}, Dir: allowedRoot, Readable: allowlist}
	r := expectClient(ctx, runner, timeout, allowedSpec, isobox.CapFSReadScope, map[string]bool{"allowed": true}, nil)
	if r.Status == CaseFail || r.Status == CaseSkip {
		return r
	}
	deniedSpec := isobox.Spec{Args: []string{client, "--probe", string(ProbeFSRead), "--allowed", denied}, Dir: allowedRoot, Readable: allowlist}
	return expectClientDenied(ctx, runner, timeout, deniedSpec, r, "denied")
}

func caseFSWriteDeny(ctx context.Context, runner *isobox.Runner, client, dir string, timeout time.Duration) CaseReport {
	path := filepath.Join(dir, "denied-write.txt")
	spec := isobox.Spec{Args: []string{client, "--probe", string(ProbeFSWrite), "--allowed", path, "--content", "deny"}, Write: isobox.WriteNone}
	return expectClient(ctx, runner, timeout, spec, isobox.CapFSWriteDeny, map[string]bool{"allowed": false}, func(r CaseReport) CaseReport {
		_, err := os.Stat(path)
		exists := err == nil
		if err != nil && !os.IsNotExist(err) {
			return fail(r, fmt.Sprintf("stat denied write: %v", err), nil, nil)
		}
		r.Checks["host_absent"] = !exists
		if exists {
			r.Status = CaseFail
			r.Details = appendDetail(r.Details, "host file exists after denied write")
		}
		return r
	})
}

func caseFSWriteScope(ctx context.Context, runner *isobox.Runner, client, dir string, timeout time.Duration) CaseReport {
	writable := filepath.Join(dir, "writable")
	readonly := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(writable, 0o755); err != nil {
		return setupFail(isobox.CapFSWriteScope, err)
	}
	if err := os.MkdirAll(readonly, 0o755); err != nil {
		return setupFail(isobox.CapFSWriteScope, err)
	}
	nonce := "scope-" + time.Now().UTC().Format("20060102150405.000000000")
	allowed := filepath.Join(writable, "allowed.txt")
	denied := filepath.Join(readonly, "denied.txt")
	overwriteTarget := filepath.Join(writable, "overwrite-target.txt")
	deleteTarget := filepath.Join(writable, "delete-target.txt")
	deleteDeniedTarget := filepath.Join(readonly, "delete-denied.txt")
	if err := os.WriteFile(overwriteTarget, []byte("pre-existing"), 0o666); err != nil {
		return setupFail(isobox.CapFSWriteScope, fmt.Errorf("precreating overwrite target: %w", err))
	}
	if err := os.WriteFile(deleteTarget, []byte("doomed"), 0o666); err != nil {
		return setupFail(isobox.CapFSWriteScope, fmt.Errorf("precreating delete target: %w", err))
	}
	if err := os.WriteFile(deleteDeniedTarget, []byte("must-survive"), 0o666); err != nil {
		return setupFail(isobox.CapFSWriteScope, fmt.Errorf("precreating delete-denied target: %w", err))
	}
	args := []string{
		client, "--probe", string(ProbeFSWrite),
		"--allowed", allowed,
		"--denied", denied,
		"--overwrite", overwriteTarget,
		"--delete", deleteTarget,
		"--delete-denied", deleteDeniedTarget,
		"--content", nonce,
	}
	spec := isobox.Spec{Args: args, Write: isobox.WriteScope, Writable: []string{writable}}
	expected := map[string]bool{
		"allowed":       true,
		"denied":        false,
		"overwrite":     true,
		"delete":        true,
		"delete_denied": false,
	}
	return expectClient(ctx, runner, timeout, spec, isobox.CapFSWriteScope, expected, func(r CaseReport) CaseReport {
		data, err := os.ReadFile(allowed)
		ok := err == nil && string(data) == nonce
		r.Checks["host_allowed_persisted"] = ok
		if !ok {
			r.Status = CaseFail
			r.Details = appendDetail(r.Details, fmt.Sprintf("allowed host file content mismatch: %v", err))
		}
		_, err = os.Stat(denied)
		absent := os.IsNotExist(err)
		if err == nil {
			absent = false
		}
		r.Checks["host_denied_absent"] = absent
		if !absent {
			r.Status = CaseFail
			r.Details = appendDetail(r.Details, "denied host file exists")
		}
		data, err = os.ReadFile(overwriteTarget)
		overwroteOK := err == nil && string(data) == nonce
		r.Checks["host_overwrite_persisted"] = overwroteOK
		if !overwroteOK {
			r.Status = CaseFail
			r.Details = appendDetail(r.Details, fmt.Sprintf("overwrite target content mismatch: have=%q err=%v", string(data), err))
		}
		if _, err := os.Stat(deleteTarget); !os.IsNotExist(err) {
			r.Checks["host_delete_removed"] = false
			r.Status = CaseFail
			r.Details = appendDetail(r.Details, "delete target was not removed inside writable scope")
		} else {
			r.Checks["host_delete_removed"] = true
		}
		if _, err := os.Stat(deleteDeniedTarget); os.IsNotExist(err) {
			r.Checks["host_delete_denied_preserved"] = false
			r.Status = CaseFail
			r.Details = appendDetail(r.Details, "delete-denied target was removed despite scope restriction")
		} else {
			r.Checks["host_delete_denied_preserved"] = true
		}
		return r
	})
}

func caseFSWriteEphemeral(ctx context.Context, runner *isobox.Runner, client, dir string, timeout time.Duration) CaseReport {
	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return setupFail(isobox.CapFSWriteEphemeral, err)
	}
	nonce := "ephemeral-" + time.Now().UTC().Format("20060102150405.000000000")
	path := filepath.Join(workspace, "created.txt")
	spec := isobox.Spec{Args: []string{client, "--probe", string(ProbeFSWrite), "--allowed", "created.txt", "--content", nonce}, Dir: workspace, Write: isobox.WriteEphemeral}
	return expectClient(ctx, runner, timeout, spec, isobox.CapFSWriteEphemeral, map[string]bool{"allowed": true}, func(r CaseReport) CaseReport {
		_, err := os.Stat(path)
		absent := os.IsNotExist(err)
		r.Checks["host_lower_absent"] = absent
		if !absent {
			r.Status = CaseFail
			r.Details = appendDetail(r.Details, "ephemeral write appeared in lower workspace")
		}
		return r
	})
}

func caseNetEnable(ctx context.Context, runner *isobox.Runner, client string, opts HostOptions) CaseReport {
	args := []string{client, "--probe", string(ProbeNetwork)}
	if opts.ConnectAddr != "" {
		args = append(args, "--connect", opts.ConnectAddr)
	}
	expected := map[string]bool{"listen": true, "udp_listen": true}
	if opts.ConnectAddr != "" {
		expected["connect"] = true
	}
	r := expectClient(ctx, runner, opts.Timeout, isobox.Spec{Args: args, Net: isobox.NetEnable}, isobox.CapNetEnable, expected, nil)
	r.Details = appendDetail(r.Details, "net.enable host-to-sandbox reachability is backend-dependent and not exercised by this harness")
	return r
}

func caseNetOutbound(ctx context.Context, runner *isobox.Runner, client string, opts HostOptions) CaseReport {
	args := []string{client, "--probe", string(ProbeNetwork)}
	if opts.ConnectAddr != "" {
		args = append(args, "--connect", opts.ConnectAddr)
	}
	expected := map[string]bool{"listen": false}
	if opts.ConnectAddr != "" {
		expected["connect"] = true
	}
	return expectClient(ctx, runner, opts.Timeout, isobox.Spec{Args: args, Net: isobox.NetOutbound}, isobox.CapNetOutbound, expected, nil)
}

// netDisableUnroutable is an RFC 5737 TEST-NET-3 address with an unassigned port.
// It is a guaranteed-blocked outbound target: even if a backend mis-enforces
// net.disable, the connect attempt will time out or be refused rather than
// succeed against a real service.
const netDisableUnroutable = "203.0.113.1:65535"

func caseNetDisable(ctx context.Context, runner *isobox.Runner, client string, opts HostOptions) CaseReport {
	connectAddr := opts.ConnectAddr
	if connectAddr == "" {
		connectAddr = netDisableUnroutable
	}
	args := []string{client, "--probe", string(ProbeNetwork), "--connect", connectAddr}
	spec := isobox.Spec{Args: args, Net: isobox.NetDisable}
	plan, err := runner.Compile(spec)
	if err != nil {
		return setupFail(isobox.CapNetDisable, fmt.Errorf("compile net.disable spec: %w", err))
	}
	loopbackAlsoBlocked := planBlocksLoopback(plan)
	expected := map[string]bool{
		"connect": false,
		"listen":  !loopbackAlsoBlocked,
	}
	r := expectClient(ctx, runner, opts.Timeout, spec, isobox.CapNetDisable, expected, nil)
	if loopbackAlsoBlocked {
		r.Details = appendDetail(r.Details, "backend caveat: net.disable additionally blocks loopback")
	}
	if opts.ConnectAddr == "" {
		r.Details = appendDetail(r.Details, "no --connect supplied; used TEST-NET-3 unroutable target")
	}
	return r
}

// planBlocksLoopback reports whether the backend's compiled caveats indicate
// that loopback is additionally blocked under net.disable. Seatbelt emits the
// "additionally blocks loopback" substring; other backends keep loopback.
func planBlocksLoopback(plan *isobox.Plan) bool {
	if plan == nil {
		return false
	}
	for _, c := range plan.Caveats {
		if strings.Contains(c, "additionally blocks loopback") {
			return true
		}
	}
	return false
}

func caseNoExec(ctx context.Context, runner *isobox.Runner, client string, timeout time.Duration) CaseReport {
	spec := isobox.Spec{Args: []string{client, "--probe", string(ProbeExec), "--exec-path", client}, NoExec: true}
	// gVisor/Seatbelt enforce no-new-exec: fork/clone remain allowed and only
	// execve is blocked. AppContainer's PROCESS_CREATION_CHILD_PROCESS_RESTRICTED
	// blocks all child creation, so fork must also fail.
	expected := map[string]bool{"exec": false}
	if runner != nil && runner.Backend() == isobox.BackendAppContainer {
		expected["fork"] = false
	} else {
		expected["fork"] = true
	}
	return expectClient(ctx, runner, timeout, spec, isobox.CapProcNoExec, expected, nil)
}

func caseIPCRestrict(ctx context.Context, runner *isobox.Runner, client, dir string, opts HostOptions) CaseReport {
	if runtime.GOOS == "darwin" {
		// Seatbelt no longer advertises CapIPCRestrict, but if any future
		// darwin backend does, Mach lookup remains the only available signal.
		spec := isobox.Spec{Args: []string{client, "--probe", string(ProbeMach), "--mach-service", opts.MachService}}
		return expectClient(ctx, runner, opts.Timeout, spec, isobox.CapIPCRestrict, map[string]bool{"lookup": false}, nil)
	}
	if runtime.GOOS == "windows" {
		return CaseReport{Capability: string(isobox.CapIPCRestrict), Case: string(isobox.CapIPCRestrict), Status: CaseSkip, Details: "Unix socket IPC probe is not supported on Windows"}
	}
	// Linux: run under Net=NetEnable so AF_UNIX is not incidentally blocked by
	// the net.disable rule, and probe both pathname and abstract-namespace
	// sockets. SysV IPC and POSIX message queues are not yet probed; see the
	// TODO in runIPCProbe.
	sock := filepath.Join(dir, "host.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return setupFail(isobox.CapIPCRestrict, err)
	}
	defer ln.Close()
	abstractName := "@isobox-testkit-ipc-" + safeName(filepath.Base(dir))
	abstractLn, err := net.Listen("unix", abstractName)
	if err != nil {
		return setupFail(isobox.CapIPCRestrict, fmt.Errorf("abstract listen: %w", err))
	}
	defer abstractLn.Close()
	accepted := make(chan string, 2)
	accept := func(l net.Listener, label string) {
		conn, err := l.Accept()
		if err == nil {
			conn.Close()
			accepted <- label
		}
	}
	go accept(ln, "pathname")
	go accept(abstractLn, "abstract")
	args := []string{client, "--probe", string(ProbeIPC), "--socket", sock, "--abstract-socket", abstractName}
	spec := isobox.Spec{Args: args, Net: isobox.NetEnable}
	r := expectClient(ctx, runner, opts.Timeout, spec, isobox.CapIPCRestrict, map[string]bool{"connect": false, "connect_abstract": false}, nil)
	drained := map[string]bool{}
drain:
	for {
		select {
		case label := <-accepted:
			drained[label] = true
		default:
			break drain
		}
	}
	if r.Checks == nil {
		r.Checks = make(map[string]bool)
	}
	r.Checks["host_socket_not_reached"] = !drained["pathname"]
	r.Checks["host_abstract_not_reached"] = !drained["abstract"]
	if drained["pathname"] {
		r.Status = CaseFail
		r.Details = appendDetail(r.Details, "host pathname Unix socket accepted a sandbox connection")
	}
	if drained["abstract"] {
		r.Status = CaseFail
		r.Details = appendDetail(r.Details, "host abstract Unix socket accepted a sandbox connection")
	}
	return r
}

func caseMachRestrict(ctx context.Context, runner *isobox.Runner, client string, opts HostOptions) CaseReport {
	if runtime.GOOS != "darwin" {
		return CaseReport{Capability: string(isobox.CapMachRestrict), Case: string(isobox.CapMachRestrict), Status: CaseSkip, Details: "Mach lookup probe is Darwin-only"}
	}
	if err := hostMachLookupReachable(opts.MachService); err != nil {
		return CaseReport{Capability: string(isobox.CapMachRestrict), Case: string(isobox.CapMachRestrict), Status: CaseSkip, Details: "host Mach lookup preflight failed: " + err.Error()}
	}
	// Denied leg: no allow-list, expect lookup denied by the default deny.
	deniedSpec := isobox.Spec{Args: []string{client, "--probe", string(ProbeMach), "--mach-service", opts.MachService}}
	denied := expectClient(ctx, runner, opts.Timeout, deniedSpec, isobox.CapMachRestrict, map[string]bool{"lookup": false}, nil)
	if denied.Status != CasePass {
		return denied
	}
	// Allowed leg: per-service allow-list, expect the same service to resolve.
	allowedSpec := isobox.Spec{
		Args:      []string{client, "--probe", string(ProbeMach), "--mach-service", opts.MachService},
		MachAllow: []string{opts.MachService},
	}
	allowed := expectClient(ctx, runner, opts.Timeout, allowedSpec, isobox.CapMachRestrict, map[string]bool{"lookup": true}, nil)
	if allowed.Status == CaseFail {
		denied.Status = CaseFail
		denied.Details = appendDetail(denied.Details, fmt.Sprintf("mach.restrict per-service allow-list did not let %q through", opts.MachService))
		if allowed.Details != "" {
			denied.Details = appendDetail(denied.Details, "allowed leg: "+allowed.Details)
		}
	}
	for k, v := range allowed.Checks {
		denied.Checks["allowed."+k] = v
	}
	if denied.Evidence == nil && len(allowed.Evidence) > 0 {
		denied.Evidence = make(map[string]string, len(allowed.Evidence))
	}
	for k, v := range allowed.Evidence {
		denied.Evidence["allowed."+k] = v
	}
	if denied.Status == CasePass {
		denied.Details = appendDetail(denied.Details, "blanket-deny + per-service allow-list both observed")
	}
	return denied
}

func caseKernelIsolation(ctx context.Context, runner *isobox.Runner, client string, timeout time.Duration) CaseReport {
	r := expectClient(ctx, runner, timeout, isobox.Spec{Args: []string{client, "--probe", string(ProbeKernelInfo)}}, isobox.CapKernelIsolation, nil, nil)
	if r.Status == CasePass {
		r.Status = CaseSkip
	}
	r.Details = appendDetail(r.Details, "kernel.isolation is backend-advertised and not directly observable from inside the sandbox without a process-on-host comparator; reported as Skip with evidence")
	return r
}

func expectClient(ctx context.Context, runner *isobox.Runner, timeout time.Duration, spec isobox.Spec, cap isobox.Capability, expected map[string]bool, post func(CaseReport) CaseReport) CaseReport {
	r := CaseReport{Capability: string(cap), Case: string(cap), Status: CasePass, Checks: make(map[string]bool)}
	clientCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	code, err := runner.Run(clientCtx, spec, isobox.Stdio{Out: &stdout, Err: &stderr})
	if errors.Is(clientCtx.Err(), context.DeadlineExceeded) {
		return fail(r, "case timed out", map[string]string{"stderr": stderr.String()}, nil)
	}
	if err != nil {
		return fail(r, fmt.Sprintf("sandbox launch failed: %v", err), map[string]string{"stderr": stderr.String()}, nil)
	}
	if code != 0 {
		return fail(r, fmt.Sprintf("client exited with code %d", code), map[string]string{"stdout": stdout.String(), "stderr": stderr.String()}, nil)
	}
	var clientReport ClientReport
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &clientReport); err != nil {
		return fail(r, fmt.Sprintf("decoding client JSON: %v", err), map[string]string{"stdout": stdout.String(), "stderr": stderr.String()}, nil)
	}
	if clientReport.Unsupported != "" {
		r.Status = CaseSkip
		r.Details = clientReport.Unsupported
	}
	if len(clientReport.Evidence) > 0 {
		r.Evidence = clientReport.Evidence
	}
	for name, want := range expected {
		got, ok := clientReport.Checks[name]
		passed := ok && got.Success == want
		r.Checks[name] = passed
		if !passed && r.Status != CaseSkip {
			r.Status = CaseFail
			if !ok {
				r.Details = appendDetail(r.Details, fmt.Sprintf("missing client check %q", name))
			} else {
				r.Details = appendDetail(r.Details, fmt.Sprintf("client check %q success=%t want %t", name, got.Success, want))
				if got.Error != "" {
					r.Details = appendDetail(r.Details, got.Error)
				}
			}
		}
	}
	if r.Status != CaseSkip && post != nil {
		r = post(r)
	}
	return r
}

func expectClientDenied(ctx context.Context, runner *isobox.Runner, timeout time.Duration, spec isobox.Spec, r CaseReport, check string) CaseReport {
	if r.Checks == nil {
		r.Checks = make(map[string]bool)
	}
	if r.Evidence == nil {
		r.Evidence = make(map[string]string)
	}
	clientCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	code, err := runner.Run(clientCtx, spec, isobox.Stdio{Out: &stdout, Err: &stderr})
	if errors.Is(clientCtx.Err(), context.DeadlineExceeded) {
		r.Checks[check] = false
		r.Status = CaseFail
		r.Details = appendDetail(r.Details, check+" probe timed out (no evidence of denial)")
		r.Evidence[check+".stderr"] = stderr.String()
		return r
	}
	if err != nil {
		r.Checks[check] = false
		r.Status = CaseFail
		r.Details = appendDetail(r.Details, check+" sandbox launch failed (no evidence of denial): "+err.Error())
		r.Evidence[check+".launch_error"] = err.Error()
		r.Evidence[check+".stderr"] = stderr.String()
		return r
	}
	if code != 0 {
		r.Checks[check] = false
		r.Status = CaseFail
		r.Details = appendDetail(r.Details, fmt.Sprintf("%s client exited with code %d (no evidence of denial)", check, code))
		r.Evidence[check+".exit_code"] = fmt.Sprint(code)
		r.Evidence[check+".stdout"] = stdout.String()
		r.Evidence[check+".stderr"] = stderr.String()
		return r
	}
	var clientReport ClientReport
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &clientReport); err != nil {
		r.Checks[check] = false
		r.Status = CaseFail
		r.Details = appendDetail(r.Details, check+" client JSON parse failed (no evidence of denial): "+err.Error())
		r.Evidence[check+".stdout"] = stdout.String()
		r.Evidence[check+".stderr"] = stderr.String()
		return r
	}
	got, ok := clientReport.Checks["allowed"]
	if !ok {
		r.Checks[check] = false
		r.Status = CaseFail
		r.Details = appendDetail(r.Details, check+" client report missing \"allowed\" check")
		r.Evidence[check+".stdout"] = stdout.String()
		return r
	}
	if got.Success {
		r.Checks[check] = false
		r.Status = CaseFail
		r.Details = appendDetail(r.Details, check+" operation unexpectedly succeeded")
		return r
	}
	r.Checks[check] = true
	if got.Error != "" {
		r.Evidence[check+".denied_error"] = got.Error
	}
	return r
}

const setupFailurePrefix = "host setup failed: "

func setupFail(cap isobox.Capability, err error) CaseReport {
	return CaseReport{Capability: string(cap), Case: string(cap), Status: CaseFail, Details: setupFailurePrefix + err.Error()}
}

func fail(r CaseReport, details string, evidence map[string]string, checks map[string]bool) CaseReport {
	r.Status = CaseFail
	r.Details = appendDetail(r.Details, details)
	if evidence != nil {
		r.Evidence = evidence
	}
	if checks != nil {
		r.Checks = checks
	}
	return r
}

func appendDetail(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "; " + b
}

func safeName(name string) string {
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, string(os.PathSeparator), "_")
	name = strings.ReplaceAll(name, ".", "_")
	return name
}

// HasFailure reports whether any case failed.
func HasFailure(reports []CaseReport) bool {
	for _, r := range reports {
		if r.Status == CaseFail {
			return true
		}
	}
	return false
}

// HasSetupError reports whether any case failed before the sandboxed client ran.
func HasSetupError(reports []CaseReport) bool {
	for _, r := range reports {
		if strings.HasPrefix(r.Details, setupFailurePrefix) {
			return true
		}
	}
	return false
}
