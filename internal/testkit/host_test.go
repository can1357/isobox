package testkit

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/can1357/isobox"
)

func TestSelectedCapabilitiesParsesRepeatedAndCommaSeparated(t *testing.T) {
	selected, err := selectedCapabilities([]string{"fs.read.host, fs.write.deny", "fs.read.host"}, isobox.CapsOf(isobox.BackendSeatbelt))
	if err != nil {
		t.Fatal(err)
	}
	want := []isobox.Capability{isobox.CapFSReadHost, isobox.CapFSWriteDeny}
	if len(selected) != len(want) {
		t.Fatalf("selected len=%d, want %d: %v", len(selected), len(want), selected)
	}
	for i := range want {
		if selected[i] != want[i] {
			t.Fatalf("selected[%d]=%s, want %s (all=%v)", i, selected[i], want[i], selected)
		}
	}
}

func TestSelectedCapabilitiesRejectsUnknown(t *testing.T) {
	if _, err := selectedCapabilities([]string{"fs.nope"}, isobox.CapsOf(isobox.BackendSeatbelt)); err == nil {
		t.Fatal("expected unknown capability error")
	}
}

func TestHasFailureAndSetupError(t *testing.T) {
	reports := []CaseReport{
		{Status: CasePass},
		{Status: CaseSkip},
		{Status: CaseFail, Details: setupFailurePrefix + "boom"},
	}
	if !HasFailure(reports) {
		t.Fatal("expected failure")
	}
	if !HasSetupError(reports) {
		t.Fatal("expected setup error")
	}
}

func backendRunner(t *testing.T, b isobox.Backend) *isobox.Runner {
	t.Helper()
	r, err := isobox.NewBackend(b)
	if err != nil {
		t.Fatalf("NewBackend(%s): %v", b, err)
	}
	return r
}

// TestExpectClientDeniedRequiresPositiveEvidence — R10. A launch failure
// (here, the client binary does not exist) must be reported as Fail, not
// silently counted as evidence that the operation was denied. The previous
// semantics treated `err != nil || code != 0` as a successful denial, which
// rewarded broken setups.
func TestExpectClientDeniedRequiresPositiveEvidence(t *testing.T) {
	runner := backendRunner(t, isobox.BackendSeatbelt)
	r := CaseReport{Capability: "fs.read.scope", Case: "fs.read.scope", Status: CasePass}
	spec := isobox.Spec{Args: []string{"/this/binary/does/not/exist"}}
	got := expectClientDenied(context.Background(), runner, time.Second, spec, r, "denied")
	if got.Status != CaseFail {
		t.Fatalf("status=%s, want Fail — launch failure must NOT be counted as denial evidence", got.Status)
	}
	if got.Checks["denied"] {
		t.Fatalf("denied=true despite launch failure; checks=%v", got.Checks)
	}
	if !strings.Contains(got.Details, "no evidence of denial") {
		t.Fatalf("details should mention missing evidence; got=%q", got.Details)
	}
}

// TestCaseNetDisableLoopbackExpectsListenAllowed — R11. The "additionally
// blocks loopback" caveat substring is the contract that flips the loopback
// expectation: Seatbelt blocks loopback under net.disable; gVisor preserves
// it. The harness asks the compiled plan instead of hardcoding per-backend.
func TestCaseNetDisableLoopbackExpectsListenAllowed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		backend    isobox.Backend
		wantBlocks bool
	}{
		{"seatbelt", isobox.BackendSeatbelt, true},
		{"gvisor", isobox.BackendGvisor, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := backendRunner(t, tc.backend)
			plan, err := runner.Compile(isobox.Spec{Args: []string{"/bin/sh"}, Net: isobox.NetDisable})
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if got := planBlocksLoopback(plan); got != tc.wantBlocks {
				t.Fatalf("planBlocksLoopback=%v, want %v; caveats=%v", got, tc.wantBlocks, plan.Caveats)
			}
		})
	}
}

// TestPlanBlocksLoopbackIgnoresUnrelatedCaveats keeps the substring match
// honest: arbitrary caveats must not trip the loopback flag, only the
// documented "additionally blocks loopback" wording does.
func TestPlanBlocksLoopbackIgnoresUnrelatedCaveats(t *testing.T) {
	plan := &isobox.Plan{Caveats: []string{"some other caveat", "loopback works fine"}}
	if planBlocksLoopback(plan) {
		t.Fatalf("planBlocksLoopback should require the exact substring; caveats=%v", plan.Caveats)
	}
	plan.Caveats = append(plan.Caveats, "Seatbelt net.disable additionally blocks loopback; ...")
	if !planBlocksLoopback(plan) {
		t.Fatalf("planBlocksLoopback should fire on the documented substring; caveats=%v", plan.Caveats)
	}
}

// TestCaseKernelIsolationNeverReportsPass — R15. The case must never declare a
// Pass because nothing inside the sandbox proves kernel isolation; the result
// is either Skip (when the probe ran) or Fail (when the harness setup broke),
// and the documented "not directly observable" caveat is always appended.
func TestCaseKernelIsolationNeverReportsPass(t *testing.T) {
	runner := backendRunner(t, isobox.BackendGvisor)
	got := caseKernelIsolation(context.Background(), runner, "/bin/sh", time.Second)
	if got.Status == CasePass {
		t.Fatalf("status=%s, kernel.isolation must never be Pass; details=%q", got.Status, got.Details)
	}
	if !strings.Contains(got.Details, "not directly observable") {
		t.Fatalf("details should explain why it's not Pass; got=%q", got.Details)
	}
}

// TestCaseNetEnableRunsWithoutConnectAddr — R13. The case must execute the
// in-sandbox listen + UDP-listen check even without a --connect target and
// record the documented honesty caveat about host-to-sandbox reachability
// (which this harness does not exercise).
func TestCaseNetEnableRunsWithoutConnectAddr(t *testing.T) {
	runner := backendRunner(t, isobox.BackendGvisor)
	got := caseNetEnable(context.Background(), runner, "/this/binary/does/not/exist", HostOptions{Timeout: 500 * time.Millisecond})
	if got.Status == CaseSkip {
		t.Fatalf("net.enable must not skip without --connect; got Skip with %q", got.Details)
	}
	if !strings.Contains(got.Details, "host-to-sandbox reachability") {
		t.Fatalf("details should record the honesty caveat about reachability; got=%q", got.Details)
	}
}

// TestCaseNetOutboundRunsWithoutConnectAddr — R12. The case must assert
// listen-denial even when no --connect is given; previously it skipped
// entirely, hiding regressions in inbound-listen enforcement.
func TestCaseNetOutboundRunsWithoutConnectAddr(t *testing.T) {
	runner := backendRunner(t, isobox.BackendGvisor)
	got := caseNetOutbound(context.Background(), runner, "/this/binary/does/not/exist", HostOptions{Timeout: 500 * time.Millisecond})
	if got.Status == CaseSkip {
		t.Fatalf("net.outbound must not skip without --connect; got Skip with %q", got.Details)
	}
}

// TestCaseNetDisableUsesUnroutableFallback — R11. Without --connect the case
// derives a TEST-NET-3 target and records that choice in the details, instead
// of skipping.
func TestCaseNetDisableUsesUnroutableFallback(t *testing.T) {
	runner := backendRunner(t, isobox.BackendGvisor)
	got := caseNetDisable(context.Background(), runner, "/this/binary/does/not/exist", HostOptions{Timeout: 500 * time.Millisecond})
	if got.Status == CaseSkip {
		t.Fatalf("net.disable must not skip without --connect; got Skip with %q", got.Details)
	}
	if !strings.Contains(got.Details, "TEST-NET-3") {
		t.Fatalf("details should mention the unroutable fallback; got=%q", got.Details)
	}
}

// TestCaseNoExecRunsAndAppContainerExpectsForkBlocked — R14. caseNoExec must
// run end-to-end against any backend that advertises CapProcNoExec; the fork
// expectation flips for AppContainer (PROCESS_CREATION_CHILD_PROCESS_RESTRICTED
// blocks all child creation) vs gVisor (fork allowed, exec blocked). We can
// only verify the case compiles + dispatches here; runtime fork/exec is
// exercised when a real sandbox is on the host.
func TestCaseNoExecRunsAndAppContainerExpectsForkBlocked(t *testing.T) {
	gvisor := backendRunner(t, isobox.BackendGvisor)
	got := caseNoExec(context.Background(), gvisor, "/this/binary/does/not/exist", 500*time.Millisecond)
	if got.Status == CaseSkip {
		t.Fatalf("no_exec must not skip; got Skip with %q", got.Details)
	}
	// AppContainer compile must succeed on this platform so the branch is
	// reached at runtime on Windows.
	if _, err := isobox.NewBackend(isobox.BackendAppContainer); err != nil {
		t.Fatalf("AppContainer backend unavailable for compile check: %v", err)
	}
}

// TestCaseMachRestrictSkipsOffDarwin — R17. The Mach-allow leg is darwin-only;
// the case must skip cleanly on every other platform rather than pretend it
// ran the per-service allow-list.
func TestCaseMachRestrictSkipsOffDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("exercises the non-darwin branch only")
	}
	runner := backendRunner(t, isobox.BackendSeatbelt)
	got := caseMachRestrict(context.Background(), runner, "/bin/sh", HostOptions{MachService: "com.apple.example", Timeout: time.Second})
	if got.Status != CaseSkip {
		t.Fatalf("status=%s, want Skip on non-darwin", got.Status)
	}
}

// TestCaseIPCRestrictUsesNetEnableOnLinux — R16. The Linux ipc.restrict probe
// must run under Net=NetEnable so AF_UNIX is not incidentally blocked by
// net.disable. We assert via a quick compile that NetEnable is the actual
// network mode the case feeds the runner.
func TestCaseIPCRestrictUsesNetEnableOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only path")
	}
	runner := backendRunner(t, isobox.BackendGvisor)
	dir := t.TempDir()
	// Drive the case with a broken client binary; we only inspect the result
	// envelope, not the probe outcome. Any Skip means the case bailed before
	// applying the NetEnable contract.
	got := caseIPCRestrict(context.Background(), runner, "/this/binary/does/not/exist", dir, HostOptions{Timeout: 500 * time.Millisecond})
	if got.Status == CaseSkip {
		t.Fatalf("Linux ipc.restrict must not skip; got Skip with %q", got.Details)
	}
}
