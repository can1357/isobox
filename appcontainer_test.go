package isobox

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func hasACSID(sids []acCapabilitySID, want acCapabilitySID) bool {
	for _, sid := range sids {
		if sid == want {
			return true
		}
	}
	return false
}

func hasString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func caveatContains(caveats []string, want string) bool {
	for _, caveat := range caveats {
		if strings.Contains(caveat, want) {
			return true
		}
	}
	return false
}

func TestAppContainerNetworkCapabilities(t *testing.T) {
	exe := testExecutable(t)
	readable := t.TempDir()

	cases := []struct {
		name    string
		net     NetMode
		want    []acCapabilitySID
		missing []acCapabilitySID
		caveat  string
	}{
		{
			name:   "disable",
			net:    NetDisable,
			caveat: "blocks loopback",
			missing: []acCapabilitySID{
				acWinCapabilityInternetClientSid,
				acWinCapabilityInternetClientServerSid,
				acWinCapabilityPrivateNetworkClientServerSid,
			},
		},
		{
			name: "enable",
			net:  NetEnable,
			want: []acCapabilitySID{
				acWinCapabilityInternetClientServerSid,
				acWinCapabilityPrivateNetworkClientServerSid,
			},
			missing: []acCapabilitySID{acWinCapabilityInternetClientSid},
		},
		{
			name:    "outbound",
			net:     NetOutbound,
			want:    []acCapabilitySID{acWinCapabilityInternetClientSid},
			missing: []acCapabilitySID{acWinCapabilityInternetClientServerSid, acWinCapabilityPrivateNetworkClientServerSid},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := compileAppContainer(Spec{Args: []string{exe}, Net: tc.net, Readable: []string{readable}})
			if err != nil {
				t.Fatal(err)
			}
			for _, sid := range tc.want {
				if !hasACSID(p.ac.CapabilitySIDs, sid) {
					t.Errorf("missing SID %s in %v", sid, p.ac.CapabilitySIDs)
				}
			}
			for _, sid := range tc.missing {
				if hasACSID(p.ac.CapabilitySIDs, sid) {
					t.Errorf("unexpected SID %s in %v", sid, p.ac.CapabilitySIDs)
				}
			}
			if tc.net == NetOutbound {
				if p.Uses.Has(CapNetOutbound) {
					t.Fatalf("outbound AppContainer plan should not claim %s: %v", CapNetOutbound, p.Uses.List())
				}
				if !caveatContains(p.Caveats, "InternetClient") {
					t.Fatalf("outbound must explain InternetClient limitation: %v", p.Caveats)
				}
			}
			if tc.caveat != "" && !caveatContains(p.Caveats, tc.caveat) {
				t.Fatalf("missing caveat %q in %v", tc.caveat, p.Caveats)
			}
		})
	}
}

func TestAppContainerReadGrants(t *testing.T) {
	exe := testExecutable(t)
	readable := t.TempDir()

	scoped, err := compileAppContainer(Spec{Args: []string{exe}, Net: NetEnable, Readable: []string{readable}})
	if err != nil {
		t.Fatal(err)
	}
	if !scoped.Uses.Has(CapFSReadScope) || scoped.Uses.Has(CapFSReadHost) {
		t.Fatalf("scoped read capabilities wrong: %v", scoped.Uses.List())
	}
	if !hasString(scoped.ac.ReadGrants, canonPath(readable)) {
		t.Fatalf("missing readable grant %s in %v", canonPath(readable), scoped.ac.ReadGrants)
	}
	if scoped.ac.WorkDir != "" {
		t.Fatalf("empty Dir with scoped reads should not invent a workdir: %+v", scoped.ac)
	}
	if !hasString(scoped.ac.ReadGrants, scoped.ac.Exe) || hasString(scoped.ac.ReadGrants, canonPath(os.TempDir())) {
		t.Fatalf("scoped read grants must include exe without unrelated workdir grants: %+v", scoped.ac)
	}
	if caveatContains(scoped.Caveats, "broad host reads") {
		t.Fatalf("scoped reads should not warn about broad reads: %v", scoped.Caveats)
	}

	coveredDir, err := compileAppContainer(Spec{Args: []string{exe}, Net: NetEnable, Dir: readable, Readable: []string{readable}})
	if err != nil {
		t.Fatal(err)
	}
	if coveredDir.ac.WorkDir != canonPath(readable) || !hasString(coveredDir.ac.ReadGrants, canonPath(readable)) {
		t.Fatalf("covered workdir should be granted once by its readable scope: %+v", coveredDir.ac)
	}

	uncoveredDir := t.TempDir()
	if _, err := compileAppContainer(Spec{Args: []string{exe}, Net: NetEnable, Dir: uncoveredDir, Readable: []string{readable}}); err == nil {
		t.Fatal("uncovered scoped workdir should be rejected before AppContainer grants are compiled")
	}

	writableDir := t.TempDir()
	coveredByWritable, err := compileAppContainer(Spec{
		Args:     []string{exe},
		Net:      NetEnable,
		Dir:      writableDir,
		Readable: []string{readable},
		Write:    WriteScope,
		Writable: []string{writableDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasString(coveredByWritable.ac.ReadGrants, canonPath(writableDir)) {
		t.Fatalf("workdir covered by writable scope should receive launch read grant: %+v", coveredByWritable.ac)
	}

	broad, err := compileAppContainer(Spec{Args: []string{exe}, Net: NetEnable})
	if err != nil {
		t.Fatal(err)
	}
	if broad.Uses.Has(CapFSReadHost) || broad.Uses.Has(CapFSReadScope) {
		t.Fatalf("empty readable AppContainer capabilities wrong: %v", broad.Uses.List())
	}
	if !hasString(broad.ac.ReadGrants, broad.ac.Exe) || !hasString(broad.ac.ReadGrants, broad.ac.WorkDir) {
		t.Fatalf("empty readable should keep only launch grants: %+v", broad.ac)
	}
	if !caveatContains(broad.Caveats, "broad host reads are not provided") {
		t.Fatalf("empty readable must carry caveat: %v", broad.Caveats)
	}
}

func TestAppContainerWriteModes(t *testing.T) {
	exe := testExecutable(t)
	readable := t.TempDir()
	writable := t.TempDir()

	scoped, err := compileAppContainer(Spec{
		Args:     []string{exe},
		Net:      NetEnable,
		Readable: []string{readable},
		Write:    WriteScope,
		Writable: []string{writable},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !scoped.Uses.Has(CapFSWriteScope) || scoped.Uses.Has(CapFSWriteEphemeral) {
		t.Fatalf("scoped write capabilities wrong: %v", scoped.Uses.List())
	}
	if !hasString(scoped.ac.WriteGrants, canonPath(writable)) {
		t.Fatalf("missing writable grant %s in %v", canonPath(writable), scoped.ac.WriteGrants)
	}

	none, err := compileAppContainer(Spec{
		Args:     []string{exe},
		Net:      NetEnable,
		Readable: []string{readable},
		Write:    WriteNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	// R1: AppContainer cannot deny all writes (per-profile storage + TEMP remain
	// writable), so it must not claim fs.write.deny and must caveat the gap.
	if none.Uses.Has(CapFSWriteDeny) {
		t.Fatalf("WriteNone on AppContainer must not claim fs.write.deny: %v", none.Uses.List())
	}
	if !caveatContains(none.Caveats, "cannot deny all writes") {
		t.Fatalf("WriteNone must carry per-profile storage caveat: %v", none.Caveats)
	}
	if !caveatContains(none.Caveats, "%LOCALAPPDATA%") {
		t.Fatalf("WriteNone caveat must name the host-backed storage location: %v", none.Caveats)
	}

	ephemeral, err := compileAppContainer(Spec{
		Args:     []string{exe},
		Net:      NetEnable,
		Readable: []string{readable},
		Write:    WriteEphemeral,
	})
	if err != nil {
		t.Fatal(err)
	}
	// R1: ephemeral degrades to "deny", but AppContainer cannot fully deny.
	if ephemeral.Uses.Has(CapFSWriteDeny) || ephemeral.Uses.Has(CapFSWriteEphemeral) {
		t.Fatalf("ephemeral degrade capabilities wrong: %v", ephemeral.Uses.List())
	}
	if !caveatContains(ephemeral.Caveats, "no ephemeral overlay") {
		t.Fatalf("missing ephemeral degrade caveat: %v", ephemeral.Caveats)
	}
	if !caveatContains(ephemeral.Caveats, "cannot deny all writes") {
		t.Fatalf("ephemeral must also carry per-profile storage caveat: %v", ephemeral.Caveats)
	}

	overlay, err := compileAppContainer(Spec{
		Args:      []string{exe},
		Net:       NetEnable,
		Readable:  []string{readable},
		ReadDeny:  []string{filepath.Join(readable, "secret")},
		Write:     WriteOverlay,
		Writable:  []string{writable},
		AllowTemp: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !overlay.Uses.Has(CapFSWriteScope) || overlay.Uses.Has(CapFSWriteEphemeral) {
		t.Fatalf("overlay degrade capabilities wrong: %v", overlay.Uses.List())
	}
	if !hasString(overlay.ac.WriteGrants, canonPath(writable)) {
		t.Fatalf("missing overlay writable grant %s in %v", canonPath(writable), overlay.ac.WriteGrants)
	}
	if !caveatContains(overlay.Caveats, "no ephemeral/shadow overlay") {
		t.Fatalf("missing overlay degrade caveat: %v", overlay.Caveats)
	}
	if !caveatContains(overlay.Caveats, "cannot carve read-deny") {
		t.Fatalf("missing read-deny caveat: %v", overlay.Caveats)
	}
}

func TestAppContainerNoExecAndProfileShape(t *testing.T) {
	exe := testExecutable(t)
	readable := t.TempDir()
	p, err := compileAppContainer(Spec{Args: []string{exe, "arg"}, Net: NetOutbound, Readable: []string{readable}, NoExec: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Backend != BackendAppContainer {
		t.Fatalf("backend=%s", p.Backend)
	}
	if len(p.Argv) != 2 || p.Argv[0] != p.ac.Exe || p.Argv[1] != "arg" {
		t.Fatalf("argv not resolved inner command: argv=%v ac=%+v", p.Argv, p.ac)
	}
	if !p.ac.ChildRestricted || !p.Uses.Has(CapProcNoExec) {
		t.Fatalf("no-exec not reflected: uses=%v ac=%+v", p.Uses.List(), p.ac)
	}
	for _, frag := range []string{"appcontainer isobox-", "WinCapabilityInternetClientSid", "child process policy: restricted", p.ac.Exe} {
		if !profileHas(p.Profile, frag) {
			t.Fatalf("profile missing %q:\n%s", frag, p.Profile)
		}
	}
	// R8: AppContainer's no-exec is no-new-process, not no-new-exec, so isobox
	// must caveat the stronger Win32 contract.
	if !caveatContains(p.Caveats, "PROCESS_CREATION_CHILD_PROCESS_RESTRICTED") {
		t.Fatalf("no-exec must caveat PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: %v", p.Caveats)
	}
	if !caveatContains(p.Caveats, "ALL child-process creation") {
		t.Fatalf("no-exec must caveat that fork-like creation is also blocked: %v", p.Caveats)
	}
	if !caveatContains(p.Caveats, "broker") {
		t.Fatalf("no-exec must caveat the out-of-process broker escape: %v", p.Caveats)
	}

	noNoExec, err := compileAppContainer(Spec{Args: []string{exe}, Net: NetEnable, Readable: []string{readable}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range noNoExec.Caveats {
		if strings.Contains(c, "PROCESS_CREATION_CHILD_PROCESS_RESTRICTED") {
			t.Fatalf("no-exec caveat must not appear when NoExec is false: %v", noNoExec.Caveats)
		}
	}
}

// R6: per-run AppContainer profile names must differ across calls so a crashed
// run cannot leak ACL grants into a future run that shares the same Spec.
func TestAppContainerProfileNameUniquePerRun(t *testing.T) {
	exe := testExecutable(t)
	readable := t.TempDir()
	spec := Spec{
		Args:     []string{exe, "arg"},
		Net:      NetEnable,
		Readable: []string{readable},
		Write:    WriteNone,
	}
	const trials = 8
	seen := make(map[string]struct{}, trials)
	for i := 0; i < trials; i++ {
		p, err := compileAppContainer(spec)
		if err != nil {
			t.Fatal(err)
		}
		name := p.ac.ProfileName
		if !strings.HasPrefix(name, "isobox-") {
			t.Fatalf("profile name %q missing isobox- prefix", name)
		}
		// 16 hex chars after "isobox-" → 21-char total.
		if len(name) != len("isobox-")+16 {
			t.Fatalf("profile name %q must be isobox- + 16 hex chars, got len=%d", name, len(name))
		}
		if _, dup := seen[name]; dup {
			t.Fatalf("profile name %q repeated across compileAppContainer calls; per-run uniqueness violated", name)
		}
		seen[name] = struct{}{}
	}
}

func TestAppContainerResourceLimits(t *testing.T) {
	exe := testExecutable(t)
	p, err := compileAppContainer(Spec{Args: []string{exe}, Net: NetEnable, CPUs: 1.5, MemoryBytes: 512 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if p.ac.CPUs != 1.5 || p.ac.MemoryBytes != 512<<20 {
		t.Fatalf("profile resource fields wrong: cpus=%v mem=%d", p.ac.CPUs, p.ac.MemoryBytes)
	}
	if !p.Uses.Has(CapResCPU) || !p.Uses.Has(CapResMemory) {
		t.Fatalf("plan uses missing resource caps: %v", p.Uses.List())
	}
	for _, frag := range []string{"cpu limit: 1.5 cores", "memory limit: 536870912 bytes"} {
		if !profileHas(p.Profile, frag) {
			t.Fatalf("profile missing %q:\n%s", frag, p.Profile)
		}
	}
}

func TestAppContainerOmitsResourceLinesWithoutLimits(t *testing.T) {
	exe := testExecutable(t)
	p, err := compileAppContainer(Spec{Args: []string{exe}, Net: NetEnable})
	if err != nil {
		t.Fatal(err)
	}
	if p.Uses.Has(CapResCPU) || p.Uses.Has(CapResMemory) {
		t.Fatalf("no limits must not claim resource caps: %v", p.Uses.List())
	}
	if strings.Contains(p.Profile, "cpu limit:") || strings.Contains(p.Profile, "memory limit:") {
		t.Fatalf("no limits must omit resource lines:\n%s", p.Profile)
	}
}

// FIX 1: scoped reads must caveat that additive ACL grants cannot revoke the
// ambient ALL APPLICATION PACKAGES readability, without claiming broad reads.
func TestAppContainerScopedReadAmbientCaveat(t *testing.T) {
	exe := testExecutable(t)
	readable := t.TempDir()
	p, err := compileAppContainer(Spec{Args: []string{exe}, Net: NetEnable, Readable: []string{readable}})
	if err != nil {
		t.Fatal(err)
	}
	if !caveatContains(p.Caveats, "ALL APPLICATION PACKAGES") {
		t.Fatalf("scoped reads must caveat ambient ALL APPLICATION PACKAGES readability: %v", p.Caveats)
	}
	if caveatContains(p.Caveats, "broad host reads") {
		t.Fatalf("scoped reads must not warn about broad host reads: %v", p.Caveats)
	}
}

// FIX 2: the memory caveat must clarify that footprint can exceed the commit cap.
func TestAppContainerMemoryCommitCaveat(t *testing.T) {
	exe := testExecutable(t)
	p, err := compileAppContainer(Spec{Args: []string{exe}, Net: NetEnable, MemoryBytes: 256 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if !caveatContains(p.Caveats, "working-set") {
		t.Fatalf("memory caveat must note that physical footprint can exceed the commit cap: %v", p.Caveats)
	}
}

// cpuRateHundredths maps a logical-core count onto the Windows job-object
// CpuRate hard cap (hundredths of a percent of all host processors).
func TestCPURateHundredths(t *testing.T) {
	n := float64(runtime.NumCPU())
	if got := cpuRateHundredths(n); got != cpuRateMaxHundredths {
		t.Fatalf("all host cores: got %d, want %d", got, cpuRateMaxHundredths)
	}
	if got := cpuRateHundredths(n * 4); got != cpuRateMaxHundredths {
		t.Fatalf("oversubscribed request must clamp to %d, got %d", cpuRateMaxHundredths, got)
	}
	if got := cpuRateHundredths(n / 2); got != cpuRateMaxHundredths/2 {
		t.Fatalf("half the host: got %d, want %d", got, cpuRateMaxHundredths/2)
	}
	if got := cpuRateHundredths(1e-9); got < 1 {
		t.Fatalf("tiny request must floor at 1, got %d", got)
	}
}
