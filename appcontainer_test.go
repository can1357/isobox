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
				if !p.Uses.Has(CapNetOutbound) {
					t.Fatalf("outbound AppContainer plan should claim %s: %v", CapNetOutbound, p.Uses.List())
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
	if !scoped.ac.DeriveOnlyLowbox {
		t.Fatalf("WriteScope must avoid per-profile storage: %+v", scoped.ac)
	}
	if !profileHas(scoped.Profile, "profile storage: derive-only") {
		t.Fatalf("WriteScope profile must show derive-only storage:\n%s", scoped.Profile)
	}
	if !caveatContains(scoped.Caveats, "ambient write access") {
		t.Fatalf("WriteScope must caveat ambient writable ACLs: %v", scoped.Caveats)
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
	if !none.Uses.Has(CapFSWriteDeny) {
		t.Fatalf("WriteNone on AppContainer must claim fs.write.deny: %v", none.Uses.List())
	}
	if !none.ac.DeriveOnlyLowbox {
		t.Fatalf("WriteNone must use derive-only profile storage: %+v", none.ac)
	}
	if len(none.ac.WriteGrants) != 0 {
		t.Fatalf("WriteNone must not grant writable host paths: %+v", none.ac)
	}
	if !profileHas(none.Profile, "profile storage: derive-only") {
		t.Fatalf("WriteNone profile must show derive-only storage:\n%s", none.Profile)
	}
	if !caveatContains(none.Caveats, "ALL APPLICATION PACKAGES") {
		t.Fatalf("WriteNone must caveat ambient ALL APPLICATION PACKAGES writes: %v", none.Caveats)
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
	if !ephemeral.Uses.Has(CapFSWriteEphemeral) || ephemeral.Uses.Has(CapFSWriteDeny) {
		t.Fatalf("ephemeral capabilities wrong: %v", ephemeral.Uses.List())
	}
	if !ephemeral.ac.DeriveOnlyLowbox {
		t.Fatalf("WriteEphemeral must avoid per-profile storage: %+v", ephemeral.ac)
	}
	if ephemeral.ac.WorkDir != isoboxEphemeralRootPlaceholder {
		t.Fatalf("ephemeral workdir=%q, want placeholder", ephemeral.ac.WorkDir)
	}
	if !hasString(ephemeral.ac.ReadGrants, isoboxEphemeralRootPlaceholder) || !hasString(ephemeral.ac.WriteGrants, isoboxEphemeralRootPlaceholder) {
		t.Fatalf("ephemeral grants must include clone placeholder: %+v", ephemeral.ac)
	}
	if ephemeral.fs == nil || ephemeral.fs.Kind != fsVirtualizationWindowsWorkspaceCopy {
		t.Fatalf("ephemeral should request Windows workspace copy, got %#v", ephemeral.fs)
	}
	if !profileHas(ephemeral.Profile, isoboxEphemeralRootPlaceholder) {
		t.Fatalf("ephemeral profile should contain clone placeholder:\n%s", ephemeral.Profile)
	}
	if !caveatContains(ephemeral.Caveats, "workspace-scoped") || !caveatContains(ephemeral.Caveats, "full byte copy") {
		t.Fatalf("missing ephemeral workspace-copy caveats: %v", ephemeral.Caveats)
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
	if !overlay.ac.DeriveOnlyLowbox {
		t.Fatalf("WriteOverlay must avoid per-profile storage: %+v", overlay.ac)
	}
	if !caveatContains(overlay.Caveats, "no ephemeral/shadow overlay") {
		t.Fatalf("missing overlay degrade caveat: %v", overlay.Caveats)
	}
	if !caveatContains(overlay.Caveats, "cannot carve read-deny") {
		t.Fatalf("missing read-deny caveat: %v", overlay.Caveats)
	}
	if !caveatContains(overlay.Caveats, "ambient write access") {
		t.Fatalf("WriteOverlay must caveat ambient writable ACLs: %v", overlay.Caveats)
	}
}

func TestAppContainerEphemeralPlaceholderReplacement(t *testing.T) {
	exe := testExecutable(t)
	p, err := compileAppContainer(Spec{Args: []string{exe}, Write: WriteEphemeral})
	if err != nil {
		t.Fatal(err)
	}
	const clone = `C:\isobox\clone`
	replacePlanPlaceholder(p, isoboxEphemeralRootPlaceholder, clone)
	if p.ac.WorkDir != clone {
		t.Fatalf("workdir placeholder not replaced: %+v", p.ac)
	}
	if !hasString(p.ac.ReadGrants, clone) || !hasString(p.ac.WriteGrants, clone) {
		t.Fatalf("grant placeholders not replaced: %+v", p.ac)
	}
	if profileHas(p.Profile, isoboxEphemeralRootPlaceholder) || !profileHas(p.Profile, clone) {
		t.Fatalf("profile placeholder replacement failed:\n%s", p.Profile)
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
