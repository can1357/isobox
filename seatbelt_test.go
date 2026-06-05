package isobox

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Pure generation tests (no execution) run on any host.

func TestSeatbeltProfileGeneration(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo", "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Argv[0] != "sandbox-exec" {
		t.Errorf("argv[0]=%q, want sandbox-exec", p.Argv[0])
	}
	for _, frag := range []string{"(version 1)", "(allow default)", "(deny network*)", `(deny file-write* (subpath "/"))`} {
		if !profileHas(p.Profile, frag) {
			t.Errorf("profile missing %q:\n%s", frag, p.Profile)
		}
	}
	if p.Argv[len(p.Argv)-1] != "hi" {
		t.Errorf("command args not appended: %v", p.Argv)
	}
}

func TestSeatbeltPlanUsesMachRestrict(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo", "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if !profileHas(p.Profile, "(deny mach-lookup)") {
		t.Fatalf("profile missing Mach default deny:\n%s", p.Profile)
	}
	if !p.Uses.Has(CapMachRestrict) {
		t.Fatalf("Seatbelt plan should surface mach.restrict: %v", p.Uses.List())
	}
	if p.Uses.Has(CapIPCRestrict) {
		t.Fatalf("Seatbelt plan should not claim broad ipc.restrict: %v", p.Uses.List())
	}
}

func TestSeatbeltNetEnableDropsDeny(t *testing.T) {
	p, _ := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Net: NetEnable})
	if profileHas(p.Profile, "(deny network*)") {
		t.Errorf("net=enable should not deny network:\n%s", p.Profile)
	}
}

func TestSeatbeltScopedWriteAllowsPath(t *testing.T) {
	w := "/tmp/isobox-gen-scope"
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Write: WriteScope, Writable: []string{w}})
	if err != nil {
		t.Fatal(err)
	}
	if !profileHas(p.Profile, sbplQuote(canonPath(w))) {
		t.Errorf("profile should allow %s (canon %s):\n%s", w, canonPath(w), p.Profile)
	}
	if !p.Uses.Has(CapFSWriteScope) {
		t.Error("expected fs.write.scope capability")
	}
}

func TestSeatbeltOverlayDegradesOutsideWritesToDeny(t *testing.T) {
	w := "/tmp/isobox-overlay-work"
	p, err := compileSeatbelt(Spec{
		Args:      []string{"/bin/echo"},
		Net:       NetOutbound,
		Write:     WriteOverlay,
		Writable:  []string{w},
		AllowTemp: true,
		ReadDeny:  []string{"/tmp/isobox-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, frag := range []string{"(deny network-inbound)", sbplQuote(canonPath(w)), sbplQuote(canonPath("/tmp/isobox-secret"))} {
		if !profileHas(p.Profile, frag) {
			t.Fatalf("overlay profile missing %q:\n%s", frag, p.Profile)
		}
	}
	if !p.Uses.Has(CapFSWriteScope) || p.Uses.Has(CapFSWriteEphemeral) {
		t.Fatalf("Seatbelt overlay should enforce scoped writes only, got %v", p.Uses.List())
	}
	if !p.Uses.Has(CapFSReadDeny) {
		t.Fatalf("Seatbelt overlay should enforce read deny, got %v", p.Uses.List())
	}
	if !caveatsContain(p.Caveats, "cannot redirect writes outside writable paths") {
		t.Fatalf("overlay caveat missing: %v", p.Caveats)
	}
}

func TestSeatbeltReadDenyFollowsReadAllows(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Readable: []string{"/tmp"}, ReadDeny: []string{"/tmp/secret"}})
	if err != nil {
		t.Fatal(err)
	}
	allow := strings.Index(p.Profile, `(allow file-read* (subpath `+sbplQuote(canonPath("/tmp"))+`)`)
	deny := strings.Index(p.Profile, `(deny file-read* (subpath `+sbplQuote(canonPath("/tmp/secret"))+`)`)
	if allow < 0 || deny < 0 || deny < allow {
		t.Fatalf("read deny must follow read allow so it wins; allow=%d deny=%d profile:\n%s", allow, deny, p.Profile)
	}
}

func TestSeatbeltEphemeralRequestsAPFSClone(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Write: WriteEphemeral})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Uses.Has(CapFSWriteEphemeral) {
		t.Fatalf("ephemeral should use fs.write.ephemeral on Seatbelt: %v", p.Uses.List())
	}
	if p.Uses.Has(CapFSWriteDeny) {
		t.Fatalf("ephemeral should not degrade to deny on Seatbelt: %v", p.Uses.List())
	}
	if p.fs == nil || p.fs.Kind != fsVirtualizationMacOSAPFSClone {
		t.Fatalf("ephemeral should request macOS APFS clone virtualization, got %#v", p.fs)
	}
	if len(p.Caveats) == 0 {
		t.Fatalf("ephemeral should report APFS clone caveats in the plan, got %#v", p.Caveats)
	}
	foundScopedCloneCaveat := false
	for _, caveat := range p.Caveats {
		if profileHas(caveat, "APFS clone") && profileHas(caveat, "not a whole-host overlay") {
			foundScopedCloneCaveat = true
		}
	}
	if !foundScopedCloneCaveat {
		t.Fatalf("ephemeral caveats should describe workspace-scoped APFS clone limits, got %#v", p.Caveats)
	}
	if !profileHas(p.Profile, isoboxEphemeralRootPlaceholder) {
		t.Fatalf("profile should contain clone placeholder %q:\n%s", isoboxEphemeralRootPlaceholder, p.Profile)
	}
	for _, caveat := range p.Caveats {
		if profileHas(caveat, "writes are denied instead of discarded") || profileHas(caveat, "no ephemeral overlay") {
			t.Fatalf("ephemeral has stale deny-only caveat: %q", caveat)
		}
	}
}

func TestSeatbeltEphemeralRejectsAllowTemp(t *testing.T) {
	_, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Write: WriteEphemeral, AllowTemp: true})
	if err == nil {
		t.Fatal("WriteEphemeral+AllowTemp should be rejected before host temp roots can be granted")
	}
}

func TestSeatbeltScopedReadRuntimeAllowancesAreNarrow(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Readable: []string{"/tmp/isobox-read-scope"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/usr/share", "/Library", "/private/etc"} {
		if profileHas(p.Profile, path) {
			t.Fatalf("scoped read profile should not include broad runtime read allowance %q:\n%s", path, p.Profile)
		}
	}
	for _, path := range seatbeltDeviceReadLiterals {
		if !profileHas(p.Profile, `(literal "`+path+`")`) {
			t.Fatalf("scoped read profile missing device literal %q:\n%s", path, p.Profile)
		}
	}
	if profileHas(p.Profile, `(subpath "/dev")`) {
		t.Fatalf("scoped read profile should not include broad /dev read:\n%s", p.Profile)
	}
}

func TestSeatbeltNoExecProfile(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, NoExec: true})
	if err != nil {
		t.Fatal(err)
	}
	if !profileHas(p.Profile, "(deny process-exec*)") || !profileHas(p.Profile, "(allow process-exec* (literal ") {
		t.Errorf("no-exec profile malformed:\n%s", p.Profile)
	}
	if p.Uses.Has(CapProcNoExec) {
		t.Fatalf("Seatbelt no-exec should not claim proc.no_exec: %v", p.Uses.List())
	}
	foundCaveat := false
	for _, caveat := range p.Caveats {
		if profileHas(caveat, "best-effort") && profileHas(caveat, "initially allowed executable") {
			foundCaveat = true
		}
	}
	if !foundCaveat {
		t.Fatalf("Seatbelt no-exec caveat missing, got %#v", p.Caveats)
	}
}

// End-to-end enforcement, macOS only: prove the kernel actually honors what we
// generated. This is the load-bearing test for the Seatbelt backend.
func TestSeatbeltEnforcement(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Seatbelt enforcement only on macOS")
	}
	runner, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if runner.Backend() != BackendSeatbelt {
		t.Fatalf("expected seatbelt backend, got %s", runner.Backend())
	}

	run := func(spec Spec) int {
		t.Helper()
		code, err := runner.Run(context.Background(), spec, Stdio{Out: io.Discard, Err: io.Discard})
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		return code
	}

	work := t.TempDir()
	okFile := filepath.Join(work, "ok.txt")
	denied := filepath.Join(work, "denied.txt")

	// Scoped write persists to the host (Seatbelt-only capability).
	if code := run(Spec{
		Args:     []string{"/bin/sh", "-c", "echo hi > " + okFile},
		Write:    WriteScope,
		Writable: []string{work},
	}); code != 0 {
		t.Fatalf("scoped write exit=%d, want 0", code)
	}
	if b, err := os.ReadFile(okFile); err != nil || string(b) != "hi\n" {
		t.Fatalf("scoped write did not persist: data=%q err=%v", b, err)
	}

	// Default policy (WriteNone) must deny writes to the same dir.
	if code := run(Spec{
		Args: []string{"/bin/sh", "-c", "echo hi > " + denied},
	}); code == 0 {
		t.Fatal("write under WriteNone unexpectedly succeeded")
	}
	if _, err := os.Stat(denied); !os.IsNotExist(err) {
		t.Fatalf("denied file should not exist, stat err=%v", err)
	}

	// A read-only, no-network command still runs fine.
	if code := run(Spec{Args: []string{"/usr/bin/true"}}); code != 0 {
		t.Fatalf("plain confined command exit=%d, want 0", code)
	}
}

// R5: WriteEphemeral + Readable must allow reads from the APFS clone (cwd at
// runtime), not only writes. The clone placeholder is substituted at runtime.
func TestSeatbeltEphemeralReadableCloneIsReadable(t *testing.T) {
	p, err := compileSeatbelt(Spec{
		Args:     []string{"/bin/echo"},
		Write:    WriteEphemeral,
		Readable: []string{"/some/path"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Order-tolerant: scan each line of the profile, accept any (allow
	// file-read* …) form that includes the clone-root subpath.
	wantSub := `(subpath "` + isoboxEphemeralRootPlaceholder + `")`
	found := false
	for _, line := range strings.Split(p.Profile, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "(allow file-read*") && strings.Contains(line, wantSub) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("WriteEphemeral+Readable should allow reads from %s in an (allow file-read* …) form; profile:\n%s",
			isoboxEphemeralRootPlaceholder, p.Profile)
	}
	// The same placeholder must remain in the file-write* allow list.
	wroteSub := false
	for _, line := range strings.Split(p.Profile, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "(allow file-write*") && strings.Contains(line, wantSub) {
			wroteSub = true
			break
		}
	}
	if !wroteSub {
		t.Fatalf("WriteEphemeral must still allow writes to %s; profile:\n%s",
			isoboxEphemeralRootPlaceholder, p.Profile)
	}
}

// R7: Seatbelt net.disable also blocks loopback; surface that as a caveat so
// callers relying on the portable contract are warned.
func TestSeatbeltNetDisableLoopbackCaveat(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Net: NetDisable})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range p.Caveats {
		if strings.Contains(c, "additionally blocks loopback") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("net.disable caveat about loopback missing, got %#v", p.Caveats)
	}
}

// R9: Seatbelt scoped reads expose /usr/lib, /System, /private/var/db/dyld so
// dynamic Mach-O binaries can load. Surface that widening as a caveat.
func TestSeatbeltScopedReadWideningCaveat(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Readable: []string{"/tmp"}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range p.Caveats {
		if strings.Contains(c, "/usr/lib") && strings.Contains(c, "/System") && strings.Contains(c, "/private/var/db/dyld") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("scoped-read widening caveat missing, got %#v", p.Caveats)
	}
}

func TestSeatbeltResourceLimitsCaveatedNotEnforced(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, CPUs: 2, MemoryBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if p.Uses.Has(CapResCPU) || p.Uses.Has(CapResMemory) {
		t.Fatalf("Seatbelt must not claim to enforce resource limits: %v", p.Uses.List())
	}
	if !caveatsContain(p.Caveats, "no CPU-limit mechanism") {
		t.Fatalf("missing CPU caveat: %v", p.Caveats)
	}
	if !caveatsContain(p.Caveats, "no memory-limit mechanism") {
		t.Fatalf("missing memory caveat: %v", p.Caveats)
	}
}

// FIX1: scoped reads must deny the firmlinked data volume that /System
// lexically covers, and the deny must follow the /System loader allow so it
// wins under SBPL last-match semantics.
func TestSeatbeltScopedReadDeniesDataVolume(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Readable: []string{"/tmp/isobox-read-scope"}})
	if err != nil {
		t.Fatal(err)
	}
	if !profileHas(p.Profile, `(deny file-read* (subpath "/System/Volumes/Data"))`) {
		t.Fatalf("scoped read profile must deny the firmlinked data volume:\n%s", p.Profile)
	}
	allow := strings.Index(p.Profile, `(allow file-read* (subpath "/usr/lib")`)
	deny := strings.Index(p.Profile, `(deny file-read* (subpath "/System/Volumes/Data"))`)
	if allow < 0 || deny < 0 || deny < allow {
		t.Fatalf("data-volume deny must follow the /System allow so it wins; allow=%d deny=%d profile:\n%s", allow, deny, p.Profile)
	}
}

// FIX2: broad host read must carry a caveat that raw device nodes are denied
// but other device nodes remain readable.
func TestSeatbeltBroadReadDeviceCaveat(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}})
	if err != nil {
		t.Fatal(err)
	}
	if !profileHas(p.Profile, `(deny file-read* (regex #"^/dev/r?disk"))`) {
		t.Fatalf("broad read profile must deny raw disk device nodes:\n%s", p.Profile)
	}
	if !caveatsContain(p.Caveats, "raw device nodes") {
		t.Fatalf("broad read should caveat raw device node denial, got %#v", p.Caveats)
	}
}

// FIX4a: read-deny matches by path, so a hardlink can bypass it; surface that.
func TestSeatbeltReadDenyHardlinkCaveat(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, ReadDeny: []string{"/tmp/isobox-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if !caveatsContain(p.Caveats, "hardlink") {
		t.Fatalf("read-deny should caveat hardlink bypass, got %#v", p.Caveats)
	}
}

// FIX4b: no-exec caveat must keep the existing substrings and additionally
// warn about interpreter re-exec.
func TestSeatbeltNoExecInterpreterCaveat(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, NoExec: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range p.Caveats {
		if strings.Contains(c, "re-exec") && strings.Contains(c, "best-effort") && strings.Contains(c, "initially allowed executable") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no-exec caveat should warn about interpreter re-exec while keeping existing wording, got %#v", p.Caveats)
	}
}
