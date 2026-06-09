package isobox

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const testLibinfoService = "com.apple.system.opendirectoryd.libinfo"

// TestSeatbeltMachAllowEmitsAllowAfterDeny verifies the per-service allowance is
// rendered, carries CapMachRestrict, and lands after the blanket Mach denial so
// SBPL's last-match-wins actually permits the lookup.
func TestSeatbeltMachAllowEmitsAllowAfterDeny(t *testing.T) {
	p, err := compileSeatbelt(Spec{
		Args:      []string{"/bin/echo"},
		MachAllow: []string{testLibinfoService},
	})
	if err != nil {
		t.Fatal(err)
	}
	allow := `(allow mach-lookup (global-name "` + testLibinfoService + `"))`
	deny := "(deny mach-lookup)"
	denyAt := strings.Index(p.Profile, deny)
	allowAt := strings.Index(p.Profile, allow)
	if denyAt < 0 {
		t.Fatalf("profile missing %q:\n%s", deny, p.Profile)
	}
	if allowAt < 0 {
		t.Fatalf("profile missing %q:\n%s", allow, p.Profile)
	}
	if allowAt < denyAt {
		t.Fatalf("allow must follow deny (last match wins); allowAt=%d denyAt=%d:\n%s", allowAt, denyAt, p.Profile)
	}
	if !p.Uses.Has(CapMachRestrict) {
		t.Error("expected mach.restrict capability in plan uses")
	}
}

func TestSeatbeltNoMachAllowEmitsNoAllow(t *testing.T) {
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}})
	if err != nil {
		t.Fatal(err)
	}
	if profileHas(p.Profile, "(allow mach-lookup") {
		t.Errorf("no MachAllow should emit no mach allowance:\n%s", p.Profile)
	}
}

// TestSeatbeltNetAllowsTLSTrustMachServices verifies isobox re-allows the Apple
// TLS trust Mach services whenever network access is enabled, so
// Security.framework certificate validation works without a manual --mach-allow.
// With network denied the services stay denied.
func TestSeatbeltNetAllowsTLSTrustMachServices(t *testing.T) {
	const deny = "(deny mach-lookup)"
	for _, net := range []NetMode{NetEnable, NetOutbound} {
		p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Net: net})
		if err != nil {
			t.Fatalf("net=%v: %v", net, err)
		}
		denyAt := strings.Index(p.Profile, deny)
		if denyAt < 0 {
			t.Fatalf("net=%v: profile missing %q:\n%s", net, deny, p.Profile)
		}
		for _, svc := range seatbeltTLSTrustMachServices {
			allow := `(allow mach-lookup (global-name "` + svc + `"))`
			at := strings.Index(p.Profile, allow)
			if at < 0 {
				t.Fatalf("net=%v: profile missing %q:\n%s", net, allow, p.Profile)
			}
			if at < denyAt {
				t.Fatalf("net=%v: %q must follow the deny (last match wins):\n%s", net, allow, p.Profile)
			}
		}
		if !caveatsContain(p.Caveats, "Apple TLS trust Mach services") {
			t.Fatalf("net=%v: expected TLS trust caveat, got %v", net, p.Caveats)
		}
	}

	// Network denied: the trust services must stay denied.
	off, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Net: NetDisable})
	if err != nil {
		t.Fatal(err)
	}
	for _, svc := range seatbeltTLSTrustMachServices {
		if profileHas(off.Profile, svc) {
			t.Fatalf("net=disable should not allow %q:\n%s", svc, off.Profile)
		}
	}
}

// TestSeatbeltMachAllowDedupesTLSTrustServices verifies an explicit --mach-allow
// for a TLS trust service is not emitted twice once the net default adds it.
func TestSeatbeltMachAllowDedupesTLSTrustServices(t *testing.T) {
	dup := seatbeltTLSTrustMachServices[0]
	p, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}, Net: NetOutbound, MachAllow: []string{dup}})
	if err != nil {
		t.Fatal(err)
	}
	allow := `(allow mach-lookup (global-name "` + dup + `"))`
	if n := strings.Count(p.Profile, allow); n != 1 {
		t.Fatalf("expected %q exactly once, got %d:\n%s", allow, n, p.Profile)
	}
}

func TestMachAllowMapsToCapability(t *testing.T) {
	plain := Spec{Args: []string{"x"}}
	if plain.Capabilities().Has(CapMachRestrict) {
		t.Error("plain spec should not request mach.restrict")
	}
	withMach := Spec{Args: []string{"x"}, MachAllow: []string{testLibinfoService}}
	if !withMach.Capabilities().Has(CapMachRestrict) {
		t.Error("MachAllow should request mach.restrict")
	}
}

// TestMachAllowIsNonPortable guards that a strict spec rejects MachAllow, since
// per-service Mach allow-listing is Seatbelt-only and not in the intersection.
func TestMachAllowIsNonPortable(t *testing.T) {
	s := Spec{Args: []string{"x"}, Strict: true, MachAllow: []string{testLibinfoService}}
	if err := s.validate(); err == nil {
		t.Fatal("strict spec with MachAllow should be rejected as non-portable")
	}
}

func TestMachAllowCaveatOnNonSeatbelt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		compile func(Spec) (*Plan, error)
	}{
		{"gvisor", compileGvisor},
		{"appcontainer", compileAppContainer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.compile(Spec{Args: []string{"/bin/echo"}, MachAllow: []string{testLibinfoService}})
			if err != nil {
				t.Fatal(err)
			}
			if !hasCaveatMentioning(p.Caveats, "Mach") {
				t.Errorf("%s should caveat that MachAllow is ignored; got %v", tc.name, p.Caveats)
			}
			if p.Uses.Has(CapMachRestrict) {
				t.Errorf("%s cannot honor mach.restrict; it must not appear in uses", tc.name)
			}
		})
	}
}

func hasCaveatMentioning(caveats []string, sub string) bool {
	for _, c := range caveats {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

// TestSeatbeltMachAllowResolvesUser proves the allowance is load-bearing: with
// the default Mach denial, macOS user-name resolution falls back to a raw uid,
// and the opendirectoryd libinfo allowance restores the name. macOS only.
func TestSeatbeltMachAllowResolvesUser(t *testing.T) {
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

	whoami := func(spec Spec) string {
		t.Helper()
		var out strings.Builder
		spec.Args = []string{"/usr/bin/id", "-un"}
		code, err := runner.Run(t.Context(), spec, Stdio{Out: &out, Err: &out})
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if code != 0 {
			t.Fatalf("id -un exit=%d, output=%q", code, out.String())
		}
		return strings.TrimSpace(out.String())
	}

	want := currentUserName(t)
	if name := whoami(Spec{}); name == want {
		t.Fatalf("default deny unexpectedly resolved the user name %q; the allowance test is meaningless", name)
	}
	if name := whoami(Spec{MachAllow: []string{testLibinfoService}}); name != want {
		t.Fatalf("with libinfo allowance id -un=%q, want %q", name, want)
	}
}

func currentUserName(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("/usr/bin/id", "-un").Output()
	if err != nil {
		t.Fatalf("host id -un: %v", err)
	}
	name := strings.TrimSpace(string(out))
	if _, err := strconv.Atoi(name); err == nil {
		t.Skipf("host id -un returned a numeric value %q; cannot distinguish name from uid", name)
	}
	return name
}
