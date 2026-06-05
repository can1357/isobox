package isobox

import (
	"strings"
	"testing"
)

// Union/Intersection must satisfy the set relationships against every backend,
// regardless of which capabilities the tables happen to contain today.
func TestUnionIntersectionInvariants(t *testing.T) {
	union, inter := Union(), Intersection()
	for _, b := range Backends() {
		caps := CapsOf(b)
		for _, c := range caps.List() {
			if !union.Has(c) {
				t.Errorf("Union missing %s supported by %s", c, b)
			}
		}
		for _, c := range inter.List() {
			if !caps.Has(c) {
				t.Errorf("Intersection has %s but %s does not support it", c, b)
			}
		}
	}
	// A capability is in the intersection iff every backend supports it.
	for _, c := range union.List() {
		all := true
		for _, b := range Backends() {
			if !CapsOf(b).Has(c) {
				all = false
				break
			}
		}
		if all != inter.Has(c) {
			t.Errorf("intersection membership wrong for %s: inAll=%v inter=%v", c, all, inter.Has(c))
		}
	}
}

// Design contracts that must not silently regress.
func TestCapabilityContracts(t *testing.T) {
	inter := Intersection()
	for _, c := range []Capability{CapNetDisable, CapNetEnable} {
		if !inter.Has(c) {
			t.Errorf("expected %s to be portable (in intersection)", c)
		}
	}
	if !CapsOf(BackendGvisor).Has(CapKernelIsolation) {
		t.Error("gVisor must advertise kernel.isolation")
	}
	if got := CapFSWriteEphemeral.Describe(); got != "permit writes but discard them; host untouched" {
		t.Fatalf("fs.write.ephemeral description must not promise overlay-specific mechanics, got %q", got)
	}
	if got := CapFSReadDeny.Describe(); got != "read broadly except denied sensitive paths" {
		t.Fatalf("fs.read.deny description=%q", got)
	}
	if !CapsOf(BackendSeatbelt).Has(CapFSWriteEphemeral) {
		t.Error("Seatbelt must advertise fs.write.ephemeral for caveated APFS clone virtualization")
	}
	if !CapsOf(BackendGvisor).Has(CapFSWriteEphemeral) {
		t.Error("gVisor must advertise fs.write.ephemeral for overlay-backed virtualization")
	}
	if inter.Has(CapFSWriteEphemeral) {
		t.Error("fs.write.ephemeral must not be treated as portable whole-host overlay parity")
	}
	for _, c := range []Capability{CapNetOutbound, CapFSReadScope, CapFSReadDeny, CapFSWriteScope} {
		if !CapsOf(BackendSeatbelt).Has(c) {
			t.Errorf("Seatbelt must advertise %s", c)
		}
	}
	if !CapsOf(BackendGvisor).Has(CapFSReadDeny) {
		t.Error("gVisor must advertise fs.read.deny for read-deny obscuring mounts")
	}
	for _, c := range []Capability{CapFSReadScope, CapFSWriteScope, CapProcNoExec} {
		if !CapsOf(BackendAppContainer).Has(c) {
			t.Errorf("AppContainer must advertise %s", c)
		}
	}
	for _, c := range []Capability{CapProcNoExec, CapIPCRestrict} {
		if CapsOf(BackendSeatbelt).Has(c) {
			t.Errorf("Seatbelt must not advertise %s", c)
		}
	}
	for _, c := range []Capability{CapNetOutbound, CapFSReadHost, CapFSReadDeny} {
		if CapsOf(BackendAppContainer).Has(c) {
			t.Errorf("AppContainer must not advertise %s", c)
		}
	}
	for _, c := range []Capability{CapNetOutbound, CapFSReadScope, CapFSReadDeny, CapFSWriteScope, CapProcNoExec, CapKernelIsolation} {
		if CapsOf(BackendDockerEphemeral).Has(c) {
			t.Errorf("Docker ephemeral must not advertise %s", c)
		}
		if c != CapNetOutbound && c != CapKernelIsolation && inter.Has(c) {
			t.Errorf("%s must remain union-only, not portable", c)
		}
	}
	for _, c := range []Capability{CapKernelIsolation, CapFSWriteEphemeral} {
		if CapsOf(BackendAppContainer).Has(c) {
			t.Errorf("AppContainer must not advertise %s", c)
		}
	}
}

func TestIPCRestrictCapabilityContracts(t *testing.T) {
	if got := CapIPCRestrict.Describe(); got != "no host local IPC endpoint reachable" {
		t.Fatalf("ipc.restrict description=%q", got)
	}
	if CapsOf(BackendSeatbelt).Has(CapIPCRestrict) {
		t.Fatal("Seatbelt must not classify Mach lookup restrictions as broad ipc.restrict")
	}
	if !CapsOf(BackendGvisor).Has(CapIPCRestrict) {
		t.Fatal("gVisor must claim ipc.restrict by construction")
	}
	if CapsOf(BackendGvisor).Has(CapMachRestrict) {
		t.Fatal("mach.restrict must stay Seatbelt-only")
	}
	if CapsOf(BackendAppContainer).Has(CapIPCRestrict) {
		t.Fatal("AppContainer must not advertise ipc.restrict until its plan surfaces the invariant")
	}
}

func TestMachAndIPCRestrictPlanUsage(t *testing.T) {
	sb, err := compileSeatbelt(Spec{Args: []string{"/bin/echo"}})
	if err != nil {
		t.Fatal(err)
	}
	if !profileHas(sb.Profile, "(deny mach-lookup)") {
		t.Fatalf("Seatbelt profile missing Mach default deny:\n%s", sb.Profile)
	}
	if !sb.Uses.Has(CapMachRestrict) {
		t.Fatalf("Seatbelt plan does not surface mach.restrict: %v", sb.Uses.List())
	}
	if sb.Uses.Has(CapIPCRestrict) {
		t.Fatalf("Seatbelt plan should not claim broad ipc.restrict: %v", sb.Uses.List())
	}

	gv, err := compileGvisor(Spec{Args: []string{"echo"}})
	if err != nil {
		t.Fatal(err)
	}
	if !gv.Uses.Has(CapIPCRestrict) {
		t.Fatalf("gVisor plan does not surface ipc.restrict: %v", gv.Uses.List())
	}
	if argvHas(gv.Argv, "--network=host") {
		t.Fatalf("gVisor plan breaches ipc.restrict with host networking: %v", gv.Argv)
	}
}

func TestGvisorOCIIPCRestrictNamespaces(t *testing.T) {
	p, err := compileGvisor(Spec{Args: []string{"echo"}, Net: NetOutbound})
	if err != nil {
		t.Fatal(err)
	}
	if p.gv == nil {
		t.Fatalf("NetOutbound must use OCI plan for namespace/firewall guards: %v", p.Argv)
	}
	if !p.Uses.Has(CapIPCRestrict) {
		t.Fatalf("OCI gVisor plan does not surface ipc.restrict: %v", p.Uses.List())
	}

	cfg := gvisorOCIConfig(Spec{Args: []string{"echo"}, Net: NetOutbound}, p.gv, "/run/netns/isobox-test")
	if !namespaceHas(cfg.Linux.Namespaces, "mount", "") {
		t.Fatalf("OCI config missing fresh mount namespace: %+v", cfg.Linux.Namespaces)
	}
	if !namespaceHas(cfg.Linux.Namespaces, "ipc", "") {
		t.Fatalf("OCI config missing fresh IPC namespace: %+v", cfg.Linux.Namespaces)
	}
	if !namespaceHas(cfg.Linux.Namespaces, "network", "/run/netns/isobox-test") {
		t.Fatalf("OCI config missing owned network namespace: %+v", cfg.Linux.Namespaces)
	}
	for _, m := range cfg.Mounts {
		if m.Type == "bind" {
			t.Fatalf("OCI config must not bind host socket paths while claiming ipc.restrict: %+v", m)
		}
	}
}

func namespaceHas(namespaces []ociNamespace, typ, path string) bool {
	for _, ns := range namespaces {
		if ns.Type == typ && (path == "" || ns.Path == path) {
			return true
		}
	}
	return false
}

func TestCapabilitySetAlgebra(t *testing.T) {
	a := NewCapabilitySet(CapNetDisable, CapFSReadHost, CapFSWriteDeny)
	b := NewCapabilitySet(CapFSWriteDeny, CapFSWriteScope)

	if got := a.Union(b); !got.Has(CapNetDisable) || !got.Has(CapFSWriteScope) || got.Len() != 4 {
		t.Errorf("union wrong: %v", got.List())
	}
	if got := a.Intersect(b); got.Len() != 1 || !got.Has(CapFSWriteDeny) {
		t.Errorf("intersect wrong: %v", got.List())
	}
	if got := a.Sub(b); got.Len() != 2 || got.Has(CapFSWriteDeny) {
		t.Errorf("sub wrong: %v", got.List())
	}
	if a.Has(CapFSWriteScope) {
		t.Error("Has false positive")
	}
}

// List must be sorted for stable CLI/test output.
func TestCapabilitySetListSorted(t *testing.T) {
	s := NewCapabilitySet(CapNetEnable, CapFSWriteDeny, CapNetDisable)
	got := s.List()
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("List not sorted: %v", got)
		}
	}
}

// R7: the portable net.disable description must no longer promise loopback,
// because Seatbelt blocks it. Callers checking Describe() should be steered to
// the per-backend caveats instead.
func TestNetDisableDescriptionAdmitsLoopbackVariance(t *testing.T) {
	desc := CapNetDisable.Describe()
	if !strings.Contains(desc, "see caveats") {
		t.Fatalf("CapNetDisable.Describe() must point at caveats for loopback variance, got %q", desc)
	}
}

// Resource-limit capabilities are supported by every backend that has a real
// enforcement mechanism, but not by Seatbelt, so they stay out of the portable
// intersection.
func TestResourceLimitCapabilityContracts(t *testing.T) {
	for _, b := range []Backend{BackendGvisor, BackendAppContainer, BackendDockerEphemeral} {
		caps := CapsOf(b)
		if !caps.Has(CapResCPU) || !caps.Has(CapResMemory) {
			t.Errorf("%s must advertise res.cpu and res.memory: %v", b, caps.List())
		}
	}
	if CapsOf(BackendSeatbelt).Has(CapResCPU) || CapsOf(BackendSeatbelt).Has(CapResMemory) {
		t.Error("Seatbelt must not advertise resource limits; SBPL has no CPU/memory mechanism")
	}
	if inter := Intersection(); inter.Has(CapResCPU) || inter.Has(CapResMemory) {
		t.Error("resource limits must not be portable while Seatbelt cannot enforce them")
	}
	if union := Union(); !union.Has(CapResCPU) || !union.Has(CapResMemory) {
		t.Error("resource limits must appear in the union of all backends")
	}
}
