package isobox

import (
	"reflect"
	"strings"
	"testing"
)

func TestDockerRequiresImageEnv(t *testing.T) {
	t.Setenv(dockerImageEnv, "")
	_, err := compileDockerEphemeral(Spec{Args: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), dockerImageEnv) {
		t.Fatalf("expected missing %s error, got %v", dockerImageEnv, err)
	}
}

func TestDockerArgvShapeNameAndDefaults(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine:3.20")
	t.Setenv(dockerRuntimeEnv, "")
	spec := Spec{Args: []string{"sh", "-c", "echo hi"}, Net: NetEnable}
	p, err := compileDockerEphemeral(spec)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		dockerBinary, "run", "--rm", "--name", stableSpecID("isobox", spec),
		"--read-only", "--tmpfs", "/tmp", "--tmpfs", "/run",
		"alpine:3.20", "sh", "-c", "echo hi",
	}
	if !reflect.DeepEqual(p.Argv, want) {
		t.Fatalf("argv mismatch\n got: %v\nwant: %v", p.Argv, want)
	}
	if argvHas(p.Argv, "--mount") || argvHas(p.Argv, "-v") || argvHas(p.Argv, "--volume") {
		t.Fatalf("docker backend must not add host mounts by default: %v", p.Argv)
	}
}

func TestDockerDeterministicName(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	spec := Spec{Args: []string{"echo", "hi"}, Net: NetDisable}
	p1, err := compileDockerEphemeral(spec)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := compileDockerEphemeral(spec)
	if err != nil {
		t.Fatal(err)
	}
	name1 := p1.Argv[argvIndex(p1.Argv, "--name")+1]
	name2 := p2.Argv[argvIndex(p2.Argv, "--name")+1]
	if name1 != name2 || name1 != stableSpecID("isobox", spec) {
		t.Fatalf("name not deterministic: %q %q", name1, name2)
	}
}

func TestDockerRuntimeEnvInsertion(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	t.Setenv(dockerRuntimeEnv, "runsc")
	p, err := compileDockerEphemeral(Spec{Args: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	idx := argvIndex(p.Argv, "--runtime")
	if idx < 0 || idx+1 >= len(p.Argv) || p.Argv[idx+1] != "runsc" {
		t.Fatalf("runtime not inserted from env: %v", p.Argv)
	}
}

func TestDockerRunnerUsesDockerOverrideEnv(t *testing.T) {
	r, err := runnerFor(BackendDockerEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	if r.binEnv != "ISOBOX_DOCKER" {
		t.Fatalf("docker runner binEnv=%q", r.binEnv)
	}
}

func TestDockerNetworkMappings(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	cases := []struct {
		name       string
		net        NetMode
		wantNone   bool
		wantCap    Capability
		wantCaveat string
		forbidCap  Capability
	}{
		{name: "disable", net: NetDisable, wantNone: true, wantCap: CapNetDisable},
		{name: "enable", net: NetEnable, wantCap: CapNetEnable},
		{name: "outbound", net: NetOutbound, wantCap: CapNetEnable, forbidCap: CapNetOutbound, wantCaveat: "net.outbound uses Docker's default bridge"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := compileDockerEphemeral(Spec{Args: []string{"true"}, Net: tc.net})
			if err != nil {
				t.Fatal(err)
			}
			if gotNone := hasArgPair(p.Argv, "--network", "none"); gotNone != tc.wantNone {
				t.Fatalf("--network none presence=%v, want %v in %v", gotNone, tc.wantNone, p.Argv)
			}
			if !p.Uses.Has(tc.wantCap) {
				t.Fatalf("plan uses missing %s", tc.wantCap)
			}
			if tc.forbidCap != "" && p.Uses.Has(tc.forbidCap) {
				t.Fatalf("plan uses must not claim %s: %v", tc.forbidCap, p.Uses.List())
			}
			if tc.wantCaveat != "" && !caveatsContain(p.Caveats, tc.wantCaveat) {
				t.Fatalf("missing caveat %q in %v", tc.wantCaveat, p.Caveats)
			}
		})
	}
}

func TestDockerIsolationCaveatDistinguishesRunsc(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	t.Setenv(dockerRuntimeEnv, "")
	p, err := compileDockerEphemeral(Spec{Args: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	if !caveatsContain(p.Caveats, "Docker VM/guest-kernel isolation") {
		t.Fatalf("missing docker-vm caveat: %v", p.Caveats)
	}
	if p.Uses.Has(CapKernelIsolation) {
		t.Fatalf("default docker runtime must not claim kernel isolation: %v", p.Uses.List())
	}

	t.Setenv(dockerRuntimeEnv, "runc")
	p, err = compileDockerEphemeral(Spec{Args: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	if !caveatsContain(p.Caveats, `Docker runtime "runc"`) {
		t.Fatalf("missing non-runsc runtime caveat: %v", p.Caveats)
	}
	if p.Uses.Has(CapKernelIsolation) {
		t.Fatalf("non-runsc docker runtime must not claim kernel isolation: %v", p.Uses.List())
	}

	t.Setenv(dockerRuntimeEnv, "runsc")
	p, err = compileDockerEphemeral(Spec{Args: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	if caveatsContain(p.Caveats, "Docker VM/guest-kernel isolation") {
		t.Fatalf("runsc runtime should not carry docker-vm isolation caveat: %v", p.Caveats)
	}
	if p.Uses.Has(CapKernelIsolation) {
		t.Fatalf("runsc runtime must not advertise kernel.isolation; backend table is static: %v", p.Uses.List())
	}
	if !caveatsContain(p.Caveats, "runtime=runsc provides user-space kernel isolation") {
		t.Fatalf("missing runsc evidence caveat: %v", p.Caveats)
	}
}

func TestDockerEphemeralNoKernelIsolationInUses(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	t.Setenv(dockerRuntimeEnv, "runsc")
	p, err := compileDockerEphemeral(Spec{Args: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Uses.Has(CapKernelIsolation) {
		t.Fatalf("compileDockerEphemeral must never add CapKernelIsolation to Uses; got %v", p.Uses.List())
	}
	if !caveatsContain(p.Caveats, "runtime=runsc provides user-space kernel isolation") {
		t.Fatalf("expected runsc evidence-only caveat; got %v", p.Caveats)
	}
	// Plan.Uses must be a subset of CapsOf(BackendDockerEphemeral).
	advertised := CapsOf(BackendDockerEphemeral)
	for _, c := range p.Uses.List() {
		if !advertised.Has(c) {
			t.Fatalf("Plan.Uses contains %v not advertised by backendCaps", c)
		}
	}
}

func TestDockerEphemeralVMCaveat(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	t.Setenv(dockerRuntimeEnv, "")
	p, err := compileDockerEphemeral(Spec{Args: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	if !caveatsContain(p.Caveats, "Docker VM/guest-kernel isolation") {
		t.Fatalf("expected VM-isolation caveat for unset runtime; got %v", p.Caveats)
	}
	if p.Uses.Has(CapKernelIsolation) {
		t.Fatalf("default docker runtime must not claim kernel.isolation: %v", p.Uses.List())
	}
}

func TestDockerEphemeralRequiresImage(t *testing.T) {
	t.Setenv(dockerImageEnv, "")
	_, err := compileDockerEphemeral(Spec{Args: []string{"true"}})
	if err == nil {
		t.Fatal("expected error when ISOBOX_DOCKER_IMAGE is unset")
	}
	if !strings.Contains(err.Error(), dockerImageEnv) {
		t.Fatalf("error must reference %s; got %v", dockerImageEnv, err)
	}
}

func TestDockerReadOnlyTmpfsNoMountAndNoFSParityClaims(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	p, err := compileDockerEphemeral(Spec{Args: []string{"true"}, Readable: []string{"/host"}, Write: WriteScope, Writable: []string{"/host/out"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--read-only", "--tmpfs"} {
		if !argvHas(p.Argv, want) {
			t.Fatalf("argv missing %s: %v", want, p.Argv)
		}
	}
	if !hasArgPair(p.Argv, "--tmpfs", "/tmp") || !hasArgPair(p.Argv, "--tmpfs", "/run") {
		t.Fatalf("argv missing tmpfs scratch: %v", p.Argv)
	}
	if argvHas(p.Argv, "--mount") || argvHas(p.Argv, "-v") || argvHas(p.Argv, "--volume") {
		t.Fatalf("docker backend must not add host mounts: %v", p.Argv)
	}
	assertNoFSCapabilities(t, p.Uses)
	assertNoFSCapabilities(t, CapsOf(BackendDockerEphemeral))
	if p.Uses.Has(CapProcNoExec) {
		t.Fatalf("docker backend claimed proc parity it does not provide: %v", p.Uses.List())
	}
}

func TestDockerWriteEphemeralCaveatsDegradation(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	p, err := compileDockerEphemeral(Spec{Args: []string{"true"}, Write: WriteEphemeral})
	if err != nil {
		t.Fatal(err)
	}
	if !caveatsContain(p.Caveats, "does not provide writable whole-filesystem ephemeral writes") {
		t.Fatalf("missing WriteEphemeral degradation caveat: %v", p.Caveats)
	}
	if p.Uses.Has(CapFSWriteEphemeral) {
		t.Fatalf("docker backend must not claim fs.write.ephemeral degradation as enforced: %v", p.Uses.List())
	}
}

func TestDockerWriteOverlayAndReadDenyCaveatsDegrade(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	p, err := compileDockerEphemeral(Spec{
		Args:     []string{"true"},
		ReadDeny: []string{"/secret"},
		Write:    WriteOverlay,
		Writable: []string{"/host/out"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !caveatsContain(p.Caveats, "hybrid shadow writes") {
		t.Fatalf("missing WriteOverlay degradation caveat: %v", p.Caveats)
	}
	if !caveatsContain(p.Caveats, "read-deny paths are not applied") {
		t.Fatalf("missing read-deny caveat: %v", p.Caveats)
	}
	assertNoFSCapabilities(t, p.Uses)
}

func TestDockerRejectsHostWorkingDirectory(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	_, err := compileDockerEphemeral(Spec{Args: []string{"true"}, Dir: "/tmp"})
	if err == nil || !strings.Contains(err.Error(), "working directory") {
		t.Fatalf("expected working directory error, got %v", err)
	}
}

func hasArgPair(argv []string, key, value string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == key && argv[i+1] == value {
			return true
		}
	}
	return false
}

func assertNoFSCapabilities(t *testing.T, caps CapabilitySet) {
	t.Helper()
	for _, cap := range caps.List() {
		if strings.HasPrefix(string(cap), "fs.") {
			t.Fatalf("docker backend claimed fs capability %s in %v", cap, caps.List())
		}
	}
}

func caveatsContain(caveats []string, substr string) bool {
	for _, caveat := range caveats {
		if strings.Contains(caveat, substr) {
			return true
		}
	}
	return false
}

func TestDockerResourceLimitFlags(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	p, err := compileDockerEphemeral(Spec{Args: []string{"true"}, Net: NetEnable, CPUs: 1.5, MemoryBytes: 512 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if !hasArgPair(p.Argv, "--cpus", "1.5") {
		t.Fatalf("--cpus 1.5 missing: %v", p.Argv)
	}
	if !hasArgPair(p.Argv, "--memory", "536870912") {
		t.Fatalf("--memory bytes missing: %v", p.Argv)
	}
	if !p.Uses.Has(CapResCPU) || !p.Uses.Has(CapResMemory) {
		t.Fatalf("plan uses missing resource caps: %v", p.Uses.List())
	}
}

func TestDockerOmitsResourceFlagsWithoutLimits(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	p, err := compileDockerEphemeral(Spec{Args: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	if argvHas(p.Argv, "--cpus") || argvHas(p.Argv, "--memory") {
		t.Fatalf("no limits must omit resource flags: %v", p.Argv)
	}
	if p.Uses.Has(CapResCPU) || p.Uses.Has(CapResMemory) {
		t.Fatalf("no limits must not claim resource caps: %v", p.Uses.List())
	}
}
