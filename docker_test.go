package isobox

import (
	"encoding/json"
	"os"
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
		dockerBinary, "run", "--rm", "--name", stableSpecID("isobox", spec), "--ipc", "private",
		"--read-only", "--tmpfs", "/tmp", "--tmpfs", "/run",
		"alpine:3.20", "sh", "-c", "echo hi",
	}
	if !reflect.DeepEqual(p.Argv, want) {
		t.Fatalf("argv mismatch\n got: %v\nwant: %v", p.Argv, want)
	}
	if argvHas(p.Argv, "--mount") || argvHas(p.Argv, "-v") || argvHas(p.Argv, "--volume") {
		t.Fatalf("docker backend must not add host mounts by default: %v", p.Argv)
	}
	if !p.Uses.Has(CapIPCRestrict) {
		t.Fatalf("docker default plan must surface ipc.restrict: %v", p.Uses.List())
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
		name        string
		net         NetMode
		wantNone    bool
		wantCap     Capability
		wantSeccomp bool
		wantCaveat  string
		forbidCap   Capability
	}{
		{name: "disable", net: NetDisable, wantNone: true, wantCap: CapNetDisable},
		{name: "enable", net: NetEnable, wantCap: CapNetEnable},
		{name: "outbound", net: NetOutbound, wantCap: CapNetOutbound, wantSeccomp: true, forbidCap: CapNetEnable, wantCaveat: "Docker seccomp profile"},
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
			if gotSeccomp := hasArgPair(p.Argv, "--security-opt", dockerSeccompSecurityOpt()); gotSeccomp != tc.wantSeccomp {
				t.Fatalf("--security-opt seccomp presence=%v, want %v in %v", gotSeccomp, tc.wantSeccomp, p.Argv)
			}
			if tc.wantCaveat != "" && !caveatsContain(p.Caveats, tc.wantCaveat) {
				t.Fatalf("missing caveat %q in %v", tc.wantCaveat, p.Caveats)
			}
			if tc.net == NetOutbound && !caveatsContain(p.Caveats, "UDP bind") {
				t.Fatalf("outbound caveat must mention UDP bind ambiguity: %v", p.Caveats)
			}
		})
	}
}

func TestDockerOutboundSeccompMaterialization(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	p, err := compileDockerEphemeral(Spec{Args: []string{"true"}, Net: NetOutbound})
	if err != nil {
		t.Fatal(err)
	}
	argv, cleanup, err := materializeDockerSeccompProfile(p.Argv)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup == nil {
		t.Fatal("expected seccomp cleanup for outbound docker plan")
	}
	defer cleanup()
	if reflect.DeepEqual(argv, p.Argv) || hasArgPair(argv, "--security-opt", dockerSeccompSecurityOpt()) {
		t.Fatalf("seccomp placeholder was not rewritten: %v", argv)
	}
	idx := argvIndex(argv, "--security-opt")
	if idx < 0 || idx+1 >= len(argv) || !strings.HasPrefix(argv[idx+1], "seccomp=") {
		t.Fatalf("missing materialized seccomp security-opt: %v", argv)
	}
	path := strings.TrimPrefix(argv[idx+1], "seccomp=")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names []string `json:"names"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("invalid seccomp json: %v", err)
	}
	if profile.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Fatalf("seccomp defaultAction=%q, want SCMP_ACT_ERRNO", profile.DefaultAction)
	}
	bindAllowed := false
	for _, syscall := range profile.Syscalls {
		for _, name := range syscall.Names {
			if name == "bind" {
				bindAllowed = true
			}
		}
	}
	if !bindAllowed {
		t.Fatal("outbound seccomp profile intentionally keeps bind allowed for client sockets; update net.outbound wording/tests if this changes")
	}
	for _, syscall := range profile.Syscalls {
		for _, name := range syscall.Names {
			if name == "listen" || name == "accept" || name == "accept4" {
				t.Fatalf("outbound seccomp profile still allows %s", name)
			}
		}
	}
}

func TestDockerReadOnlyImageVolumePolicy(t *testing.T) {
	argv := []string{
		dockerBinary, "run", "--rm", "--read-only",
		"--tmpfs", "/tmp",
		"--mount", "type=bind,src=/host/out,dst=/host/out",
		"--mount", "type=bind,src=/ro,dst=/ro,readonly",
		"alpine", "true",
	}
	if image, ok := dockerRunImage(argv); !ok || image != "alpine" {
		t.Fatalf("dockerRunImage=%q,%v", image, ok)
	}
	got := dockerReadOnlyVolumeViolations(argv, []string{"/data", "/tmp/cache", "/host/out/nested", "/ro/cache"})
	want := []string{"/data", "/ro/cache"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("volume violations=%v, want %v", got, want)
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

func TestDockerScopedFSMountsAndCapabilities(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	p, err := compileDockerEphemeral(Spec{Args: []string{"true"}, Readable: []string{"/host"}, Write: WriteScope, Writable: []string{"/host/out"}})
	if err != nil {
		t.Fatal(err)
	}
	if !argvHas(p.Argv, "--read-only") {
		t.Fatalf("scoped filesystem must keep container root read-only: %v", p.Argv)
	}
	if argvHas(p.Argv, "--tmpfs") {
		t.Fatalf("WriteScope must not add default tmpfs scratch without AllowTemp: %v", p.Argv)
	}
	if !hasArgPair(p.Argv, "--mount", "type=bind,src=/host,dst=/host,readonly") {
		t.Fatalf("missing read-only readable bind mount: %v", p.Argv)
	}
	if !hasArgPair(p.Argv, "--mount", "type=bind,src=/host/out,dst=/host/out") {
		t.Fatalf("missing writable bind mount: %v", p.Argv)
	}
	if !p.Uses.Has(CapFSReadScope) || !p.Uses.Has(CapFSWriteScope) {
		t.Fatalf("docker scoped fs capabilities wrong: %v", p.Uses.List())
	}
	if p.Uses.Has(CapProcNoExec) || p.Uses.Has(CapFSReadDeny) || p.Uses.Has(CapFSReadHost) {
		t.Fatalf("docker backend claimed unsupported parity: %v", p.Uses.List())
	}
	if p.Uses.Has(CapIPCRestrict) {
		t.Fatalf("docker plan with host filesystem scopes must not claim ipc.restrict: %v", p.Uses.List())
	}
	if !caveatsContain(p.Caveats, "host IPC endpoints") {
		t.Fatalf("missing host IPC caveat for scoped mounts: %v", p.Caveats)
	}

	temp, err := compileDockerEphemeral(Spec{Args: []string{"true"}, Write: WriteScope, Writable: []string{"/host/out"}, AllowTemp: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasArgPair(temp.Argv, "--tmpfs", "/tmp") || hasArgPair(temp.Argv, "--tmpfs", "/run") {
		t.Fatalf("AllowTemp WriteScope should add only /tmp tmpfs: %v", temp.Argv)
	}
}

func TestDockerWriteEphemeralUsesContainerLayer(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	p, err := compileDockerEphemeral(Spec{Args: []string{"true"}, Write: WriteEphemeral})
	if err != nil {
		t.Fatal(err)
	}
	if argvHas(p.Argv, "--read-only") {
		t.Fatalf("WriteEphemeral must leave the container layer writable: %v", p.Argv)
	}
	if !hasArgPair(p.Argv, "--tmpfs", "/tmp") || !hasArgPair(p.Argv, "--tmpfs", "/run") {
		t.Fatalf("WriteEphemeral should keep disposable tmpfs scratch: %v", p.Argv)
	}
	if !caveatsContain(p.Caveats, "disposable container writable layer") {
		t.Fatalf("missing WriteEphemeral container-layer caveat: %v", p.Caveats)
	}
	if !p.Uses.Has(CapFSWriteEphemeral) {
		t.Fatalf("docker backend must claim enforced fs.write.ephemeral: %v", p.Uses.List())
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
	if !caveatsContain(p.Caveats, "no hybrid shadow layer") {
		t.Fatalf("missing WriteOverlay degradation caveat: %v", p.Caveats)
	}
	if !caveatsContain(p.Caveats, "read-deny paths are not applied") {
		t.Fatalf("missing read-deny caveat: %v", p.Caveats)
	}
	if !hasArgPair(p.Argv, "--mount", "type=bind,src=/host/out,dst=/host/out") {
		t.Fatalf("missing writable overlay bind mount: %v", p.Argv)
	}
	if !p.Uses.Has(CapFSWriteScope) || p.Uses.Has(CapFSWriteEphemeral) || p.Uses.Has(CapFSReadDeny) {
		t.Fatalf("overlay capabilities wrong: %v", p.Uses.List())
	}
}

func TestDockerWorkingDirectoryMustBeMounted(t *testing.T) {
	t.Setenv(dockerImageEnv, "alpine")
	if _, err := compileDockerEphemeral(Spec{Args: []string{"true"}, Dir: "/tmp"}); err == nil || !strings.Contains(err.Error(), "working directory") {
		t.Fatalf("expected working directory error, got %v", err)
	}

	p, err := compileDockerEphemeral(Spec{Args: []string{"true"}, Dir: "/host/out", Readable: []string{"/host"}, Write: WriteScope, Writable: []string{"/host/out"}})
	if err != nil {
		t.Fatalf("mounted working directory should compile: %v", err)
	}
	if !hasArgPair(p.Argv, "--workdir", "/host/out") {
		t.Fatalf("missing --workdir for mounted host dir: %v", p.Argv)
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
	if !hasArgPair(p.Argv, "--memory-swap", "536870912") {
		t.Fatalf("--memory-swap bytes missing: %v", p.Argv)
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
