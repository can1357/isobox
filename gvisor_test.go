package isobox

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"testing"
)

// The gVisor compiler is pure, so it is fully testable on any host.

func TestGvisorNetworkPlans(t *testing.T) {
	cases := map[NetMode]string{
		NetDisable: "--network=none",
		NetEnable:  "--network=sandbox",
	}
	for net, flag := range cases {
		p, err := compileGvisor(Spec{Args: []string{"echo", "hi"}, Net: net})
		if err != nil {
			t.Fatalf("net=%v: %v", net, err)
		}
		if p.gv != nil {
			t.Errorf("net=%v: simple plan unexpectedly used OCI", net)
		}
		if !argvHas(p.Argv, flag) {
			t.Errorf("net=%v: argv %v missing %s", net, p.Argv, flag)
		}
	}

	p, err := compileGvisor(Spec{Args: []string{"curl", "https://example.com"}, Net: NetOutbound})
	if err != nil {
		t.Fatal(err)
	}
	if p.gv == nil {
		t.Fatal("NetOutbound must use OCI gVisor plan")
	}
	want := []string{gvisorBinary, "--oci-seccomp", "run", "--bundle", gvisorBundlePlaceholder, p.gv.ContainerID}
	if !reflect.DeepEqual(p.Argv, want) {
		t.Fatalf("argv=%v, want %v", p.Argv, want)
	}
	if !p.Uses.Has(CapNetOutbound) {
		t.Fatal("NetOutbound plan should exercise net.outbound")
	}
	if !caveatsContain(p.Caveats, "UDP bind") {
		t.Fatalf("NetOutbound caveat must mention UDP bind ambiguity: %v", p.Caveats)
	}
	if !caveatsContain(p.Caveats, "not an egress filter") {
		t.Fatalf("NetOutbound caveat must mention unrestricted egress/exfiltration risk: %v", p.Caveats)
	}
}

func TestGvisorFlagsPrecedeDo(t *testing.T) {
	p, err := compileGvisor(Spec{Args: []string{"ls", "/"}, Net: NetDisable, Write: WriteEphemeral})
	if err != nil {
		t.Fatal(err)
	}
	do := argvIndex(p.Argv, "do")
	if do < 0 {
		t.Fatalf("no 'do' in %v", p.Argv)
	}
	for i, a := range p.Argv {
		if len(a) > 2 && a[:2] == "--" && i > do {
			t.Errorf("global flag %q appears after 'do' in %v", a, p.Argv)
		}
	}
	if p.Argv[do+1] != "--" {
		t.Errorf("expected '--' terminator after 'do': %v", p.Argv[do:])
	}
	if p.Argv[do+2] != "ls" || p.Argv[do+3] != "/" {
		t.Errorf("command not appended after 'do --': %v", p.Argv[do:])
	}
}

func TestGvisorWriteModes(t *testing.T) {
	ephemeral, err := compileGvisor(Spec{Args: []string{"x"}, Write: WriteEphemeral})
	if err != nil {
		t.Fatal(err)
	}
	if !argvHas(ephemeral.Argv, "--overlay2=all:memory") {
		t.Errorf("WriteEphemeral expected overlay flag, got %v", ephemeral.Argv)
	}
	if !ephemeral.Uses.Has(CapFSWriteEphemeral) {
		t.Error("WriteEphemeral should enforce fs.write.ephemeral")
	}
	if !caveatsContain(ephemeral.Caveats, "memory overlays keep non-persistent writes off host disk") {
		t.Fatalf("WriteEphemeral should caveat memory overlay disk behavior: %v", ephemeral.Caveats)
	}

	scoped, err := compileGvisor(Spec{Args: []string{"x"}, Write: WriteScope, Writable: []string{"/w"}})
	if err != nil {
		t.Fatal(err)
	}
	if argvHas(scoped.Argv, "--overlay2=all:memory") {
		t.Errorf("WriteScope must not use ephemeral overlay: %v", scoped.Argv)
	}
	if !scoped.Uses.Has(CapFSWriteScope) || scoped.Uses.Has(CapFSWriteEphemeral) {
		t.Errorf("WriteScope capabilities wrong: %v", scoped.Uses)
	}
	if scoped.fs == nil || scoped.fs.Kind != fsVirtualizationLinuxNamespaceView {
		t.Fatalf("WriteScope should request linux namespace filesystem view, got %#v", scoped.fs)
	}
	if scoped.gv == nil || argvHas(scoped.Argv, "do") {
		t.Fatalf("WriteScope should force OCI run path, argv=%v gv=%#v", scoped.Argv, scoped.gv)
	}
	if !caveatsContain(scoped.Caveats, "does not enforce res.disk") {
		t.Fatalf("WriteScope should caveat missing disk quota: %v", scoped.Caveats)
	}

	overlay, err := compileGvisor(Spec{Args: []string{"x"}, Write: WriteOverlay, Writable: []string{"/work"}, AllowTemp: true})
	if err != nil {
		t.Fatal(err)
	}
	if !argvHas(overlay.Argv, "--overlay2=root:memory") {
		t.Errorf("WriteOverlay expected root overlay flag, got %v", overlay.Argv)
	}
	if !overlay.Uses.Has(CapFSWriteScope) || !overlay.Uses.Has(CapFSWriteEphemeral) {
		t.Errorf("WriteOverlay capabilities wrong: %v", overlay.Uses.List())
	}
	if overlay.fs == nil || overlay.fs.Kind != fsVirtualizationLinuxNamespaceView {
		t.Fatalf("WriteOverlay should request linux namespace filesystem view, got %#v", overlay.fs)
	}
	if overlay.gv == nil || argvHas(overlay.Argv, "do") {
		t.Fatalf("WriteOverlay should force OCI run path, argv=%v gv=%#v", overlay.Argv, overlay.gv)
	}
	if !caveatsContain(overlay.Caveats, "--overlay2=root:memory") {
		t.Fatalf("WriteOverlay caveat missing overlay flag: %v", overlay.Caveats)
	}
	if !caveatsContain(overlay.Caveats, "does not enforce res.disk") || !caveatsContain(overlay.Caveats, "writable bind mounts still consume host disk") {
		t.Fatalf("WriteOverlay should caveat disk quota and memory-overlay behavior: %v", overlay.Caveats)
	}

	deny, _ := compileGvisor(Spec{Args: []string{"x"}, Write: WriteNone})
	if argvHas(deny.Argv, "--overlay2=all:memory") {
		t.Errorf("WriteNone should not add overlay: %v", deny.Argv)
	}
	if !deny.Uses.Has(CapFSWriteDeny) {
		t.Error("WriteNone should enforce fs.write.deny")
	}
}

func TestGvisorReadableRequestsNativeView(t *testing.T) {
	p, err := compileGvisor(Spec{Args: []string{"x"}, Readable: []string{"/r"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Uses.Has(CapFSReadScope) || p.Uses.Has(CapFSReadHost) {
		t.Errorf("Readable capabilities wrong: %v", p.Uses)
	}
	if p.fs == nil || p.fs.Kind != fsVirtualizationLinuxNamespaceView {
		t.Fatalf("Readable should request linux namespace filesystem view, got %#v", p.fs)
	}
	if !reflect.DeepEqual(p.fs.Readable, []string{"/r"}) {
		t.Fatalf("readable scopes=%v, want [/r]", p.fs.Readable)
	}

	host, err := compileGvisor(Spec{Args: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !host.Uses.Has(CapFSReadHost) || host.Uses.Has(CapFSReadScope) {
		t.Errorf("empty Readable should keep broad host read, got %v", host.Uses)
	}
	if host.fs != nil {
		t.Fatalf("empty Readable/WriteNone should not request fs view, got %#v", host.fs)
	}

	deny, err := compileGvisor(Spec{Args: []string{"x"}, ReadDeny: []string{"/secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if !deny.Uses.Has(CapFSReadHost) || !deny.Uses.Has(CapFSReadDeny) {
		t.Errorf("ReadDeny capabilities wrong: %v", deny.Uses.List())
	}
	if deny.fs == nil || !reflect.DeepEqual(deny.fs.ReadDeny, []string{"/secret"}) {
		t.Fatalf("ReadDeny should request filesystem view with denylist, got %#v", deny.fs)
	}
	if !caveatsContain(deny.Caveats, "nonexistent denied paths") {
		t.Fatalf("ReadDeny caveat missing: %v", deny.Caveats)
	}
}

func TestGvisorFSScopesForceOCIPlan(t *testing.T) {
	readable, err := compileGvisor(Spec{Args: []string{"x"}, Readable: []string{"/r"}})
	if err != nil {
		t.Fatal(err)
	}
	if readable.fs == nil {
		t.Fatal("filesystem-scoped plan should request filesystem virtualization")
	}
	if !gvisorUsesOCI(readable) {
		t.Fatal("Readable gVisor plans must use OCI so the scoped root is enforceable")
	}
	if argvHas(readable.Argv, "do") {
		t.Fatalf("Readable plan must not use runsc do: %v", readable.Argv)
	}

	writable, err := compileGvisor(Spec{Args: []string{"x"}, Write: WriteScope, Writable: []string{"/w"}})
	if err != nil {
		t.Fatal(err)
	}
	if writable.fs == nil {
		t.Fatal("write-scoped plan should request filesystem virtualization")
	}
	if !gvisorUsesOCI(writable) || argvHas(writable.Argv, "do") {
		t.Fatalf("WriteScope must use OCI run path, argv=%v gv=%#v", writable.Argv, writable.gv)
	}
}

func TestGvisorAlwaysIsolatesKernel(t *testing.T) {
	p, _ := compileGvisor(Spec{Args: []string{"echo"}})
	if !p.Uses.Has(CapKernelIsolation) {
		t.Error("gVisor must always report kernel.isolation")
	}
	if p.Argv[0] != gvisorBinary {
		t.Errorf("argv[0]=%q, want %q", p.Argv[0], gvisorBinary)
	}
}

func TestGvisorCaveats(t *testing.T) {
	scoped, _ := compileGvisor(Spec{Args: []string{"x"}, Write: WriteScope, Writable: []string{"/w"}})
	if !caveatsContain(scoped.Caveats, "host filesystem scopes can expose host IPC endpoints") {
		t.Errorf("WriteScope host filesystem scope should carry IPC caveat, got %v", scoped.Caveats)
	}

	readable, _ := compileGvisor(Spec{Args: []string{"x"}, Readable: []string{"/r"}})
	if !caveatsContain(readable.Caveats, "host filesystem scopes can expose host IPC endpoints") {
		t.Errorf("Readable host filesystem scope should carry IPC caveat, got %v", readable.Caveats)
	}
	if !caveatsContain(readable.Caveats, "wider than the explicit allowlist") {
		t.Errorf("Readable should carry ELF/library widening caveat, got %v", readable.Caveats)
	}

	if p, _ := compileGvisor(Spec{Args: []string{"x"}, Net: NetOutbound}); !caveatsContain(p.Caveats, "UDP bind") {
		t.Errorf("NetOutbound should carry TCP-only/UDP caveat, got %v", p.Caveats)
	}
	if p, _ := compileGvisor(Spec{Args: []string{"x"}, NoExec: true}); len(p.Caveats) != 0 {
		t.Errorf("NoExec alone should be enforced without degradation caveat, got %v", p.Caveats)
	}
}

func TestGvisorNetEnableOCICaveat(t *testing.T) {
	const want = "no host-publish/DNAT"

	// NetEnable + NoExec forces the OCI bundle path; isobox owns the sandbox
	// network namespace and cannot accept inbound traffic from the host.
	oci, err := compileGvisor(Spec{Args: []string{"x"}, Net: NetEnable, NoExec: true})
	if err != nil {
		t.Fatalf("compile NetEnable+NoExec: %v", err)
	}
	if oci.gv == nil {
		t.Fatalf("NetEnable+NoExec should use OCI plan, got %#v", oci)
	}
	if !caveatsContain(oci.Caveats, want) {
		t.Errorf("NetEnable+OCI should carry inbound-unreachable caveat, got %v", oci.Caveats)
	}

	// Plain NetEnable stays on `runsc do`, which uses runsc's own networking
	// stack instead of isobox's veth + iptables; the inbound-reachability
	// caveat is specific to the OCI path and must not appear.
	simple, err := compileGvisor(Spec{Args: []string{"x"}, Net: NetEnable})
	if err != nil {
		t.Fatalf("compile NetEnable: %v", err)
	}
	if simple.gv != nil {
		t.Fatalf("plain NetEnable should not use OCI plan, got %#v", simple.gv)
	}
	if caveatsContain(simple.Caveats, want) {
		t.Errorf("plain NetEnable should not carry OCI inbound caveat, got %v", simple.Caveats)
	}

	// NetDisable+NoExec hits the OCI path too but must not get the NetEnable note.
	disabled, err := compileGvisor(Spec{Args: []string{"x"}, Net: NetDisable, NoExec: true})
	if err != nil {
		t.Fatalf("compile NetDisable+NoExec: %v", err)
	}
	if caveatsContain(disabled.Caveats, want) {
		t.Errorf("NetDisable+OCI should not carry inbound caveat, got %v", disabled.Caveats)
	}
}

func TestGvisorIPCRestrictOnlyWithoutHostFilesystemScopes(t *testing.T) {
	host, err := compileGvisor(Spec{Args: []string{"x"}, Net: NetOutbound})
	if err != nil {
		t.Fatal(err)
	}
	if !host.Uses.Has(CapIPCRestrict) {
		t.Fatalf("gVisor without host filesystem scopes should claim ipc.restrict: %v", host.Uses)
	}

	readable, err := compileGvisor(Spec{Args: []string{"x"}, Readable: []string{"/r"}})
	if err != nil {
		t.Fatal(err)
	}
	if readable.Uses.Has(CapIPCRestrict) {
		t.Fatalf("gVisor with host filesystem scopes must not claim ipc.restrict: %v", readable.Uses)
	}
	if len(readable.Caveats) == 0 {
		t.Fatal("gVisor with host filesystem scopes should explain host IPC exposure")
	}
}

func TestGvisorOCIIDDeterministic(t *testing.T) {
	s := Spec{Args: []string{"sh", "-c", "true"}, Net: NetOutbound, NoExec: true, Dir: "/work", Env: []string{"A=B"}}
	p1, err := compileGvisor(s)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := compileGvisor(s)
	if err != nil {
		t.Fatal(err)
	}
	if p1.gv.ContainerID != p2.gv.ContainerID {
		t.Fatalf("ids differ: %q != %q", p1.gv.ContainerID, p2.gv.ContainerID)
	}
	p3, err := compileGvisor(Spec{Args: []string{"sh", "-c", "false"}, Net: NetOutbound, NoExec: true, Dir: "/work", Env: []string{"A=B"}})
	if err != nil {
		t.Fatal(err)
	}
	if p1.gv.ContainerID == p3.gv.ContainerID {
		t.Fatalf("different specs got same id %q", p1.gv.ContainerID)
	}
}

func TestGvisorOCINoExecUsesUsableRoot(t *testing.T) {
	s := Spec{Args: []string{"/bin/sh"}, NoExec: true}
	p, err := compileGvisor(s)
	if err != nil {
		t.Fatal(err)
	}
	if p.gv == nil {
		t.Fatal("NoExec must use OCI gVisor plan")
	}
	cfg := gvisorOCIConfig(s, p.gv, "")
	if cfg.Root.Path != "/" {
		t.Fatalf("root path=%q, want existing host root", cfg.Root.Path)
	}
	if !cfg.Root.Readonly {
		t.Fatalf("root=%#v, want readonly for WriteNone", cfg.Root)
	}
	if info, err := os.Stat(cfg.Root.Path); err != nil || !info.IsDir() {
		t.Fatalf("root path %q is not an existing directory: info=%#v err=%v", cfg.Root.Path, info, err)
	}
}

func TestGvisorOCISeccompAndCapabilities(t *testing.T) {
	s := Spec{Args: []string{"/bin/app"}, Net: NetOutbound, NoExec: true, Env: []string{"K=V"}, Dir: "/work"}
	p, err := compileGvisor(s)
	if err != nil {
		t.Fatal(err)
	}
	cfg := gvisorOCIConfig(s, p.gv, "/var/run/netns/isobox-test")
	if !cfg.Process.NoNewPrivileges {
		t.Fatal("noNewPrivileges must be set")
	}
	if !reflect.DeepEqual(cfg.Process.Args, s.Args) || cfg.Process.Cwd != "/work" || !reflect.DeepEqual(cfg.Process.Env, s.Env) {
		t.Fatalf("process fields not preserved: %#v", cfg.Process)
	}
	if cfg.Root.Path != "/" || !cfg.Root.Readonly {
		t.Fatalf("root=%#v, want readonly host root", cfg.Root)
	}
	if info, err := os.Stat(cfg.Root.Path); err != nil || !info.IsDir() {
		t.Fatalf("root path %q is not an existing directory: info=%#v err=%v", cfg.Root.Path, info, err)
	}
	if cfg.Root.Path == "rootfs" {
		t.Fatal("OCI root must not point at the empty bundle rootfs directory")
	}
	if cfg.Process.Capabilities.Bounding != nil || cfg.Process.Capabilities.Effective != nil || cfg.Process.Capabilities.Permitted != nil || cfg.Process.Capabilities.Ambient != nil {
		t.Fatalf("broad capabilities granted: %#v", cfg.Process.Capabilities)
	}
	data, err := json.Marshal(cfg.Process.Capabilities)
	if err != nil {
		t.Fatal(err)
	}
	if profileHas(string(data), "CAP_NET_RAW") {
		t.Fatal("CAP_NET_RAW must not be granted")
	}
	if cfg.Linux.Seccomp == nil || cfg.Linux.Seccomp.DefaultAction != "SCMP_ACT_ALLOW" {
		t.Fatalf("seccomp missing/default wrong: %#v", cfg.Linux.Seccomp)
	}
	denied := cfg.Linux.Seccomp.Syscalls[0].Names
	for _, name := range []string{"listen", "accept", "accept4", "execve", "execveat"} {
		if !hasGvisorString(denied, name) {
			t.Fatalf("seccomp denied syscalls %v missing %s", denied, name)
		}
	}
	if hasGvisorString(denied, "bind") {
		t.Fatalf("bind must not be denied: %v", denied)
	}
	for _, ns := range []string{"pid", "mount", "ipc", "uts", "network"} {
		if !hasNamespace(cfg.Linux.Namespaces, ns) {
			t.Fatalf("namespace %q missing from %#v", ns, cfg.Linux.Namespaces)
		}
	}
}

func TestGvisorOCINetworkIntent(t *testing.T) {
	out := newGvisorOCIPlan(Spec{Args: []string{"x"}, Net: NetOutbound})
	if !out.EnableLoopback || !out.DisableIPv6 || !out.OutboundFirewall {
		t.Fatalf("outbound network intent wrong: %#v", out)
	}
	if !hasGvisorString(out.DeniedSyscalls, "listen") || hasGvisorString(out.DeniedSyscalls, "bind") {
		t.Fatalf("outbound seccomp intent wrong: %v", out.DeniedSyscalls)
	}
	if _, hostIP, guestIP := gvisorSubnet(out.ContainerID); hostIP == guestIP || hostIP == "" || guestIP == "" {
		t.Fatalf("bad veth addresses host=%q guest=%q", hostIP, guestIP)
	}

	enabled := newGvisorOCIPlan(Spec{Args: []string{"x"}, Net: NetEnable, NoExec: true})
	if !enabled.EnableLoopback || enabled.DisableIPv6 || enabled.OutboundFirewall {
		t.Fatalf("NetEnable OCI should keep IPv6 enabled and avoid outbound firewall: %#v", enabled)
	}

	disabled := newGvisorOCIPlan(Spec{Args: []string{"x"}, Net: NetDisable, NoExec: true})
	if !disabled.EnableLoopback || !disabled.DisableIPv6 {
		t.Fatalf("NetDisable OCI should keep loopback and disable IPv6: %#v", disabled)
	}
	if disabled.OutboundFirewall {
		t.Fatalf("NetDisable OCI should be loopback-only without outbound firewall: %#v", disabled)
	}
}

func TestGvisorOutboundIngressDropRulesIncludeHostOutput(t *testing.T) {
	rules := gvisorOutboundIngressDropRules("10.0.0.0/30")
	if len(rules) != 2 {
		t.Fatalf("rules=%#v, want forwarded and host-output drops", rules)
	}
	if !reflect.DeepEqual(rules[0], []string{"-I", "FORWARD", "-d", "10.0.0.0/30", "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"}) {
		t.Fatalf("forward rule=%#v", rules[0])
	}
	if !reflect.DeepEqual(rules[1], []string{"-I", "OUTPUT", "-d", "10.0.0.0/30", "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"}) {
		t.Fatalf("output rule=%#v", rules[1])
	}
}

func TestCleanupStackRunsLIFO(t *testing.T) {
	var got []int
	c := newCleanupStack()
	c.push(func() { got = append(got, 1) })
	c.push(func() { got = append(got, 2) })
	c.run()
	if !reflect.DeepEqual(got, []int{2, 1}) {
		t.Fatalf("cleanup order=%v", got)
	}
}

func hasGvisorString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func hasNamespace(values []ociNamespace, want string) bool {
	for _, value := range values {
		if value.Type == want {
			return true
		}
	}
	return false
}

func TestGvisorResourceLimitsForceOCIAndConfig(t *testing.T) {
	s := Spec{Args: []string{"/bin/app"}, CPUs: 1.5, MemoryBytes: 256 << 20, PIDs: 64}
	p, err := compileGvisor(s)
	if err != nil {
		t.Fatal(err)
	}
	if p.gv == nil {
		t.Fatal("resource limits must force the OCI bundle plan")
	}
	if !p.Uses.Has(CapResCPU) || !p.Uses.Has(CapResMemory) || !p.Uses.Has(CapResPIDs) {
		t.Fatalf("plan must use res.cpu/res.memory/res.pids: %v", p.Uses.List())
	}
	if !caveatsContain(p.Caveats, "host cgroup") {
		t.Fatalf("resource enforcement caveat missing: %v", p.Caveats)
	}
	cfg := gvisorOCIConfig(s, p.gv, "")
	res := cfg.Linux.Resources
	if res == nil || res.CPU == nil || res.Memory == nil || res.Pids == nil {
		t.Fatalf("OCI linux.resources incomplete: %#v", res)
	}
	if res.CPU.Quota == nil || *res.CPU.Quota != 150000 {
		t.Fatalf("cpu quota=%v, want 150000 (1.5 * 100000)", res.CPU.Quota)
	}
	if res.CPU.Period == nil || *res.CPU.Period != 100000 {
		t.Fatalf("cpu period=%v, want 100000", res.CPU.Period)
	}
	if res.Memory.Limit == nil || *res.Memory.Limit != 256<<20 {
		t.Fatalf("memory limit=%v, want %d", res.Memory.Limit, 256<<20)
	}
	if res.Memory.Swap == nil || *res.Memory.Swap != 256<<20 {
		t.Fatalf("memory swap=%v, want %d", res.Memory.Swap, 256<<20)
	}
	if res.Pids.Limit != 64 {
		t.Fatalf("pids limit=%v, want 64", res.Pids.Limit)
	}
}

func TestGvisorOmitsResourcesWithoutLimits(t *testing.T) {
	// NoExec forces the OCI path but requests no resource limits.
	s := Spec{Args: []string{"/bin/app"}, NoExec: true}
	p, err := compileGvisor(s)
	if err != nil {
		t.Fatal(err)
	}
	if p.gv == nil {
		t.Fatal("NoExec should still produce an OCI plan")
	}
	if p.Uses.Has(CapResCPU) || p.Uses.Has(CapResMemory) || p.Uses.Has(CapResPIDs) {
		t.Fatalf("no limits must not claim resource caps: %v", p.Uses.List())
	}
	if cfg := gvisorOCIConfig(s, p.gv, ""); cfg.Linux.Resources != nil {
		t.Fatalf("no limits must omit linux.resources: %#v", cfg.Linux.Resources)
	}
}

func TestGvisorCPUQuotaRoundsUpToFloor(t *testing.T) {
	// A tiny fractional CPU request must still yield a quota of at least 1.
	p, err := compileGvisor(Spec{Args: []string{"/bin/app"}, CPUs: 0.000001})
	if err != nil {
		t.Fatal(err)
	}
	res := gvisorOCIResources(p.gv)
	if res == nil || res.CPU == nil || res.CPU.Quota == nil || *res.CPU.Quota < 1 {
		t.Fatalf("quota must floor at 1: %#v", res)
	}
}

func TestGvisorPreloadFallbackDropsGuaranteedCaps(t *testing.T) {
	t.Setenv("ISOBOX_PRELOAD_FALLBACK", "1")

	read, err := compileGvisor(Spec{Args: []string{"x"}, Readable: []string{"/r"}})
	if err != nil {
		t.Fatal(err)
	}
	if read.Uses.Has(CapFSReadScope) {
		t.Errorf("preload fallback must not claim CapFSReadScope: %v", read.Uses)
	}
	if read.Uses.Has(CapFSReadHost) {
		t.Errorf("preload fallback must not fall through to CapFSReadHost: %v", read.Uses)
	}
	if !caveatsContain(read.Caveats, "best-effort") || !caveatsContain(read.Caveats, "ISOBOX_PRELOAD_FALLBACK") {
		t.Errorf("preload fallback should carry degradation caveat, got %v", read.Caveats)
	}

	write, err := compileGvisor(Spec{Args: []string{"x"}, Write: WriteScope, Writable: []string{"/w"}})
	if err != nil {
		t.Fatal(err)
	}
	if write.Uses.Has(CapFSWriteScope) {
		t.Errorf("preload fallback must not claim CapFSWriteScope: %v", write.Uses)
	}
}

func TestGvisorReadDenyHardlinkCaveat(t *testing.T) {
	p, err := compileGvisor(Spec{Args: []string{"x"}, ReadDeny: []string{"/secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if !caveatsContain(p.Caveats, "hardlink") {
		t.Errorf("read-deny should carry hardlink-bypass caveat, got %v", p.Caveats)
	}
	if !caveatsContain(p.Caveats, "nonexistent denied paths") {
		t.Errorf("read-deny should still carry the original caveat, got %v", p.Caveats)
	}
}

func TestGvisorKernelIsolationTrustCaveatWithRunscOverride(t *testing.T) {
	const want = "genuine gVisor"

	t.Setenv("ISOBOX_RUNSC", "/usr/bin/runc")
	overridden, err := compileGvisor(Spec{Args: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !caveatsContain(overridden.Caveats, want) {
		t.Errorf("ISOBOX_RUNSC override should warn about unverified runtime, got %v", overridden.Caveats)
	}

	os.Unsetenv("ISOBOX_RUNSC")
	defaulted, err := compileGvisor(Spec{Args: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	if caveatsContain(defaulted.Caveats, want) {
		t.Errorf("default runsc should not carry trust caveat, got %v", defaulted.Caveats)
	}
}

func TestGvisorSubnetEntropy(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		id := fmt.Sprintf("isobox-gvisor-%016x", r.Uint64())
		subnet, hostIP, guestIP := gvisorSubnet(id)
		if hostIP == guestIP {
			t.Fatalf("host==guest for id %q: %q", id, hostIP)
		}
		if hostIP == "" || guestIP == "" {
			t.Fatalf("empty veth address for id %q: host=%q guest=%q", id, hostIP, guestIP)
		}
		var oct3, block, mask int
		if n, err := fmt.Sscanf(subnet, "10.203.%d.%d/%d", &oct3, &block, &mask); n != 3 || err != nil {
			t.Fatalf("malformed subnet %q (n=%d err=%v)", subnet, n, err)
		}
		if oct3 < 0 || oct3 > 255 || block < 0 || block > 252 || block%4 != 0 || mask != 30 {
			t.Fatalf("ill-formed subnet %q", subnet)
		}
		if hostIP != fmt.Sprintf("10.203.%d.%d", oct3, block+1) || guestIP != fmt.Sprintf("10.203.%d.%d", oct3, block+2) {
			t.Fatalf("veth addresses outside /30 for %q: host=%q guest=%q", subnet, hostIP, guestIP)
		}
		seen[subnet] = true
	}
	if len(seen) <= 128 {
		t.Fatalf("expected well more than 128 distinct subnets across 2000 ids, got %d", len(seen))
	}
}
