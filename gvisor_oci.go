package isobox

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	gvisorBundlePlaceholder = "<bundle>"
	gvisorNetnsPlaceholder  = "<netns>"
)

type gvisorOCIPlan struct {
	ContainerID       string
	BundlePlaceholder string
	Net               NetMode
	NoExec            bool
	DeniedSyscalls    []string
	DisableIPv6       bool
	RuntimeFlags      []string
	EnableLoopback    bool
	OutboundFirewall  bool
	Rootfs            string
	RootReadonly      bool
	FSMounts          []ociMount
	CPUs              float64
	MemoryBytes       int64
}

func newGvisorOCIPlan(s Spec) *gvisorOCIPlan {
	p := &gvisorOCIPlan{
		ContainerID:       stableSpecID("isobox-gvisor", s),
		BundlePlaceholder: gvisorBundlePlaceholder,
		Net:               s.Net,
		NoExec:            s.NoExec,
		DisableIPv6:       s.Net != NetEnable,
		EnableLoopback:    true,
		CPUs:              s.CPUs,
		MemoryBytes:       s.MemoryBytes,
	}
	if s.Net == NetOutbound {
		// Strict AF_UNIX over-block: seccomp cannot distinguish socket families,
		// so these denies also block Unix-domain stream servers. TODO.md asks to
		// deny listen/accept, so isobox chooses "no listening sockets" over only
		// "no externally reachable TCP/UDP listeners".
		p.DeniedSyscalls = append(p.DeniedSyscalls, "listen", "accept", "accept4")
		p.OutboundFirewall = true
	}
	if s.NoExec {
		p.DeniedSyscalls = append(p.DeniedSyscalls, "execve", "execveat")
	}
	return p
}

func gvisorOCIArgv(p *gvisorOCIPlan) []string {
	argv := []string{gvisorBinary}
	argv = append(argv, p.RuntimeFlags...)
	if len(p.DeniedSyscalls) > 0 {
		argv = append(argv, "--oci-seccomp")
	}
	return append(argv, "run", "--bundle", p.BundlePlaceholder, p.ContainerID)
}

func gvisorOCIConfigJSON(s Spec, p *gvisorOCIPlan, netnsPath string) (string, error) {
	cfg := gvisorOCIConfig(s, p, netnsPath)
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

func gvisorOCIConfig(s Spec, p *gvisorOCIPlan, netnsPath string) ociConfig {
	cwd := s.Dir
	if cwd == "" {
		cwd = "/"
	}
	env := s.Env
	if env == nil {
		env = os.Environ()
	}
	namespaces := []ociNamespace{
		{Type: "pid"},
		{Type: "mount"},
		{Type: "ipc"},
		{Type: "uts"},
	}
	if netnsPath != "" {
		namespaces = append(namespaces, ociNamespace{Type: "network", Path: netnsPath})
	}
	cfg := ociConfig{
		OCIVersion: "1.0.2",
		Process: ociProcess{
			Terminal:        false,
			Args:            append([]string(nil), s.Args...),
			Env:             append([]string(nil), env...),
			Cwd:             cwd,
			NoNewPrivileges: true,
			Capabilities:    ociCapabilities{},
		},
		Root:   ociRoot{Path: gvisorOCIRootfs(p), Readonly: gvisorOCIRootReadonly(s, p)},
		Mounts: gvisorOCIMounts(p),
		Linux:  ociLinux{Namespaces: namespaces},
	}
	if len(p.DeniedSyscalls) > 0 {
		cfg.Linux.Seccomp = &ociSeccomp{
			DefaultAction: "SCMP_ACT_ALLOW",
			Syscalls: []ociSeccompSyscall{{
				Names:    append([]string(nil), p.DeniedSyscalls...),
				Action:   "SCMP_ACT_ERRNO",
				ErrnoRet: 1,
			}},
		}
	}
	if res := gvisorOCIResources(p); res != nil {
		cfg.Linux.Resources = res
	}
	return cfg
}

func gvisorOCIRootfs(p *gvisorOCIPlan) string {
	if p != nil && p.Rootfs != "" {
		return p.Rootfs
	}
	return "/"
}

func gvisorOCIRootReadonly(s Spec, p *gvisorOCIPlan) bool {
	if p != nil && p.Rootfs != "" {
		return p.RootReadonly
	}
	return s.Write == WriteNone
}

func gvisorOCIMounts(p *gvisorOCIPlan) []ociMount {
	mounts := []ociMount{{Destination: "/proc", Type: "proc", Source: "proc"}}
	if p != nil && len(p.FSMounts) > 0 {
		mounts = append(mounts, p.FSMounts...)
	}
	return mounts
}

type ociConfig struct {
	OCIVersion string     `json:"ociVersion"`
	Process    ociProcess `json:"process"`
	Root       ociRoot    `json:"root"`
	Mounts     []ociMount `json:"mounts,omitempty"`
	Linux      ociLinux   `json:"linux"`
}

type ociProcess struct {
	Terminal        bool            `json:"terminal"`
	Args            []string        `json:"args"`
	Env             []string        `json:"env,omitempty"`
	Cwd             string          `json:"cwd"`
	NoNewPrivileges bool            `json:"noNewPrivileges"`
	Capabilities    ociCapabilities `json:"capabilities"`
}

type ociCapabilities struct {
	Bounding    []string `json:"bounding,omitempty"`
	Effective   []string `json:"effective,omitempty"`
	Inheritable []string `json:"inheritable,omitempty"`
	Permitted   []string `json:"permitted,omitempty"`
	Ambient     []string `json:"ambient,omitempty"`
}

type ociRoot struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type ociMount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options,omitempty"`
}

// gvisorCPUPeriodMicros is the CFS scheduling period gVisor's host cgroup uses
// to express a fractional CPU cap; quota = CPUs * period.
const gvisorCPUPeriodMicros = 100_000

// gvisorOCIResources builds the OCI linux.resources block from the plan's CPU
// and memory limits, or nil when neither is set. runsc maps these onto the
// sandbox's host cgroup.
func gvisorOCIResources(p *gvisorOCIPlan) *ociResources {
	if p == nil || (p.CPUs <= 0 && p.MemoryBytes <= 0) {
		return nil
	}
	res := &ociResources{}
	if p.CPUs > 0 {
		quota := int64(p.CPUs*gvisorCPUPeriodMicros + 0.5)
		if quota < 1 {
			quota = 1
		}
		period := uint64(gvisorCPUPeriodMicros)
		res.CPU = &ociCPU{Quota: &quota, Period: &period}
	}
	if p.MemoryBytes > 0 {
		limit := p.MemoryBytes
		swap := p.MemoryBytes
		res.Memory = &ociMemory{Limit: &limit, Swap: &swap}
	}
	return res
}

type ociLinux struct {
	Namespaces []ociNamespace `json:"namespaces"`
	Seccomp    *ociSeccomp    `json:"seccomp,omitempty"`
	Resources  *ociResources  `json:"resources,omitempty"`
}

type ociResources struct {
	CPU    *ociCPU    `json:"cpu,omitempty"`
	Memory *ociMemory `json:"memory,omitempty"`
}

type ociCPU struct {
	Quota  *int64  `json:"quota,omitempty"`
	Period *uint64 `json:"period,omitempty"`
}

type ociMemory struct {
	Limit *int64 `json:"limit,omitempty"`
	Swap  *int64 `json:"swap,omitempty"`
}

type ociNamespace struct {
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
}

type ociSeccomp struct {
	DefaultAction string              `json:"defaultAction"`
	Syscalls      []ociSeccompSyscall `json:"syscalls"`
}

type ociSeccompSyscall struct {
	Names    []string `json:"names"`
	Action   string   `json:"action"`
	ErrnoRet int      `json:"errnoRet"`
}

func gvisorUsesOCI(plan *Plan) bool {
	return plan != nil && plan.gv != nil
}

func runGvisor(ctx context.Context, plan *Plan, s Spec, streams Stdio) (int, error) {
	if !gvisorUsesOCI(plan) {
		if plan != nil && plan.fs != nil && plan.fs.Kind == fsVirtualizationLinuxNamespaceView {
			return -1, fmt.Errorf("isobox: gvisor filesystem scopes require OCI execution")
		}
		return runPlanExec(ctx, BackendGvisor, "ISOBOX_RUNSC", plan, s, streams)
	}

	fsRuntime, err := prepareFSVirtualization(plan, s)
	if err != nil {
		return -1, err
	}
	if fsRuntime != nil {
		appendPlanFSCaveats(plan, fsRuntime)
		if fsRuntime.Cleanup != nil {
			defer func() { _ = fsRuntime.Cleanup() }()
		}
		s.Env = commandEnv(s.Env, fsRuntime.Env)
		if fsRuntime.Dir != "" {
			s.Dir = fsRuntime.Dir
		}
	}
	return runGvisorOCI(ctx, plan, s, streams)
}

func runGvisorOCI(ctx context.Context, plan *Plan, s Spec, streams Stdio) (int, error) {
	bundle, err := os.MkdirTemp("", "isobox-runsc-")
	if err != nil {
		return -1, fmt.Errorf("isobox: creating gvisor OCI bundle: %w", err)
	}
	defer os.RemoveAll(bundle)

	runtime := gvisorBinary
	if override := os.Getenv("ISOBOX_RUNSC"); override != "" {
		runtime = override
	}

	if len(plan.gv.DeniedSyscalls) > 0 {
		if err := preflightGvisorOCISeccomp(ctx, runtime); err != nil {
			return -1, err
		}
	}

	netPath, cleanupNet, err := setupGvisorNetwork(ctx, plan.gv)
	if cleanupNet != nil {
		defer cleanupNet()
	}
	if err != nil {
		return -1, err
	}

	config, err := gvisorOCIConfigJSON(s, plan.gv, netPath)
	if err != nil {
		return -1, fmt.Errorf("isobox: rendering gvisor OCI config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte(config), 0o600); err != nil {
		return -1, fmt.Errorf("isobox: writing gvisor OCI config: %w", err)
	}

	argv := append([]string(nil), plan.Argv...)
	for i, a := range argv {
		if a == gvisorBundlePlaceholder {
			argv[i] = bundle
		}
	}
	argv[0] = runtime

	defer func() {
		deleteArgv := []string{argv[0], "delete", "--force", plan.gv.ContainerID}
		_ = exec.CommandContext(context.Background(), deleteArgv[0], deleteArgv[1:]...).Run()
	}()

	in, out, errw := streams.orDefaults()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errw
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return -1, fmt.Errorf("isobox: launching %s backend: %w", BackendGvisor, err)
	}
	return 0, nil
}

func setupGvisorNetwork(ctx context.Context, p *gvisorOCIPlan) (string, func(), error) {
	name := shortLinuxName("cg", p.ContainerID)
	path := "/var/run/netns/" + name
	cleanup := newCleanupStack()
	fail := func(err error) (string, func(), error) {
		return "", cleanup.run, err
	}

	if err := runQuiet(ctx, "ip", "netns", "add", name); err != nil {
		return fail(fmt.Errorf("isobox: creating network namespace: %w", err))
	}
	cleanup.push(func() { _ = runQuiet(context.Background(), "ip", "netns", "delete", name) })
	if err := runQuiet(ctx, "ip", "netns", "exec", name, "ip", "link", "set", "lo", "up"); err != nil {
		return fail(fmt.Errorf("isobox: enabling sandbox loopback: %w", err))
	}
	if p.DisableIPv6 {
		if err := runQuiet(ctx, "ip", "netns", "exec", name, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"); err != nil {
			return fail(fmt.Errorf("isobox: disabling sandbox IPv6: %w", err))
		}
		if err := runQuiet(ctx, "ip", "netns", "exec", name, "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"); err != nil {
			return fail(fmt.Errorf("isobox: disabling sandbox default IPv6: %w", err))
		}
	}
	if p.Net == NetDisable {
		return path, cleanup.run, nil
	}

	hostLink := shortLinuxName("ch", p.ContainerID)
	guestLink := shortLinuxName("cs", p.ContainerID)
	subnet, hostIP, guestIP := gvisorSubnet(p.ContainerID)
	if err := runQuiet(ctx, "ip", "link", "add", hostLink, "type", "veth", "peer", "name", guestLink); err != nil {
		return fail(fmt.Errorf("isobox: creating veth pair: %w", err))
	}
	cleanup.push(func() { _ = runQuiet(context.Background(), "ip", "link", "delete", hostLink) })
	for _, args := range [][]string{
		{"addr", "add", hostIP + "/30", "dev", hostLink},
		{"link", "set", hostLink, "up"},
		{"link", "set", guestLink, "netns", name},
		{"netns", "exec", name, "ip", "addr", "add", guestIP + "/30", "dev", guestLink},
		{"netns", "exec", name, "ip", "link", "set", guestLink, "up"},
		{"netns", "exec", name, "ip", "route", "add", "default", "via", hostIP},
	} {
		if err := runQuiet(ctx, "ip", args...); err != nil {
			return fail(fmt.Errorf("isobox: configuring sandbox network: %w", err))
		}
	}

	restoreForward, err := enableIPv4Forwarding(ctx)
	if err != nil {
		return fail(err)
	}
	if restoreForward != nil {
		cleanup.push(restoreForward)
	}
	if err := addIPTablesRule(ctx, cleanup, "-t", "nat", "-I", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"); err != nil {
		return fail(err)
	}
	if err := addIPTablesRule(ctx, cleanup, "-I", "FORWARD", "-s", subnet, "-j", "ACCEPT"); err != nil {
		return fail(err)
	}
	if err := addIPTablesRule(ctx, cleanup, "-I", "FORWARD", "-d", subnet, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return fail(err)
	}
	if p.Net == NetOutbound {
		for _, args := range gvisorOutboundIngressDropRules(subnet) {
			if err := addIPTablesRule(ctx, cleanup, args...); err != nil {
				return fail(err)
			}
		}
	}
	return path, cleanup.run, nil
}

func gvisorOutboundIngressDropRules(subnet string) [][]string {
	return [][]string{
		{"-I", "FORWARD", "-d", subnet, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"},
		{"-I", "OUTPUT", "-d", subnet, "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"},
	}
}

type cleanupStack struct {
	fns []func()
}

func newCleanupStack() *cleanupStack { return &cleanupStack{} }

func (s *cleanupStack) push(fn func()) { s.fns = append(s.fns, fn) }

func (s *cleanupStack) run() {
	for i := len(s.fns) - 1; i >= 0; i-- {
		s.fns[i]()
	}
}

func addIPTablesRule(ctx context.Context, cleanup *cleanupStack, args ...string) error {
	if err := runQuiet(ctx, "iptables", args...); err != nil {
		return fmt.Errorf("isobox: installing firewall rule: %w", err)
	}
	deleteArgs := append([]string(nil), args...)
	for i, arg := range deleteArgs {
		if arg == "-I" {
			deleteArgs[i] = "-D"
			break
		}
	}
	cleanup.push(func() { _ = runQuiet(context.Background(), "iptables", deleteArgs...) })
	return nil
}

func enableIPv4Forwarding(ctx context.Context) (func(), error) {
	out, err := exec.CommandContext(ctx, "sysctl", "-n", "net.ipv4.ip_forward").Output()
	if err != nil {
		return nil, fmt.Errorf("isobox: reading IPv4 forwarding setting: %w", err)
	}
	old := strings.TrimSpace(string(out))
	if old == "1" {
		return nil, nil
	}
	if err := runQuiet(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return nil, fmt.Errorf("isobox: enabling IPv4 forwarding: %w", err)
	}
	return func() { _ = runQuiet(context.Background(), "sysctl", "-w", "net.ipv4.ip_forward="+old) }, nil
}

func runQuiet(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Run()
}

func preflightGvisorOCISeccomp(ctx context.Context, runtime string) error {
	out, err := exec.CommandContext(ctx, runtime, "features").CombinedOutput()
	if err != nil {
		return fmt.Errorf("isobox: checking gvisor oci-seccomp support: %w", err)
	}
	if !strings.Contains(string(out), "oci-seccomp") {
		return fmt.Errorf("isobox: gvisor runtime %q does not report oci-seccomp support", runtime)
	}
	return nil
}

func shortLinuxName(prefix, id string) string {
	digest := id
	if i := strings.LastIndexByte(id, '-'); i >= 0 && i+1 < len(id) {
		digest = id[i+1:]
	}
	if len(digest) > 8 {
		digest = digest[:8]
	}
	name := prefix + digest
	if len(name) > 15 {
		return name[:15]
	}
	return name
}

func gvisorSubnet(id string) (subnet, hostIP, guestIP string) {
	digest := id
	if i := strings.LastIndexByte(id, '-'); i >= 0 && i+1 < len(id) {
		digest = id[i+1:]
	}
	// Derive the /30 from two digest bytes so concurrent runs are far less
	// likely to collide: byte0 picks the third octet (0-255) and byte1 picks a
	// /30 block in the fourth octet ({0,4,...,252}).
	oct3, block := 88, 0
	if len(digest) >= 4 {
		if b, err := hex.DecodeString(digest[:4]); err == nil && len(b) == 2 {
			oct3 = int(b[0])
			block = (int(b[1]) % 64) * 4
		}
	}
	base := "10.203." + strconv.Itoa(oct3) + "."
	return base + strconv.Itoa(block) + "/30", base + strconv.Itoa(block+1), base + strconv.Itoa(block+2)
}
