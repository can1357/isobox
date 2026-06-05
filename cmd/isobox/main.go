// Command isobox runs a command inside a host-native or portability-workaround
// sandbox backend: Seatbelt on macOS, gVisor on Linux, AppContainer on Windows,
// and optional ephemeral container backends where available.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/can1357/isobox"
	"github.com/can1357/isobox/internal/reslimit"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("isobox", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "isobox — run a command in a sandbox backend (%s)\n\n"+
			"usage: isobox [flags] [--] command [args...]\n\nflags:\n", backendChoices())
		fs.PrintDefaults()
		fmt.Fprint(os.Stderr, "\nexamples:\n"+
			"  isobox -- echo hi                        # agent defaults: outbound net, cwd writable\n"+
			"  isobox --profile=tight -- echo hi        # no external network, read-only host, no writes\n"+
			"  isobox --net=enable -- curl https://example.com\n"+
			"  isobox --writable ./work -- just build   # persist ./work plus the default cwd\n"+
			"  isobox --print --backend gvisor -- ls /  # preview the Linux command on any OS\n"+
			"  isobox --caps                            # show the capability matrix\n"+
			"  isobox --mach-allow com.apple.system.opendirectoryd.libinfo -- id  # allow a Mach service (Seatbelt)\n")
	}
	return fs
}

func main() {
	os.Exit(run())
}

func run() int {
	fs := newFlagSet()
	var (
		profile     = fs.String("profile", "agent", "policy profile: agent|tight")
		netFlag     = fs.String("net", "disable", "network policy: disable|enable|outbound")
		writeFlag   = fs.String("write", "none", "write policy: none|scope|ephemeral|overlay")
		cpusFlag    = fs.String("cpus", "", "limit CPU usage to this many logical cores (e.g. 1.5); empty means no limit")
		memFlag     = fs.String("memory", "", "limit memory (e.g. 512m, 2g, or raw bytes); empty means no limit")
		writable    stringList
		readable    stringList
		readDeny    stringList
		machAllow   stringList
		noExec      = fs.Bool("no-exec", false, "forbid executing another program image")
		allowTemp   = fs.Bool("allow-temp", false, "add the OS temp dir as a scoped write target; requires --write=scope or --write=overlay")
		strict      = fs.Bool("strict", false, "reject non-portable capabilities (identical on all backends)")
		dir         = fs.String("dir", "", "working directory for the command")
		backend     = fs.String("backend", "", "force a backend for inspection: "+backendChoices())
		printOnly   = fs.Bool("print", false, "compile and print the plan; do not run")
		showCaps    = fs.Bool("caps", false, "print the capability matrix and exit")
		showVersion = fs.Bool("version", false, "print version information and exit")
	)
	fs.Var(&writable, "writable", "path the sandbox may write (repeatable)")
	fs.Var(&readable, "readable", "restrict reads to this path (repeatable)")
	fs.Var(&readDeny, "read-deny", "path the sandbox may not read (repeatable)")
	fs.Var(&machAllow, "mach-allow", "Mach service global-name to allow (repeatable; Seatbelt)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	seen := seenFlags(fs)

	if *showVersion {
		printVersion(os.Stdout)
		return 0
	}

	if *showCaps {
		printCaps(os.Stdout)
		return 0
	}

	args := fs.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "isobox: no command given")
		fs.Usage()
		return 2
	}

	net, err := parseNet(*netFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox:", err)
		return 2
	}
	write, err := parseWrite(*writeFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox:", err)
		return 2
	}
	cpus, err := reslimit.ParseCPUs(*cpusFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox:", err)
		return 2
	}
	memBytes, err := reslimit.ParseMemory(*memFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox:", err)
		return 2
	}
	spec := isobox.Spec{
		Args:        args,
		Dir:         *dir,
		Net:         net,
		Write:       write,
		Writable:    writable,
		Readable:    readable,
		ReadDeny:    readDeny,
		MachAllow:   machAllow,
		NoExec:      *noExec,
		AllowTemp:   *allowTemp,
		Strict:      *strict,
		CPUs:        cpus,
		MemoryBytes: memBytes,
	}
	if err := applyProfile(*profile, &spec, seen); err != nil {
		fmt.Fprintln(os.Stderr, "isobox:", err)
		return 2
	}
	if len(spec.Writable) > 0 && spec.Write == isobox.WriteNone && !seen["write"] {
		spec.Write = isobox.WriteScope // --writable implies scoped writes outside the agent profile
	}

	runner, err := newRunner(*backend)
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox:", err)
		return 1
	}

	if *printOnly {
		plan, err := runner.Compile(spec)
		if err != nil {
			fmt.Fprintln(os.Stderr, "isobox:", err)
			return 1
		}
		printPlan(os.Stdout, plan)
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code, err := runner.Run(ctx, spec, isobox.Stdio{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox:", err)
		return 1
	}
	return code
}

func newRunner(backend string) (*isobox.Runner, error) {
	if backend == "" {
		return isobox.New()
	}
	return isobox.NewBackend(isobox.Backend(backend))
}

func seenFlags(fs *flag.FlagSet) map[string]bool {
	seen := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		seen[f.Name] = true
	})
	return seen
}

func applyProfile(name string, spec *isobox.Spec, seen map[string]bool) error {
	switch name {
	case "agent":
		if spec.Strict && !seen["profile"] {
			return nil
		}
		applyAgentProfile(spec, seen)
		return nil
	case "tight", "none":
		return nil
	default:
		return fmt.Errorf("invalid --profile %q (want agent|tight)", name)
	}
}

func applyAgentProfile(spec *isobox.Spec, seen map[string]bool) {
	if !seen["net"] {
		spec.Net = isobox.NetOutbound
	}
	if !seen["write"] {
		spec.Write = isobox.WriteOverlay
	}
	if spec.Write == isobox.WriteScope || spec.Write == isobox.WriteOverlay {
		spec.Writable = appendPathUnique(spec.Writable, profileWorkspacePath(spec))
		if !seen["allow-temp"] {
			spec.AllowTemp = true
		}
	}
	if len(spec.Readable) == 0 {
		for _, p := range agentReadDenyDefaults() {
			spec.ReadDeny = appendPathUnique(spec.ReadDeny, p)
		}
	}
}

func profileWorkspacePath(spec *isobox.Spec) string {
	if spec.Dir != "" {
		return spec.Dir
	}
	return "."
}

func appendPathUnique(paths []string, path string) []string {
	clean := filepath.Clean(path)
	for _, existing := range paths {
		if filepath.Clean(existing) == clean {
			return paths
		}
	}
	return append(paths, path)
}

func agentReadDenyDefaults() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	rel := []string{
		".ssh",
		".gnupg",
		".aws",
		".azure",
		".docker",
		".kube",
		".npmrc",
		".pypirc",
		".netrc",
		".git-credentials",
		".config/gcloud",
		".config/gh",
		".config/op",
		".config/1Password",
		"Library/Keychains",
		"Library/Application Support/1Password",
	}
	out := make([]string, 0, len(rel))
	for _, p := range rel {
		out = append(out, filepath.Join(home, p))
	}
	return out
}

func backendChoices() string {
	backends := isobox.Backends()
	names := make([]string, 0, len(backends))
	for _, b := range backends {
		names = append(names, string(b))
	}
	return strings.Join(names, "|")
}

func parseNet(s string) (isobox.NetMode, error) {
	switch s {
	case "disable":
		return isobox.NetDisable, nil
	case "enable":
		return isobox.NetEnable, nil
	case "outbound":
		return isobox.NetOutbound, nil
	default:
		return 0, fmt.Errorf("invalid --net %q (want disable|enable|outbound)", s)
	}
}

func parseWrite(s string) (isobox.WriteMode, error) {
	switch s {
	case "none":
		return isobox.WriteNone, nil
	case "scope":
		return isobox.WriteScope, nil
	case "ephemeral":
		return isobox.WriteEphemeral, nil
	case "overlay":
		return isobox.WriteOverlay, nil
	default:
		return 0, fmt.Errorf("invalid --write %q (want none|scope|ephemeral|overlay)", s)
	}
}

func printPlan(w *os.File, p *isobox.Plan) {
	fmt.Fprintf(w, "backend:  %s\n", p.Backend)
	caps := make([]string, 0, p.Uses.Len())
	for _, c := range p.Uses.List() {
		caps = append(caps, string(c))
	}
	fmt.Fprintf(w, "enforces: %s\n", strings.Join(caps, ", "))
	if fs := p.FilesystemVirtualization(); fs != "" {
		fmt.Fprintf(w, "filesystem: %s\n", fs)
	}
	if len(p.Caveats) > 0 {
		fmt.Fprintln(w, "caveats:")
		for _, c := range p.Caveats {
			fmt.Fprintf(w, "  - %s\n", c)
		}
	}
	if p.Profile != "" {
		fmt.Fprintln(w, "profile:")
		for _, line := range strings.Split(strings.TrimRight(p.Profile, "\n"), "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
	fmt.Fprintln(w, "argv:")
	for _, a := range p.Argv {
		if a == p.Profile && p.Profile != "" {
			fmt.Fprintln(w, "  <profile-above>")
			continue
		}
		fmt.Fprintf(w, "  %s\n", a)
	}
}

func printCaps(w *os.File) {
	inter := isobox.Intersection()
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprint(tw, "CAPABILITY")
	backends := isobox.Backends()
	for _, b := range backends {
		fmt.Fprintf(tw, "\t%s", capColumnName(b))
	}
	fmt.Fprintln(tw, "\tPORTABLE\tDESCRIPTION")
	yn := func(b bool) string {
		if b {
			return "yes"
		}
		return "-"
	}
	for _, c := range isobox.Union().List() {
		fmt.Fprintf(tw, "%s", c)
		for _, b := range backends {
			fmt.Fprintf(tw, "\t%s", yn(isobox.CapsOf(b).Has(c)))
		}
		fmt.Fprintf(tw, "\t%s\t%s\n", yn(inter.Has(c)), c.Describe())
	}
	tw.Flush()
}

func capColumnName(b isobox.Backend) string {
	switch b {
	case isobox.BackendAppContainer:
		return "WINDOWS"
	default:
		return strings.ToUpper(string(b))
	}
}
