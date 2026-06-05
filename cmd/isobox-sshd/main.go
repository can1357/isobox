// Command isobox-sshd launches an SSH server inside an isobox sandbox so you can ssh
// in and explore the confinement interactively, the way a remote user would.
//
// It is a development/inspection helper, not a production SSH daemon. macOS
// OpenSSH cannot run inside isobox's Seatbelt sandbox: sshd's mandatory preauth
// privilege-separation child calls sandbox_init(), and the kernel forbids
// applying a second Seatbelt profile once isobox has applied one. So instead of
// shelling out to /usr/sbin/sshd, isobox-sshd embeds a small SSH server that runs
// as the sandboxed command itself and spawns the login shell as its child, so
// the whole session inherits the isobox.
//
// By default it accepts any login with no credentials. Pass -key to require a
// specific public key instead.
//
// The process runs in two modes. The default (supervisor) mode compiles an isobox
// spec that re-execs this same binary in -serve mode inside the sandbox. The
// -serve mode is the actual SSH server and is not meant to be invoked directly.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/can1357/isobox"
	"github.com/can1357/isobox/internal/reslimit"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// opendirectoryLibinfo is the Mach service macOS libinfo consults for user and
// group resolution (getpwnam/getpwuid). Without it, the isobox's ipc.restrict
// Mach-lookup denial makes the login shell resolve to a raw uid instead of a
// name. It is the one Mach allowance an interactive login needs.
const opendirectoryLibinfo = "com.apple.system.opendirectoryd.libinfo"

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		serve     = flag.Bool("serve", false, "internal: run the SSH server (invoked inside the sandbox)")
		addr      = flag.String("addr", "127.0.0.1", "listen address")
		port      = flag.Int("port", 2222, "listen port")
		key       = flag.String("key", "", "authorized public key file; empty accepts any login with no credentials")
		shell     = flag.String("shell", "", "login shell to spawn for sessions (default: $SHELL, else /bin/sh)")
		backend   = flag.String("backend", "", "force an isobox backend; empty selects the native one")
		dir       = flag.String("dir", "", "working directory for the sandboxed server")
		allowTemp = flag.Bool("allow-temp", false, "let sessions write to the OS temp dir")
		cpus      = flag.String("cpus", "", "limit CPU usage to this many logical cores (e.g. 1.5); empty means no limit")
		memory    = flag.String("memory", "", "limit memory (e.g. 512m, 2g, or raw bytes); empty means no limit")
		writable  stringList
	)
	flag.Var(&writable, "writable", "path sessions may write (repeatable; implies --write=scope)")
	flag.Parse()

	cpuLimit, err := reslimit.ParseCPUs(*cpus)
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox-sshd:", err)
		return 2
	}
	memLimit, err := reslimit.ParseMemory(*memory)
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox-sshd:", err)
		return 2
	}

	if *serve {
		return runServe(*addr, *port, *key, *shell)
	}
	return runSupervisor(supervisorOpts{
		addr:        *addr,
		port:        *port,
		key:         *key,
		shell:       *shell,
		backend:     *backend,
		dir:         *dir,
		allowTemp:   *allowTemp,
		writable:    writable,
		cpus:        cpuLimit,
		memoryBytes: memLimit,
	})
}

type supervisorOpts struct {
	addr        string
	port        int
	key         string
	shell       string
	backend     string
	dir         string
	allowTemp   bool
	writable    []string
	cpus        float64
	memoryBytes int64
}

// runSupervisor compiles an isobox spec that runs this binary in -serve mode inside
// the sandbox, prints how to connect, then launches it.
func runSupervisor(o supervisorOpts) int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox-sshd:", err)
		return 1
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}

	keyPath := o.key
	if keyPath != "" {
		abs, err := filepath.Abs(keyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "isobox-sshd:", err)
			return 1
		}
		if _, err := os.Stat(abs); err != nil {
			fmt.Fprintln(os.Stderr, "isobox-sshd: cannot read -key:", err)
			return 1
		}
		keyPath = abs
	}

	serveArgs := []string{self, "-serve", "-addr", o.addr, "-port", strconv.Itoa(o.port)}
	if keyPath != "" {
		serveArgs = append(serveArgs, "-key", keyPath)
	}
	if o.shell != "" {
		serveArgs = append(serveArgs, "-shell", o.shell)
	}

	spec := isobox.Spec{
		Args:      serveArgs,
		Dir:       o.dir,
		Net:       isobox.NetEnable, // the server must listen and accept connections
		MachAllow: []string{opendirectoryLibinfo},
		AllowTemp: o.allowTemp,
		// Interactive sessions allocate PTYs, which means writing /dev/ptmx and
		// the slave /dev/ttys* nodes. /dev holds only device nodes, so the rest
		// of the host filesystem stays read-only. Extra --writable paths widen
		// this scope.
		Write:       isobox.WriteScope,
		Writable:    append([]string{"/dev"}, o.writable...),
		CPUs:        o.cpus,
		MemoryBytes: o.memoryBytes,
	}

	runner, err := newRunner(o.backend)
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox-sshd:", err)
		return 1
	}

	plan, err := runner.Compile(spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox-sshd:", err)
		return 1
	}
	printConnectInfo(os.Stderr, o, plan)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code, err := runner.Run(ctx, spec, isobox.Stdio{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox-sshd:", err)
		return 1
	}
	return code
}

func printConnectInfo(w io.Writer, o supervisorOpts, plan *isobox.Plan) {
	fmt.Fprintf(w, "isobox-sshd: SSH server listening inside the %s sandbox on %s\n",
		plan.Backend, net.JoinHostPort(o.addr, strconv.Itoa(o.port)))
	user := os.Getenv("USER")
	if user == "" {
		user = "any"
	}
	common := fmt.Sprintf("-p %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s",
		o.port, user, o.addr)
	if o.key == "" {
		fmt.Fprintln(w, "isobox-sshd: accepting ANY login (no credentials; any username)")
		fmt.Fprintf(w, "  ssh %s\n", common)
	} else {
		fmt.Fprintf(w, "isobox-sshd: accepting the public key in %s\n", o.key)
		fmt.Fprintf(w, "  ssh -i <matching-private-key> %s\n", common)
	}
	writable := append([]string{"/dev"}, o.writable...)
	fmt.Fprintf(w, "isobox-sshd: host filesystem is read-only except writes to: %s\n", strings.Join(writable, " "))
	for _, c := range plan.Caveats {
		fmt.Fprintln(w, "  caveat:", c)
	}
	fmt.Fprintln(w, "isobox-sshd: press Ctrl-C to stop")
}

func newRunner(backend string) (*isobox.Runner, error) {
	if backend == "" {
		return isobox.New()
	}
	return isobox.NewBackend(isobox.Backend(backend))
}

// runServe runs the embedded SSH server. It executes inside the isobox sandbox, so
// the login shells it spawns are confined by the same profile.
func runServe(addr string, port int, keyPath, shellOverride string) int {
	signer, err := newHostSigner()
	if err != nil {
		fmt.Fprintln(os.Stderr, "isobox-sshd: host key:", err)
		return 1
	}

	srv := &ssh.Server{
		Addr:    net.JoinHostPort(addr, strconv.Itoa(port)),
		Handler: sessionHandler(shellOverride),
	}
	srv.AddHostKey(signer)

	// With no auth handlers, gliderlabs/ssh allows connections with no
	// authentication at all. Setting a PublicKeyHandler requires that key.
	if keyPath != "" {
		authorized, err := loadAuthorizedKey(keyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "isobox-sshd:", err)
			return 1
		}
		srv.PublicKeyHandler = func(_ ssh.Context, offered ssh.PublicKey) bool {
			return ssh.KeysEqual(offered, authorized)
		}
	}

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "isobox-sshd: serve:", err)
		return 1
	}
	return 0
}

func newHostSigner() (gossh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return gossh.NewSignerFromKey(priv)
}

func loadAuthorizedKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read -key: %w", err)
	}
	pub, _, _, _, err := gossh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse -key %q: %w", path, err)
	}
	return pub, nil
}

func sessionHandler(shellOverride string) ssh.Handler {
	return func(s ssh.Session) {
		shell := resolveShell(shellOverride)
		ptyReq, winCh, isPty := s.Pty()

		var cmd *exec.Cmd
		if raw := s.RawCommand(); raw != "" {
			// `ssh host -- some command`: run the verbatim command line through
			// the shell, exactly as a real sshd would.
			cmd = exec.Command(shell, "-c", raw)
		} else {
			// Interactive session: a login shell, mirroring real sshd.
			cmd = exec.Command(shell)
			cmd.Args = []string{"-" + filepath.Base(shell)}
		}
		cmd.Dir = sessionDir()
		cmd.Env = sessionEnv(ptyReq.Term, isPty)

		if isPty {
			f, err := pty.Start(cmd)
			if err != nil {
				fmt.Fprintln(s.Stderr(), "isobox-sshd: pty:", err)
				_ = s.Exit(1)
				return
			}
			defer func() { _ = f.Close() }()
			setWinsize(f, ptyReq.Window.Width, ptyReq.Window.Height)
			go func() {
				for win := range winCh {
					setWinsize(f, win.Width, win.Height)
				}
			}()
			go func() { _, _ = io.Copy(f, s) }() // client -> pty
			_, _ = io.Copy(s, f)                 // pty -> client (until the shell exits)
			_ = s.Exit(exitCode(cmd.Wait()))
			return
		}

		cmd.Stdin = s
		cmd.Stdout = s
		cmd.Stderr = s.Stderr()
		_ = s.Exit(exitCode(cmd.Run()))
	}
}

func resolveShell(override string) string {
	if override != "" {
		return override
	}
	if sh := os.Getenv("SHELL"); sh != "" {
		return sh
	}
	return "/bin/sh"
}

func sessionDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	return "/"
}

func sessionEnv(term string, isPty bool) []string {
	env := os.Environ()
	if isPty {
		if term == "" {
			term = "xterm"
		}
		env = append(env, "TERM="+term)
	}
	return env
}

func setWinsize(f *os.File, w, h int) {
	_ = pty.Setsize(f, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)})
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 1
}
