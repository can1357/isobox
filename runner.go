package isobox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
)

// Stdio wires the sandboxed process's standard streams. The zero value uses the
// caller's os.Stdin/Stdout/Stderr.
type Stdio struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

func (s Stdio) orDefaults() (in io.Reader, out, errw io.Writer) {
	in, out, errw = s.In, s.Out, s.Err
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	if errw == nil {
		errw = os.Stderr
	}
	return
}

// Runner compiles specs for one backend and runs them.
type Runner struct {
	backend Backend
	compile func(Spec) (*Plan, error)
	run     func(context.Context, *Plan, Spec, Stdio) (int, error)
	binEnv  string // env var that overrides the sandbox tool path (argv[0])
}

func runnerFor(b Backend) (*Runner, error) {
	switch b {
	case BackendSeatbelt:
		return &Runner{backend: b, compile: compileSeatbelt, binEnv: "ISOBOX_SANDBOX_EXEC"}, nil
	case BackendGvisor:
		return &Runner{backend: b, compile: compileGvisor, run: runGvisor, binEnv: "ISOBOX_RUNSC"}, nil
	case BackendAppContainer:
		return &Runner{backend: b, compile: compileAppContainer, run: runAppContainer}, nil
	case BackendDockerEphemeral:
		return &Runner{backend: b, compile: compileDockerEphemeral, binEnv: "ISOBOX_DOCKER"}, nil
	default:
		return nil, fmt.Errorf("isobox: unknown backend %q", b)
	}
}

// New returns a Runner for the current OS, or an error on unsupported platforms.
func New() (*Runner, error) {
	switch runtime.GOOS {
	case "darwin":
		return runnerFor(BackendSeatbelt)
	case "linux":
		return runnerFor(BackendGvisor)
	case "windows":
		return runnerFor(BackendAppContainer)
	default:
		return nil, fmt.Errorf("isobox: no sandbox backend for GOOS %q (supported: darwin, linux, windows)", runtime.GOOS)
	}
}

// NewBackend returns a Runner for a specific backend regardless of host OS. This
// lets you compile and inspect a plan for a non-native backend (e.g. preview the
// Windows AppContainer grants from a Mac). Running it still requires the native
// backend to exist on the host.
func NewBackend(b Backend) (*Runner, error) { return runnerFor(b) }

// Backend reports which backend this runner uses.
func (r *Runner) Backend() Backend { return r.backend }

// Capabilities reports what this runner's backend can enforce.
func (r *Runner) Capabilities() CapabilitySet { return CapsOf(r.backend) }

// Compile prepares a Spec into an inspectable Plan without running anything.
func (r *Runner) Compile(s Spec) (*Plan, error) { return r.compile(s) }

// Run compiles the spec and executes it, returning the command's exit code. A
// non-nil error means isobox failed to launch the sandbox; a command that runs
// and exits non-zero returns that code with a nil error.
func (r *Runner) Run(ctx context.Context, s Spec, streams Stdio) (int, error) {
	plan, err := r.compile(s)
	if err != nil {
		return -1, err
	}

	if r.run != nil {
		return r.run(ctx, plan, s, streams)
	}
	return r.runExec(ctx, plan, s, streams)
}

func (r *Runner) runExec(ctx context.Context, plan *Plan, s Spec, streams Stdio) (int, error) {
	return runPlanExec(ctx, r.backend, r.binEnv, plan, s, streams)
}

func runPlanExec(ctx context.Context, backend Backend, binEnv string, plan *Plan, s Spec, streams Stdio) (int, error) {
	runtime, err := prepareFSVirtualization(plan, s)
	if err != nil {
		return -1, err
	}
	appendPlanFSCaveats(plan, runtime)
	cleanup := func() error { return nil }
	if runtime != nil && runtime.Cleanup != nil {
		cleanup = runtime.Cleanup
	}

	argv := plan.Argv
	if override := os.Getenv(binEnv); override != "" {
		argv = append([]string{override}, argv[1:]...)
	}
	if backend == BackendDockerEphemeral {
		if err := validateDockerReadOnlyImageVolumes(ctx, argv); err != nil {
			if cleanupErr := cleanup(); cleanupErr != nil {
				return -1, fmt.Errorf("isobox: preparing docker image volume policy: %w", errors.Join(err, cleanupErr))
			}
			return -1, err
		}
		var seccompCleanup func() error
		argv, seccompCleanup, err = materializeDockerSeccompProfile(argv)
		if err != nil {
			if cleanupErr := cleanup(); cleanupErr != nil {
				return -1, fmt.Errorf("isobox: preparing docker seccomp profile: %w", errors.Join(err, cleanupErr))
			}
			return -1, err
		}
		if seccompCleanup != nil {
			priorCleanup := cleanup
			cleanup = func() error {
				return errors.Join(priorCleanup(), seccompCleanup())
			}
		}
	}

	in, out, errw := streams.orDefaults()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errw
	cmd.Dir = s.Dir
	if runtime != nil && runtime.Dir != "" {
		cmd.Dir = runtime.Dir
	}
	if runtime != nil {
		cmd.Env = commandEnv(s.Env, runtime.Env)
	} else if s.Env != nil {
		cmd.Env = s.Env
	}

	runErr := cmd.Run()
	cleanupErr := cleanup()
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			return ee.ExitCode(), nil
		}
		if cleanupErr != nil {
			return -1, fmt.Errorf("isobox: launching %s backend: %w", backend, errors.Join(runErr, cleanupErr))
		}
		return -1, fmt.Errorf("isobox: launching %s backend: %w", backend, runErr)
	}
	if cleanupErr != nil {
		return -1, fmt.Errorf("isobox: cleaning filesystem virtualization: %w", cleanupErr)
	}
	return 0, nil
}
