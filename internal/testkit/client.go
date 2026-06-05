package testkit

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"
)

const probeTimeout = 2 * time.Second

// ClientConfig describes one isobox-testkit-client probe invocation.
type ClientConfig struct {
	Probe          Probe
	Allowed        []string
	Denied         []string
	Content        string
	Connect        string
	ExecPath       string
	Socket         string
	AbstractSocket string
	MachService    string
	// Overwrite is a precreated path the FSWrite probe should overwrite with
	// Content (writes to an existing file, not create). Empty skips the leg.
	Overwrite string
	// Delete is a precreated path the FSWrite probe should remove. Empty skips.
	Delete string
	// DeleteDenied is a precreated path the FSWrite probe should attempt to
	// remove and expect denied. Empty skips.
	DeleteDenied string
}

// RunClientProbe executes one concrete client-side probe and returns the JSON
// protocol report consumed by the host test kit. Operation denial is recorded as
// a failed check, not returned as an error.
func RunClientProbe(cfg ClientConfig) (ClientReport, error) {
	report := ClientReport{Probe: cfg.Probe}

	switch cfg.Probe {
	case ProbeNoop:
		return report, nil
	case ProbeFSRead:
		runPathChecks(&report, "allowed", cfg.Allowed, readFile)
		runPathChecks(&report, "denied", cfg.Denied, readFile)
		return report, nil
	case ProbeFSWrite:
		content := cfg.Content
		if content == "" {
			content = "isobox-testkit\n"
		}
		write := func(path string) error {
			return os.WriteFile(path, []byte(content), 0o666)
		}
		runPathChecks(&report, "allowed", cfg.Allowed, write)
		runPathChecks(&report, "denied", cfg.Denied, write)
		if cfg.Overwrite != "" {
			err := write(cfg.Overwrite)
			report.AddCheck("overwrite", err == nil, err)
			report.AddEvidence("overwrite.path", cfg.Overwrite)
		}
		if cfg.Delete != "" {
			err := os.Remove(cfg.Delete)
			report.AddCheck("delete", err == nil, err)
			report.AddEvidence("delete.path", cfg.Delete)
		}
		if cfg.DeleteDenied != "" {
			err := os.Remove(cfg.DeleteDenied)
			report.AddCheck("delete_denied", err == nil, err)
			report.AddEvidence("delete_denied.path", cfg.DeleteDenied)
		}
		return report, nil
	case ProbeNetwork:
		runNetworkProbe(&report, cfg.Connect)
		return report, nil
	case ProbeExec:
		if cfg.ExecPath == "" {
			return report, errors.New("exec probe requires --exec-path")
		}
		runExecProbe(&report, cfg.ExecPath)
		runForkProbe(&report)
		return report, nil
	case ProbeIPC:
		if cfg.Socket == "" && cfg.AbstractSocket == "" {
			return report, errors.New("ipc probe requires --socket or --abstract-socket")
		}
		runIPCProbe(&report, cfg.Socket, cfg.AbstractSocket)
		return report, nil
	case ProbeMach:
		if cfg.MachService == "" {
			return report, errors.New("mach probe requires --mach-service")
		}
		runMachProbe(&report, cfg.MachService)
		return report, nil
	case ProbeKernelInfo:
		runKernelInfoProbe(&report)
		return report, nil
	default:
		return report, fmt.Errorf("unknown probe %q", cfg.Probe)
	}
}

func readFile(path string) error {
	_, err := os.ReadFile(path)
	return err
}

func runPathChecks(report *ClientReport, base string, paths []string, op func(string) error) {
	for i, path := range paths {
		name := checkName(base, i, len(paths))
		err := op(path)
		report.AddCheck(name, err == nil, err)
		report.AddEvidence(name+".path", path)
	}
}

func checkName(base string, index, total int) string {
	if total <= 1 {
		return base
	}
	return fmt.Sprintf("%s.%d", base, index)
}

func runNetworkProbe(report *ClientReport, connect string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	report.AddCheck("listen", err == nil, err)
	if listener != nil {
		_ = listener.Close()
	}

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	report.AddCheck("udp_listen", err == nil, err)
	if udpConn != nil {
		_ = udpConn.Close()
	}

	if connect != "" {
		conn, err := net.DialTimeout("tcp", connect, probeTimeout)
		report.AddCheck("connect", err == nil, err)
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func runExecProbe(report *ClientReport, path string) {
	err := exec.Command(path, "--probe", string(ProbeNoop)).Run()
	report.AddCheck("exec", err == nil, err)
	report.AddEvidence("exec.path", path)
}

func runIPCProbe(report *ClientReport, socket, abstract string) {
	if runtime.GOOS == "windows" {
		report.Unsupported = "unix sockets are unsupported on windows"
		return
	}
	if socket != "" {
		conn, err := net.DialTimeout("unix", socket, probeTimeout)
		report.AddCheck("connect", err == nil, err)
		if conn != nil {
			_ = conn.Close()
		}
		report.AddEvidence("socket.path", socket)
	}
	if abstract != "" {
		if runtime.GOOS != "linux" {
			report.AddCheck("connect_abstract", false, errors.New("abstract unix sockets are linux-only"))
			report.AddEvidence("abstract.unsupported", runtime.GOOS)
		} else {
			// Abstract namespace: leading "@" is translated to a NUL byte by
			// Go's net package, matching how the kernel encodes it.
			name := abstract
			if name[0] != '@' {
				name = "@" + name
			}
			conn, err := net.DialTimeout("unix", name, probeTimeout)
			report.AddCheck("connect_abstract", err == nil, err)
			if conn != nil {
				_ = conn.Close()
			}
			report.AddEvidence("abstract.name", name)
		}
	}
	// TODO: SysV IPC (shmget/semget/msgget) and POSIX message queues
	// (mq_open) are not currently probed. The current case asserts only
	// AF_UNIX pathname + abstract reachability, which is sufficient to catch
	// the most common bind-mount escape; SysV/POSIX-mqueue probes need raw
	// syscall helpers and a host-side listener and are deferred.
}

func runKernelInfoProbe(report *ClientReport) {
	report.AddEvidence("goos", runtime.GOOS)
	report.AddEvidence("goarch", runtime.GOARCH)
	if hostname, err := os.Hostname(); err == nil {
		report.AddEvidence("hostname", hostname)
	} else {
		report.AddEvidence("hostname.error", err.Error())
	}
	if runtime.GOOS == "linux" {
		addReadableSnippet(report, "proc.version", "/proc/version", 4096)
		addReadableSnippet(report, "proc.self.status", "/proc/self/status", 8192)
	}
}

func addReadableSnippet(report *ClientReport, name, path string, max int) {
	data, err := os.ReadFile(path)
	if err != nil {
		report.AddEvidence(name+".error", err.Error())
		return
	}
	if len(data) > max {
		data = data[:max]
	}
	report.AddEvidence(name, string(data))
}
