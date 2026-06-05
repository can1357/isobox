package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/can1357/isobox/internal/testkit"
)

type pathList []string

func (p *pathList) String() string {
	return fmt.Sprint([]string(*p))
}

func (p *pathList) Set(value string) error {
	*p = append(*p, value)
	return nil
}

func main() {
	var allowed pathList
	var denied pathList
	var probe string
	var content string
	var connect string
	var execPath string
	var socket string
	var abstractSocket string
	var machService string
	var overwrite string
	var deletePath string
	var deleteDenied string

	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&probe, "probe", "", "probe to run")
	flags.Var(&allowed, "allowed", "path expected to be allowed by the host case; may be repeated")
	flags.Var(&denied, "denied", "path expected to be denied by the host case; may be repeated")
	flags.StringVar(&content, "content", "", "content for fs-write probes")
	flags.StringVar(&connect, "connect", "", "tcp address for network connect probe")
	flags.StringVar(&execPath, "exec-path", "", "path to execute for exec probe")
	flags.StringVar(&socket, "socket", "", "unix socket path for ipc probe")
	flags.StringVar(&abstractSocket, "abstract-socket", "", "abstract-namespace unix socket name for ipc probe (Linux)")
	flags.StringVar(&machService, "mach-service", "", "mach service name for mach probe")
	flags.StringVar(&overwrite, "overwrite", "", "precreated path the fs-write probe should overwrite")
	flags.StringVar(&deletePath, "delete", "", "precreated path the fs-write probe should delete")
	flags.StringVar(&deleteDenied, "delete-denied", "", "precreated path the fs-write probe should attempt to delete and expect denied")
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n", flags.Args())
		os.Exit(2)
	}
	if probe == "" {
		fmt.Fprintln(os.Stderr, "--probe is required")
		os.Exit(2)
	}

	report, err := testkit.RunClientProbe(testkit.ClientConfig{
		Probe:          testkit.Probe(probe),
		Allowed:        []string(allowed),
		Denied:         []string(denied),
		Content:        content,
		Connect:        connect,
		ExecPath:       execPath,
		Socket:         socket,
		AbstractSocket: abstractSocket,
		MachService:    machService,
		Overwrite:      overwrite,
		Delete:         deletePath,
		DeleteDenied:   deleteDenied,
	})

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
