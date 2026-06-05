package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/can1357/isobox/internal/testkit"
)

type capFlags []string

func (c *capFlags) String() string { return strings.Join(*c, ",") }
func (c *capFlags) Set(v string) error {
	*c = append(*c, v)
	return nil
}

func main() {
	var caps capFlags
	var opts testkit.HostOptions
	var jsonOut bool
	flag.StringVar(&opts.ClientPath, "client", "", "compiled isobox-testkit-client binary to run inside isobox")
	flag.StringVar(&opts.Backend, "backend", "", "backend to test; empty selects native backend")
	flag.Var(&caps, "cap", "capability to test; may be repeated or comma-separated")
	flag.DurationVar(&opts.Timeout, "timeout", 10*time.Second, "timeout per capability case")
	flag.BoolVar(&jsonOut, "json", false, "emit JSON array of case reports")
	flag.BoolVar(&opts.Keep, "keep", false, "keep fixture directory and report it in evidence")
	flag.StringVar(&opts.ConnectAddr, "connect", "", "network address for outbound/connect probes")
	flag.StringVar(&opts.MachService, "mach-service", "com.apple.coreservices.launchservicesd", "Mach service name for Darwin lookup probes")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %s\n", strings.Join(flag.Args(), " "))
		os.Exit(2)
	}
	opts.Caps = caps

	reports, err := testkit.RunHost(context.Background(), opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	} else {
		printHuman(reports)
	}
	if testkit.HasSetupError(reports) {
		os.Exit(2)
	}
	if testkit.HasFailure(reports) {
		os.Exit(1)
	}
}

func printHuman(reports []testkit.CaseReport) {
	for _, r := range reports {
		fmt.Printf("%s %s", r.Status, r.Capability)
		if r.Details != "" {
			fmt.Printf(": %s", r.Details)
		}
		fmt.Println()
		for k, v := range r.Checks {
			fmt.Printf("  check %s=%t\n", k, v)
		}
		for k, v := range r.Evidence {
			if v != "" {
				fmt.Printf("  evidence %s=%s\n", k, v)
			}
		}
	}
}
