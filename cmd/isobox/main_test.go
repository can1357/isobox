package main

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/can1357/isobox"
)

func TestApplyAgentProfileDefaults(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	spec := isobox.Spec{Args: []string{"echo"}, Dir: "/work"}
	if err := applyProfile("agent", &spec, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if spec.Net != isobox.NetOutbound {
		t.Fatalf("Net=%s, want outbound", spec.Net)
	}
	if spec.Write != isobox.WriteOverlay {
		t.Fatalf("Write=%s, want overlay", spec.Write)
	}
	if !spec.AllowTemp {
		t.Fatal("agent profile should enable temp writes")
	}
	if !hasPath(spec.Writable, "/work") {
		t.Fatalf("workspace writable missing: %v", spec.Writable)
	}
	if len(spec.ReadDeny) == 0 {
		t.Fatal("agent profile should install sensitive read deny defaults")
	}
	if len(spec.EnvDeny) == 0 {
		t.Fatal("agent profile should install environment deny defaults")
	}
	for _, want := range []string{"*_TOKEN", "*_KEY", "*_SECRET", "AWS_*", "GITHUB_*", "SSH_AUTH_SOCK"} {
		if !hasString(spec.EnvDeny, want) {
			t.Fatalf("agent env deny default %q missing: %v", want, spec.EnvDeny)
		}
	}
}

func TestPrintCapsWarnsNetOutboundIsNotAllowlist(t *testing.T) {
	var buf bytes.Buffer
	printCaps(&buf)
	out := buf.String()
	if !strings.Contains(out, "net.outbound") || !strings.Contains(out, "not a domain/CIDR allowlist") {
		t.Fatalf("--caps output must warn that net.outbound is not egress filtering, got:\n%s", out)
	}
	if strings.Contains(out, "res.disk") {
		t.Fatalf("--caps must not advertise res.disk without an enforced disk quota, got:\n%s", out)
	}
}

func TestApplyAgentProfileHonorsExplicitOverrides(t *testing.T) {
	spec := isobox.Spec{
		Args:     []string{"echo"},
		Net:      isobox.NetDisable,
		Write:    isobox.WriteNone,
		Readable: []string{"/project"},
	}
	seen := map[string]bool{"net": true, "write": true, "readable": true, "allow-temp": true}
	if err := applyProfile("agent", &spec, seen); err != nil {
		t.Fatal(err)
	}
	if spec.Net != isobox.NetDisable || spec.Write != isobox.WriteNone || spec.AllowTemp {
		t.Fatalf("explicit overrides not preserved: %+v", spec)
	}
	if len(spec.Writable) != 0 {
		t.Fatalf("explicit write=none should not gain writable paths: %v", spec.Writable)
	}
	if len(spec.ReadDeny) != 0 {
		t.Fatalf("explicit readable should suppress default read deny list: %v", spec.ReadDeny)
	}
	if len(spec.EnvDeny) == 0 {
		t.Fatal("agent profile should keep env scrub defaults when only reads are explicit")
	}
}

func TestApplyAgentProfileAppendsExplicitEnvDeny(t *testing.T) {
	spec := isobox.Spec{Args: []string{"echo"}, EnvDeny: []string{"CUSTOM_SECRET"}}
	if err := applyProfile("agent", &spec, map[string]bool{"env-deny": true}); err != nil {
		t.Fatal(err)
	}
	if !hasString(spec.EnvDeny, "CUSTOM_SECRET") || !hasString(spec.EnvDeny, "*_TOKEN") {
		t.Fatalf("EnvDeny should contain explicit and default patterns: %v", spec.EnvDeny)
	}
}

func TestAgentEnvDenyDefaultsReturnsCopy(t *testing.T) {
	got := agentEnvDenyDefaults()
	got[0] = "MUTATED"
	if agentEnvDenyDefaults()[0] == "MUTATED" {
		t.Fatal("agentEnvDenyDefaults returned shared backing array")
	}
}

func TestStrictWithoutExplicitProfileKeepsTightDefaults(t *testing.T) {
	spec := isobox.Spec{Args: []string{"echo"}, Strict: true}
	if err := applyProfile("agent", &spec, map[string]bool{"strict": true}); err != nil {
		t.Fatal(err)
	}
	if spec.Net != isobox.NetDisable || spec.Write != isobox.WriteNone || len(spec.Writable) != 0 || len(spec.ReadDeny) != 0 || len(spec.EnvDeny) != 0 {
		t.Fatalf("strict should keep tight defaults unless profile is explicit: %+v", spec)
	}
}

func hasPath(paths []string, want string) bool {
	for _, path := range paths {
		if path == want {
			return true
		}
	}
	return false
}
func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestParseMachAllowFlag(t *testing.T) {
	fs := newFlagSet()
	var machAllow stringList
	fs.Var(&machAllow, "mach-allow", "")
	if err := fs.Parse([]string{"--mach-allow", "a", "--mach-allow", "b", "--", "echo"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := []string(machAllow)
	want := []string{"a", "b"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("MachAllow=%v, want %v", got, want)
	}
	if args := fs.Args(); len(args) != 1 || args[0] != "echo" {
		t.Fatalf("positional args=%v, want [echo]", args)
	}
}

func TestParsePIDsFlag(t *testing.T) {
	fs := newFlagSet()
	pids := fs.String("pids", "", "")
	if err := fs.Parse([]string{"--pids", "64", "--", "echo"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if *pids != "64" {
		t.Fatalf("pids=%q, want 64", *pids)
	}
	if args := fs.Args(); len(args) != 1 || args[0] != "echo" {
		t.Fatalf("positional args=%v, want [echo]", args)
	}
}

func TestParseTimeoutFlag(t *testing.T) {
	fs := newFlagSet()
	timeout := fs.Duration("timeout", 0, "")
	if err := fs.Parse([]string{"--timeout", "1500ms", "--", "echo"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if *timeout != 1500*time.Millisecond {
		t.Fatalf("timeout=%s, want 1.5s", *timeout)
	}
	if args := fs.Args(); len(args) != 1 || args[0] != "echo" {
		t.Fatalf("positional args=%v, want [echo]", args)
	}
}

func TestCommandContextTimeout(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	ctx, cancel := commandContext(parent, time.Nanosecond)
	defer cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("timeout context did not expire")
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("ctx.Err()=%v, want DeadlineExceeded", ctx.Err())
	}
}

func TestCommandContextZeroTimeoutPreservesParent(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	ctx, cancel := commandContext(parent, 0)
	cancel()
	select {
	case <-ctx.Done():
		t.Fatal("zero-timeout cancel should not cancel parent context")
	default:
	}
	cancelParent()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not reach command context")
	}
}

func TestNewRunnerAutoDelegatesToSelector(t *testing.T) {
	r, err := newRunner("auto", isobox.Spec{Args: []string{"echo"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]isobox.Backend{
		"darwin":  isobox.BackendSeatbelt,
		"linux":   isobox.BackendGvisor,
		"windows": isobox.BackendAppContainer,
	}[runtime.GOOS]
	if want != "" && r.Backend() != want {
		t.Fatalf("auto backend=%s, want %s", r.Backend(), want)
	}
}
