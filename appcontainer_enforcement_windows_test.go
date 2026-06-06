//go:build windows

package isobox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppContainerEnforcement(t *testing.T) {

	// AppContainer runtime enforcement is environment-sensitive and needs a real
	// Windows host explicitly prepared for E2E validation. The regular CI matrix
	// keeps AppContainer covered by compiler/unit tests; opt into this load-bearing
	// runtime probe on a dedicated Windows machine.
	if os.Getenv("ISOBOX_WINDOWS_E2E") != "1" {
		t.Skip("set ISOBOX_WINDOWS_E2E=1 to run AppContainer runtime enforcement")
	}

	runner, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if runner.Backend() != BackendAppContainer {
		t.Fatalf("expected appcontainer backend, got %s", runner.Backend())
	}

	cmd := os.Getenv("ComSpec")
	if cmd == "" {
		cmd = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	}
	if _, err := os.Stat(cmd); err != nil {
		t.Fatalf("cmd.exe not found at %q: %v", cmd, err)
	}

	run := func(spec Spec) (int, string, *Plan) {
		t.Helper()
		plan, err := runner.Compile(spec)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		var out bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		code, err := runner.Run(ctx, spec, Stdio{Out: &out, Err: &out})
		if err != nil {
			t.Fatalf("run: %v\nplan:\n%s\noutput:\n%s", err, plan.Profile, out.String())
		}
		return code, out.String(), plan
	}

	work := t.TempDir()
	okFile := filepath.Join(work, "ok.txt")
	deniedFile := filepath.Join(work, "denied.txt")

	spec := Spec{
		Args:     []string{cmd, "/C", "echo hi>" + cmdQuote(okFile)},
		Net:      NetEnable,
		Write:    WriteScope,
		Writable: []string{work},
	}
	if code, out, plan := run(spec); code != 0 {
		t.Fatalf("scoped write exit=%d, want 0\noutput:\n%s\nplan:\n%s", code, out, plan.Profile)
	}
	if b, err := os.ReadFile(okFile); err != nil || !strings.Contains(string(b), "hi") {
		t.Fatalf("scoped write did not persist: data=%q err=%v", b, err)
	}

	nested := filepath.Join(work, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	overwriteFile := filepath.Join(nested, "overwrite.txt")
	deleteFile := filepath.Join(nested, "delete.txt")
	renameFile := filepath.Join(nested, "rename.txt")
	renamedFile := filepath.Join(nested, "renamed.txt")
	for _, path := range []string{overwriteFile, deleteFile, renameFile} {
		if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if code, out, plan := run(Spec{
		Args: []string{cmd, "/C",
			"echo changed>" + cmdQuote(overwriteFile) +
				" && del " + cmdQuote(deleteFile) +
				" && ren " + cmdQuote(renameFile) + " renamed.txt"},
		Net:      NetEnable,
		Write:    WriteScope,
		Writable: []string{work},
	}); code != 0 {
		t.Fatalf("scoped descendant mutation exit=%d, want 0\noutput:\n%s\nplan:\n%s", code, out, plan.Profile)
	}
	if b, err := os.ReadFile(overwriteFile); err != nil || !strings.Contains(string(b), "changed") {
		t.Fatalf("scoped overwrite failed: data=%q err=%v", b, err)
	}
	if _, err := os.Stat(deleteFile); !os.IsNotExist(err) {
		t.Fatalf("scoped delete failed, stat err=%v", err)
	}
	if _, err := os.Stat(renamedFile); err != nil {
		t.Fatalf("scoped rename failed: %v", err)
	}

	if code, out, plan := run(Spec{Args: []string{cmd, "/C", "echo hi>" + cmdQuote(deniedFile)}, Net: NetEnable}); code == 0 {
		t.Fatalf("out-of-scope write unexpectedly succeeded\noutput:\n%s\nplan:\n%s", out, plan.Profile)
	}
	if _, err := os.Stat(deniedFile); !os.IsNotExist(err) {
		t.Fatalf("denied file should not exist, stat err=%v", err)
	}

	writeNoneTemp := filepath.Join(t.TempDir(), "write-none-temp.txt")
	if code, out, plan := run(Spec{Args: []string{cmd, "/C", "echo no>" + cmdQuote(writeNoneTemp)}, Net: NetEnable, Write: WriteNone}); code == 0 {
		t.Fatalf("WriteNone temp write unexpectedly succeeded\noutput:\n%s\nplan:\n%s", out, plan.Profile)
	}
	if _, err := os.Stat(writeNoneTemp); !os.IsNotExist(err) {
		t.Fatalf("WriteNone temp file should not exist, stat err=%v", err)
	}

	ephemeralWork := t.TempDir()
	ephemeralExisting := filepath.Join(ephemeralWork, "existing.txt")
	ephemeralNew := filepath.Join(ephemeralWork, "new.txt")
	if err := os.WriteFile(ephemeralExisting, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, plan := run(Spec{
		Args:  []string{cmd, "/C", "echo changed>existing.txt && echo clone>new.txt"},
		Net:   NetEnable,
		Dir:   ephemeralWork,
		Write: WriteEphemeral,
	}); code != 0 {
		t.Fatalf("WriteEphemeral workspace command exit=%d, want 0\noutput:\n%s\nplan:\n%s", code, out, plan.Profile)
	}
	if b, err := os.ReadFile(ephemeralExisting); err != nil || string(b) != "original" {
		t.Fatalf("WriteEphemeral changed host existing file: data=%q err=%v", b, err)
	}
	if _, err := os.Stat(ephemeralNew); !os.IsNotExist(err) {
		t.Fatalf("WriteEphemeral new file leaked to host, stat err=%v", err)
	}

	if code, out, plan := run(Spec{Args: []string{cmd, "/C", "exit /B 0"}}); code != 0 {
		t.Fatalf("no-net command exit=%d, want 0\noutput:\n%s\nplan:\n%s", code, out, plan.Profile)
	}

	if code, out, plan := run(Spec{Args: []string{cmd, "/C", cmdQuote(cmd) + " /C exit /B 0"}, Net: NetEnable, NoExec: true}); code == 0 {
		t.Fatalf("NoExec did not block child process creation\noutput:\n%s\nplan:\n%s", out, plan.Profile)
	}
}

func cmdQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
