//go:build windows

package isobox

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppContainerEnforcement(t *testing.T) {
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

	run := func(spec Spec) int {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		code, err := runner.Run(ctx, spec, Stdio{Out: io.Discard, Err: io.Discard})
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		return code
	}

	work := t.TempDir()
	okFile := filepath.Join(work, "ok.txt")
	deniedFile := filepath.Join(work, "denied.txt")

	if code := run(Spec{
		Args:     []string{cmd, "/C", "echo hi>" + cmdQuote(okFile)},
		Net:      NetEnable,
		Write:    WriteScope,
		Writable: []string{work},
	}); code != 0 {
		t.Fatalf("scoped write exit=%d, want 0", code)
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
	if code := run(Spec{
		Args: []string{cmd, "/C",
			"echo changed>" + cmdQuote(overwriteFile) +
				" && del " + cmdQuote(deleteFile) +
				" && ren " + cmdQuote(renameFile) + " renamed.txt"},
		Net:      NetEnable,
		Write:    WriteScope,
		Writable: []string{work},
	}); code != 0 {
		t.Fatalf("scoped descendant mutation exit=%d, want 0", code)
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

	if code := run(Spec{Args: []string{cmd, "/C", "echo hi>" + cmdQuote(deniedFile)}, Net: NetEnable}); code == 0 {
		t.Fatal("out-of-scope write unexpectedly succeeded")
	}
	if _, err := os.Stat(deniedFile); !os.IsNotExist(err) {
		t.Fatalf("denied file should not exist, stat err=%v", err)
	}

	if code := run(Spec{Args: []string{cmd, "/C", "exit /B 0"}}); code != 0 {
		t.Fatalf("no-net command exit=%d, want 0", code)
	}

	if code := run(Spec{Args: []string{cmd, "/C", cmdQuote(cmd) + " /C exit /B 0"}, Net: NetEnable, NoExec: true}); code == 0 {
		t.Fatal("NoExec did not block child process creation")
	}
}

func cmdQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
