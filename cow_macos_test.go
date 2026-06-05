//go:build darwin

package isobox

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestMacOSCloneWorkspaceTreePreservesEntries(t *testing.T) {
	src := t.TempDir()
	if err := os.Mkdir(filepath.Join(src, "dir"), 0o750); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(src, "dir", "regular.txt")
	if err := os.WriteFile(regular, []byte("lower"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(regular, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dir/regular.txt", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "clone")
	if err := cloneWorkspaceTree(src, dst); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dst, "dir", "regular.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("lower")) {
		t.Fatalf("cloned data=%q, want lower", data)
	}
	if info, err := os.Lstat(filepath.Join(dst, "dir", "regular.txt")); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("regular mode=%#o, want %#o", got, os.FileMode(0o640))
	}
	if info, err := os.Lstat(filepath.Join(dst, "dir")); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("dir mode=%#o, want %#o", got, os.FileMode(0o750))
	}
	link := filepath.Join(dst, "link")
	if info, err := os.Lstat(link); err != nil {
		t.Fatal(err)
	} else if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link mode=%s, want symlink", info.Mode())
	}
	if target, err := os.Readlink(link); err != nil {
		t.Fatal(err)
	} else if target != "dir/regular.txt" {
		t.Fatalf("symlink target=%q, want dir/regular.txt", target)
	}
}

func TestSeatbeltEphemeralRelativeWriteDoesNotMutateLower(t *testing.T) {
	runner, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if runner.Backend() != BackendSeatbelt {
		t.Fatalf("expected seatbelt backend, got %s", runner.Backend())
	}

	work := t.TempDir()
	lowerFile := filepath.Join(work, "file.txt")
	if err := os.WriteFile(lowerFile, []byte("lower\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, err := runner.Run(context.Background(), Spec{
		Args:  []string{"/bin/sh", "-c", "printf 'clone\\n' > file.txt && test \"$(cat file.txt)\" = clone && exit 7 || exit 3"},
		Dir:   work,
		Write: WriteEphemeral,
	}, Stdio{Out: io.Discard, Err: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Fatalf("exit=%d, want 7", code)
	}
	data, err := os.ReadFile(lowerFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("lower\n")) {
		t.Fatalf("lower mutated: %q", data)
	}
}

func TestSeatbeltEphemeralDeniesAbsoluteWriteOutsideClone(t *testing.T) {
	runner, err := New()
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")

	code, err := runner.Run(context.Background(), Spec{
		Args:  []string{"/bin/sh", "-c", "echo nope > \"$1\"", "_", outside},
		Dir:   work,
		Write: WriteEphemeral,
	}, Stdio{Out: io.Discard, Err: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if code == 0 {
		t.Fatal("absolute write outside clone unexpectedly succeeded")
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("outside file should not exist, stat err=%v", err)
	}
}
