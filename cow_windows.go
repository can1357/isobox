//go:build windows

package isobox

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func prepareWindowsWorkspaceCopy(fs *fsVirtualizationPlan, plan *Plan, s Spec) (*fsVirtualizationRuntime, error) {
	if fs == nil {
		return nil, fmt.Errorf("isobox: missing Windows workspace-copy filesystem plan")
	}

	root := fs.WorkspaceRoot
	if root == "" {
		resolved, err := windowsWorkspaceRoot(s)
		if err != nil {
			return nil, err
		}
		root = resolved
	}

	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("isobox: stat workspace root %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("isobox: Windows ephemeral workspace root %q is not a directory", root)
	}

	tmp, err := os.MkdirTemp("", "isobox-windows-ephemeral-")
	if err != nil {
		return nil, fmt.Errorf("isobox: create ephemeral workspace temp dir: %w", err)
	}
	cloneRoot := filepath.Join(tmp, "workspace")
	if err := copyWindowsWorkspaceTree(root, cloneRoot); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	cloneRoot = canonPath(cloneRoot)

	replacePlanPlaceholder(plan, isoboxEphemeralRootPlaceholder, cloneRoot)
	return &fsVirtualizationRuntime{
		Dir:     cloneRoot,
		Cleanup: func() error { return os.RemoveAll(tmp) },
	}, nil
}

func windowsWorkspaceRoot(s Spec) (string, error) {
	root := s.Dir
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("isobox: resolving workspace root from cwd: %w", err)
		}
		root = wd
	}

	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("isobox: resolving workspace root %q: %w", root, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("isobox: resolving workspace root %q: %w", root, err)
	}
	return canonPath(resolved), nil
}

func copyWindowsWorkspaceTree(src, dst string) error {
	if err := copyWindowsEntry(src, dst); err != nil {
		return fmt.Errorf("isobox: copy ephemeral workspace %q to %q: %w", src, dst, err)
	}
	return nil
}

func copyWindowsEntry(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}

	switch {
	case info.Mode().IsRegular():
		return copyWindowsRegularFile(src, dst, info)
	case info.IsDir():
		return copyWindowsDirectory(src, dst, info)
	case info.Mode()&os.ModeSymlink != 0:
		return copyWindowsSymlink(src, dst)
	default:
		return fmt.Errorf("unsupported workspace entry type %s at %q", info.Mode().Type(), src)
	}
}

func copyWindowsDirectory(src, dst string, info os.FileInfo) error {
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if err := copyWindowsEntry(filepath.Join(src, name), filepath.Join(dst, name)); err != nil {
			return err
		}
	}
	preserveWindowsBestEffort(dst, info, false)
	return nil
}

func copyWindowsRegularFile(src, dst string, info os.FileInfo) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	perm := info.Mode().Perm()
	if perm == 0 {
		perm = 0o600
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	preserveWindowsBestEffort(dst, info, false)
	return nil
}

func copyWindowsSymlink(src, dst string) error {
	target, err := os.Readlink(src)
	if err != nil {
		return err
	}
	return os.Symlink(target, dst)
}

func preserveWindowsBestEffort(path string, info os.FileInfo, noFollow bool) {
	if noFollow {
		return
	}
	_ = os.Chmod(path, info.Mode().Perm())
	_ = os.Chtimes(path, info.ModTime(), info.ModTime())
}
