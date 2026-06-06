//go:build darwin

package isobox

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// workspaceRoot returns the canonical workspace root used by filesystem
// virtualization. Spec.Dir takes precedence; empty Dir inherits the caller's
// current working directory.
func workspaceRoot(s Spec) (string, error) {
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

func prepareMacOSAPFSWorkspaceClone(fs *fsVirtualizationPlan, plan *Plan, s Spec) (*fsVirtualizationRuntime, error) {
	root := fs.WorkspaceRoot
	if root == "" {
		resolved, err := workspaceRoot(s)
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
		return nil, fmt.Errorf("isobox: macOS ephemeral workspace root %q is not a directory", root)
	}

	tmp, err := os.MkdirTemp("", "isobox-ephemeral-")
	if err != nil {
		return nil, fmt.Errorf("isobox: create ephemeral workspace temp dir: %w", err)
	}
	cloneRoot := filepath.Join(tmp, "workspace")
	if err := cloneWorkspaceTree(root, cloneRoot); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	cloneRoot = canonPath(cloneRoot)

	if plan != nil {
		replacePlanPlaceholder(plan, isoboxEphemeralRootPlaceholder, cloneRoot)
	}

	return &fsVirtualizationRuntime{
		Dir:     cloneRoot,
		Cleanup: func() error { return os.RemoveAll(tmp) },
	}, nil
}

func cloneWorkspaceTree(src, dst string) error {
	if err := cloneEntry(src, dst); err != nil {
		return fmt.Errorf("isobox: clone ephemeral workspace %q to %q: %w", src, dst, err)
	}
	return nil
}

func cloneEntry(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}

	switch {
	case info.Mode().IsRegular():
		return cloneRegularFile(src, dst, info)
	case info.IsDir():
		return cloneDirectory(src, dst, info)
	case info.Mode()&os.ModeSymlink != 0:
		return cloneSymlink(src, dst, info)
	default:
		return fmt.Errorf("unsupported workspace entry type %s at %q", info.Mode().Type(), src)
	}
}

func cloneDirectory(src, dst string, info os.FileInfo) error {
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if err := cloneEntry(filepath.Join(src, name), filepath.Join(dst, name)); err != nil {
			return err
		}
	}
	preserveBestEffort(dst, info, false)
	return nil
}

func cloneRegularFile(src, dst string, info os.FileInfo) error {
	if err := unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW); err == nil {
		preserveBestEffort(dst, info, false)
		return nil
	}
	if err := copyRegularFile(src, dst, info); err != nil {
		return err
	}
	preserveBestEffort(dst, info, false)
	return nil
}

func copyRegularFile(src, dst string, info os.FileInfo) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func cloneSymlink(src, dst string, info os.FileInfo) error {
	target, err := os.Readlink(src)
	if err != nil {
		return err
	}
	if err := os.Symlink(target, dst); err != nil {
		return err
	}
	preserveBestEffort(dst, info, true)
	return nil
}

func preserveBestEffort(path string, info os.FileInfo, noFollow bool) {
	if !noFollow {
		_ = os.Chmod(path, info.Mode().Perm())
	}
	if st, ok := info.Sys().(*unix.Stat_t); ok {
		_ = unix.Lchown(path, int(st.Uid), int(st.Gid))
		atimeSpec := st.Atim
		mtimeSpec := st.Mtim
		atime := timevalFromTimespec(atimeSpec)
		mtime := timevalFromTimespec(mtimeSpec)
		if noFollow {
			_ = unix.Lutimes(path, []unix.Timeval{atime, mtime})
		} else {
			_ = os.Chtimes(path, timeFromTimespec(atimeSpec), timeFromTimespec(mtimeSpec))
		}
	}
}

func timeFromTimespec(ts unix.Timespec) time.Time {
	return time.Unix(ts.Sec, ts.Nsec)
}

func timevalFromTimespec(ts unix.Timespec) unix.Timeval {
	return unix.NsecToTimeval(ts.Sec*1_000_000_000 + ts.Nsec)
}
