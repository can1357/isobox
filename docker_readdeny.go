package isobox

import (
	"fmt"
	"os"
	"path/filepath"
)

func materializeDockerReadDenyMasks(argv []string, readDeny []string) ([]string, func() error, error) {
	if len(readDeny) == 0 {
		return argv, nil, nil
	}
	imageIndex, ok := dockerRunImageIndex(argv)
	if !ok {
		return argv, nil, nil
	}

	tmp, err := os.MkdirTemp("", "isobox-docker-read-deny-")
	if err != nil {
		return nil, nil, fmt.Errorf("isobox: creating docker read-deny masks: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(tmp) }

	mounts := make([]string, 0, len(readDeny)*2)
	for i, denied := range readDeny {
		info, err := os.Lstat(denied)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			_ = cleanup()
			return nil, nil, fmt.Errorf("isobox: checking docker read-deny path %q: %w", denied, err)
		}
		mask := filepath.Join(tmp, fmt.Sprintf("mask-%d", i))
		if info.IsDir() {
			if err := os.Mkdir(mask, 0o555); err != nil {
				_ = cleanup()
				return nil, nil, fmt.Errorf("isobox: creating docker read-deny directory mask: %w", err)
			}
		} else {
			file, err := os.OpenFile(mask, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
			if err != nil {
				_ = cleanup()
				return nil, nil, fmt.Errorf("isobox: creating docker read-deny file mask: %w", err)
			}
			if err := file.Close(); err != nil {
				_ = cleanup()
				return nil, nil, fmt.Errorf("isobox: closing docker read-deny file mask: %w", err)
			}
		}
		mount, err := dockerBindMountSpecPaths(mask, denied, true)
		if err != nil {
			_ = cleanup()
			return nil, nil, err
		}
		mounts = append(mounts, "--mount", mount)
	}
	if len(mounts) == 0 {
		_ = cleanup()
		return argv, nil, nil
	}

	rewritten := make([]string, 0, len(argv)+len(mounts))
	rewritten = append(rewritten, argv[:imageIndex]...)
	rewritten = append(rewritten, mounts...)
	rewritten = append(rewritten, argv[imageIndex:]...)
	return rewritten, cleanup, nil
}
