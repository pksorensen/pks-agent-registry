package dockercfg

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// InstallResult describes what Install did, so the caller can tell the user
// something true rather than a generic success line.
type InstallResult struct {
	// Path the helper was installed at.
	Path string
	// Existed is true when a correct helper was already in place.
	Existed bool
	// OnPath is false when docker will not find the helper because its
	// directory is not on PATH.
	OnPath bool
}

// Install puts a `docker-credential-agentics` next to the running binary that
// re-executes it in credential-helper mode.
//
// On Unix that is a symlink, and the binary recognises the name it was invoked
// under. On Windows, where symlinks need a privilege an ordinary user does not
// have, it is a one-line .cmd shim instead — docker's PATH lookup honours
// PATHEXT, so a .cmd is found the same way an .exe would be.
func Install(dir string) (*InstallResult, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return nil, err
	}
	if dir == "" {
		dir = filepath.Dir(exe)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	name := BinaryName
	if runtime.GOOS == "windows" {
		name += ".cmd"
	}
	target := filepath.Join(dir, name)

	res := &InstallResult{Path: target}
	if current, err := currentTarget(target); err == nil && current == exe {
		res.Existed = true
	} else {
		if err := write(target, exe); err != nil {
			return nil, err
		}
	}

	if found, err := exec.LookPath(BinaryName); err == nil {
		// A *different* helper of the same name earlier on PATH would silently
		// win every lookup, so the check is on the resolved path, not on
		// whether the name resolves at all.
		if resolved, err := filepath.EvalSymlinks(found); err == nil {
			if installed, err := filepath.EvalSymlinks(target); err == nil {
				res.OnPath = resolved == installed
			}
		}
		if !res.OnPath && found == target {
			res.OnPath = true
		}
	}
	return res, nil
}

func currentTarget(path string) (string, error) {
	if runtime.GOOS == "windows" {
		return "", os.ErrNotExist
	}
	return os.Readlink(path)
}

func write(target, exe string) error {
	if runtime.GOOS == "windows" {
		shim := fmt.Sprintf("@echo off\r\n\"%s\" docker-credential %%*\r\n", exe)
		return os.WriteFile(target, []byte(shim), 0o755)
	}
	// Replace rather than fail: a symlink left over from an older install
	// location is exactly the case where re-running install should fix things.
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(exe, target)
}

// Uninstall removes the helper binary. Reports whether anything was removed.
func Uninstall(dir string) (string, bool, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", false, err
	}
	if dir == "" {
		dir = filepath.Dir(exe)
	}
	name := BinaryName
	if runtime.GOOS == "windows" {
		name += ".cmd"
	}
	target := filepath.Join(dir, name)
	if err := os.Remove(target); err != nil {
		if os.IsNotExist(err) {
			return target, false, nil
		}
		return target, false, err
	}
	return target, true, nil
}
