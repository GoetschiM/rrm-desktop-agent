package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const serviceName = "RRMDesktopAgent"
const macLabel = "ch.goetschi.rrm-agent"

func binaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
func (c Config) autoUpdates() bool { return c.AutoUpdate == nil || *c.AutoUpdate }
func command(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if exec.CommandContext(ctx, name, args...).Run() != nil {
		return errors.New("service command failed: " + name)
	}
	return nil
}
func ignoreCommand(name string, args ...string) { _ = command(name, args...) }
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".rrm-new-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func copyBinary(from, to string) error {
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return atomicWrite(to, data, 0755)
}

// Preserve unknown configuration keys used by existing Python installers/updaters.
func saveActive(c Config, binary, newVersion string) error {
	raw, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	var values map[string]any
	if json.Unmarshal(trimBOM(raw), &values) != nil {
		return errors.New("invalid configuration")
	}
	values["active_binary"] = binary
	values["version"] = newVersion
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}
	return atomicWrite(c.path, data, 0600)
}
func installAgent(c Config) error {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		return errors.New("installation supports Windows and macOS only")
	}
	if !releaseVersion.MatchString(version) {
		return errors.New("release version required")
	}
	root := filepath.Dir(c.path)
	previous, err := os.ReadFile(c.path)
	if err != nil {
		return errors.New("cannot preserve previous configuration")
	}
	if err := protectRoot(root, c.path); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	updater := filepath.Join(root, binaryName("rrm-updater"))
	if _, err := os.Stat(updater); os.IsNotExist(err) {
		if err := copyBinary(exe, updater); err != nil {
			return err
		}
	}
	binary := filepath.Join(root, "versions", version, binaryName("rrm-agent"))
	if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		return err
	}
	if filepath.Clean(exe) != filepath.Clean(binary) {
		if err := copyBinary(exe, binary); err != nil {
			return err
		}
	}
	if err := saveActive(c, binary, version); err != nil {
		return err
	}
	err = installOS(c, binary, updater)
	if err == nil {
		err = healthVersion(c, version)
	}
	if err == nil {
		return nil
	}
	if restore := atomicWrite(c.path, previous, 0600); restore != nil {
		return errors.New("installation failed; configuration rollback failed")
	}
	if filepath.IsAbs(c.ActiveBinary) {
		if restore := activate(c, c.ActiveBinary); restore != nil {
			return errors.New("installation failed; previous service activation failed")
		}
		if restore := healthVersion(c, c.Version); restore != nil {
			return errors.New("installation failed; previous service health failed")
		}
	} else if restore := uninstallOS(c); restore != nil {
		return errors.New("installation failed; service cleanup failed")
	}
	return errors.New("installation failed; previous state restored")
}
func healthVersion(c Config, want string) error {
	client := httpClient(2 * time.Second)
	for i := 0; i < 30; i++ {
		if checkHealth(client, c, want) == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return errors.New("authenticated service health check failed")
}
