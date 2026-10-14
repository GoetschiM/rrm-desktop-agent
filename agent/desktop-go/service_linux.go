//go:build !windows && !darwin

package main

import "errors"

func protectRoot(root, config string) error {
	return errors.New("desktop installation supports Windows and macOS only")
}
func activate(c Config, binary string) error {
	return errors.New("desktop services unsupported on this OS")
}
func installOS(c Config, binary, updater string) error {
	return errors.New("desktop services unsupported on this OS")
}
func uninstallOS(c Config) error { return errors.New("desktop services unsupported on this OS") }
func serviceRun(c Config) error  { return errors.New("Windows service mode unsupported") }
