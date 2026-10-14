//go:build darwin

package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func xmlText(v string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(v))
	return b.String()
}
func plist(label string, args []string, root string, interval int) []byte {
	text := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>` + xmlText(label) + `</string><key>ProgramArguments</key><array>`
	for _, a := range args {
		text += `<string>` + xmlText(a) + `</string>`
	}
	text += `</array>`
	if interval > 0 {
		text += fmt.Sprintf(`<key>StartInterval</key><integer>%d</integer>`, interval)
	} else {
		text += `<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>`
	}
	text += `<key>StandardErrorPath</key><string>` + xmlText(filepath.Join(root, "agent.log")) + `</string><key>StandardOutPath</key><string>` + xmlText(filepath.Join(root, "agent.log")) + `</string></dict></plist>`
	return []byte(text)
}
func protectRoot(root, config string) error {
	if os.Geteuid() != 0 {
		return errors.New("sudo required")
	}
	if err := os.Chmod(root, 0700); err != nil {
		return err
	}
	return os.Chmod(config, 0600)
}
func installPlist(label string, args []string, root string, interval int) error {
	path := filepath.Join("/Library/LaunchDaemons", label+".plist")
	ignoreCommand("launchctl", "bootout", "system", path)
	if err := atomicWrite(path, plist(label, args, root, interval), 0644); err != nil {
		return err
	}
	return command("launchctl", "bootstrap", "system", path)
}
func activate(c Config, binary string) error {
	return installPlist(macLabel, []string{binary, "--run", "--config", c.path}, filepath.Dir(c.path), 0)
}
func installOS(c Config, binary, updater string) error {
	if err := installPlist(macLabel+"-update", []string{updater, "--update", "--config", c.path}, filepath.Dir(c.path), 900); err != nil {
		return err
	}
	return activate(c, binary)
}
func uninstallOS(c Config) error {
	if os.Geteuid() != 0 {
		return errors.New("sudo required")
	}
	for _, label := range []string{macLabel, macLabel + "-update"} {
		path := filepath.Join("/Library/LaunchDaemons", label+".plist")
		ignoreCommand("launchctl", "bootout", "system", path)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
func serviceRun(c Config) error {
	return errors.New("--service is Windows-only; use --run under launchd")
}
