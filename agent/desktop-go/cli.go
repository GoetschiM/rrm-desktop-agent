package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"
)

func nativeTarget() (string, error) {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "windows/amd64":
		return "windows-x64", nil
	case "darwin/amd64":
		return "macos-x64", nil
	case "darwin/arm64":
		return "macos-arm64", nil
	}
	return "", errors.New("unsupported desktop target")
}
func main() {
	config := flag.String("config", "", "existing agent configuration")
	selfTest := flag.Bool("self-test", false, "validate executable and report version")
	preview := flag.Bool("preview", false, "run health preview only")
	run := flag.Bool("run", false, "run agent")
	service := flag.Bool("service", false, "Windows SCM service")
	install := flag.Bool("install", false, "install service and updater")
	uninstall := flag.Bool("uninstall", false, "remove service, retain recovery files")
	update := flag.Bool("update", false, "verify and apply signed update")
	restart := flag.Bool("restart", false, "restart installed service")
	flag.Parse()
	if *selfTest {
		if !releaseVersion.MatchString(version) {
			fail(errors.New("release version not set"))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		rows, err := processRows(ctx)
		if err != nil || len(rows) == 0 {
			fail(errors.New("native process self-test failed"))
		}
		data := metrics(ctx, Config{IP: "127.0.0.1", HubURL: "http://127.0.0.1", path: filepath.Join(os.TempDir(), "rrm-self-test", "config.json")})
		memory, ok := data["mem_total_gb"].(float64)
		if !ok || memory <= 0 {
			fail(errors.New("native memory self-test failed"))
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"version": version, "platform": runtime.GOOS, "architecture": runtime.GOARCH, "processes": len(rows)})
		return
	}
	selected := 0
	for _, v := range []bool{*run, *service, *install, *uninstall, *update, *restart, *preview} {
		if v {
			selected++
		}
	}
	if selected > 1 {
		fail(errors.New("select one action"))
	}
	if *config == "" {
		fail(errors.New("--config required"))
	}
	c, err := loadConfig(*config)
	if err != nil {
		fail(err)
	}
	if !*preview {
		var values map[string]any
		raw, _ := os.ReadFile(c.path)
		json.Unmarshal(trimBOM(raw), &values)
		if _, ok := values["bind_ip"]; !ok {
			c.BindIP = "0.0.0.0"
		}
	}
	root := filepath.Dir(c.path)
	logPath := filepath.Join(root, "agent.log")
	if info, e := os.Stat(logPath); e == nil && info.Size() > 1024*1024 {
		_ = os.Rename(logPath, logPath+".1")
	}
	file, e := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		fail(errors.New("cannot open protected log"))
	}
	defer file.Close()
	log.SetOutput(file)
	switch {
	case *install:
		target, e := nativeTarget()
		if e != nil || target != c.Target {
			fail(errors.New("installer target mismatches OS"))
		}
		err = installAgent(c)
	case *uninstall:
		err = uninstallOS(c)
	case *update:
		err = updateAgent(c)
	case *restart:
		if !filepath.IsAbs(c.ActiveBinary) {
			err = errors.New("installed active binary required")
		} else {
			err = activate(c, c.ActiveBinary)
			if err == nil {
				err = healthVersion(c, c.Version)
			}
		}
	case *service:
		err = serviceRun(c)
	default:
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		if *preview {
			err = runPreview(ctx, c)
		} else {
			err = runAgent(ctx, c)
		}
	}
	if err != nil {
		fail(err)
	}
}
func fail(err error) { fmt.Fprintln(os.Stderr, err.Error()); os.Exit(1) }
