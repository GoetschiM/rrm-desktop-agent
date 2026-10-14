//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func protectRoot(root, config string) error {
	if err := command("icacls", root, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"); err != nil {
		return err
	}
	return command("icacls", filepath.Join(root, "*"), "/reset", "/T")
}
func windowsArgs(args ...string) string {
	quoted := []string{}
	for _, a := range args {
		quoted = append(quoted, syscall.EscapeArg(a))
	}
	return strings.Join(quoted, " ")
}
func activate(c Config, binary string) error {
	m, err := mgr.Connect()
	if err != nil {
		return errors.New("administrator service access required")
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		s, err = m.CreateService(serviceName, binary, mgr.Config{StartType: mgr.StartAutomatic, DisplayName: "RRM Desktop Agent"}, "--service", "--config", c.path)
	} else {
		if err = stopWindowsService(s); err != nil {
			s.Close()
			return err
		}
		cfg, e := s.Config()
		if e != nil {
			s.Close()
			return e
		}
		cfg.BinaryPathName = windowsArgs(binary, "--service", "--config", c.path)
		cfg.StartType = mgr.StartAutomatic
		err = s.UpdateConfig(cfg)
	}
	if err != nil {
		return errors.New("service configuration failed")
	}
	defer s.Close()
	if err = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}, {Type: mgr.ServiceRestart, Delay: 30 * time.Second}, {Type: mgr.ServiceRestart, Delay: 60 * time.Second}}, 86400); err != nil {
		return err
	}
	return s.Start()
}
func stopWindowsService(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if status.State != svc.StopPending {
		if _, err = s.Control(svc.Stop); err != nil {
			return err
		}
	}
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		status, err = s.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
	}
	return errors.New("service stop timeout")
}
func installOS(c Config, binary, updater string) error {
	task := windowsArgs(updater, "--update", "--config", c.path)
	if err := command("schtasks.exe", "/Create", "/TN", "RRM Agent Update", "/SC", "MINUTE", "/MO", "15", "/RU", "SYSTEM", "/TR", task, "/F"); err != nil {
		return err
	}
	ignoreCommand("netsh", "advfirewall", "firewall", "delete", "rule", "name=RRM Agent")
	if err := command("netsh", "advfirewall", "firewall", "add", "rule", "name=RRM Agent", "dir=in", "action=allow", "protocol=TCP", fmt.Sprintf("localport=%d", c.Port), "remoteip="+strings.Join(c.AllowedIPs, ",")); err != nil {
		return err
	}
	return activate(c, binary)
}
func uninstallOS(c Config) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		defer s.Close()
		if err := stopWindowsService(s); err != nil {
			return err
		}
		if err := s.Delete(); err != nil {
			return err
		}
	}
	ignoreCommand("schtasks.exe", "/Delete", "/TN", "RRM Agent Update", "/F")
	ignoreCommand("netsh", "advfirewall", "firewall", "delete", "rule", "name=RRM Agent")
	return nil
}

type windowsService struct{ c Config }

func (w windowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, w.c) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				return false, 1
			}
			return false, 0
		case req := <-requests:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			case svc.Interrogate:
				changes <- req.CurrentStatus
			}
		}
	}
}
func serviceRun(c Config) error { return svc.Run(serviceName, windowsService{c}) }
func launchDetached(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS, HideWindow: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
