package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func productionHandler(c Config) http.Handler {
	allowed := map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true, netip.MustParseAddr("::1"): true}
	for _, ip := range c.AllowedIPs {
		a, _ := netip.ParseAddr(ip)
		allowed[a.Unmap()] = true
	}
	var actions sync.Mutex
	var lastAction time.Time
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		addr, e := netip.ParseAddr(host)
		if err != nil || e != nil || !allowed[addr.Unmap()] {
			http.Error(w, "forbidden", 403)
			return
		}
		path := strings.TrimRight(r.URL.Path, "/")
		if path != "/health" || r.Method != "GET" {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+c.Token)) != 1 {
				http.Error(w, "unauthorized", 401)
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		var data any
		if r.Method == "GET" {
			switch path {
			case "/health", "/version":
				name, _ := os.Hostname()
				data = map[string]any{"ok": true, "version": version, "hostname": name, "port": c.Port}
			case "":
				data = metrics(ctx, c)
			case "/procs":
				rows, err := processRows(ctx)
				if err != nil {
					http.Error(w, "process collection failed", 503)
					return
				}
				data = map[string]any{"procs": rows}
			case "/ports":
				ports, err := listeningPorts(ctx)
				if err != nil {
					http.Error(w, "port collection failed", 503)
					return
				}
				data = map[string]any{"listening_ports": ports}
			case "/update/status":
				data = readUpdateState(c.path)
			case "/docker":
				data = map[string]any{"containers": []any{}, "supported": false}
			case "/docker/policies":
				data = map[string]any{"policies": []any{}, "supported": false}
			case "/logs":
				data = map[string]any{"lines": tailLog(filepath.Join(filepath.Dir(c.path), "agent.log"))}
			default:
				http.NotFound(w, r)
				return
			}
		} else if r.Method == "POST" && (path == "/update" || path == "/restart" || path == "/uninstall") {
			var body struct {
				Confirm bool `json:"confirm"`
			}
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
			if err != nil {
				http.Error(w, "body too large", 400)
				return
			}
			if len(raw) > 0 && json.Unmarshal(raw, &body) != nil {
				http.Error(w, "invalid JSON", 400)
				return
			}
			if path == "/uninstall" && !body.Confirm {
				http.Error(w, "confirmation required", 400)
				return
			}
			updater := filepath.Join(filepath.Dir(c.path), binaryName("rrm-updater"))
			if info, err := os.Stat(updater); err != nil || !info.Mode().IsRegular() {
				http.Error(w, "installed updater required", 409)
				return
			}
			actions.Lock()
			if time.Since(lastAction) < 30*time.Second {
				actions.Unlock()
				http.Error(w, "action rate limited", 429)
				return
			}
			lastAction = time.Now()
			actions.Unlock()
			time.AfterFunc(2*time.Second, func() {
				if err := launchDetached(exec.Command(updater, "--"+path[1:], "--config", c.path)); err != nil {
					log.Print("agent action could not start")
				}
			})
			w.WriteHeader(http.StatusAccepted)
			data = map[string]any{"ok": true, "msg": "Agent-Auftrag gestartet; Status folgt beim nächsten Abruf"}
		} else {
			http.Error(w, "method not allowed", 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	})
}
func tailLog(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return []string{}
	}
	if info.Size() > 65536 {
		f.Seek(-65536, io.SeekEnd)
	}
	raw, _ := io.ReadAll(io.LimitReader(f, 65536))
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) > 100 {
		lines = lines[len(lines)-100:]
	}
	return lines
}
func runAgent(ctx context.Context, c Config) error {
	server := &http.Server{Addr: net.JoinHostPort(c.BindIP, fmt.Sprint(c.Port)), Handler: productionHandler(c), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	go func() {
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(stop)
	}()
	go heartbeatLoop(ctx, c)
	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func heartbeatLoop(ctx context.Context, c Config) {
	client := &http.Client{Timeout: 10 * time.Second}
	security := newSecurityCollector(c.SecurityFiles)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		sample, cancel := context.WithTimeout(ctx, 10*time.Second)
		security.scan(true)
		payload := metrics(sample, c)
		if len(security.paths) > 0 || c.SecurityAuth {
			status := security.snapshot()
			if c.SecurityAuth {
				sources := status["sources"].([]string)
				sources = append(sources, "windows_eventlog")
				status["sources"] = sources
				authEvents, err := collectWindowsAuth(sample)
				if err != nil {
					status["errors"] = append(status["errors"].([]string), err.Error())
				} else {
					events := append(status["events"].([]securityEvent), authEvents...)
					if len(events) > 48 {
						events = events[:48]
					}
					status["events"] = events
				}
			}
			payload["security"] = status
		}
		raw, _ := json.Marshal(payload)
		cancel()
		req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(c.HubURL, "/")+"/api/agent/register", bytes.NewReader(raw))
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+c.Token)
			req.Header.Set("Content-Type", "application/json")
			res, e := client.Do(req)
			if e == nil {
				io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
				res.Body.Close()
				if res.StatusCode != 200 {
					log.Print("heartbeat rejected")
				} else {
					security.commit()
				}
			} else {
				log.Print("heartbeat unavailable")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
