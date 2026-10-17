// Desktop agent configuration and optional restricted preview endpoints.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var version = "development"

type Config struct {
	Token         string   `json:"token"`
	SecurityFiles []string `json:"security_files,omitempty"`
	SecurityAuth  bool     `json:"security_auth,omitempty"`
	HubURL        string   `json:"hub_url"`
	AllowedIPs    []string `json:"allowed_ips"`
	BindIP        string   `json:"bind_ip"`
	Port          int      `json:"port"`
	Target        string   `json:"target"`
	IP            string   `json:"ip,omitempty"`
	Version       string   `json:"version"`
	ActiveBinary  string   `json:"active_binary,omitempty"`
	AutoUpdate    *bool    `json:"auto_update,omitempty"`
	path          string
}

func loadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, errors.New("cannot read configuration")
	}
	if len(data) > 65536 {
		return c, errors.New("configuration too large")
	}
	data = []byte(strings.TrimPrefix(string(data), "\ufeff")) // PowerShell UTF-8 BOM
	if json.Unmarshal(data, &c) != nil {
		return c, errors.New("invalid configuration JSON")
	}
	u, err := url.Parse(c.HubURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return c, errors.New("invalid hub URL")
	}
	if len(c.Token) < 20 || len(c.Token) > 200 || len(c.AllowedIPs) == 0 {
		return c, errors.New("token and allowed hub IPs required")
	}
	for _, ip := range c.AllowedIPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			return c, errors.New("invalid allowed IP")
		}
	}
	if c.Port == 0 {
		c.Port = 9998
	}
	if c.Port < 1 || c.Port > 65535 {
		return c, errors.New("invalid port")
	}
	if c.BindIP == "" {
		c.BindIP = "127.0.0.1"
	} // Prototype is loopback-only by default.
	if _, err := netip.ParseAddr(c.BindIP); err != nil {
		return c, errors.New("invalid bind IP")
	}
	c.path, err = filepath.Abs(path)
	return c, err
}

func handler(c Config) http.Handler {
	allowed := map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true, netip.MustParseAddr("::1"): true}
	for _, ip := range c.AllowedIPs {
		a, _ := netip.ParseAddr(ip)
		allowed[a.Unmap()] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		addr, addrErr := netip.ParseAddr(host)
		if err != nil || addrErr != nil || !allowed[addr.Unmap()] {
			http.Error(w, "forbidden", 403)
			return
		}
		path := strings.TrimRight(r.URL.Path, "/")
		if path != "/health" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+c.Token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "migration actions not implemented", 405)
			return
		}
		if path == "/health" || path == "/version" {
			hostname, _ := os.Hostname()
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": version, "hostname": hostname, "port": c.Port, "migration_preview": true})
			return
		}
		// Never fabricate zero metrics or advertise unfinished updater/service support.
		http.Error(w, "migration preview: monitoring and service lifecycle not implemented", http.StatusNotImplemented)
	})
}
