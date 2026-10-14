package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestProductionProtocolAndAccess(t *testing.T) {
	c := Config{Token: "12345678901234567890", AllowedIPs: []string{"10.0.60.181"}, Port: 9998, IP: "127.0.0.1", path: filepath.Join(t.TempDir(), "config.json")}
	h := productionHandler(c)
	for _, tc := range []struct {
		method, path, peer, auth string
		want                     int
	}{{"GET", "/health", "10.0.60.181", "", 200}, {"GET", "/version", "10.0.60.181", "", 401}, {"GET", "/version", "10.0.60.181", "Bearer " + c.Token, 200}, {"GET", "/version", "10.0.60.182", "Bearer " + c.Token, 403}, {"POST", "/uninstall", "127.0.0.1", "Bearer " + c.Token, 400}, {"POST", "/restart", "127.0.0.1", "Bearer " + c.Token, 409}, {"GET", "/docker", "127.0.0.1", "Bearer " + c.Token, 200}} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.RemoteAddr = tc.peer + ":1234"
		r.Header.Set("Authorization", tc.auth)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s %s: %d", tc.method, tc.path, w.Code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	data := metrics(ctx, c)
	for _, key := range []string{"hostname", "ip", "agent_version", "platform", "cpu_cores", "ts", "port", "capabilities", "telemetry_errors"} {
		if _, ok := data[key]; !ok {
			t.Errorf("missing monitoring contract field %s", key)
		}
	}
}
func TestConfigurationCommitPreservesLegacyFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(p, []byte(`{"token":"unchanged-secret","version":"1.0.003","unknown_setting":true}`), 0600)
	c := Config{path: p}
	if err := saveActive(c, "new", "1.0.004"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	var result map[string]any
	json.Unmarshal(raw, &result)
	if result["token"] != "unchanged-secret" || result["unknown_setting"] != true || result["active_binary"] != "new" {
		t.Fatal("configuration contract lost")
	}
}
func TestUpdateLockExcludesSecondUpdater(t *testing.T) {
	p := filepath.Join(t.TempDir(), "update.lock")
	unlock, err := updateLock(p)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := updateLock(p); err == nil {
		second()
		t.Fatal("simultaneous updater allowed")
	}
	unlock()
	next, err := updateLock(p)
	if err != nil {
		t.Fatal("lock not released")
	}
	next()
}
