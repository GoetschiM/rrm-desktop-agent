package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiveHTTPMonitoringAndHeartbeat(t *testing.T) {
	received := make(chan map[string]any, 1)
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/register" || r.Header.Get("Authorization") != "Bearer integration-test-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		var data map[string]any
		if json.NewDecoder(r.Body).Decode(&data) != nil {
			http.Error(w, "bad JSON", 400)
			return
		}
		received <- data
		w.Write([]byte(`{"ok":true}`))
	}))
	defer hub.Close()
	c := Config{Token: "integration-test-token", HubURL: hub.URL, AllowedIPs: []string{"127.0.0.1"}, IP: "127.0.0.1", Port: 9998, path: filepath.Join(t.TempDir(), "config.json")}
	agent := httptest.NewServer(productionHandler(c))
	defer agent.Close()
	for _, path := range []string{"/", "/procs", "/version", "/update/status"} {
		req, _ := http.NewRequest("GET", agent.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+c.Token)
		res, err := agent.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		err = json.NewDecoder(res.Body).Decode(&body)
		res.Body.Close()
		if res.StatusCode != 200 || err != nil {
			t.Fatalf("live %s: %d %v", path, res.StatusCode, err)
		}
		if path == "/procs" && len(body["procs"].([]any)) == 0 {
			t.Fatal("no real process data")
		}
		if path == "/" && body["hostname"] == "" {
			t.Fatal("missing real hostname")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { heartbeatLoop(ctx, c); close(done) }()
	select {
	case data := <-received:
		if data["ip"] != "127.0.0.1" || data["agent_version"] != version {
			t.Fatal("registration protocol changed")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no authenticated heartbeat")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat does not stop")
	}
}
func TestPinnedRootMatchesLegacyUpdater(t *testing.T) {
	raw, err := os.ReadFile("../desktop/release-public-key.txt")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != releasePublicKey {
		t.Fatal("Go and Python updater trust roots diverged")
	}
}
