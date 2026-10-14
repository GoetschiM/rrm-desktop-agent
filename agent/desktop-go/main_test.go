package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAccessAndPreviewBoundary(t *testing.T) {
	h := handler(Config{Token: "test-token", AllowedIPs: []string{"10.0.60.181"}, Port: 9998})
	for _, tc := range []struct {
		ip, path, auth, method string
		want                   int
	}{
		{"10.0.60.181", "/health", "", "GET", 200},
		{"10.0.60.182", "/health", "", "GET", 403},
		{"10.0.60.181", "/version", "", "GET", 401},
		{"10.0.60.181", "/version", "Bearer test-token", "GET", 200},
		{"127.0.0.1", "/", "Bearer test-token", "GET", 501},
		{"127.0.0.1", "/update", "Bearer test-token", "POST", 405},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.RemoteAddr = tc.ip + ":1234"
		r.Header.Set("Authorization", tc.auth)
		// Forwarded headers must never grant access to an untrusted peer.
		r.Header.Set("X-Forwarded-For", "10.0.60.181")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s %s: got %d want %d", tc.ip, tc.path, w.Code, tc.want)
		}
	}
}
func TestConfigBOMAndSecretRedaction(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(p, []byte("\ufeff"+`{"token":"12345678901234567890","hub_url":"https://rrm.example","allowed_ips":["10.0.60.181"]}`), 0600)
	c, err := loadConfig(p)
	if err != nil || c.Port != 9998 || c.BindIP != "127.0.0.1" {
		t.Fatalf("config defaults: %v", err)
	}
	os.WriteFile(p, []byte(`{"token":"secret","hub_url":"https://user:password@example.com"}`), 0600)
	if _, err = loadConfig(p); err == nil {
		t.Fatal("credentials in URL accepted")
	}
}
func TestSignedManifestTamperAndWrongRepository(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{Version: "1.0.004", Repository: releaseRepository, Assets: map[string]Asset{}}
	for _, target := range []string{"windows-x64", "macos-x64", "macos-arm64"} {
		m.Assets[target] = Asset{File: "rrm-agent-" + target + ".zip", SHA256: hex.EncodeToString(make([]byte, 32))}
	}
	raw, _ := json.Marshal(m)
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw)))
	if _, err := verifyManifestWithKey(raw, sig, pub); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), raw...)
	changed[0] = ' '
	if _, err := verifyManifestWithKey(changed, sig, pub); err == nil {
		t.Fatal("tamper accepted")
	}
	m.Repository = "attacker/repo"
	raw, _ = json.Marshal(m)
	sig = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw)))
	if _, err := verifyManifestWithKey(raw, sig, pub); err == nil {
		t.Fatal("wrong repository accepted")
	}
}
func TestPackageRejectsTraversalAndChecksum(t *testing.T) {
	for _, name := range []string{"rrm-agent.exe", "../rrm-agent.exe"} {
		var b bytes.Buffer
		z := zip.NewWriter(&b)
		f, _ := z.Create(name)
		f.Write([]byte("test"))
		z.Close()
		sum := sha256.Sum256(b.Bytes())
		a := Asset{SHA256: hex.EncodeToString(sum[:])}
		_, err := verifyPackage(b.Bytes(), a, "windows-x64")
		if (err == nil) != (name == "rrm-agent.exe") {
			t.Fatalf("archive %s: %v", name, err)
		}
		a.SHA256 = "bad"
		if _, err = verifyPackage(b.Bytes(), a, "windows-x64"); err == nil {
			t.Fatal("checksum accepted")
		}
	}
}
