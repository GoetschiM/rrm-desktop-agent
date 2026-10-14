package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestCandidateRollbackBeforeConfigurationCommit(t *testing.T) {
	c := Config{ActiveBinary: "old", Version: "1.0.003"}
	calls := []string{}
	activate := func(_ Config, b string) error { calls = append(calls, "activate:"+b); return nil }
	health := func(_ Config, v string) error {
		calls = append(calls, "health:"+v)
		if v == "1.0.004" {
			return errors.New("unhealthy")
		}
		return nil
	}
	save := func(_ Config, b, v string) error { t.Fatal("failed candidate committed"); return nil }
	if activateCandidate(c, "new", "1.0.004", activate, health, save) == nil {
		t.Fatal("unhealthy update accepted")
	}
	want := []string{"activate:new", "health:1.0.004", "activate:old", "health:1.0.003"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("rollback order %v", calls)
	}
}
func TestCandidateCommitFailureRollsBack(t *testing.T) {
	c := Config{ActiveBinary: "old", Version: "1.0.003"}
	calls := []string{}
	a := func(_ Config, b string) error { calls = append(calls, b); return nil }
	h := func(Config, string) error { return nil }
	s := func(Config, string, string) error { return errors.New("disk full") }
	if activateCandidate(c, "new", "1.0.004", a, h, s) == nil || !reflect.DeepEqual(calls, []string{"new", "old"}) {
		t.Fatal("commit failure did not rollback")
	}
}
func TestReleaseIndexIgnoresNewerAndroidAndIncompleteDesktop(t *testing.T) {
	complete := releaseItem{Tag: "desktop-agent-v1.0.004"}
	for _, name := range []string{"manifest.json", "manifest.sig", "rrm-agent-windows-x64.zip", "rrm-agent-macos-x64.zip", "rrm-agent-macos-arm64.zip"} {
		complete.Assets = append(complete.Assets, struct {
			Name  string `json:"name"`
			State string `json:"state"`
			URL   string `json:"browser_download_url"`
		}{name, "uploaded", "https://github.com/" + releaseRepository + "/releases/download/" + complete.Tag + "/" + name})
	}
	raw, _ := json.Marshal([]releaseItem{{Tag: "android-v9.0.0"}, {Tag: "desktop-agent-v2.0.0"}, complete})
	tag, err := selectRelease(raw)
	if err != nil || tag != complete.Tag {
		t.Fatalf("wrong release %s %v", tag, err)
	}
}
func TestVersionOrdering(t *testing.T) {
	if !newerVersion("1.10.0", "1.9.0") || newerVersion("1.0.003", "1.0.3") || newerVersion("bad", "1.0.0") {
		t.Fatal("invalid version ordering")
	}
}
