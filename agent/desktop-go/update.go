package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const releasePrefix = "desktop-agent-v"

func trimBOM(raw []byte) []byte { return []byte(strings.TrimPrefix(string(raw), "\ufeff")) }
func httpClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) > 5 {
			return errors.New("insecure or excessive redirects")
		}
		return nil
	}}
}
func downloadRelease(client *http.Client, address string, limit int64) ([]byte, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.User != nil || (u.RawQuery != "" && !(u.Host == "api.github.com" && u.RawQuery == "per_page=100")) || u.Fragment != "" {
		return nil, errors.New("untrusted release URL")
	}
	if !(u.Host == "github.com" && strings.HasPrefix(u.Path, "/"+releaseRepository+"/releases/download/")) && !(u.Host == "api.github.com" && u.Path == "/repos/"+releaseRepository+"/releases") {
		return nil, errors.New("untrusted release source")
	}
	req, _ := http.NewRequest("GET", address, nil)
	req.Header.Set("User-Agent", "RRM-Desktop-Agent")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("release download unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New("release source returned non-success")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("release download limit exceeded")
	}
	return raw, nil
}
func versionParts(v string) ([3]uint64, error) {
	var out [3]uint64
	if !releaseVersion.MatchString(v) {
		return out, errors.New("invalid version")
	}
	for i, p := range strings.Split(v, ".") {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return out, err
		}
		out[i] = n
	}
	return out, nil
}
func newerVersion(a, b string) bool {
	aa, e := versionParts(a)
	bb, f := versionParts(b)
	if e != nil || f != nil {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return aa[i] > bb[i]
		}
	}
	return false
}

type releaseItem struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name  string `json:"name"`
		State string `json:"state"`
		URL   string `json:"browser_download_url"`
	} `json:"assets"`
}

func selectRelease(raw []byte) (string, error) {
	var items []releaseItem
	if json.Unmarshal(raw, &items) != nil {
		return "", errors.New("invalid release index")
	}
	tags := []string{}
	for _, item := range items {
		if item.Draft || item.Prerelease || !strings.HasPrefix(item.Tag, releasePrefix) {
			continue
		}
		if _, err := versionParts(strings.TrimPrefix(item.Tag, releasePrefix)); err != nil {
			continue
		}
		required := map[string]bool{"manifest.json": false, "manifest.sig": false, "rrm-agent-windows-x64.zip": false, "rrm-agent-macos-x64.zip": false, "rrm-agent-macos-arm64.zip": false}
		for _, a := range item.Assets {
			if _, ok := required[a.Name]; ok && a.State == "uploaded" && a.URL == "https://github.com/"+releaseRepository+"/releases/download/"+item.Tag+"/"+a.Name {
				required[a.Name] = true
			}
		}
		complete := true
		for _, ok := range required {
			complete = complete && ok
		}
		if complete {
			tags = append(tags, item.Tag)
		}
	}
	if len(tags) == 0 {
		return "", errors.New("no complete desktop release")
	}
	sort.Slice(tags, func(i, j int) bool {
		return newerVersion(strings.TrimPrefix(tags[i], releasePrefix), strings.TrimPrefix(tags[j], releasePrefix))
	})
	return tags[0], nil
}
func latestManifest(client *http.Client) (Manifest, string, error) {
	raw, err := downloadRelease(client, "https://api.github.com/repos/"+releaseRepository+"/releases?per_page=100", 512*1024)
	if err != nil {
		return Manifest{}, "", err
	}
	tag, err := selectRelease(raw)
	if err != nil {
		return Manifest{}, "", err
	}
	base := "https://github.com/" + releaseRepository + "/releases/download/" + tag + "/"
	raw, err = downloadRelease(client, base+"manifest.json", 65536)
	if err != nil {
		return Manifest{}, "", err
	}
	sig, err := downloadRelease(client, base+"manifest.sig", 1024)
	if err != nil {
		return Manifest{}, "", err
	}
	m, err := verifyManifest(raw, sig)
	if err == nil && tag != releasePrefix+m.Version {
		err = errors.New("release tag and signed version mismatch")
	}
	return m, base, err
}
func readUpdateState(config string) map[string]any {
	state := map[string]any{"current_version": version}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(config), "update-state.json"))
	if err == nil && len(raw) <= 65536 {
		json.Unmarshal(raw, &state)
	}
	return state
}
func writeUpdateState(c Config, values map[string]any) error {
	state := readUpdateState(c.path)
	for k, v := range values {
		state[k] = v
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(filepath.Dir(c.path), "update-state.json"), raw, 0600)
}
func checkHealth(client *http.Client, c Config, want string) error {
	req, err := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(c.Port)+"/version", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	res, err := client.Do(req)
	if err != nil {
		return errors.New("service unavailable")
	}
	defer res.Body.Close()
	var data struct {
		Version string `json:"version"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&data) != nil || data.Version != want {
		return errors.New("service version health mismatch")
	}
	return nil
}

// Inject lifecycle hooks for tests: activation, health, rollback and commit order matter.
func activateCandidate(c Config, binary, newVersion string, activateFn func(Config, string) error, healthFn func(Config, string) error, saveFn func(Config, string, string) error) error {
	rollback := func(cause error) error {
		if err := activateFn(c, c.ActiveBinary); err != nil {
			return errors.New("update failed; rollback activation failed")
		}
		if err := healthFn(c, c.Version); err != nil {
			return errors.New("update failed; rollback health failed")
		}
		return cause
	}
	if err := activateFn(c, binary); err != nil {
		return rollback(errors.New("candidate activation failed"))
	}
	if err := healthFn(c, newVersion); err != nil {
		return rollback(errors.New("candidate health failed"))
	}
	if err := saveFn(c, binary, newVersion); err != nil {
		return rollback(errors.New("candidate configuration commit failed"))
	}
	return nil
}
func updateAgent(c Config) (err error) {
	release, err := updateLock(filepath.Join(filepath.Dir(c.path), "update.lock"))
	if err != nil {
		return errors.New("update already running or lock unavailable")
	}
	defer release()
	defer func() {
		if err != nil {
			_ = writeUpdateState(c, map[string]any{"error": err.Error()})
		}
	}()
	client := httpClient(60 * time.Second)
	m, base, err := latestManifest(client)
	if err != nil {
		return err
	}
	newer := newerVersion(m.Version, c.Version)
	if err = writeUpdateState(c, map[string]any{"last_check": time.Now().Unix(), "current_version": c.Version, "latest_version": m.Version, "update_available": newer, "error": ""}); err != nil {
		return err
	}
	if !newer || !c.autoUpdates() {
		return nil
	}
	if !filepath.IsAbs(c.ActiveBinary) {
		return errors.New("installed active binary required")
	}
	expected, err := nativeTarget()
	if err != nil || c.Target != expected {
		return errors.New("configured update target mismatches OS")
	}
	directory := filepath.Join(filepath.Dir(c.path), "versions", m.Version)
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		return errors.New("candidate exists; previous failure requires inspection")
	}
	raw, err := downloadRelease(client, base+m.Assets[c.Target].File, 150*1024*1024)
	if err != nil {
		return err
	}
	data, err := verifyPackage(raw, m.Assets[c.Target], c.Target)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(directory), 0700); err != nil {
		return err
	}
	if err = os.Mkdir(directory, 0700); err != nil {
		return err
	}
	binary := filepath.Join(directory, binaryName("rrm-agent"))
	if err = atomicWrite(binary, data, 0755); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--self-test")
	output, e := cmd.Output()
	var report struct {
		Version string `json:"version"`
	}
	if e != nil || len(output) > 4096 || json.Unmarshal(output, &report) != nil || report.Version != m.Version {
		return errors.New("candidate self-test failed")
	}
	if err = activateCandidate(c, binary, m.Version, activate, healthVersion, saveActive); err != nil {
		return err
	}
	return writeUpdateState(c, map[string]any{"current_version": m.Version, "last_update": time.Now().Unix(), "update_available": false, "error": ""})
}
