package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

// Existing trust root; private signing material never enters the build.
const releasePublicKey = "BzWKEAo9MpqWUxx8if+KBPD/D9O6AH+oqrYcTi8Auu8="
const releaseRepository = "GoetschiM/rrm-desktop-agent"

type Asset struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Version    string           `json:"version"`
	Repository string           `json:"repository"`
	Assets     map[string]Asset `json:"assets"`
}

var releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

func verifyManifest(raw, signature []byte) (Manifest, error) {
	key, _ := base64.StdEncoding.DecodeString(releasePublicKey)
	return verifyManifestWithKey(raw, signature, ed25519.PublicKey(key))
}
func verifyManifestWithKey(raw, signature []byte, key ed25519.PublicKey) (Manifest, error) {
	var m Manifest
	if len(raw) > 65536 || len(signature) > 1024 || len(key) != ed25519.PublicKeySize {
		return m, errors.New("invalid manifest size or root")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSpace(signature)))
	if err != nil || !ed25519.Verify(key, raw, sig) {
		return m, errors.New("manifest signature rejected")
	}
	if json.Unmarshal(raw, &m) != nil || !releaseVersion.MatchString(m.Version) || m.Repository != releaseRepository {
		return Manifest{}, errors.New("manifest contract rejected")
	}
	for _, target := range []string{"windows-x64", "macos-x64", "macos-arm64"} {
		a, ok := m.Assets[target]
		sum, err := hex.DecodeString(a.SHA256)
		if !ok || a.File != "rrm-agent-"+target+".zip" || err != nil || len(sum) != 32 {
			return Manifest{}, errors.New("incomplete or invalid release assets")
		}
	}
	return m, nil
}

// Validate in memory; no archive-controlled filenames are written to disk.
func verifyPackage(raw []byte, asset Asset, target string) ([]byte, error) {
	if len(raw) > 150*1024*1024 {
		return nil, errors.New("package too large")
	}
	if target != "windows-x64" && target != "macos-x64" && target != "macos-arm64" {
		return nil, errors.New("unsupported target")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != asset.SHA256 {
		return nil, errors.New("package checksum rejected")
	}
	z, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, errors.New("invalid package archive")
	}
	expected := "rrm-agent"
	if target == "windows-x64" {
		expected += ".exe"
	}
	if len(z.File) != 1 || z.File[0].Name != expected || z.File[0].UncompressedSize64 > 250*1024*1024 || !z.File[0].Mode().IsRegular() {
		return nil, errors.New("unexpected package contents")
	}
	r, err := z.File[0].Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	binary, err := io.ReadAll(io.LimitReader(r, 250*1024*1024+1))
	if err != nil || len(binary) > 250*1024*1024 {
		return nil, errors.New("invalid unpacked binary")
	}
	return binary, nil
}
