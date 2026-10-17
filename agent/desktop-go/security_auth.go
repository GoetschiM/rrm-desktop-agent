package main

// Optional Windows Security Event Log source. Only Windows event 4625 (failed
// authentication) is collected; usernames and raw log messages are discarded.
// The hub deduplicates stable EventRecordID-derived identifiers across retries.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type windowsSecurityEvent struct {
	System struct {
		EventID   int    `xml:"EventID"`
		RecordID  string `xml:"EventRecordID"`
		CreatedAt struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

func parseWindowsAuth(raw []byte, now time.Time) []securityEvent {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	events := []securityEvent{}
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Event" {
			continue
		}
		var event windowsSecurityEvent
		if err := decoder.DecodeElement(&event, &start); err != nil {
			continue
		}
		if event.System.EventID != 4625 || event.System.RecordID == "" {
			continue
		}
		occurred, err := time.Parse(time.RFC3339Nano, event.System.CreatedAt.SystemTime)
		if err != nil || occurred.Before(now.Add(-3*time.Minute)) || occurred.After(now.Add(time.Minute)) {
			continue
		}
		peer := ""
		for _, field := range event.Data {
			if field.Name != "IpAddress" {
				continue
			}
			candidate := strings.TrimSpace(field.Value)
			if addr, err := netip.ParseAddr(candidate); err == nil && !addr.IsUnspecified() {
				peer = addr.String()
			}
		}
		hash := sha256.Sum256([]byte("windows-security-4625:" + event.System.RecordID))
		message := "SSH authentication failed"
		// Keep the shared kind for the initial auth-failure correlation, while
		// clearly identifying the Windows logon source in the message.
		kind := "windows_logon_failure"
		message = "Windows logon failed"
		if peer != "" {
			message += " from " + peer
		}
		events = append(events, securityEvent{
			ID: hex.EncodeToString(hash[:16]), Kind: kind, Severity: "medium",
			Message: message, TS: occurred.Unix(),
		})
		if len(events) >= 48 {
			break
		}
	}
	return events
}

func collectWindowsAuth(ctx context.Context) ([]securityEvent, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New("windows_eventlog_unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wevtutil", "qe", "Security",
		"/q:*[System[(EventID=4625)]]", "/c:48", "/rd:true", "/f:xml")
	output, err := cmd.Output()
	if err != nil {
		return nil, errors.New("windows_eventlog_read_failed")
	}
	if len(output) > 256*1024 {
		return nil, errors.New("windows_eventlog_result_too_large")
	}
	return parseWindowsAuth(output, time.Now()), nil
}
