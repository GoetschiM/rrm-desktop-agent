package main

import (
	"strings"
	"testing"
	"time"
)

func TestWindowsAuthEventParsing(t *testing.T) {
	now := time.Now().UTC()
	xml := "<Event><System><EventID>4625</EventID><EventRecordID>123</EventRecordID>" +
		"<TimeCreated SystemTime=\"" + now.Format(time.RFC3339Nano) +
		"\"/></System><EventData><Data Name=\"TargetUserName\">private-user</Data>" +
		"<Data Name=\"IpAddress\">192.0.2.45</Data></EventData></Event>"
	events := parseWindowsAuth([]byte(xml), now)
	if len(events) != 1 || events[0].Kind != "windows_logon_failure" {
		t.Fatalf("wrong Windows auth event: %+v", events)
	}
	if !strings.Contains(events[0].Message, "192.0.2.45") {
		t.Fatal("valid source address missing")
	}
	if strings.Contains(events[0].Message, "private-user") {
		t.Fatal("Windows event leaked username")
	}
	other := strings.Replace(xml, "<EventID>4625</EventID>", "<EventID>4624</EventID>", 1)
	if got := parseWindowsAuth([]byte(other), now); len(got) != 0 {
		t.Fatal("successful authentication must not appear as failure")
	}
	eventsAgain := parseWindowsAuth([]byte(xml), now)
	if eventsAgain[0].ID != events[0].ID {
		t.Fatal("record id should be stable for deduplication")
	}
}

func TestWindowsAuthOldEventsExcluded(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-20 * time.Minute)
	xml := "<Event><System><EventID>4625</EventID><EventRecordID>1</EventRecordID>" +
		"<TimeCreated SystemTime=\"" + old.Format(time.RFC3339Nano) +
		"\"/></System></Event>"
	if len(parseWindowsAuth([]byte(xml), now)) != 0 {
		t.Fatal("old event outside bounded window accepted")
	}
}
