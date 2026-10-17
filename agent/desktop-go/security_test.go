package main

import (
 "os"
 "path/filepath"
 "testing"
)

func TestSecurityIntegrityLifecycle(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"watched.conf")
 if err:=os.WriteFile(path,[]byte("before"),0600);err!=nil{t.Fatal(err)}
 s:=newSecurityCollector([]string{path})
 if got:=len(s.snapshot()["events"].([]securityEvent));got!=0{t.Fatalf("initial baseline raised %d events",got)}
 if err:=os.WriteFile(path,[]byte("after"),0600);err!=nil{t.Fatal(err)}
 s.scan(true)
 events:=s.snapshot()["events"].([]securityEvent)
 if len(events)!=1 || events[0].Kind!="file_changed"{t.Fatalf("unexpected change events: %+v",events)}
 if events[0].Message!="Integrity change: watched.conf"{t.Fatal("full path leaked")}
 s.scan(true)
 if len(s.snapshot()["events"].([]securityEvent))!=1{t.Fatal("unchanged file caused repeated alert")}
 s.commit()
 if len(s.snapshot()["events"].([]securityEvent))!=0{t.Fatal("acknowledged telemetry was not cleared")}
 if err:=os.Remove(path);err!=nil{t.Fatal(err)}
 s.scan(true)
 events=s.snapshot()["events"].([]securityEvent)
 if len(events)!=1 || events[0].Kind!="file_deleted"{t.Fatalf("missing deletion: %+v",events)}
}

func TestSecurityPathsAreOptInAndBounded(t *testing.T) {
 s:=newSecurityCollector([]string{"relative.txt","","/tmp/x","/tmp/x"})
 if len(s.paths)!=1{t.Fatalf("unexpected watched paths: %+v",s.paths)}
}
