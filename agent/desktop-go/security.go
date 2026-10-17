package main

// Opt-in, bounded file-integrity telemetry. It deliberately does not transmit
// contents, file hashes, account names or arbitrary paths to the hub.
import (
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "time"
)

type securityEvent struct {
 ID string `json:"id"`
 Kind string `json:"kind"`
 Severity string `json:"severity"`
 Message string `json:"message"`
 TS int64 `json:"ts"`
}
type fileState struct { sum [32]byte; exists bool }
type securityCollector struct {
 mu sync.Mutex
 paths []string
 baseline map[string]fileState
 pending []securityEvent
 errors []string
}
func newSecurityCollector(paths []string) *securityCollector {
 s:=&securityCollector{baseline:make(map[string]fileState)}
 for _,p:=range paths {
  p=strings.TrimSpace(p)
  if p=="" || len(p)>512 || !filepath.IsAbs(p) || len(s.paths)>=16 {continue}
  clean:=filepath.Clean(p)
  dup:=false;for _,old:=range s.paths{if old==clean {dup=true}}
  if !dup {s.paths=append(s.paths,clean)}
 }
 // First scan establishes a baseline and MUST NOT signal a false incident.
 s.scan(false)
 return s
}
func readIntegrity(path string) (fileState,error) {
 info,err:=os.Lstat(path)
 if os.IsNotExist(err){return fileState{},nil}
 if err!=nil {return fileState{},err}
 // Only small regular files: no symlinks, devices, sockets, directories or
 // arbitrarily large secrets. Hashes never leave the endpoint.
 if !info.Mode().IsRegular() || info.Size()>1<<20 {return fileState{},os.ErrPermission}
 raw,err:=os.ReadFile(path);if err!=nil{return fileState{},err}
 return fileState{sum:sha256.Sum256(raw),exists:true},nil
}
func(s *securityCollector) scan(emit bool){
 s.mu.Lock();defer s.mu.Unlock()
 s.errors=nil
 for _,path:=range s.paths {
  current,err:=readIntegrity(path)
  if err!=nil{s.errors=append(s.errors,"integrity_read_failed");continue}
  previous,had:=s.baseline[path]
  if emit && had && previous!=current {
   kind:="file_changed"
   if !previous.exists && current.exists {kind="file_created"}
   if previous.exists && !current.exists {kind="file_deleted"}
   now:=time.Now().Unix()
   name:=filepath.Base(path)
   // Avoid exposing full path or file contents in reported messages.
   idRaw:=sha256.Sum256([]byte(path+"|"+kind+"|"+hex.EncodeToString(current.sum[:])+"|"+time.Now().Format(time.RFC3339Nano)))
   event:=securityEvent{ID:hex.EncodeToString(idRaw[:16]),Kind:kind,Severity:"medium",Message:"Integrity change: "+name,TS:now}
   if len(s.pending)>=48 {s.pending=s.pending[1:]}
   s.pending=append(s.pending,event)
  }
  s.baseline[path]=current
 }
}
func(s *securityCollector) snapshot() map[string]any {
 s.mu.Lock();defer s.mu.Unlock()
 events:=append([]securityEvent{},s.pending...)
 errors:=append([]string{},s.errors...)
 // Clear only after an acknowledged HTTP push (see commit method).
 return map[string]any{"sources":[]string{"file_integrity"},"watched_files":len(s.paths),"errors":errors,"events":events}
}
func(s *securityCollector) commit() {
 s.mu.Lock();defer s.mu.Unlock();s.pending=nil
}
