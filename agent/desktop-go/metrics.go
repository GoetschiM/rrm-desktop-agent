package main

import (
	"context"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	gn "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"net"
	"net/url"
	"os"
	"runtime"
	"sort"
	"time"
)

func primaryIP(c Config) string {
	if c.IP != "" {
		return c.IP
	}
	u, err := url.Parse(c.HubURL)
	if err != nil {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(u.Hostname(), port), 3*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	a, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return a.IP.String()
}
func metrics(ctx context.Context, c Config) map[string]any {
	hostname, _ := os.Hostname()
	platform := map[string]string{"windows": "Windows", "darwin": "Darwin", "linux": "Linux"}[runtime.GOOS]
	data := map[string]any{"hostname": hostname, "ip": primaryIP(c), "agent_version": version, "platform": platform, "os": runtime.GOOS, "cpu_cores": runtime.NumCPU(), "load": []float64{}, "docker_ok": false, "nanoclaw": false, "ts": time.Now().Unix(), "port": c.Port, "auto_update": c.autoUpdates(), "capabilities": []string{"metrics", "processes", "ports", "signed_updates"}, "update_status": readUpdateState(c.path)}
	failures := []string{}
	if v, err := host.InfoWithContext(ctx); err == nil {
		data["os"] = v.Platform + " " + v.PlatformVersion
		data["uptime_h"] = float64(v.Uptime) / 3600
	} else {
		failures = append(failures, "host")
	}
	if v, err := cpu.PercentWithContext(ctx, 0, false); err == nil && len(v) > 0 {
		data["cpu_pct"] = v[0]
	} else {
		failures = append(failures, "cpu")
	}
	const gib = 1024 * 1024 * 1024
	if v, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		data["mem_pct"] = v.UsedPercent
		data["mem_used_gb"] = float64(v.Used) / gib
		data["mem_total_gb"] = float64(v.Total) / gib
	} else {
		failures = append(failures, "memory")
	}
	root := "/"
	if runtime.GOOS == "windows" {
		root = os.Getenv("SystemDrive") + `\`
		if root == `\` {
			root = `C:\`
		}
	}
	if v, err := disk.UsageWithContext(ctx, root); err == nil {
		data["disk"] = map[string]any{"total_gb": float64(v.Total) / gib, "used_gb": float64(v.Used) / gib, "avail_gb": float64(v.Free) / gib, "pct": v.UsedPercent}
	} else {
		failures = append(failures, "disk")
	}
	interfaces := map[string]any{}
	if v, err := gn.IOCountersWithContext(ctx, true); err == nil {
		for _, n := range v {
			interfaces[n.Name] = map[string]uint64{"rx_bytes": n.BytesRecv, "tx_bytes": n.BytesSent}
		}
	} else {
		failures = append(failures, "network")
	}
	data["net"] = interfaces
	ports, err := listeningPorts(ctx)
	data["listening_ports"] = ports
	if err != nil {
		failures = append(failures, "ports")
	}
	data["telemetry_errors"] = failures
	return data
}
func listeningPorts(ctx context.Context) ([]uint32, error) {
	list, err := gn.ConnectionsWithContext(ctx, "tcp")
	ports := []uint32{}
	seen := map[uint32]bool{}
	for _, c := range list {
		if c.Status == "LISTEN" && !seen[c.Laddr.Port] {
			seen[c.Laddr.Port] = true
			ports = append(ports, c.Laddr.Port)
		}
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports, err
}

type ProcessRow struct {
	PID     int32   `json:"pid"`
	User    string  `json:"user"`
	Command string  `json:"cmd"`
	CPU     float64 `json:"cpu"`
	Memory  float32 `json:"mem"`
}

func processRows(ctx context.Context) ([]ProcessRow, error) {
	list, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	rows := []ProcessRow{}
	for _, p := range list {
		if ctx.Err() != nil {
			return rows, ctx.Err()
		}
		name, e := p.NameWithContext(ctx)
		if e != nil {
			continue
		}
		user, _ := p.UsernameWithContext(ctx)
		cpu, _ := p.CPUPercentWithContext(ctx)
		memory, _ := p.MemoryPercentWithContext(ctx)
		rows = append(rows, ProcessRow{p.Pid, user, name, cpu, memory})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CPU == rows[j].CPU {
			return rows[i].Memory > rows[j].Memory
		}
		return rows[i].CPU > rows[j].CPU
	})
	if len(rows) > 200 {
		rows = rows[:200]
	}
	return rows, nil
}
