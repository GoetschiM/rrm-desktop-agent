# Go desktop agent 1.0.004

The agent is cross-built on CT128 for Windows x64, macOS Intel and macOS Apple Silicon with CGO disabled. Android remains the existing Flutter pipeline on CT128. No Windows or macOS build runner is required.

## Implemented

- Existing JSON configuration, PowerShell UTF-8 BOM, IP allow-list and constant-time Bearer authentication.
- Real CPU, RAM, disk, uptime, network counters, processes and listening ports via native Go adapters. Collection failures are explicit in telemetry_errors.
- Existing HTTP monitoring routes and authenticated /api/agent/register heartbeat every minute.
- Windows SCM service RRMDesktopAgent, restart policy, protected root ACL, restricted inbound firewall rule, independent updater and 15-minute scheduled task.
- macOS launchd labels ch.goetschi.rrm-agent and ch.goetschi.rrm-agent-update, protected configuration and 15-minute updater.
- Existing Ed25519 root/manifest, complete desktop-release selection that ignores Android releases, bounded downloads, checksum/ZIP validation, native target validation, OS update lock and candidate self-test.
- Independent updater, authenticated version health check, activation and configuration commit ordering, rollback activation **and health verification**, explicit rollback failures. Failed candidates remain quarantined.
- Existing --install, --run, --service, --update, --restart, --uninstall, --config and --self-test flags. Uninstall retains protected recovery files.
- ZIP layout and version directories compatible with existing Python installers/updaters. The existing updater copy is preserved during installation.

## Build and packages

Run go test ./... and go vet ./... locally. CT128 also runs go test -race ./... and builds all target binaries. .github/workflows/desktop-agent.yml packages the existing single-executable ZIP format. Package uploads are best-effort because GitHub storage can be full; the build report states upload availability separately. CT128 retains packages at $HOME/rrm-builds/GoetschiM/goetschi-control/<commit>/ (or the corresponding repository path). Local copies require operator retention management.

Release publication remains restricted to GoetschiM/rrm-desktop-agent and an explicit desktop-agent-v tag, requires all packages uploaded, and uses the desktop-agent-release environment. Configure environment reviewers to require native acceptance before publication. No tag, signed release or deployment is created by this PR.

## Acceptance and deployment gates

Cross-compilation proves file production; it does not prove Windows SCM, macOS launchd, firewall, Gatekeeper or native upgrade behavior. Before publication run agent/desktop/smoke_service.py against the Go binary on clean Windows and macOS devices with administrator/root privileges. The script refuses to replace an already-installed production service. Native install, process query, restart, uninstall and signed upgrade/rollback must pass on both platforms.

Apple Developer ID signing/notarization remains a separate distribution gate from Ed25519 update signatures. These binaries have not been notarized. Keep the release in review until native and Apple distribution requirements are resolved.

A Go updater staged by a new installation can update future Go agents. Existing Python updater copies continue to understand these ZIPs and CLI flags; migration from an already-installed Python agent still requires an actual signed upgrade pilot before broad rollout.

For nonprivileged protocol checks use --run --config with bind_ip=127.0.0.1, a separate port and an isolated hub. --preview exposes only health/version and never registers.
