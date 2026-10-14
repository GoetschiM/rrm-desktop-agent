# RRM Desktop Agent 1.0.004 (Go migration)

Windows x64 and macOS Intel/Apple Silicon monitoring agent, cross-built with CGO disabled on Proxmox CT128. Android is built separately with Flutter on the same Linux container.

The Go agent implements monitoring, authenticated HTTP/heartbeat, native service installation and signed automatic updates with rollback. Existing personalized PowerShell/macOS installers and Ed25519 update trust root remain compatible. See agent/desktop-go/README.md for contracts, tests and remaining native acceptance gates.

This repository requires its own repository-scoped Linux runner on CT128. deploy/desktop-ci-runner.conf.example configures a separate service user/directory without replacing goetschi-control's runner. Both advertise rrm-ci. Registration and activation remain pending until CT128 access is available.

All compilation and packaging runs on Linux. Real Windows SCM and macOS launchd/install/update acceptance must still run on clean target devices before a signed release. macOS binaries are not Apple-notarized. Release publication is gated by the desktop-agent-release environment; configure reviewers for native acceptance. No release tag is created by the migration PR.