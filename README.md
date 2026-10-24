# G-Control – Public Desktop Agent Releases v1.0.002

**Development has moved to the [Goetschi Labs organisation source repository](https://github.com/Goetschi-Lab-s/goetschi-control).** All Windows/macOS Desktop Agent source, installer code, tests and CI are maintained there, under [`agent/desktop-go/`](https://github.com/Goetschi-Lab-s/goetschi-control/tree/main/agent/desktop-go), [`agent/desktop/`](https://github.com/Goetschi-Lab-s/goetschi-control/tree/main/agent/desktop), and [`.github/workflows/desktop-agent.yml`](https://github.com/Goetschi-Lab-s/goetschi-control/blob/main/.github/workflows/desktop-agent.yml).

This **public repository is a release distribution channel, not a second development project**. The main source repository is private; access to source code requires organisation permission. Public customers and installed agents do not need private GitHub credentials to download release assets.

## Download / update channels

- [Windows x64 and macOS Intel/Apple Silicon Desktop Agent releases](https://github.com/GoetschiM/rrm-desktop-agent/releases) — signed `desktop-agent-vX.Y.Z` manifests and complete ZIP packages.
- Android G-Control releases use `android-vX.Y.Z` tags in the **same** public release channel; use the official app update UI for the installed instance.
- The Desktop Agent update code deliberately validates **this repository path** (`GoetschiM/rrm-desktop-agent`) in its existing signed manifests. That field and the pinned Ed25519 public key must remain unchanged until existing clients receive a separate, verified signed transition update.

## Release policy

New builds and native Windows/macOS acceptance are performed in the [canonical private repository](https://github.com/Goetschi-Lab-s/goetschi-control). Publication of a Desktop Agent release requires a manual approval and environment review, an authenticated cross-repository release token, the original Ed25519 signing key, verified checksums, and a complete five-asset public release. Android is published from the canonical Android CI.

**Historical tags and release assets must not be deleted or replaced.** Existing devices continue using them for upgrades and recovery. This repo does not accept Agent source PRs, duplicate runner registrations or local builds; open development PRs and issues in [Götschi Control](https://github.com/Goetschi-Lab-s/goetschi-control/issues).

Migration reference: [DESKTOP-AGENT-SINGLE-SOURCE-v1.0.001.md](https://github.com/Goetschi-Lab-s/goetschi-control/blob/main/docs/DESKTOP-AGENT-SINGLE-SOURCE-v1.0.001.md).
