# RRM Desktop Agent

Windows x64 and macOS Intel/Apple Silicon monitoring agent for RRM. Download your personalized installer in your RRM administration page under Hosts & Agenten. Run PowerShell as administrator on Windows, or sudo on macOS.

Reports CPU, memory, disks, listening ports and processes. Native Windows service or macOS launchd daemon; independent updater checks signed GitHub releases every 15 minutes and rolls back unhealthy releases.

The RRM server is maintained separately. This repository contains only the agent and release workflow; no server configuration or credentials. CI builds and tests actual native services on all three platforms and verifies a real signed release upgrade. macOS packages are not Apple-notarized.
