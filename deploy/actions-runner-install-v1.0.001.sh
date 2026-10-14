#!/usr/bin/env bash
# Goetschi Control – GitHub Actions runner bootstrap v1.0.001
# Opt-in; do not put credentials in Git or the RRM application environment.
set -euo pipefail
CONFIG=/etc/rrm-ci-runner.conf
if [ -n "${RRM_CI_RUNNER_CONFIG:-}" ]; then CONFIG="${RRM_CI_RUNNER_CONFIG:-}"; fi
if [ ! -e "$CONFIG" ]; then exit 0; fi
if [ ! -f "$CONFIG" ] || [ -L "$CONFIG" ] || [ "$(stat -c %u "$CONFIG")" != 0 ]; then
  echo "Runner configuration must be a root-owned regular file" >&2; exit 1
fi
config_mode="$(stat -c %a "$CONFIG")"
if (( (8#$config_mode & 077) != 0 )); then
  echo "Runner config must have private permissions (chmod 600)" >&2; exit 1
fi
# shellcheck disable=SC1090
source "$CONFIG"
if [ "${RRM_CI_RUNNER_ENABLED:-}" != 1 ]; then exit 0; fi
if [ "$(id -u)" != 0 ]; then echo "Root required for first setup" >&2; exit 1; fi
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
  echo "Only Linux x86_64 with systemd is supported" >&2; exit 1
fi
if [ ! -d /run/systemd/system ]; then
  echo "Requires systemd (not the RRM Docker application image)" >&2; exit 1
fi
for program in curl python3 tar sha256sum runuser useradd systemctl; do
  command -v "$program" >/dev/null || { echo "Missing $program" >&2; exit 1; }
done
REPO=GoetschiM/goetschi-control
if [ -n "${RRM_CI_RUNNER_REPO:-}" ]; then REPO="${RRM_CI_RUNNER_REPO:-}"; fi
if ! [[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "Invalid GitHub repository" >&2; exit 1
fi
RUNNER_USER=rrm-ci
RUNNER_DIR=/var/lib/rrm-ci-runner
TOKEN_FILE=/etc/rrm-ci-runner.token
if [ -n "${RRM_CI_RUNNER_USER:-}" ]; then RUNNER_USER="$RRM_CI_RUNNER_USER"; fi
if [ -n "${RRM_CI_RUNNER_DIR:-}" ]; then RUNNER_DIR="$RRM_CI_RUNNER_DIR"; fi
if ! [[ "$RUNNER_USER" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]]; then
  echo "Invalid runner service user" >&2; exit 1
fi
if ! [[ "$RUNNER_DIR" =~ ^/(opt/ci|var/lib)/[a-zA-Z0-9_-]+$ ]]; then
  echo "Runner directory must be a dedicated child of /opt/ci or /var/lib" >&2; exit 1
fi
if [ -n "${RRM_CI_RUNNER_TOKEN_FILE:-}" ]; then TOKEN_FILE="${RRM_CI_RUNNER_TOKEN_FILE:-}"; fi
NAME="rrm-ci-$(hostname -s | tr -c 'a-zA-Z0-9_.-' '-' | cut -c1-45)"
if [ -L "$RUNNER_DIR" ]; then echo "Runner path is a symlink" >&2; exit 1; fi
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$RUNNER_DIR" --shell /usr/sbin/nologin "$RUNNER_USER"
fi
install -d -m 0750 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_DIR"
cd "$RUNNER_DIR"
if [ -f .runner ]; then
  python3 - "$REPO" <<'PY'
import json, sys
with open('.runner') as stream:
    settings = json.load(stream)
if settings.get('gitHubUrl', '').rstrip('/') != 'https://github.com/' + sys.argv[1]:
    raise SystemExit('Existing runner belongs to another repository; choose a separate directory/user')
PY
fi
if [ ! -f .runner ]; then
  if [ ! -f "$TOKEN_FILE" ] || [ -L "$TOKEN_FILE" ]; then
    echo "One-time GitHub registration token missing: $TOKEN_FILE" >&2; exit 2
  fi
  if [ "$(stat -c %u "$TOKEN_FILE")" != 0 ]; then
    echo "Runner token must be root-owned" >&2; exit 2
  fi
  mode="$(stat -c %a "$TOKEN_FILE")"
  if (( (8#$mode & 077) != 0 )); then
    echo "Runner token must have private permissions (chmod 600)" >&2; exit 2
  fi
  token="$(tr -d '\r\n' < "$TOKEN_FILE")"
  if [ -z "$token" ]; then echo "Empty registration token" >&2; exit 2; fi

  metadata="$(curl -fsSL --retry 3 --max-time 30 -H 'Accept: application/vnd.github+json' https://api.github.com/repos/actions/runner/releases/latest)"
  release="$(printf '%s' "$metadata" | python3 -c '
import json, re, sys
data = json.load(sys.stdin)
for a in data.get("assets", []):
    if re.fullmatch(r"actions-runner-linux-x64-[0-9.]+\.tar\.gz", a.get("name", "")):
        url, digest = a.get("browser_download_url", ""), a.get("digest") or ""
        if url.startswith("https://github.com/actions/runner/releases/download/") and re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
            print(url + " " + digest.split(":", 1)[1])
            sys.exit(0)
sys.exit("No SHA-256 verified Linux x64 runner archive in latest release")
')"
  read -r asset_url expected_sha <<< "$release"
  archive="$(mktemp /tmp/rrm-ci-runner.XXXXXX)"
  trap 'rm -f "$archive"' EXIT
  curl -fsSL --retry 3 --max-time 300 -o "$archive" "$asset_url"
  printf '%s  %s\n' "$expected_sha" "$archive" | sha256sum --check --status
  tar -xzf "$archive" -C "$RUNNER_DIR" --no-same-owner
  chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR"
  runuser -u "$RUNNER_USER" -- ./config.sh --unattended --url "https://github.com/$REPO" \
    --token "$token" --name "$NAME" --labels rrm-ci --work _work --replace
  unset token
  rm -f "$TOKEN_FILE"
fi
if [ ! -x ./svc.sh ]; then
  echo "Runner setup incomplete (svc.sh missing)" >&2; exit 1
fi
if [ ! -f .service ]; then ./svc.sh install "$RUNNER_USER"; fi
./svc.sh start
echo "Runner available (repo: $REPO, label: rrm-ci)"
