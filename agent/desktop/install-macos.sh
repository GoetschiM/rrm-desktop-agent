#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Mit sudo ausführen.'; exit 1; }
umask 077
ROOT=/Library/Application\ Support/RRM-Agent
mkdir -p "$ROOT"
curl --fail --silent --show-error --location '__DOWNLOAD__' -o "$ROOT/download.zip"
[ "$(shasum -a 256 "$ROOT/download.zip" | cut -d ' ' -f 1)" = '__SHA256__' ] || { echo 'Paket-Prüfsumme falsch'; exit 1; }
mkdir -p "$ROOT/bootstrap-__VERSION__"
unzip -o -q "$ROOT/download.zip" -d "$ROOT/bootstrap-__VERSION__"
cat > "$ROOT/config.json" <<'RRM_CONFIG'
__CONFIG__
RRM_CONFIG
chmod 755 "$ROOT/bootstrap-__VERSION__/rrm-agent"
"$ROOT/bootstrap-__VERSION__/rrm-agent" --install --config "$ROOT/config.json"
rm "$ROOT/download.zip"
echo 'RRM-Agent installiert. Updateprüfung: alle 15 Minuten.'
