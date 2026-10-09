"""CI-only build packaging and manifest signing. Never print the private key."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

parser = argparse.ArgumentParser()
parser.add_argument('--target')
parser.add_argument('--sign',action='store_true')
args = parser.parse_args()
out = Path('desktop-dist');out.mkdir(exist_ok=True)
if args.sign:
    assets = {}
    for path in sorted(out.glob('rrm-agent-*.zip')):
        assets[path.stem.removeprefix('rrm-agent-')] = {'file':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    if set(assets) != {'windows-x64','macos-x64','macos-arm64'}:
        raise ValueError('Incomplete release')
    version = Path('agent/desktop/version.txt').read_text().strip()
    raw = json.dumps({'version':version,'repository':'GoetschiM/rrm-desktop-agent','assets':assets},sort_keys=True,separators=(',',':')).encode()
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(os.environ['AGENT_RELEASE_SIGNING_KEY'],validate=True))
    (out/'manifest.json').write_bytes(raw)
    (out/'manifest.sig').write_bytes(base64.b64encode(key.sign(raw)))
else:
    name = 'rrm-agent.exe' if args.target.startswith('windows') else 'rrm-agent'
    with zipfile.ZipFile(out/f'rrm-agent-{args.target}.zip','w',zipfile.ZIP_DEFLATED) as archive:
        archive.write(Path('dist')/name,name)
