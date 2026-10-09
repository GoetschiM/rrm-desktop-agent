"""Public GitHub releases; pinned Ed25519 root, bounded downloads and safe staging."""
import base64
import hashlib
import json
from pathlib import Path
import re
import urllib.request
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPO = 'GoetschiM/rrm-desktop-agent'
PREFIX = 'desktop-agent-v'
ROOT = Path(__file__).parent


def version(value):
    if not re.fullmatch(r'\d+\.\d+\.\d+', value):
        raise ValueError('Invalid release version')
    return tuple(map(int, value.split('.')))


def download(url, limit=150 * 1024 * 1024):
    if not url.startswith(('https://github.com/' + REPO + '/releases/download/',
                           'https://github.com/' + REPO + '/releases/latest/download/')):
        raise ValueError('Untrusted release URL')
    req = urllib.request.Request(url, headers={'User-Agent': 'RRM-Desktop-Agent', 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=60) as response:
        if not response.url.startswith('https://'):
            raise ValueError('Insecure redirect')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Oversized download')
    return data


def verify_manifest(raw, signature, public_key=None):
    key = public_key or (ROOT / 'release-public-key.txt').read_text().strip()
    Ed25519PublicKey.from_public_bytes(base64.b64decode(key, validate=True)).verify(
        base64.b64decode(signature, validate=True), raw)
    manifest = json.loads(raw)
    version(manifest['version'])
    if manifest.get('repository') != REPO:
        raise ValueError('Wrong repository')
    return manifest


def latest():
    # The dedicated repository publishes only desktop releases. The public
    # download redirect avoids the shared-IP unauthenticated API quota.
    latest_url = f'https://github.com/{REPO}/releases/latest/download/'
    manifest = verify_manifest(download(latest_url + 'manifest.json', 65536),
                               download(latest_url + 'manifest.sig', 1024))
    url = f"https://github.com/{REPO}/releases/download/{PREFIX}{manifest['version']}/"
    return manifest, url


def stage(manifest, base_url, target, directory):
    asset = manifest['assets'][target]
    filename = asset['file']
    if not re.fullmatch(r'rrm-agent-[a-z0-9-]+\.zip', filename):
        raise ValueError('Invalid asset name')
    raw = download(base_url + filename)
    if hashlib.sha256(raw).hexdigest() != asset['sha256']:
        raise ValueError('Package checksum mismatch')
    import io
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            expected = 'rrm-agent.exe' if target.startswith('windows') else 'rrm-agent'
            if archive.namelist() != [expected] or archive.getinfo(expected).file_size > 250 * 1024 * 1024:
                raise ValueError('Unexpected package contents')
            archive.extractall(directory)
        binary = directory / expected
        binary.chmod(0o755)
        return binary
    except Exception:
        import shutil
        shutil.rmtree(directory)
        raise
