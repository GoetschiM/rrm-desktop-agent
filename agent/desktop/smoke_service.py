"""CI test: install the frozen package as an actual service, query it, uninstall."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
import urllib.request

binary = Path(sys.argv[1]).resolve()
# Acceptance must not replace a production service on the test machine.
if sys.platform == 'win32':
    probe = subprocess.run(['sc.exe', 'query', 'RRMDesktopAgent'], capture_output=True)
    if probe.returncode == 0:
        raise SystemExit('RRMDesktopAgent already exists; use a clean acceptance device.')
elif Path('/Library/LaunchDaemons/ch.goetschi.rrm-agent.plist').exists():
    raise SystemExit('RRM launchd service already exists; use a clean acceptance device.')
test_token = 'ci-service-test-token-not-production'
with tempfile.TemporaryDirectory(prefix='rrm-service-test-', dir=os.environ.get('ProgramData') if sys.platform=='win32' else None) as folder:
    config = Path(folder)/'config.json'
    config.write_text(json.dumps({'token':test_token,'hub_url':'http://127.0.0.1:18181',
                                  'allowed_ips':['127.0.0.1'],'port':19998,'bind_ip':'127.0.0.1',
                                  'version':Path('agent/desktop/version.txt').read_text().strip(),
                                  'target':'windows-x64' if sys.platform=='win32' else 'macos-'+('arm64' if platform.machine()=='arm64' else 'x64'),
                                  'auto_update':False}))
    try:
        subprocess.run([str(binary),'--install','--config',str(config)],check=True,timeout=120)
        result=None
        for _ in range(30):
            time.sleep(1)
            try:
                request=urllib.request.Request('http://127.0.0.1:19998/procs',headers={'Authorization':'Bearer '+test_token})
                result=json.loads(urllib.request.urlopen(request,timeout=5).read())
                if result['procs']:break
            except Exception:pass
        assert result and result['procs'], 'Service did not start or returned no process data'
        print('Frozen OS service returned authenticated real process data')
        if '--upgrade' in sys.argv:
            installed=json.loads(config.read_text())
            installed['auto_update']=True
            config.write_text(json.dumps(installed))
            updater=config.parent/('rrm-updater.exe' if sys.platform=='win32' else 'rrm-updater')
            subprocess.run([str(updater),'--update','--config',str(config)],check=True,timeout=180)
            state=json.loads((config.parent/'update-state.json').read_text())
            assert not state.get('error'), state.get('error')
            assert state.get('last_update') and state['current_version'] != installed['version'], 'No signed upgrade activated'
            request=urllib.request.Request('http://127.0.0.1:19998/version',headers={'Authorization':'Bearer '+test_token})
            current=json.loads(urllib.request.urlopen(request,timeout=10).read())
            assert current['version']==state['current_version']
            print('Signed GitHub release downloaded, verified, activated and read back:',current['version'])
    finally:
        subprocess.run([str(binary),'--uninstall','--config',str(config)],check=True,timeout=120)
        time.sleep(5)
