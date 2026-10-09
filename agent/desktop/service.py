"""Install/activate/remove OS services; updater remains independent of main agent."""
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import time

NAME = 'RRMDesktopAgent'
MAC_LABEL = 'ch.goetschi.rrm-agent'


def command(*args, check=True):
    result = subprocess.run(list(args), capture_output=True, text=True, timeout=60)
    if check and result.returncode:
        raise RuntimeError(args[0] + ': ' + result.stdout.strip() + ' ' + result.stderr.strip())
    return result


def activate(binary, config):
    if sys.platform == 'win32':
        command('sc.exe', 'stop', NAME, check=False)
        for _ in range(30):
            query=command('sc.exe', 'query', NAME, check=False)
            if query.returncode or 'STOPPED' in query.stdout:
                break
            time.sleep(1)
        path = f'"{binary}" --service --config "{config}"'
        exists = command('sc.exe', 'query', NAME, check=False).returncode == 0
        command('sc.exe', 'config' if exists else 'create', NAME, 'binPath=', path, 'start=', 'auto')
        command('sc.exe', 'failure', NAME, 'reset=', '86400', 'actions=', 'restart/10000/restart/30000/restart/60000')
        command('sc.exe', 'start', NAME)
    else:
        path = Path('/Library/LaunchDaemons/' + MAC_LABEL + '.plist')
        command('launchctl', 'bootout', 'system', str(path), check=False)
        path.write_bytes(plistlib.dumps({'Label': MAC_LABEL, 'ProgramArguments': [str(binary), '--run', '--config', str(config)],
                                        'RunAtLoad': True, 'KeepAlive': True,
                                        'StandardOutPath': str(config.parent / 'agent.log'),
                                        'StandardErrorPath': str(config.parent / 'agent.log')}))
        path.chmod(0o644)
        command('launchctl', 'bootstrap', 'system', str(path))


def install(config_path):
    root = config_path.parent
    root.mkdir(parents=True, exist_ok=True)
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    if not config.get('token') or not config.get('hub_url'):
        raise ValueError('Hub and token required')
    # An immutable updater copy can run even when a main-agent release is broken.
    updater = root / ('rrm-updater.exe' if sys.platform == 'win32' else 'rrm-updater')
    if not updater.exists():
        shutil.copy2(sys.executable, updater)
    binary = root / 'versions' / config['version'] / Path(sys.executable).name
    binary.parent.mkdir(parents=True, exist_ok=True)
    if Path(sys.executable).resolve() != binary.resolve():
        shutil.copy2(sys.executable, binary)
    config['active_binary'] = str(binary)
    config.setdefault('auto_update', True)
    config_path.write_text(json.dumps(config))
    if sys.platform == 'win32':
        command('icacls', str(root), '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
        # Reset children to inherit the protected directory ACL. Applying
        # inheritance removal recursively can leave files without usable ACEs.
        command('icacls', str(root / '*'), '/reset', '/T')
        task = f'"{updater}" --update --config "{config_path}"'
        command('schtasks.exe', '/Create', '/TN', 'RRM Agent Update', '/SC', 'MINUTE', '/MO', '15', '/RU', 'SYSTEM', '/TR', task, '/F')
        # Limit inbound agent access to the configured hub addresses.
        command('netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=RRM Agent', check=False)
        command('netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=RRM Agent', 'dir=in', 'action=allow',
                'protocol=TCP', f"localport={config.get('port',9998)}", 'remoteip=' + ','.join(config['allowed_ips']))
    else:
        root.chmod(0o700)
        config_path.chmod(0o600)
        path = Path('/Library/LaunchDaemons/' + MAC_LABEL + '-update.plist')
        command('launchctl', 'bootout', 'system', str(path), check=False)
        path.write_bytes(plistlib.dumps({'Label': MAC_LABEL + '-update', 'ProgramArguments': [str(updater), '--update', '--config', str(config_path)],
                                        'StartInterval': 900,
                                        'StandardErrorPath': str(root / 'updater.log')}))
        path.chmod(0o644)
        command('launchctl', 'bootstrap', 'system', str(path))
    activate(binary, config_path)


def uninstall(config_path):
    if sys.platform == 'win32':
        command('schtasks.exe', '/Delete', '/TN', 'RRM Agent Update', '/F', check=False)
        command('sc.exe', 'stop', NAME, check=False)
        command('sc.exe', 'delete', NAME, check=False)
        command('netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=RRM Agent', check=False)
    else:
        for label in [MAC_LABEL, MAC_LABEL + '-update']:
            path = Path('/Library/LaunchDaemons/' + label + '.plist')
            command('launchctl', 'bootout', 'system', str(path), check=False)
            path.unlink(missing_ok=True)
    # Keep protected configuration and versions for deliberate recovery/reinstall.


def windows_service(run):
    import servicemanager
    import win32service
    import win32serviceutil
    import threading
    class AgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = NAME
        _svc_display_name_ = 'RRM Desktop Agent'
        def __init__(self, args):
            super().__init__(args)
            self.stop_event = threading.Event()
        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_event.set()
        def SvcDoRun(self):
            run(self.stop_event)
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(AgentService)
    servicemanager.StartServiceCtrlDispatcher()
