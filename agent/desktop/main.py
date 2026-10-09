"""Windows/macOS agent with the existing gl-agent monitoring protocol."""
import argparse
import hmac
import http.server
import json
import logging
import logging.handlers
import os
from pathlib import Path
import platform
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request
import psutil

import releases
import service

VERSION = (Path(__file__).parent / 'version.txt').read_text().strip()
GIB = 1024 ** 3


def primary_ip(hub):
    parsed = urllib.parse.urlparse(hub)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((socket.gethostbyname(parsed.hostname), parsed.port or (443 if parsed.scheme == 'https' else 80)))
        return sock.getsockname()[0]


def processes():
    result = []
    # process_iter caches process objects, allowing useful CPU deltas after warm-up.
    for process in psutil.process_iter(['pid', 'username', 'name', 'cpu_percent', 'memory_percent'], ad_value=None):
        try:
            p = process.info
            result.append({'pid': p['pid'], 'user': p['username'] or '', 'cmd': p['name'] or '',
                           'cpu': round(p['cpu_percent'] or 0, 1), 'mem': round(p['memory_percent'] or 0, 1)})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(result, key=lambda p: (p['cpu'], p['mem']), reverse=True)[:200]


def status(config):
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage(os.environ.get('SystemDrive', 'C:') + '\\' if sys.platform == 'win32' else '/')
    ports = []
    try:
        ports = sorted({c.laddr.port for c in psutil.net_connections(kind='tcp') if c.status == psutil.CONN_LISTEN})
    except psutil.AccessDenied:
        pass
    state = {}
    if config.get('_state_path') and Path(config['_state_path']).exists():
        try:
            state = json.loads(Path(config['_state_path']).read_text())
        except (ValueError,OSError):
            pass
    return {'hostname': socket.gethostname(), 'ip': config.get('ip') or primary_ip(config['hub_url']),
            'agent_version': VERSION, 'platform': platform.system(), 'os': platform.platform(),
            'uptime_h': round((time.time() - psutil.boot_time()) / 3600, 2),
            'cpu_pct': psutil.cpu_percent(), 'cpu_cores': psutil.cpu_count(), 'load': [],
            'mem_pct': mem.percent, 'mem_used_gb': round(mem.used / GIB, 2), 'mem_total_gb': round(mem.total / GIB, 2),
            'disk': {'total_gb': round(disk.total / GIB, 1), 'used_gb': round(disk.used / GIB, 1),
                     'avail_gb': round(disk.free / GIB, 1), 'pct': disk.percent},
            'net': {k: {'rx_bytes': v.bytes_recv, 'tx_bytes': v.bytes_sent} for k, v in psutil.net_io_counters(pernic=True).items()},
            'listening_ports': ports, 'docker_ok': False, 'nanoclaw': False, 'ts': int(time.time()),
            'capabilities': ['metrics', 'processes', 'ports', 'signed_updates'],
            'port': config.get('port', 9998), 'update_status':state, 'auto_update':config.get('auto_update',True)}


def update_state(path, **values):
    previous = {}
    state = path.parent / 'update-state.json'
    if state.exists():
        previous = json.loads(state.read_text())
    previous.update(values)
    temp = state.with_suffix('.tmp')
    temp.write_text(json.dumps(previous))
    os.replace(temp, state)


def update(config_path):
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    lock = config_path.parent / 'update.lock'
    with lock.open('a+b') as handle:
        if sys.platform == 'win32':
            import msvcrt
            handle.seek(0); handle.write(b'0'); handle.flush(); handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                return
        else:
            import fcntl
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
        old = Path(config['active_binary'])
        try:
            manifest, url = releases.latest()
            newer = releases.version(manifest['version']) > releases.version(config['version'])
            update_state(config_path, last_check=int(time.time()), current_version=config['version'],
                         latest_version=manifest['version'], update_available=newer, error='')
            if not newer or not config.get('auto_update', True):
                return
            target = config['target']
            destination = config_path.parent / 'versions' / manifest['version']
            if destination.exists():
                # An earlier failed candidate is quarantined, never silently retried.
                raise ValueError('Candidate already exists; inspect previous failure before retry')
            binary = releases.stage(manifest, url, target, destination)
            import subprocess
            subprocess.run([str(binary), '--self-test'], check=True, capture_output=True, timeout=30)
            try:
                service.activate(binary, config_path)
                healthy = False
                for _ in range(30):
                    time.sleep(1)
                    try:
                        req = urllib.request.Request(f"http://127.0.0.1:{config.get('port',9998)}/version",
                                                     headers={'Authorization': 'Bearer ' + config['token']})
                        data = json.loads(urllib.request.urlopen(req, timeout=2).read())
                        if data['version'] == manifest['version']:
                            healthy = True; break
                    except Exception:
                        pass
                if not healthy:
                    raise RuntimeError('New agent failed health check')
            except Exception:
                service.activate(old, config_path)
                raise
            config.update(active_binary=str(binary), version=manifest['version'])
            temp = config_path.with_suffix('.tmp')
            temp.write_text(json.dumps(config));temp.chmod(0o600)
            os.replace(temp, config_path)
            update_state(config_path, current_version=manifest['version'], last_update=int(time.time()), update_available=False)
        except Exception as exc:
            update_state(config_path, error=type(exc).__name__ + ': ' + str(exc)[:240])
            logging.error('Update failed: %s', type(exc).__name__)


def run(config_path, stop):
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    config['_state_path'] = str(config_path.parent / 'update-state.json')
    if not config.get('token') or not config.get('allowed_ips'):
        raise ValueError('Token and allowed hub IPs required')
    token = 'Bearer ' + config['token']
    class Handler(http.server.BaseHTTPRequestHandler):
        last_action = 0
        def log_message(self, *_):
            pass
        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path.rstrip('/')
            if self.client_address[0] not in config['allowed_ips'] + ['127.0.0.1']:
                self.send_error(403);return
            if path != '/health' and not hmac.compare_digest(self.headers.get('Authorization', ''), token):
                self.send_error(401);return
            try:
                if path in ('/health', '/version'):
                    data = {'ok': True, 'version': VERSION, 'hostname': socket.gethostname(), 'port': config.get('port',9998)}
                elif path in ('', '/'):
                    data = status(config)
                elif path == '/procs':
                    data = {'procs': processes()}
                elif path == '/ports':
                    data = {'listening_ports': status(config)['listening_ports']}
                elif path == '/update/status':
                    state = config_path.parent / 'update-state.json'
                    data = json.loads(state.read_text()) if state.exists() else {'current_version': VERSION}
                elif path == '/docker':
                    data = {'containers': [], 'supported': False}
                elif path == '/docker/policies':
                    data = {'policies': [], 'supported': False}
                elif path == '/logs':
                    log = config_path.parent / 'agent.log'
                    data = {'lines': log.read_text(errors='replace').splitlines()[-100:] if log.exists() else []}
                else:
                    self.send_error(404);return
                body = json.dumps(data).encode()
                self.send_response(200);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            except Exception as exc:
                logging.error('Request failed: %s',type(exc).__name__)
                self.send_error(500)
        def do_POST(self):
            if self.client_address[0] not in config['allowed_ips'] + ['127.0.0.1'] or not hmac.compare_digest(self.headers.get('Authorization',''),token):
                self.send_error(401);return
            path = urllib.parse.urlparse(self.path).path.rstrip('/')
            if path not in ('/update','/uninstall','/restart'):
                self.send_error(404);return
            try:
                length = int(self.headers.get('Content-Length','0'))
                if not 0 <= length <= 1024:raise ValueError()
                data = json.loads(self.rfile.read(length) or b'{}')
            except ValueError:
                self.send_error(400);return
            if path == '/uninstall' and data.get('confirm') is not True:
                self.send_error(400);return
            if time.time() - Handler.last_action < 30:
                self.send_error(429);return
            Handler.last_action=time.time()
            updater=config_path.parent / ('rrm-updater.exe' if sys.platform=='win32' else 'rrm-updater')
            if not updater.exists():
                self.send_error(409,'Installed service required');return
            import subprocess
            def launch():
                options={'creationflags':subprocess.CREATE_NO_WINDOW} if sys.platform=='win32' else {'start_new_session':True}
                subprocess.Popen([str(updater),'--'+path[1:],'--config',str(config_path)],**options)
            timer=threading.Timer(2,launch);timer.daemon=True;timer.start()
            body=json.dumps({'ok':True,'msg':'Agent-Auftrag gestartet; Status folgt beim nächsten Abruf'}).encode()
            self.send_response(202);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    server = http.server.ThreadingHTTPServer((config.get('bind_ip','0.0.0.0'),config.get('port',9998)),Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    psutil.cpu_percent();processes()
    try:
        while not stop.is_set():
            try:
                data = status(config)
                req = urllib.request.Request(config['hub_url'].rstrip('/')+'/api/agent/register',
                                             data=json.dumps(data).encode(),headers={'Authorization':token,'Content-Type':'application/json'})
                urllib.request.urlopen(req, timeout=10).close()
            except Exception as exc:
                logging.warning('Heartbeat failed: %s',type(exc).__name__)
            # Warm process CPU sampling independently of HTTP requests.
            for _ in range(12):
                if stop.wait(5):break
                processes()
    finally:
        server.shutdown();server.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config',type=Path)
    for arg in ['run','service','install','uninstall','update','restart','self-test']:
        parser.add_argument('--'+arg,action='store_true')
    args = parser.parse_args()
    if args.self_test:
        releases.version(VERSION)
        print(json.dumps({'version':VERSION,'platform':platform.system(),'processes':len(processes())}));return
    if not args.config:
        parser.error('--config required')
    log = logging.handlers.RotatingFileHandler(args.config.parent/'agent.log',maxBytes=1024*1024,backupCount=3)
    logging.basicConfig(handlers=[log],level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    if args.install:service.install(args.config)
    elif args.uninstall:service.uninstall(args.config)
    elif args.update:update(args.config)
    elif args.restart:
        config=json.loads(args.config.read_text(encoding='utf-8-sig'))
        service.activate(Path(config['active_binary']),args.config)
    elif args.service:service.windows_service(lambda stop:run(args.config,stop))
    else:run(args.config,threading.Event())


if __name__ == '__main__':
    main()
