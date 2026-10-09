import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.request
import urllib.error
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'agent/desktop'))
import releases
spec=importlib.util.spec_from_file_location('desktop_main',ROOT/'agent/desktop/main.py')
agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)


class DesktopTests(unittest.TestCase):
    def test_real_process_and_status_schema(self):
        rows=agent.processes()
        self.assertTrue(rows)
        self.assertTrue(any(r['pid']==__import__('os').getpid() for r in rows))
        data=agent.status({'hub_url':'http://127.0.0.1:8181'})
        for key in ['cpu_pct','mem_pct','disk','net','os','ip','agent_version']:
            self.assertIn(key,data)
        self.assertGreater(data['mem_total_gb'],0)

    def test_numeric_versions(self):
        self.assertGreater(releases.version('1.0.010'),releases.version('1.0.009'))
        with self.assertRaises(ValueError):releases.version('../bad')

    def test_signature_and_package_tampering(self):
        key=Ed25519PrivateKey.generate()
        public=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
        raw=json.dumps({'version':'1.0.002','repository':releases.REPO}).encode()
        signature=base64.b64encode(key.sign(raw))
        self.assertEqual(releases.verify_manifest(raw,signature,public)['version'],'1.0.002')
        with self.assertRaises(Exception):releases.verify_manifest(raw+b' ',signature,public)
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as archive:archive.writestr('../escape.exe',b'bad')
        data=stream.getvalue()
        manifest={'assets':{'windows-x64':{'file':'rrm-agent-windows-x64.zip','sha256':hashlib.sha256(data).hexdigest()}}}
        with tempfile.TemporaryDirectory() as folder,patch.object(releases,'download',return_value=data):
            with self.assertRaises(ValueError):releases.stage(manifest,'url/','windows-x64',Path(folder)/'candidate')
            manifest['assets']['windows-x64']['sha256']='0'*64
            with self.assertRaises(ValueError):releases.stage(manifest,'url/','windows-x64',Path(folder)/'candidate')

    def test_failed_activation_rolls_back(self):
        with tempfile.TemporaryDirectory() as folder:
            config=Path(folder)/'config.json'
            config.write_text(json.dumps({'active_binary':'old.exe','version':'1.0.001','target':'windows-x64','token':'secret'}))
            with patch.object(releases,'latest',return_value=({'version':'1.0.002'},'url/')),patch.object(releases,'stage',return_value=Path('new.exe')),patch('subprocess.run'),patch.object(agent.service,'activate',side_effect=[RuntimeError('failed'),None]) as activate:
                agent.update(config)
            self.assertEqual(activate.call_count,2)
            self.assertEqual(str(activate.call_args.args[0]),'old.exe')
            self.assertEqual(json.loads(config.read_text())['version'],'1.0.001')
            self.assertIn('failed',json.loads((Path(folder)/'update-state.json').read_text())['error'])

    def test_manual_policy_never_activates(self):
        with tempfile.TemporaryDirectory() as folder:
            config=Path(folder)/'config.json'
            config.write_text(json.dumps({'active_binary':'old.exe','version':'1.0.001','auto_update':False}))
            with patch.object(releases,'latest',return_value=({'version':'1.0.002'},'url/')),patch.object(agent.service,'activate') as activate:
                agent.update(config)
            activate.assert_not_called()


if __name__=='__main__':unittest.main()
