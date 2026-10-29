import importlib.machinery
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("AGENT_DATA_DIR", tempfile.mkdtemp(prefix="desktop-api-tests-"))
os.environ.setdefault("AGENT_API_TOKEN", "synthetic-test-key-not-a-production-secret")
from fastapi import HTTPException
from fastapi.testclient import TestClient
from main import app
from local_desktop import LocalDesktopSessions


class LocalDesktopSessionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.override = patch('main.DATA_DIR', Path(self.directory.name))
        self.override.start()
        self.client = TestClient(app, base_url='http://127.0.0.1:8010', client=('127.0.0.1', 45001)).__enter__()
        self.token = os.environ['AGENT_API_TOKEN']
        self.headers = {'Authorization': 'Bearer ' + self.token}
        self.server = SimpleNamespace(should_exit=False)
        app.state.local_desktop = LocalDesktopSessions('http://127.0.0.1:8010', self.server)

    def tearDown(self):
        if hasattr(app.state, 'local_desktop'):
            del app.state.local_desktop
        self.client.__exit__(None,None,None)
        self.override.stop()
        self.directory.cleanup()

    def ticket(self):
        response=self.client.post('/api/desktop/session-ticket',headers=self.headers,json={})
        self.assertEqual(response.status_code,200,response.text)
        return response.json()['path']

    def test_ticket_is_single_use_bounded_and_creates_httponly_session(self):
        path=self.ticket()
        self.assertNotIn(self.token,path)
        self.assertRegex(path,r'^/_desktop/connect/[A-Za-z0-9_-]{43}$')
        response=self.client.get(path,follow_redirects=False)
        self.assertEqual(response.status_code,303)
        self.assertEqual(response.headers['location'],'/')
        self.assertEqual(response.headers['cache-control'],'no-store')
        self.assertEqual(response.headers['referrer-policy'],'no-referrer')
        self.assertIn('HttpOnly',response.headers['set-cookie'])
        self.assertIn('SameSite=strict',response.headers['set-cookie'])
        self.assertEqual(self.client.get('/api/settings').status_code,200)
        self.assertEqual(self.client.get(path).status_code,410)
        self.assertEqual(self.client.post('/api/desktop/session-ticket',json={}).status_code,403)
        self.assertEqual(self.client.post('/api/desktop/session-ticket',headers={'Authorization':'Bearer invalid'},json={}).status_code,403)

    def test_token_remote_host_origin_and_mode_boundaries(self):
        self.assertEqual(self.client.post('/api/desktop/session-ticket',json={}).status_code,401)
        self.assertEqual(self.client.post('/api/desktop/session-ticket',headers={**self.headers,'Origin':'https://evil.test'},json={}).status_code,403)
        self.assertEqual(self.client.post('/api/desktop/session-ticket',headers={**self.headers,'Host':'evil.test'},json={}).status_code,403)
        remote=TestClient(app,base_url='http://127.0.0.1:8010',client=('192.0.2.10',45001))
        self.assertEqual(remote.post('/api/desktop/session-ticket',headers=self.headers,json={}).status_code,403)
        path=self.ticket()
        self.assertEqual(remote.get(path).status_code,403)
        self.assertEqual(self.client.get(path,follow_redirects=False).status_code,303)
        del app.state.local_desktop
        self.assertEqual(self.client.post('/api/desktop/session-ticket',headers=self.headers,json={}).status_code,404)

    def test_stop_requires_bearer_idle_and_never_unlocks_pentest(self):
        self.client.post('/api/session',json={'token':self.token})
        self.assertEqual(self.client.post('/api/desktop/stop',json={}).status_code,403)
        with patch('local_desktop.runtime.active',1):
            self.assertEqual(self.client.post('/api/desktop/stop',headers=self.headers,json={}).status_code,409)
        self.assertFalse(self.server.should_exit)
        response=self.client.post('/api/desktop/stop',headers=self.headers,json={})
        self.assertEqual(response.status_code,200)
        self.assertTrue(self.server.should_exit)
        with patch('main.assess') as scanner:
            locked=self.client.post('/api/pentest/run',headers=self.headers,json={'target_id':'builtin-lab'})
            self.assertEqual(locked.status_code,423)
            scanner.assert_not_called()

    def test_expiry_and_capacity_do_not_issue_reusable_api_credentials(self):
        store=LocalDesktopSessions('http://127.0.0.1:8010')
        with patch.object(store,'clock',return_value=10):
            first=store.issue(self.token)
            for _ in range(7): store.issue(self.token)
            with self.assertRaises(HTTPException) as failure: store.issue(self.token)
            self.assertEqual(failure.exception.status_code,429)
        with patch.object(store,'clock',return_value=56):
            with self.assertRaises(HTTPException) as failure: store.consume(first.rsplit('/',1)[1])
            self.assertEqual(failure.exception.status_code,410)
            self.assertTrue(store.issue(self.token))


def load_launcher():
    path=Path(__file__).resolve().parents[2]/'scripts/local_desktop_launcher.pyw'
    loader=importlib.machinery.SourceFileLoader('local_launcher_test',str(path))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    module=importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class LocalLauncherTests(unittest.TestCase):
    def setUp(self):
        self.launcher=load_launcher()

    def test_unknown_backend_receives_no_api_token(self):
        with patch.object(self.launcher,'assert_owned_backend',side_effect=RuntimeError('foreign service')), patch.object(self.launcher,'urlopen') as network:
            with self.assertRaises(RuntimeError): self.launcher.api({'data_dir':'no-secret-read'},'/api/metrics')
            network.assert_not_called()

    def test_shutdown_http_404_compatibility_and_busy_denial_without_uninstall(self):
        from urllib.error import HTTPError
        for code in (404,409,503):
            with patch.object(self.launcher,'api',side_effect=[{'active':0,'waiting':0},HTTPError('http://127.0.0.1',code,'synthetic',{},None)]):
                if code==404:self.launcher.stop_idle_backend({})
                else:
                    with self.assertRaises(HTTPError):self.launcher.stop_idle_backend({})
        with patch.object(self.launcher,'api',return_value={'active':1,'waiting':0}) as network:
            with self.assertRaises(RuntimeError):self.launcher.stop_idle_backend({})
            self.assertEqual(network.call_count,1)

    def test_backend_other_than_locked_stage_seven_is_rejected(self):
        for caps in ({'stage':6,'execution_enabled':False},{'stage':7,'execution_enabled':True}):
            with patch.object(self.launcher,'api',side_effect=[caps,{'execution_enabled':False}]):
                with self.assertRaises(RuntimeError):self.launcher.verify_stage({})

    def test_invalid_handoff_is_never_sent_to_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            browser=Path(directory)/'chrome.exe';browser.touch()
            for path in ('https://evil.test/', '/_desktop/connect/../../evil', '/_desktop/connect/'+'x'*44):
                with patch.object(self.launcher,'start_backend'), patch.object(self.launcher,'start_ollama'), patch.object(self.launcher,'api',return_value={'path':path}), patch.object(self.launcher.subprocess,'Popen') as process:
                    with self.assertRaises(RuntimeError):self.launcher.launch({'browser':str(browser),'port':8010})
                    process.assert_not_called()

    def test_uninstall_cancel_is_default_and_makes_no_changes(self):
        # Real uninstall logic is not invoked in this test.
        import tkinter
        from tkinter import messagebox
        with patch.object(tkinter,'Tk') as root, patch.object(self.launcher,'read_config',return_value={}), patch.object(self.launcher.sys,'argv',['launcher.pyw','--uninstall']), patch.object(messagebox,'askyesno',return_value=False) as question, patch.object(self.launcher,'remove_installation') as remove:
            self.launcher.main()
            self.assertEqual(question.call_args.kwargs['default'],messagebox.NO)
            remove.assert_not_called()
            root.return_value.mainloop.assert_not_called()


if __name__=='__main__':
    unittest.main()
