import asyncio
from contextlib import asynccontextmanager
import json
import unittest
from unittest.mock import AsyncMock, patch

from bounded_scan import validate_scan
from nuclei_adapter import run, binary_hash
from local_monitoring import snapshot


class LocalToolsTests(unittest.IsolatedAsyncioTestCase):
    async def test_model_sampling_is_explicit_and_source_unchanged(self):
        from deep_analysis import model_context
        source={'evidence_id':'e','artifact_hash':'h','target':{'kind':'domain','value':'owned.example'},
                'result':{'tool':'amass-passive','discovered_names':[f'n{i}.owned.example' for i in range(30)]}}
        view,note=model_context(source)
        self.assertEqual(view['result']['names_omitted_from_model'],22)
        self.assertEqual(len(source['result']['discovered_names']),30)
        self.assertIn('22',note)
    async def test_real_nuclei_single_head_no_redirect(self):
        fingerprint=binary_hash()
        if not fingerprint:self.skipTest('Nuclei unavailable')
        requests=[]
        async def handle(reader,writer):
            try:
                data=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),3)
                requests.append(data.split(b'\r\n')[0].decode())
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                await writer.drain()
            finally:writer.close()
        server=await asyncio.start_server(handle,'127.0.0.1',0)
        try:
            port=server.sockets[0].getsockname()[1]
            url=f'http://127.0.0.1:{port}/'
            plan={'scan':{'tool':'nuclei-head','binary_sha256':fingerprint},'wall_timeout_seconds':60,
                  'steps':[{'target':{'kind':'url','value':url},'action':'http_headers','ports':[port],
                            'max_concurrency':1,'max_http_rps':1,'max_duration_minutes':1}]}
            validate_scan(plan)
            result=await asyncio.wait_for(run(plan,AsyncMock()),45)
            self.assertEqual(result['csp_observation'],'missing_header_candidate',result)
            self.assertEqual(requests,['HEAD / HTTP/1.1'])
        finally:
            server.close()
            await server.wait_closed()

    async def test_zap_model_context_compacts_head_preserves_full_evidence(self):
        from deep_analysis import model_context
        source={'evidence_id':'e','artifact_hash':'h','target':{'kind':'url','value':'https://owned.example/'},
                'result':{'tool':'zap-head','head':{'http_status':200,'checks':[{'check':'csp','status':'missing','review_required':True}],
                           'cookie_flags':[],'limits':'x'*2000},'passive':{'alerts':[]}}}
        context,note=model_context(source)
        self.assertEqual(context['result']['head']['headers']['csp'],'missing')
        self.assertNotIn('limits',context['result']['head'])
        self.assertEqual(len(source['result']['head']['limits']),2000)
        self.assertIn('evidence lengkap',note)

    async def test_nuclei_domain_pins_resolved_ip_and_sends_host(self):
        fingerprint=binary_hash()
        if not fingerprint:self.skipTest('Nuclei unavailable')
        requests=[]
        async def handle(reader,writer):
            try:
                requests.append(await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),5))
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                await writer.drain()
            finally:writer.close()
        server=await asyncio.start_server(handle,'127.0.0.1',0)
        try:
            port=server.sockets[0].getsockname()[1]
            target=f'http://owned.example:{port}/'
            plan={'scan':{'tool':'nuclei-head','binary_sha256':fingerprint},'steps':[{'target':{'value':target}}]}
            with patch('web_checks.resolve',new=AsyncMock(return_value='127.0.0.1')) as lookup:
                result=await asyncio.wait_for(run(plan,AsyncMock(),['exclusion']),45)
            self.assertTrue(result['dns_pinned'])
            lookup.assert_awaited_once_with('owned.example',port,['exclusion'])
            self.assertEqual(len(requests),1)
            self.assertIn(f'host: owned.example:{port}'.encode(),requests[0].lower())
        finally:
            server.close()
            await server.wait_closed()

    async def test_zap_forwards_roe_exclusions_to_dns_probe(self):
        from zap_adapter import run as zap_run
        plan={'scan':{'binary_sha256':'a'*64},'steps':[{'target':{'value':'https://owned.example/'}}]}
        observed={'http_status':200,'analysis_headers':{}}
        with patch('web_checks.probe',new=AsyncMock(return_value=observed)) as probe, patch('zap_adapter.inspect_headers',new=AsyncMock(return_value={})):
            await zap_run(plan,AsyncMock(),['excluded'])
        self.assertEqual(probe.await_args.args[1],['excluded'])

    async def test_get_probe_sends_no_credentials_and_does_not_follow_redirect(self):
        from web_checks import probe
        requests=[]
        async def handle(reader,writer):
            try:
                requests.append(await reader.readuntil(b'\r\n\r\n'))
                writer.write(b'HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                await writer.drain()
            finally:writer.close()
        server=await asyncio.start_server(handle,'127.0.0.1',0)
        try:
            port=server.sockets[0].getsockname()[1]
            result=await probe(f'http://127.0.0.1:{port}/private',[],AsyncMock(),method='GET',allow_loopback=True)
            self.assertEqual(result['http_status'],302)
            self.assertFalse(result['redirect_followed'])
            self.assertEqual(len(requests),1)
            self.assertTrue(requests[0].startswith(b'GET /private HTTP/1.1'))
            self.assertNotIn(b'authorization:',requests[0].lower())
            self.assertNotIn(b'cookie:',requests[0].lower())
        finally:
            server.close();await server.wait_closed()

    async def test_probe_bearer_is_only_in_request_not_result(self):
        from web_checks import probe
        requests=[]
        async def handle(reader,writer):
            try:
                requests.append(await reader.readuntil(b'\r\n\r\n'))
                writer.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');await writer.drain()
            finally:writer.close()
        server=await asyncio.start_server(handle,'127.0.0.1',0)
        try:
            port=server.sockets[0].getsockname()[1];token='fake.session.signature'
            result=await probe(f'http://127.0.0.1:{port}/private',[],AsyncMock(),method='GET',allow_loopback=True,bearer=token)
            self.assertIn(b'Authorization: Bearer '+token.encode(),requests[0])
            self.assertNotIn(token,json.dumps(result));self.assertTrue(result['credentials_sent'])
        finally:
            server.close();await server.wait_closed()

    async def test_inventory_one_request_and_candidates_never_contacted(self):
        from inventory_adapter import run as inventory
        html=b'<script src="/app.js?secret=discard"></script><a href="https://api.example.test/x?token=discard">API</a><a href="https://u:p@example.test/">bad</a>'
        class Reader:
            async def readuntil(self,separator):return b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '+str(len(html)).encode()+b'\r\n\r\n'
            async def readexactly(self,n):return html
        class Writer:
            def __init__(self):self.requests=[]
            def write(self,data):self.requests.append(data)
            async def drain(self):pass
            def close(self):pass
            async def wait_closed(self):pass
        writer=Writer();guard=AsyncMock()
        plan={'steps':[{'target':{'value':'https://owned.example/'}}]}
        with patch('inventory_adapter.resolve',new=AsyncMock(return_value='8.8.8.8')) as dns, \
             patch('inventory_adapter.asyncio.open_connection',new=AsyncMock(return_value=(Reader(),writer))) as connect:
            result=await inventory(plan,guard,['excluded'])
        dns.assert_awaited_once_with('owned.example',443,['excluded'])
        connect.assert_awaited_once();self.assertEqual(len(writer.requests),1)
        self.assertTrue(writer.requests[0].startswith(b'GET / HTTP/1.1'))
        self.assertNotIn(b'cookie:',writer.requests[0].lower())
        self.assertNotIn(b'authorization:',writer.requests[0].lower())
        self.assertEqual([x['url'] for x in result['candidates']],['https://owned.example/','https://api.example.test/'])
        self.assertTrue(all(not x['contacted'] for x in result['candidates']))
        self.assertNotIn('discard',json.dumps(result))

    async def test_scoped_spider_obeys_guard_and_same_origin(self):
        from active_web_adapter import run
        plan={'scan':{'tool':'scoped-spider'},'steps':[{'target':{'value':'https://owned.example/'}}]}
        fetched=[]
        async def guard(url):
            if '/private' in url:raise ValueError('excluded')
        async def fetch(url,check,exclusions,query=''):
            await check(url);fetched.append(url)
            if url.endswith('/'):
                return 200,b'<a href="/page">page</a><a href="/private">private</a><a href="/logout">logout</a><a href="https://other.example/">other</a><a href="/x?token=secret">query</a>'
            return 200,b'<a href="/">back</a>'
        with patch('active_web_adapter.fetch',new=AsyncMock(side_effect=fetch)),patch('active_web_adapter.asyncio.sleep',new=AsyncMock()):
            result=await run(plan,guard,[])
        self.assertEqual(fetched,['https://owned.example/','https://owned.example/page'])
        self.assertEqual(len(result['pages']),2)
        self.assertNotIn('private',json.dumps(result));self.assertNotIn('other.example',json.dumps(result))

    async def test_active_reflection_only_reports_benign_marker(self):
        from active_web_adapter import run
        plan={'scan':{'tool':'active-reflection'},'steps':[{'target':{'value':'https://owned.example/'}}]}
        async def fetch(url,check,exclusions,query=''):
            self.assertTrue(query.startswith('?jo_probe=joworkspace'))
            return 200,query.encode()
        with patch('active_web_adapter.fetch',new=AsyncMock(side_effect=fetch)):
            result=await run(plan,AsyncMock(),[])
        self.assertTrue(result['marker_reflected'])
        self.assertNotIn('jo_probe',json.dumps(result))
        self.assertIn('bukan bukti',result['limitation'])

    async def test_active_fetch_uses_pinned_address_and_no_credentials(self):
        from active_web_adapter import fetch
        class Reader:
            async def readuntil(self,separator):return b'HTTP/1.1 302 Found\r\nLocation: https://other.example/\r\nContent-Length: 0\r\n\r\n'
        class Writer:
            def __init__(self):self.requests=[]
            def write(self,data):self.requests.append(data)
            async def drain(self):pass
            def close(self):pass
            async def wait_closed(self):pass
        writer=Writer();guard=AsyncMock()
        with patch('active_web_adapter.resolve',new=AsyncMock(return_value='8.8.8.8')) as dns, \
             patch('active_web_adapter.asyncio.open_connection',new=AsyncMock(return_value=(Reader(),writer))) as connect:
            status,body=await fetch('https://owned.example/path',guard,['excluded'],'?jo_probe=example')
        self.assertEqual(status,302);self.assertEqual(body,b'');self.assertEqual(len(writer.requests),1)
        self.assertTrue(writer.requests[0].startswith(b'GET /path?jo_probe=example HTTP/1.1'))
        self.assertNotIn(b'cookie:',writer.requests[0].lower());self.assertNotIn(b'authorization:',writer.requests[0].lower())
        dns.assert_awaited_once_with('owned.example',443,['excluded'])
        self.assertEqual(connect.await_args.args[:2],('8.8.8.8',443))
        self.assertEqual(connect.await_args.kwargs['server_hostname'],'owned.example')
        self.assertEqual(guard.await_count,3)

    async def test_js_bundle_candidates_are_bounded_and_not_contacted(self):
        from js_inventory_adapter import run
        bundle=b'const a="https://api.example/path?token=secret"; fetch("/api/v1/profile"); const x="secretKey";'
        plan={'steps':[{'target':{'value':'https://owned.example/app.js'}}]}
        with patch('js_inventory_adapter.fetch',new=AsyncMock(return_value=(200,bundle))) as get:
            result=await run(plan,AsyncMock(),[])
        self.assertEqual(get.await_count,1)
        self.assertEqual(result['candidate_origins'],['https://api.example/'])
        self.assertEqual(result['candidate_api_paths'],['/api/v1/profile'])
        self.assertNotIn('secretKey',json.dumps(result))
        self.assertNotIn('token=secret',json.dumps(result))
        self.assertIn('tidak dihubungi',result['limitation'])

    async def test_compare_body_digests_are_transient_and_bounded(self):
        from web_checks import probe
        body=b'{"hello":"sensitive-value"}'
        async def handle(reader,writer):
            try:
                await reader.readuntil(b'\r\n\r\n')
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body);await writer.drain()
            finally:writer.close()
        server=await asyncio.start_server(handle,'127.0.0.1',0)
        try:
            port=server.sockets[0].getsockname()[1]
            result=await probe(f'http://127.0.0.1:{port}/private',[],AsyncMock(),method='GET',allow_loopback=True,compare_body=True)
            import hashlib
            self.assertEqual(result.pop('_transient_body_digest'),hashlib.sha256(body).digest())
            self.assertEqual(len(result.pop('_transient_semantic_digest')),32)
            self.assertEqual(len(result.pop('_transient_shape_digest')),32)
            self.assertNotIn('sensitive-value',json.dumps(result))
        finally:server.close();await server.wait_closed()

    async def test_monitoring_filters_metrics_and_checks_guard(self):
        class Response:
            status_code=200
            def __init__(self,data):self.data=data
            async def aiter_bytes(self):yield self.data
        values=[b'ready',json.dumps({'status':'success','data':{'result':[
            {'metric':{'job':'prometheus','secret':'omit'},'value':[1,'1']},
            {'metric':{'job':'unrelated'},'value':[1,'1']} ]}}).encode(),b'{"database":"ok"}']
        class Client:
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
            @asynccontextmanager
            async def stream(self,method,url):
                self_test.assertEqual(method,'GET')
                self_test.assertTrue(url.startswith(('http://127.0.0.1:9090/','http://127.0.0.1:3000/')))
                yield Response(values.pop(0))
        self_test=self
        guard=AsyncMock()
        with patch('local_monitoring.httpx.AsyncClient',return_value=Client()):result=await snapshot(guard)
        self.assertEqual(result['services'],[{'service':'prometheus','up':True}])
        self.assertNotIn('secret',json.dumps(result))
        self.assertEqual(guard.await_count,3)

    async def test_monitoring_and_nuclei_validation(self):
        plan={'scan':{'tool':'monitoring-local','binary_sha256':''},'wall_timeout_seconds':60,
              'steps':[{'target':{'kind':'ip','value':'127.0.0.1'},'action':'monitoring_read','ports':[3000,9090],
                        'max_concurrency':1,'max_http_rps':1,'max_duration_minutes':1}]}
        validate_scan(plan)
        with self.assertRaises(ValueError):validate_scan({**plan,'steps':[{**plan['steps'][0],'ports':[80]}]})
        with self.assertRaises(ValueError):validate_scan({**plan,'steps':[{**plan['steps'][0],'target':{'kind':'ip','value':'8.8.8.8'}}]})

    async def test_subfinder_requires_disclosure_and_passive_action(self):
        plan={'scan':{'tool':'subfinder-passive','binary_sha256':'a'*64,'provider_disclosure':True},'wall_timeout_seconds':120,
              'steps':[{'target':{'kind':'domain','value':'owned.example'},'action':'passive_recon','ports':[443],
                        'max_concurrency':1,'max_http_rps':1,'max_duration_minutes':2}]}
        with patch('subfinder_adapter.fingerprint',return_value='a'*64):
            validate_scan(plan)
            with self.assertRaises(ValueError):validate_scan({**plan,'scan':{**plan['scan'],'provider_disclosure':False}})
            with self.assertRaises(ValueError):validate_scan({**plan,'steps':[{**plan['steps'][0],'action':'tcp_discovery'}]})

    async def test_subfinder_rejects_result_outside_requested_domain(self):
        from subfinder_adapter import run as subfinder_run
        process=AsyncMock()
        process.returncode=0
        process.stdout.read=AsyncMock(return_value=b'outside.example\n')
        plan={'scan':{'tool':'subfinder-passive','binary_sha256':'a'*64},'steps':[{'target':{'kind':'domain','value':'owned.example'}}]}
        with patch('subfinder_adapter.fingerprint',return_value='a'*64), \
             patch('subfinder_adapter.shutil.which',return_value='docker'), \
             patch('subfinder_adapter.asyncio.create_subprocess_exec',return_value=process) as command:
            with self.assertRaises(ValueError):await subfinder_run(plan,AsyncMock())
            args=command.call_args_list[0].args
            self.assertIn('crtsh',args)
            self.assertNotIn('-active',args)
            self.assertNotIn('-nW',args)

    async def test_amass_fixed_profile_and_seed_filter(self):
        from subfinder_adapter import run as recon
        process=AsyncMock()
        process.returncode=0
        process.stdout.read=AsyncMock(return_value=b'owned.example\napi.owned.example\n')
        plan={'scan':{'tool':'amass-passive','binary_sha256':'a'*64,'provider_disclosure':True},'wall_timeout_seconds':240,
              'steps':[{'target':{'kind':'domain','value':'owned.example'},'action':'passive_recon','ports':[443],
                        'max_http_rps':1,'max_concurrency':1,'max_duration_minutes':4}]}
        with patch('subfinder_adapter.amass_fingerprint',return_value='a'*64),patch('subfinder_adapter.shutil.which',return_value='docker'), \
             patch('subfinder_adapter.asyncio.create_subprocess_exec',return_value=process) as command:
            validate_scan(plan)
            row=await recon(plan,AsyncMock())
            self.assertEqual(row['discovered_names'],['api.owned.example'])
            self.assertFalse(row['authorization_extended'])
            args=command.call_args_list[0].args
            self.assertIn('JO_DOMAIN=owned.example',args)
            self.assertIn('-passive',args[-1])
            self.assertIn('-rigid',args[-1])
            self.assertNotIn('-active',args[-1])
