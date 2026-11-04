"""Bounded runner for *external* MCP servers (gated opt-in only).

This path deliberately does NOT use the Windows AppContainer fixture sandbox
(mcp_sandbox.py) — that runner is pinned to the offline fixture. External servers are
third-party processes/endpoints, so they are only ever reached when the operator has
set AGENT_ALLOW_EXTERNAL_MCP=1 and reviewed the server. Everything here is bounded:
short timeouts, output caps, no shell, minimal environment, kill-on-exit. Results are
clearly marked isolation='external_no_appcontainer' so they are never confused with the
isolated fixture.
"""
import asyncio
import json
import os
import subprocess

import httpx

PROTOCOL = '2025-11-25'
CLIENT_INFO = {'name': 'Jo Workspace', 'version': '1.5.0'}


def _minimal_env(env_keys):
    env = {key: os.environ[key] for key in ('SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'LOCALAPPDATA') if key in os.environ}
    # Forward only the explicitly allow-listed ENV var names that actually exist.
    missing = [key for key in env_keys if key not in os.environ]
    for key in env_keys:
        if key in os.environ:
            env[key] = os.environ[key]
    return env, missing


async def _stdio_health(config, deadline_seconds, max_output_kb):
    env, missing = _minimal_env(config.get('env_keys', []))
    process = await asyncio.create_subprocess_exec(
        config['command'], *config.get('args', []),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        env=env, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    try:
        async def request(rpc_id, method, params):
            process.stdin.write((json.dumps({'jsonrpc': '2.0', 'id': rpc_id, 'method': method, 'params': params}) + '\n').encode())
            await process.stdin.drain()
            line = await asyncio.wait_for(process.stdout.readline(), deadline_seconds)
            if len(line) > max_output_kb * 1024:
                raise ValueError('OUTPUT_LIMIT')
            message = json.loads(line or b'{}')
            if message.get('jsonrpc') != '2.0' or message.get('id') != rpc_id or 'result' not in message:
                raise ValueError('Respons MCP tidak valid.')
            return message['result']
        initialized = await request(1, 'initialize', {'protocolVersion': PROTOCOL, 'capabilities': {}, 'clientInfo': CLIENT_INFO})
        process.stdin.write((json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + '\n').encode())
        await process.stdin.drain()
        tools = await request(2, 'tools/list', {})
        return {'status': 'passed', 'transport': 'stdio',
                'protocol': initialized.get('protocolVersion'),
                'server_info': initialized.get('serverInfo', {}),
                'tools_count': len(tools.get('tools', []) if isinstance(tools, dict) else []),
                'env_keys_missing': missing, 'isolation': 'external_no_appcontainer', 'tool_called': False}
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


async def _http_health(config, deadline_seconds, max_output_kb):
    payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
               'params': {'protocolVersion': PROTOCOL, 'capabilities': {}, 'clientInfo': CLIENT_INFO}}
    async with httpx.AsyncClient(timeout=deadline_seconds, trust_env=False, follow_redirects=False) as client:
        response = await client.post(config['url'], json=payload,
                                     headers={'Accept': 'application/json, text/event-stream'})
    if response.status_code >= 400:
        raise ValueError(f'HTTP {response.status_code}')
    body = response.content[:max_output_kb * 1024].decode(errors='replace')
    # Streamable HTTP may answer with SSE; take the first JSON object either way.
    chunk = body
    if 'data:' in body:
        chunk = next((line[5:].strip() for line in body.splitlines() if line.startswith('data:')), body)
    try:
        message = json.loads(chunk)
        info = (message.get('result') or {}).get('serverInfo', {})
        protocol = (message.get('result') or {}).get('protocolVersion')
    except ValueError:
        info, protocol = {}, None
    return {'status': 'passed', 'transport': 'http', 'protocol': protocol, 'server_info': info,
            'http_status': response.status_code, 'isolation': 'external_no_appcontainer', 'tool_called': False}


async def health_check(config, max_wall_seconds=10, max_output_kb=64):
    """Handshake with an external MCP server to confirm reachability and protocol.
    Never calls a tool. Returns a bounded, normalized status dict."""
    deadline = max(1, min(15, max_wall_seconds))
    try:
        async with asyncio.timeout(deadline + 2):
            if config.get('transport') == 'stdio':
                return await _stdio_health(config, deadline, max_output_kb)
            return await _http_health(config, deadline, max_output_kb)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return {'status': 'failed', 'transport': config.get('transport'),
                'message': ('OUTPUT_LIMIT' if 'OUTPUT_LIMIT' in str(exc) else type(exc).__name__ + ': ' + str(exc)[:200]),
                'isolation': 'external_no_appcontainer', 'tool_called': False}
