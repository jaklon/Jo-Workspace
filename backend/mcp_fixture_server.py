"""Pinned, dependency-free MCP stdio fixture. Never contacts a target."""
import json
import sys

PROTOCOL = '2025-11-25'
VERSION = '1.0.0'
FIXTURES = {
    'headers_missing': {'kind':'headers','headers':{'Content-Type':'text/html'},'synthetic':True},
    'headers_present': {'kind':'headers','headers':{'Content-Type':'text/html','X-Synthetic-Header':'enabled'},'synthetic':True},
    'config_insecure': {'kind':'configuration','debug':True,'synthetic':True},
    'config_hardened': {'kind':'configuration','debug':False,'synthetic':True},
}
CHOICE = {'type':'string','enum':list(FIXTURES)}
TOOLS = [
    {'name':'fixture.inspect','description':'Read a bundled synthetic fixture; no target/network access.',
     'inputSchema':{'type':'object','properties':{'fixture':CHOICE},'required':['fixture'],'additionalProperties':False}},
    {'name':'fixture.compare','description':'Compare two bundled synthetic fixtures; no target/network access.',
     'inputSchema':{'type':'object','properties':{'before':CHOICE,'after':CHOICE},'required':['before','after'],'additionalProperties':False}},
]


def inspect_arguments(tool, arguments):
    required = {'fixture.inspect':{'fixture'},'fixture.compare':{'before','after'}}
    if tool not in required or not isinstance(arguments,dict) or set(arguments) != required[tool]:
        raise ValueError('Invalid tool schema')
    if any(not isinstance(v,str) or v not in FIXTURES for v in arguments.values()):
        raise ValueError('Unknown fixture')
    return arguments


def isolation_probe(params):
    """Test diagnostic, never exposed as a catalog tool or by the gateway."""
    import os
    import socket
    import subprocess
    result = {'private_read_denied':False,'runtime_write_denied':False,'network_denied':False,'workspace_write_allowed':False,
              'child_denied':False,'environment_clean':not any(k in os.environ for k in ('AGENT_API_TOKEN','OPENAI_API_KEY','USERPROFILE','VIRTUAL_ENV','PYTHONPATH'))}
    try:
        with open(params['private_path'],'rb') as file: file.read(1)
    except OSError: result['private_read_denied']=True
    try:
        with open(__file__+'.unauthorized','w') as file:file.write('test')
    except OSError: result['runtime_write_denied']=True
    try:
        with open('synthetic-work.txt','w') as file:file.write('synthetic')
        result['workspace_write_allowed']=True
    except OSError:pass
    try:
        with socket.create_connection(('127.0.0.1',params['port']),timeout=.1): pass
    except OSError: result['network_denied']=True
    try:
        child=subprocess.Popen([sys.executable,'-I','-S','-c','pass'])
        child.wait(timeout=1)
    except OSError: result['child_denied']=True
    return result


def main():
    sys.stdin.reconfigure(encoding='utf-8')
    sys.stdout.reconfigure(encoding='utf-8',line_buffering=True)
    initialized = False
    for line in sys.stdin:
        request=None
        try:
            request=json.loads(line)
            method=request.get('method')
            if method=='initialize':
                if request['params'].get('protocolVersion')!=PROTOCOL:raise ValueError('Unsupported protocol')
                result={'protocolVersion':PROTOCOL,'capabilities':{'tools':{'listChanged':False}},'serverInfo':{'name':'agentos-fixture','version':VERSION}}
            elif method=='notifications/initialized':
                initialized=True
                continue
            elif not initialized:raise ValueError('Initialize first')
            elif method=='tools/list':result={'tools':TOOLS}
            elif method=='tools/call':
                p=request['params'];args=inspect_arguments(p['name'],p['arguments'])
                data={'fixture_only':True,'pentest_executed':False,'tool':p['name'],'fixtures':{k:FIXTURES[v] for k,v in args.items()}}
                result={'content':[{'type':'text','text':json.dumps(data,separators=(',',':'))}],'structuredContent':data,'isError':False}
            elif method=='agentos/isolation-probe':result=isolation_probe(request['params'])
            else:raise ValueError('Unsupported method')
            print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result},separators=(',',':')))
        except Exception:
            if isinstance(request,dict) and 'id' in request:
                print(json.dumps({'jsonrpc':'2.0','id':request['id'],'error':{'code':-32602,'message':'Invalid fixture request'}}))


if __name__=='__main__':main()
