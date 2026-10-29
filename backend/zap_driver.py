"""Trusted driver inside a network-disabled ZAP container. Never sends HAR requests."""
import json
import subprocess
import time
from urllib.parse import urlencode
from urllib.request import urlopen


def api(path, **params):
    with urlopen('http://127.0.0.1:8090/JSON/'+path+'/?'+urlencode(params),timeout=3) as response:
        raw=response.read(64000)
    return json.loads(raw)


process=subprocess.Popen(['/zap/zap.sh','-daemon','-host','127.0.0.1','-port','8090',
    '-dir','/tmp/zap-home','-config','api.disablekey=true','-config','autoupdate.checkOnStart=false',
    '-config','autoupdate.downloadNewRelease=false','-config','autoupdate.installAddonUpdates=false'],
    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    deadline=time.monotonic()+100
    while True:
        try:
            api('core/view/version');break
        except Exception:
            if time.monotonic()>deadline:raise RuntimeError('ZAP startup timeout')
            time.sleep(1)
    result=api('exim/action/importHar',filePath='/work/input.har',sendRequests='false')
    if result.get('code'):raise RuntimeError('HAR import failed')
    while int(api('pscan/view/recordsToScan').get('recordsToScan','1')):
        if time.monotonic()>deadline:raise RuntimeError('Passive scan timeout')
        time.sleep(.5)
    alerts=api('core/view/alerts',count='20').get('alerts',[])
    output=[{'name':str(a.get('name',''))[:180],'risk':str(a.get('risk',''))[:30],
             'confidence':str(a.get('confidence',''))[:30],'plugin_id':str(a.get('pluginId',''))[:30]} for a in alerts]
    print(json.dumps({'alerts':output,'network':'none','requests_replayed':False}))
finally:
    process.terminate()
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:process.kill()
