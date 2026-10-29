"""Create the reviewed crt.sh-only profile from an already checked-out Amass source."""
from pathlib import Path
import subprocess
import re

root=Path(__file__).resolve().parents[1]
source=root/'output'/'amass-source'
commit=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
if commit!='a284d25a890cbb561a53410080a3fd96bbaa7312':raise SystemExit('Amass source revision must match reviewed profile commit')
plugin=source/'engine/plugins/load.go'
session=source/'engine/sessions/session.go'
original=plugin.read_text()
if 'api.NewCrtsh' not in original:raise SystemExit('Unexpected Amass source')
plugin.write_text('''// Jo Workspace profile: upstream Apache-2.0; only crt.sh registered.
package plugins
import (
  "github.com/owasp-amass/amass/v5/engine/plugins/api"
  et "github.com/owasp-amass/amass/v5/engine/types"
)
func LoadAndStartPlugins(r et.Registry) error { return api.NewCrtsh().Start(r) }
''')
text=session.read_text()
anchor='NewSessSemaphore(amassnet.MaxNetworkConns / numOfSessions)'
if anchor not in text and 'NewSessSemaphore(1)' not in text:raise SystemExit('Unexpected Amass semaphore source')
text=text.replace(anchor,'NewSessSemaphore(1)')
text=text.replace('ss.Lock()\n\tdefer ss.Unlock()\n\n\tss.sem.Acquire()', 'ss.sem.Acquire()')
text=text.replace('ss.Lock()\n\tdefer ss.Unlock()\n\n\tss.sem.Release()', 'ss.sem.Release()')
text=re.sub(r'func \(s \*Session\) buildNewSessionSemaphore\(\) \{.*?^\}',
            'func (s *Session) buildNewSessionSemaphore() { /* fixed profile: never resize */ }',text,flags=re.S|re.M)
session.write_text(text)
(source/'.dockerignore').write_text('.git\n')
(root/'output/dist-release/amass-profile-source.txt').write_text('Upstream commit: '+commit+'\nProfile: only api.NewCrtsh; network semaphore=1, no resize, direct acquire/release.\n')
print('Amass crt.sh-only build context ready:',commit)
