"""Bundle only stdlib Python for the zero-capability MCP AppContainer, no site packages."""
from pathlib import Path
import shutil
import sys
import zipfile

root=Path(__file__).resolve().parents[1]
target=root/'output/windows-build/fixture-python'
target.mkdir(parents=True,exist_ok=True)
base=Path(sys.base_prefix)
for file in [base/'python.exe',*base.glob('*.dll')]:shutil.copy2(file,target/file.name)
(target/'DLLs').mkdir(exist_ok=True)
for file in (base/'DLLs').iterdir():
    if file.suffix.lower() in ('.pyd','.dll'):shutil.copy2(file,target/'DLLs'/file.name)
skip={'site-packages','test','idlelib','tkinter','turtledemo','ensurepip','venv','lib2to3','__pycache__'}
with zipfile.ZipFile(target/'stdlib.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
    for file in (base/'Lib').rglob('*.py'):
        rel=file.relative_to(base/'Lib')
        if not any(part in skip for part in rel.parts):archive.write(file,rel.as_posix())
print('Isolated stdlib runtime prepared:',target)
