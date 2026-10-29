"""Derive native packaging icons from the supplied Jo Workspace artwork."""
from pathlib import Path
from PIL import Image
root=Path(__file__).resolve().parents[1]/'desktop-app'
source=Image.open(root/'src/renderer/src/assets/jo-workspace-logo.jpg').convert('RGB')
w,h=source.size
# Same monogram viewport used by the frontend; keep the supplied source untouched.
image=source.crop((int(w*.33),int(h*.27),int(w*.69),int(h*.59))).resize((512,512),Image.Resampling.LANCZOS)
image.save(root/'resources/agent-os.png')
(root/'build').mkdir(exist_ok=True)
image.save(root/'build/agent-os.ico',sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
