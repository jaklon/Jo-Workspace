"""Exercise local UI at desktop, tablet and mobile sizes using an isolated QA server."""
import json
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE='http://127.0.0.1:18337'
TOKEN='qa-local-token-jo-workspace-123456789'
OUT=Path('output/qa-responsive/screens')
OUT.mkdir(parents=True,exist_ok=True)
SECTIONS=['Umum','Tampilan','Personalisasi','Model & inferensi','Koneksi','Kontrol data','Privasi & keamanan','Pintasan','Tentang']
sys.stdout.reconfigure(encoding='utf-8')

def snapshot(page,name,issues):
    page.wait_for_timeout(200)
    page.screenshot(path=str(OUT/(name+'.png')))
    state=page.evaluate('''() => ({title:document.title, width:innerWidth, documentWidth:document.documentElement.scrollWidth,
      offenders:[...document.querySelectorAll('body *')].filter(e=>{
        const s=getComputedStyle(e),r=e.getBoundingClientRect();
        return r.width>0 && r.height>0 && e.scrollWidth>e.clientWidth+3 &&
          !['auto','scroll','hidden','clip'].includes(s.overflowX) && e.clientWidth>20
      }).slice(0,20).map(e=>({tag:e.tagName,cls:String(e.className).slice(0,100),client:e.clientWidth,scroll:e.scrollWidth,text:(e.innerText||'').slice(0,90)}))})''')
    if state['documentWidth']>state['width']+1 or state['offenders']:
        issues.append({'view':name,**state})
    print(name,json.dumps(state,ensure_ascii=False),flush=True)

def main():
    issues=[]; errors=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True,args=['--disable-gpu'])
        for name,width,height in [('desktop',1440,900),('tablet',768,1024),('mobile',390,844),('small-mobile',320,640)]:
            context=browser.new_context(viewport={'width':width,'height':height},device_scale_factor=1)
            page=context.new_page()
            page.on('pageerror',lambda error: errors.append(str(error)))
            page.goto(BASE,wait_until='domcontentloaded')
            page.get_by_label('Token akses').wait_for(timeout=15000)
            snapshot(page,name+'-connection',issues)
            page.get_by_label('Token akses').fill(TOKEN)
            page.get_by_role('button',name='Hubungkan',exact=True).click()
            page.get_by_label('Buka Settings').wait_for(timeout=15000)
            snapshot(page,name+'-chat',issues)
            for mode in ['code','vision','docs','chat']:
                page.get_by_label('Pilih mode').select_option(mode)
                snapshot(page,name+'-mode-'+mode,issues)
            page.get_by_label('Buka Settings').click()
            for section in SECTIONS:
                page.get_by_role('button',name=section,exact=True).click()
                snapshot(page,name+'-settings-'+section.replace(' ','-').replace('&','and'),issues)
                if section=='Tampilan':
                    page.get_by_role('button',name='Terang',exact=True).click()
                    snapshot(page,name+'-light-settings',issues)
                    page.get_by_role('button',name='Gelap',exact=True).click()
            page.keyboard.press('Escape')
            if page.get_by_label('Buka Settings').is_visible() is False:
                page.get_by_label('Tutup').first.click()
            page.get_by_label('Buka Usage').click()
            snapshot(page,name+'-usage',issues)
            if width<1024:page.get_by_label('Buka sidebar').click()
            page.get_by_role('button',name='Cari web & gambar').click()
            snapshot(page,name+'-search',issues)
            if width<1024:page.get_by_label('Buka sidebar').click()
            page.get_by_role('button',name='Security Workspace').click()
            snapshot(page,name+'-security',issues)
            page.get_by_role('button',name='Project baru',exact=True).click()
            snapshot(page,name+'-project-dialog',issues)
            page.get_by_label('Nama project').fill('QA '+name)
            page.get_by_role('dialog',name='Project baru').get_by_role('button',name='Buat project',exact=True).click()
            selector=page.get_by_label('Project Security Workspace')
            selector.select_option(label='QA '+name)
            project=selector.input_value()
            page.get_by_role('button',name='Engagement baru',exact=True).click()
            snapshot(page,name+'-engagement-editor',issues)
            row=page.request.post(BASE+'/api/security/projects/'+project+'/engagements',data={'content':{'name':'QA fixture'}})
            if row.status!=201: raise AssertionError('Failed to create isolated engagement: '+row.text())
            page.get_by_role('button',name='Batal edit').click()
            page.get_by_role('button',name='Muat ulang',exact=True).click()
            for tab in ['Scope, RoE & Policy','Runs · offline','Pemeriksaan URL','Deep Analisis','Tools & monitoring','Evidence','Findings','Reports','MCP Integrations','Orkestrasi','Agents']:
                page.get_by_role('tab',name=tab,exact=True).click(timeout=10000)
                page.locator('.security-workspace').evaluate('(e) => e.scrollTop=0')
                snapshot(page,name+'-security-'+tab.replace(' ','-').replace('&','and').replace('·',''),issues)
            context.close()
        browser.close()
    Path('output/qa-responsive/issues.json').write_text(json.dumps({'layout':issues,'page_errors':errors},ensure_ascii=False,indent=2),encoding='utf-8')
    print('ISSUE_COUNT',len(issues),'PAGE_ERRORS',len(errors),flush=True)
    if issues or errors:
        raise SystemExit('Responsive QA detected layout or page errors; see output/qa-responsive/issues.json')

if __name__=='__main__':main()
