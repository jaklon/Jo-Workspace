import { useEffect, useState, type JSX } from 'react'
import { apiFetch } from '../lib/api'
import type { Engagement } from '../lib/engagements'
import type { SecurityJob } from '../lib/securityJobs'

export function TCPScan({ engagement }: { engagement: Engagement }): JSX.Element {
  const base = `/api/security/projects/${engagement.project_id}/engagements/${engagement.id}/jobs`
  const [ip, setIp] = useState('')
  const [ports, setPorts] = useState('443')
  const [tool, setTool] = useState('tcp-connect')
  const [hash, setHash] = useState('')
  const [nucleiHash, setNucleiHash] = useState('')
  const [zapHash, setZapHash] = useState('')
  const [subfinderHash, setSubfinderHash] = useState('')
  const [amassHash, setAmassHash] = useState('')
  const [disclosure, setDisclosure] = useState(false)
  const [accountA, setAccountA] = useState('')
  const [accountB, setAccountB] = useState('')
  const [ownerPointer, setOwnerPointer] = useState('')
  const [tokenA, setTokenA] = useState('')
  const [tokenB, setTokenB] = useState('')
  const [actor, setActor] = useState('')
  const [note, setNote] = useState('')
  const [ack, setAck] = useState(false)
  const [items, setItems] = useState<SecurityJob[]>([])
  const [job, setJob] = useState<SecurityJob | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const load = async (): Promise<void> => {
    const data = await (await apiFetch(base)).json()
    setItems((data.items as SecurityJob[]).filter((item) => item.plan.scan))
  }
  useEffect(() => {
    void load().catch((e) => setError(String(e)))
    void apiFetch('/api/pentest/capabilities').then((r) => r.json()).then((data) => { setHash(data.nmap_binary_sha256 || ''); setNucleiHash(data.nuclei_binary_sha256 || ''); setZapHash(data.zap_image_sha256 || ''); setSubfinderHash(data.subfinder_image_sha256 || ''); setAmassHash(data.amass_image_sha256 || '') }).catch((e) => setError(String(e)))
  }, [base])
  useEffect(() => { setTokenA(''); setTokenB('') }, [base, job?.id])
  useEffect(() => {
    if (!job || !['queued', 'running'].includes(job.status)) return
    const timer = window.setInterval(() => {
      void apiFetch(`${base}/${job.id}`).then((r) => r.json()).then((data: SecurityJob) => { setJob(data); if (!['queued', 'running'].includes(data.status)) void load() }).catch((e) => setError(String(e)))
    }, 1000)
    return () => window.clearInterval(timer)
  }, [base, job?.id, job?.status])
  const act = async (path: string, payload: unknown): Promise<void> => {
    setBusy(true); setError('')
    try { setJob(await (await apiFetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })).json()); setAck(false); await load() }
    catch (e) { setError(String(e)) } finally { setBusy(false) }
  }
  const head = engagement.versions[0]
  const httpTool = tool === 'nuclei-head' || tool === 'zap-head' || tool === 'auth-unauthenticated-get' || tool === 'auth-two-session' || tool === 'inventory-html' || tool === 'js-bundle-inventory' || tool === 'scoped-spider' || tool === 'active-reflection'
  const passiveTool = tool === 'subfinder-passive' || tool === 'amass-passive'
  const duration = tool === 'zap-head' ? 3 : tool === 'amass-passive' ? 4 : tool === 'subfinder-passive' ? 2 : 1
  return <section className="security-jobs" aria-label="TCP Scan">
    <h3>Tools dan monitoring · run yang disetujui</h3>
    <p>Setiap profil membatasi target, jenis request dan durasi. TCP memakai satu IP dan maksimal 16 port; adapter lain dijelaskan di bawah. Persetujuan per run dan RoE aktif wajib.</p>
    <label className="field-block">{httpTool ? 'URL domain atau IP' : passiveTool ? 'Domain target' : 'IP target'}<input value={ip} onChange={(e) => setIp(e.target.value)} placeholder={httpTool ? 'https://domain-milik-anda/' : passiveTool ? 'domain milik Anda dalam scope' : 'IP eksplisit dalam scope'} /></label>
    <label className="field-block">Port, pisahkan koma<input value={ports} onChange={(e) => setPorts(e.target.value)} /></label>
    <label className="field-block">Adapter<select value={tool} onChange={(e) => { setTool(e.target.value); setDisclosure(false); if (e.target.value === 'monitoring-local') { setIp('127.0.0.1'); setPorts('3000,9090') } if (['subfinder-passive','amass-passive'].includes(e.target.value)) setPorts('443') }}><option value="tcp-connect">TCP connect bawaan</option><option value="nmap" disabled={!hash}>Nmap · connect scan {hash ? '' : '(belum terpasang)'}</option><option value="nuclei-head" disabled={!nucleiHash}>Nuclei · template HEAD CSP {nucleiHash ? '' : '(belum terpasang)'}</option><option value="zap-head" disabled={!zapHash}>ZAP · review pasif header {zapHash ? '' : '(image belum tersedia)'}</option><option value="subfinder-passive" disabled={!subfinderHash}>Subfinder · pasif crt.sh {subfinderHash ? '' : '(image belum tersedia)'}</option><option value="amass-passive" disabled={!amassHash}>Amass · profil crt.sh-only {amassHash ? '' : '(image belum tersedia)'}</option><option value="scoped-spider">Spider terbatas · maksimal 5 halaman</option><option value="active-reflection">Scan aktif · marker refleksi aman</option><option value="js-bundle-inventory">Inventaris bundle JavaScript</option><option value="inventory-html">Inventaris tautan HTML · GET terbatas</option><option value="auth-two-session">Perbandingan akses · dua akun uji</option><option value="auth-unauthenticated-get">Akses tanpa sesi · GET terbatas</option><option value="monitoring-local">Monitoring lokal · Prometheus/Grafana</option></select></label>
    {tool === 'zap-head' && <p>Satu HEAD diambil oleh adapter lokal, lalu header terpilih dianalisis ZAP di container tanpa jaringan. Tanpa spider atau active scan. Batas 180 detik; RoE memerlukan http_headers dan durasi 3 menit.</p>}
    {passiveTool && <label className="roe-ack"><input type="checkbox" checked={disclosure} onChange={(e) => setDisclosure(e.target.checked)} />Saya mengizinkan domain ini dikirim ke crt.sh. RoE memerlukan passive_recon. Nama hasil tidak otomatis diizinkan untuk scan. Batas {duration * 60} detik.</label>}
    {tool === 'nuclei-head' && <p>Satu template HEAD untuk observasi CSP pada URL domain atau IP, dengan DNS terikat, tanpa redirect atau template pengguna. RoE harus mengizinkan http_headers dan port URL. Tidak ada hasil match dapat berarti target gagal diakses.</p>}
    {tool === 'scoped-spider' && <p>Hingga lima GET same-origin, satu per detik. Setiap halaman diperiksa terhadap scope dan pengecualian; tidak ada JavaScript, form, query atau redirect.</p>}
    {tool === 'active-reflection' && <p>Satu GET dengan marker alfanumerik pada parameter jo_probe. Refleksi tidak membuktikan XSS atau bypass login; isi respons tidak disimpan.</p>}
    {tool === 'js-bundle-inventory' && <p>Satu GET bundle JavaScript eksplisit dalam scope, maksimal 1 MB. Kandidat statis tidak dihubungi dan tidak otomatis diizinkan. Tidak menjalankan JavaScript.</p>}
    {tool === 'inventory-html' && <p>Satu GET HTML tanpa sesi. Hanya asal tautan (origin) dicatat; kandidat layanan tidak dihubungi dan tidak otomatis masuk scope; JavaScript tidak dijalankan.</p>}
    {tool === 'auth-two-session' && <>
      <p>Tiga GET pada URL yang sama: tanpa sesi, akun A, dan akun B. Gunakan token ID staging untuk dua akun berbeda pada project yang sama. Klaim token diperiksa tanpa memverifikasi tanda tangan; server target yang melakukan verifikasi. Token dikirim hanya ke origin yang disetujui, disimpan sementara di memori (antrean maksimal dua menit), lalu dibuang. Isi dan struktur JSON hingga 32 KiB dibandingkan sementara tanpa disimpan; status atau isi yang sama saja bukan bukti bypass.</p>
      <label className="field-block">Alias akun A<select value={accountA} onChange={(e) => setAccountA(e.target.value)}><option value="">Pilih akun A dari RoE</option>{head.content.test_account_refs.map((ref) => <option value={ref} key={ref}>{ref}</option>)}</select></label>
      <label className="field-block">Alias akun B<select value={accountB} onChange={(e) => setAccountB(e.target.value)}><option value="">Pilih akun B dari RoE</option>{head.content.test_account_refs.map((ref) => <option value={ref} key={ref}>{ref}</option>)}</select></label>
      <label className="field-block">Field pemilik dalam JSON (opsional, JSON Pointer)<input value={ownerPointer} maxLength={256} onChange={(e) => setOwnerPointer(e.target.value)} placeholder="/ownerId atau /data/ownerId" /></label>
      <p>Jika diisi, nilai field dibandingkan di memori dengan klaim sub kedua token. Klaim tidak diverifikasi oleh Jo Workspace dan kecocokan bukan bukti kepemilikan atau bypass; pastikan field memang berisi ID akun staging.</p>
    </>}
    {tool === 'auth-unauthenticated-get' && <p>Satu GET tanpa cookie/token, tanpa membaca body atau mengikuti redirect. Status 200 belum membuktikan bypass. RoE memerlukan unauthenticated_access_check.</p>}
    {tool === 'monitoring-local' && <p>Monitoring lokal harus sudah berjalan. RoE lab harus mencakup 127.0.0.1, port 3000/9090 dan monitoring_read. Run membaca status, tanpa login. Dashboard: http://127.0.0.1:3000/d/jo-health</p>}
    <button className="primary-button" disabled={busy || !ip || head.status !== 'approved' || (passiveTool && !disclosure) || (tool === 'auth-two-session' && (!accountA || !accountB || accountA === accountB))} onClick={() => void act(base, {
      name: 'Approved adapter · ' + tool, expected_roe_revision: engagement.revision, roe_version: head.version, content_hash: head.content_hash,
      scan: { tool, binary_sha256: tool === 'nmap' ? hash : tool === 'nuclei-head' ? nucleiHash : tool === 'zap-head' ? zapHash : tool === 'subfinder-passive' ? subfinderHash : tool === 'amass-passive' ? amassHash : '', provider_disclosure: passiveTool && disclosure, account_refs: tool === 'auth-two-session' ? [accountA, accountB] : [], owner_json_pointer: tool === 'auth-two-session' ? ownerPointer.trim() : '' }, wall_timeout_seconds: duration * 60, max_output_kb: 64,
      steps: [{ target: { kind: httpTool ? 'url' : passiveTool ? 'domain' : 'ip', value: ip.trim() }, action: tool === 'monitoring-local' ? 'monitoring_read' : tool === 'scoped-spider' ? 'scoped_spider' : tool === 'active-reflection' ? 'active_reflection' : (tool === 'inventory-html' || tool === 'js-bundle-inventory') ? 'service_inventory' : tool === 'auth-two-session' ? 'authenticated_api_review' : tool === 'auth-unauthenticated-get' ? 'unauthenticated_access_check' : httpTool ? 'http_headers' : passiveTool ? 'passive_recon' : 'tcp_discovery', ports: ports.split(',').map((s) => Number(s.trim())), max_http_rps: 1, max_concurrency: 1, max_duration_minutes: duration, test_account_ref: tool === 'auth-two-session' ? accountA : '' }]
    })}>Siapkan rencana</button>
    {error && <p role="alert">{error}</p>}
    <h4>Riwayat scan</h4>
    {items.map((item) => <button className="secondary-button" key={item.id} onClick={() => { setAck(false); void apiFetch(`${base}/${item.id}`).then((r) => r.json()).then(setJob).catch((e) => setError(String(e))) }}>{item.plan.steps[0].target.value} · {item.status}</button>)}
    {job && <article className="security-card">
      <h4>{job.status} · {job.plan.steps[0].target.value}</h4>
      <p>Tool: {job.plan.scan?.tool} · port: {job.plan.steps[0].ports.join(', ')} · RoE v{job.plan.roe_version}</p>
      <p>Batas run: {job.plan.wall_timeout_seconds} detik · concurrency/RPS: 1. {job.plan.scan?.provider_disclosure ? 'Domain dikirim ke crt.sh; hasil tidak mengubah izin scope.' : ''}</p>
      <p className="record-hash">Hash rencana: {job.plan_hash}<br />Hash RoE: {job.plan.content_hash}<br />Identitas binary/image: {job.plan.scan?.binary_sha256 || 'adapter bawaan'}</p>
      {job.status === 'awaiting_approval' && <>
        <label className="field-block">Peninjau<input value={actor} maxLength={120} onChange={(e) => setActor(e.target.value)} /></label>
        <label className="field-block">Catatan persetujuan<textarea value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} /></label>
        {job.plan.scan?.tool === 'auth-two-session' && <>
          <p>Masukkan token ID sementara milik dua akun staging pada perangkat ini. Jangan gunakan password; token tidak dikirim ke LLM atau disimpan dalam laporan.</p>
          <label className="field-block">Token sementara {job.plan.scan.account_refs?.[0]}<input type="password" autoComplete="off" value={tokenA} onChange={(e) => setTokenA(e.target.value)} /></label>
          <label className="field-block">Token sementara {job.plan.scan.account_refs?.[1]}<input type="password" autoComplete="off" value={tokenB} onChange={(e) => setTokenB(e.target.value)} /></label>
        </>}
        <label className="roe-ack"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />Saya berwenang dan menyetujui tool, URL, port serta batas run ini.</label>
        <button className="primary-button" disabled={busy || !ack || !actor.trim() || !note.trim() || (job.plan.scan?.tool === 'auth-two-session' && (!tokenA || !tokenB))} onClick={() => {
          const sessions=job.plan.scan?.tool === 'auth-two-session' ? [tokenA,tokenB] : undefined
          setTokenA('');setTokenB('')
          void act(`${base}/${job.id}/approve`, { expected_revision: job.revision, actor_label: actor, note, acknowledge: ack, ...(sessions ? {session_tokens:sessions} : {}) })
        }}>Setujui dan jalankan</button>
      </>}
      {['awaiting_approval','queued','running'].includes(job.status) && <button className="secondary-button" disabled={busy} onClick={() => void act(`${base}/${job.id}/stop`, { actor_label: actor || 'operator-lokal', note: 'Stop eksplisit.' })}>Hentikan</button>}
      {job.error_message && <p role="alert">{job.error_message}</p>}
      {job.scan_result && <><pre className="record-output">{JSON.stringify(job.scan_result, null, 2)}</pre><p>Evidence tersimpan; pilih run ini pada Deep Analisis.</p></>}
    </article>}
  </section>
}

