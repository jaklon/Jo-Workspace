import { useEffect, useState, type JSX } from 'react'
import { apiFetch } from '../lib/api'
import type { Engagement } from '../lib/engagements'
import type { SecurityJob } from '../lib/securityJobs'
import type { Evidence, RecordsListing } from '../lib/securityEvidence'
import { downloadFile } from '../lib/preferences'

type Report = {
  id: string
  created_at: string
  model: string
  assessment_mode?: 'blackbox' | 'whitebox' | 'greybox'
  context_note?: string
  source: { evidence_id: string; target: { value: string }; artifact_hash: string; result: { kind?: string } }
  output: { summary: string; observations: string[]; limitations: string[]; recommendations: string[] }
}
type ToolStatus = { name: string; installed: boolean | null; execution_enabled: boolean; reason: string }
const modes = {
  blackbox: { label: 'BlackBox', description: 'Observasi eksternal tanpa akses internal atau akun uji.', kinds: ['external_observation'] },
  whitebox: { label: 'WhiteBox', description: 'Review kode sumber, konfigurasi, dokumentasi, dan monitoring yang diimpor.', kinds: ['source_code', 'configuration', 'api_documentation', 'monitoring'] },
  greybox: { label: 'GreyBox', description: 'Review evidence dengan akses terbatas dan alias akun uji dalam RoE.', kinds: ['api_documentation', 'authenticated_observation', 'configuration'] }
}
const kindLabels: Record<string, string> = { external_observation: 'Observasi eksternal', source_code: 'Kode sumber', configuration: 'Konfigurasi', api_documentation: 'Dokumentasi API', authenticated_observation: 'Observasi akun uji', monitoring: 'Monitoring / log' }

export function DeepAnalysis({ engagement }: { engagement: Engagement }): JSX.Element {
  const base = `/api/security/projects/${engagement.project_id}/engagements/${engagement.id}`
  const [jobs, setJobs] = useState<SecurityJob[]>([])
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [evidenceId, setEvidenceId] = useState('')
  const [models, setModels] = useState<{ name: string }[]>([])
  const [reports, setReports] = useState<Report[]>([])
  const [tools, setTools] = useState<ToolStatus[]>([])
  const [job, setJob] = useState('')
  const [model, setModel] = useState('')
  const [actor, setActor] = useState('')
  const [ack, setAck] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [mode, setMode] = useState<keyof typeof modes>('blackbox')
  const [kind, setKind] = useState('external_observation')
  const [account, setAccount] = useState('')

  const load = async (): Promise<void> => {
    const [j, a, records, capabilities] = await Promise.all([
      apiFetch(`${base}/jobs`).then((r) => r.json()),
      apiFetch(`${base}/deep-analysis`).then((r) => r.json()),
      apiFetch(`${base}/records`).then((r) => r.json()) as Promise<RecordsListing>,
      apiFetch(`${base}/deep-analysis/capabilities`).then((r) => r.json())
    ])
    setJobs((j.items as SecurityJob[]).filter((item) => item.status === 'completed'))
    setEvidence(records.evidence.filter((item) => item.provenance === 'operator_declared_import'))
    setReports(a.items as Report[])
    setTools(capabilities.tools as ToolStatus[])
    try {
      const m = await apiFetch('/api/security/orchestration/catalog').then((r) => r.json())
      setModels(m.models as { name: string }[])
    } catch {
      setModels([])
      setError('Model lokal tidak tersedia. Riwayat tetap dapat dibaca; jalankan Ollama untuk analisis baru.')
    }
  }
  useEffect(() => { void load().catch((e) => setError(String(e))) }, [base])
  const run = async (): Promise<void> => {
    setBusy(true); setError('')
    try {
      await apiFetch(`${base}/deep-analysis`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ job_id: job, evidence_id: evidenceId || null, model, actor_label: actor, acknowledge: ack,
          assessment_mode: mode, evidence_kind: kind, test_account_ref: mode === 'greybox' ? account : '' })
      })
      setAck(false)
      await load()
    } catch (e) { setError(String(e)) } finally { setBusy(false) }
  }
  return <section className="security-jobs" aria-label="Deep Analisis">
    <div className="section-title"><h3>Deep Analisis · evidence</h3><span className="planning-badge">Review evidence</span></div>
    <p>Model lokal meninjau hasil HEAD, scan TCP atau evidence impor yang terkait job disetujui. Hasil memerlukan review manusia.</p>
    <p>Impor adalah deklarasi operator dan memerlukan izin document_review. Scan TCP dijalankan melalui tab TCP Scan setelah persetujuan terpisah. Tool lain mengikuti status kemampuan di bawah.</p>
    <label className="field-block">Kategori VA
      <select value={mode} onChange={(e) => { const next = e.target.value as keyof typeof modes; setMode(next); setKind(modes[next].kinds[0]); setAck(false) }}>
        {Object.entries(modes).map(([key, value]) => <option key={key} value={key}>{value.label}</option>)}
      </select>
    </label>
    <p>{modes[mode].description} Kategori ini menentukan konteks analisis; hak eksekusi tetap mengikuti RoE.</p>
    <label className="field-block">Jenis evidence (deklarasi peninjau)
      <select value={kind} onChange={(e) => { setKind(e.target.value); setAck(false) }}>{modes[mode].kinds.map((key) => <option key={key} value={key}>{kindLabels[key]}</option>)}</select>
    </label>
    {mode === 'greybox' && <label className="field-block">Alias akun uji dari RoE
      <select value={account} onChange={(e) => { setAccount(e.target.value); setAck(false) }}><option value="">Pilih alias akun</option>{engagement.versions[0].content.test_account_refs.map((ref) => <option key={ref} value={ref}>{ref}</option>)}</select>
      <small>Hanya alias; jangan masukkan password, token, atau data pengguna asli.</small>
    </label>}
    <details><summary>Status tools dan monitoring</summary>
      <ul>{tools.map((item) => <li key={item.name}>{item.name}: {item.installed === null ? 'status belum diperiksa' : item.installed ? 'tersedia' : 'tidak ditemukan'}. {item.reason}</li>)}</ul>
    </details>
    <label className="field-block">Job selesai dan disetujui
      <select value={job} onChange={(e) => { setJob(e.target.value); setEvidenceId(''); setAck(false) }}><option value="">Pilih job</option>
        {jobs.map((item) => <option key={item.id} value={item.id}>{item.plan.steps[0].target.value} · {item.id}</option>)}
      </select>
    </label>
    <label className="field-block">Evidence untuk dianalisis
      <select value={evidenceId} onChange={(e) => { setEvidenceId(e.target.value); setAck(false) }}>
        <option value="">{jobs.find((item) => item.id === job)?.plan.scan ? 'Hasil scan TCP disetujui' : jobs.find((item) => item.id === job)?.plan.web ? 'Hasil HEAD terverifikasi' : 'Pilih evidence impor'}</option>
        {evidence.filter((item) => item.job_id === job).map((item) => <option key={item.id} value={item.id}>{item.title} · {item.tool_name} · impor operator</option>)}
      </select>
    </label>
    <label className="field-block">Model lokal
      <select value={model} onChange={(e) => { setModel(e.target.value); setAck(false) }}><option value="">Pilih model</option>
        {models.map((item) => <option key={item.name} value={item.name}>{item.name}</option>)}
      </select>
    </label>
    <label className="field-block">Nama peninjau<input maxLength={120} value={actor} onChange={(e) => setActor(e.target.value)} /></label>
    <label className="roe-ack"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />Saya menyetujui analisis lokal atas evidence ini.</label>
    <button className="primary-button" disabled={busy || !job || (mode !== 'blackbox' && !evidenceId) || (mode === 'greybox' && !account) || (!evidenceId && !jobs.find((item) => item.id === job)?.plan.web && !jobs.find((item) => item.id === job)?.plan.scan) || !model || !actor.trim() || !ack} onClick={() => void run()}>{busy ? 'Menganalisis…' : 'Analisis evidence'}</button>
    {error && <p role="alert" className="notice error">{error}</p>}
    <h4>Riwayat analisis</h4>
    {reports.map((report) => <article className="security-card" key={report.id}>
      <h4>{modes[report.assessment_mode || 'blackbox'].label} · {report.source.target.value}</h4>
      <p>{report.created_at} · {report.model} · perlu review manusia</p>
      {report.context_note && <p>{report.context_note}</p>}
      <p>{report.source.result.kind === 'operator_import' ? 'Impor deklarasi operator; pelaksanaan tool tidak diverifikasi.' : 'Hasil adapter pemeriksaan yang disetujui.'}</p>
      <p>Evidence: {report.source.evidence_id} · SHA-256: {report.source.artifact_hash}</p>
      <p>{report.output.summary}</p>
      <strong>Observasi</strong><ul>{report.output.observations.map((x, i) => <li key={i}>{x}</li>)}</ul>
      <strong>Keterbatasan</strong><ul>{report.output.limitations.map((x, i) => <li key={i}>{x}</li>)}</ul>
      <strong>Rekomendasi</strong><ul>{report.output.recommendations.map((x, i) => <li key={i}>{x}</li>)}</ul>
      <button className="secondary-button" onClick={() => downloadFile(`va-${report.id}.json`, JSON.stringify(report, null, 2), 'application/json')}>Unduh laporan VA JSON</button>
    </article>)}
  </section>
}
