import { useEffect, useState, type JSX, type ReactNode } from 'react'
import { Plus, Download, RefreshCw, FileCheck2 } from 'lucide-react'
import { apiFetch } from '../lib/api'
import { engagementPath, type Engagement, type ScopeKind } from '../lib/engagements'
import type { JobsListing, SecurityJob } from '../lib/securityJobs'
import { downloadFile } from '../lib/preferences'
import { Modal } from './Modal'
import {
  sourceLabels,
  findingLabels,
  emptyFinding,
  type Evidence,
  type EvidenceSource,
  type Finding,
  type FindingContent,
  type FindingStatus,
  type RecordsListing,
  type SecurityReport
} from '../lib/securityEvidence'

type View = 'evidence' | 'findings' | 'reports'
type ImportDraft = {
  job_id: string
  step_ordinal: number
  source: EvidenceSource
  title: string
  captured_at: string
  tool_name: string
  tool_version: string
  parameters: string
  content: string
}
const initialImport = (): ImportDraft => ({
  job_id: '',
  step_ordinal: 1,
  source: 'offline_policy' as EvidenceSource,
  title: '',
  captured_at: new Date().toISOString(),
  tool_name: '',
  tool_version: '',
  parameters: '',
  content: ''
})
function Field({ label, children }: { label: string; children: ReactNode }): JSX.Element {
  return (
    <label className="field-block">
      {label}
      {children}
    </label>
  )
}
function Json({ value }: { value: unknown }): JSX.Element {
  return <pre className="record-output">{JSON.stringify(value, null, 2)}</pre>
}
function Save({
  busy,
  disabled = false,
  children
}: {
  busy: boolean
  disabled?: boolean
  children: ReactNode
}): JSX.Element {
  return (
    <button className="primary-button" disabled={busy || disabled} type="submit">
      {busy ? 'Menyimpan…' : children}
    </button>
  )
}
export function SecurityRecords({
  engagement,
  view
}: {
  engagement: Engagement
  view: View
}): JSX.Element {
  const path = engagementPath(engagement.project_id, engagement.id)
  const [records, setRecords] = useState<RecordsListing | null>(null)
  const [jobs, setJobs] = useState<SecurityJob[]>([])
  const [job, setJob] = useState<SecurityJob | null>(null)
  const [evidence, setEvidence] = useState<Evidence | null>(null)
  const [finding, setFinding] = useState<Finding | null>(null)
  const [report, setReport] = useState<SecurityReport | null>(null)
  const [modal, setModal] = useState<
    'import' | 'finding' | 'review' | 'report' | 'original' | null
  >(null)
  const [importDraft, setImportDraft] = useState(initialImport)
  const [draft, setDraft] = useState<FindingContent>(emptyFinding)
  const [editing, setEditing] = useState<Finding | null>(null)
  const [terms, setTerms] = useState('')
  const [actor, setActor] = useState('')
  const [note, setNote] = useState('')
  const [ack, setAck] = useState(false)
  const [status, setStatus] = useState<FindingStatus>('validated')
  const [retests, setRetests] = useState<string[]>([])
  const [reportTitle, setReportTitle] = useState('')
  const [filter, setFilter] = useState('')
  const [query, setQuery] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [refresh, setRefresh] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    void Promise.all([
      apiFetch(path + '/records', { signal: controller.signal }).then((r) => r.json()),
      apiFetch(path + '/jobs', { signal: controller.signal }).then((r) => r.json())
    ])
      .then(([data, listing]: [RecordsListing, JobsListing]) => {
        if (!controller.signal.aborted) {
          setRecords(data)
          setJobs(listing.items)
        }
      })
      .catch((e) => {
        if (!controller.signal.aborted) setError(e.message)
      })
    return () => controller.abort()
  }, [path, refresh])
  useEffect(() => {
    if (!importDraft.job_id) return
    const controller = new AbortController()
    void apiFetch(path + '/jobs/' + importDraft.job_id, { signal: controller.signal })
      .then((r) => r.json())
      .then((j: SecurityJob) => {
        if (!controller.signal.aborted) setJob(j)
      })
      .catch((e) => {
        if (!controller.signal.aborted) setError(e.message)
      })
    return () => controller.abort()
  }, [path, importDraft.job_id])
  const fetchRecord = async <T,>(endpoint: string): Promise<T> =>
    (await apiFetch(path + endpoint)).json()
  const mutate = async <T,>(endpoint: string, body: unknown, method = 'POST'): Promise<T> =>
    (
      await apiFetch(path + endpoint, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      })
    ).json()
  const operate = async (action: () => Promise<void>): Promise<void> => {
    setBusy(true)
    setError('')
    try {
      await action()
      setRefresh((v) => v + 1)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Operasi gagal.')
    } finally {
      setBusy(false)
    }
  }
  const open = (next: typeof modal): void => {
    setModal(next)
    setTerms('')
    setActor('')
    setNote('')
    setAck(false)
    setError('')
  }
  const change = (value: Partial<FindingContent>): void => setDraft((old) => ({ ...old, ...value }))
  const toggle = (ids: string[], id: string): string[] =>
    ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id]
  const exportJson = (value: unknown, name: string): void =>
    downloadFile(name + '.json', JSON.stringify(value, null, 2), 'application/json')
  const readyJobs = jobs.filter(
    (j) => j.progress > 0 && ['completed', 'failed', 'cancelled'].includes(j.status)
  )
  const evidenceChoices = records?.evidence || []
  const label = { evidence: 'Evidence', findings: 'Findings', reports: 'Reports' }[view]
  return (
    <section className="security-records" aria-label={label}>
      <div className="section-title">
        <h3>
          <FileCheck2 size={18} />
          {label}
        </h3>
        <span className="planning-badge">Pentest terkunci</span>
      </div>
      <p className="notice">
        Bukti, interpretasi AI, dan keputusan analis disimpan terpisah. Semua impor adalah deklarasi
        lokal. Fixture bukan bukti target nyata; policy offline saja tidak dapat memvalidasi
        kerentanan.
      </p>
      <p className="muted-text">
        Sensor otomatis bersifat best effort. Tambahkan istilah sensor untuk data khusus dan periksa
        artefak sebelum membagikan laporan. Tampilan/laporan memakai teks tersensor; arsip asli baru
        pada Windows dienkripsi untuk akun lokal.
      </p>
      <div className="roe-decision-actions">
        <button
          className="primary-button"
          disabled={busy || !records}
          onClick={() => {
            if (view === 'evidence') {
              setJob(null)
              setImportDraft(initialImport())
              open('import')
            }
            if (view === 'findings') {
              setDraft(emptyFinding())
              setEditing(null)
              open('finding')
            }
            if (view === 'reports') {
              setReportTitle('Laporan ' + engagement.versions[0].content.name)
              open('report')
            }
          }}
        >
          <Plus size={14} />
          {view === 'evidence'
            ? 'Tambah evidence'
            : view === 'findings'
              ? 'Finding baru'
              : 'Buat snapshot laporan'}
        </button>
        <button
          className="secondary-button"
          disabled={busy}
          onClick={() => {
            setError('')
            setFinding(null)
            setEvidence(null)
            setReport(null)
            setRefresh((v) => v + 1)
          }}
        >
          <RefreshCw size={14} />
          Muat ulang catatan
        </button>
        <small>
          {records
            ? `${records.evidence.length}/100 evidence · ${records.findings.length}/100 findings · ${records.reports.length}/30 laporan`
            : 'Memuat…'}
        </small>
      </div>
      {error && !modal && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
      {view === 'evidence' && (
        <>
          {!records?.evidence.length && (
            <p>
              Belum ada evidence. Selesaikan validasi offline pada Runs, lalu simpan hasil policy
              atau impor bukti teks dari fixture/hasil eksternal.
            </p>
          )}
          <div className="record-list">
            {records?.evidence.map((e) => (
              <button
                className={evidence?.id === e.id ? 'selected' : ''}
                key={e.id}
                disabled={busy}
                onClick={() =>
                  void operate(async () => setEvidence(await fetchRecord('/evidence/' + e.id)))
                }
              >
                <strong>{e.title}</strong>
                <small>{sourceLabels[e.source]}</small>
                <small>
                  {e.target.value} · {e.artifact_bytes} byte · {e.redactions} sensor
                </small>
              </button>
            ))}
          </div>
          {evidence && (
            <article className="record-detail">
              <h4>{evidence.title}</h4>
              <p>{sourceLabels[evidence.source]}</p>
              <div className="roe-decision-actions">
                <button
                  className="secondary-button"
                  onClick={() => exportJson(evidence, 'evidence-' + evidence.id)}
                >
                  <Download size={14} />
                  Ekspor evidence JSON
                </button>
                <button
                  className="secondary-button"
                  onClick={() =>
                    downloadFile(
                      'evidence-' + evidence.id + '.txt',
                      evidence.content || '',
                      'text/plain'
                    )
                  }
                >
                  Unduh teks tersensor
                </button>
                {evidence.original_available && (
                  <button className="secondary-button" onClick={() => open('original')}>
                    Unduh asli · konfirmasi khusus
                  </button>
                )}
              </div>
              <dl className="roe-grid">
                <dt>Run / langkah</dt>
                <dd>
                  {evidence.job_id} / {evidence.step_ordinal}
                </dd>
                <dt>Target</dt>
                <dd>{evidence.target.value}</dd>
                <dt>Tool / versi (deklarasi untuk impor)</dt>
                <dd>
                  {evidence.tool_name} / {evidence.tool_version}
                </dd>
                <dt>Waktu pengambilan</dt>
                <dd>{evidence.captured_at}</dd>
                <dt>Policy historis</dt>
                <dd>
                  {evidence.policy?.decision} · RoE v{evidence.roe_version}
                </dd>
                <dt>Sensor</dt>
                <dd>
                  {evidence.redactions} penggantian · integritas {evidence.integrity}
                </dd>
              </dl>
              <p className="record-hash">
                SHA-256 asli: {evidence.original_hash}
                <br />
                SHA-256 artefak tersensor: {evidence.artifact_hash}
                <br />
                Hash record: {evidence.record_hash}
              </p>
              {Boolean(evidence.mcp) && (
                <>
                  <h4>Provenance MCP fixture</h4>
                  <p>Dibuat oleh runner terisolasi; bukan hasil pentest target nyata.</p>
                  <Json value={evidence.mcp} />
                </>
              )}
              <h4>Parameter {evidence.mcp ? '(fixture offline)' : '(tidak dieksekusi)'}</h4>
              <pre className="record-output">{evidence.parameters}</pre>
              <h4>Artefak tersensor · terpisah dari interpretasi</h4>
              <pre className="record-output">{evidence.content}</pre>
              <details>
                <summary>Keputusan policy lengkap</summary>
                <Json value={evidence.policy} />
              </details>
            </article>
          )}
        </>
      )}
      {view === 'findings' && (
        <>
          <div className="record-filters">
            <Field label="Cari findings">
              <input value={query} onChange={(e) => setQuery(e.target.value)} />
            </Field>
            <Field label="Filter status finding">
              <select value={filter} onChange={(e) => setFilter(e.target.value)}>
                <option value="">Semua status</option>
                {Object.entries(findingLabels).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <div className="record-list">
            {records?.findings
              .filter(
                (f) =>
                  (!filter || f.status === filter) &&
                  (f.content.title + ' ' + f.content.target.value)
                    .toLowerCase()
                    .includes(query.toLowerCase())
              )
              .map((f) => (
                <button
                  key={f.id}
                  className={finding?.id === f.id ? 'selected' : ''}
                  disabled={busy}
                  onClick={() =>
                    void operate(async () => setFinding(await fetchRecord('/findings/' + f.id)))
                  }
                >
                  <strong>{f.content.title}</strong>
                  <span>
                    {findingLabels[f.status]} · {f.content.severity}
                  </span>
                  <small>
                    {f.content.target.value} · {f.content.assignee || 'Belum ada penanggung jawab'}
                  </small>
                  {f.content.duplicate_of && <small>Duplikat dari {f.content.duplicate_of}</small>}
                </button>
              ))}
          </div>
          {!records?.findings.length && (
            <p>Belum ada finding. Temuan baru selalu Candidate; narasi AI tidak mengubah status.</p>
          )}
          {finding && (
            <article className="record-detail">
              <h4>{finding.content.title}</h4>
              <p>
                {findingLabels[finding.status]} · revisi {finding.revision} · {finding.id}
              </p>
              <div className="roe-decision-actions">
                <button
                  className="secondary-button"
                  disabled={busy}
                  onClick={() => {
                    setDraft(finding.content)
                    setEditing(finding)
                    open('finding')
                  }}
                >
                  Edit dan tinjau ulang
                </button>
                <button
                  className="primary-button"
                  disabled={busy}
                  onClick={() => {
                    setStatus(finding.status === 'candidate' ? 'validated' : 'candidate')
                    setRetests([])
                    open('review')
                  }}
                >
                  Keputusan analis
                </button>
                <button
                  className="secondary-button"
                  onClick={() => exportJson(finding, 'finding-' + finding.id)}
                >
                  <Download size={14} />
                  Ekspor finding
                </button>
              </div>
              <dl className="roe-grid">
                <dt>Target / kategori</dt>
                <dd>
                  {finding.content.target.value} / {finding.content.category}
                </dd>
                <dt>Penanggung jawab</dt>
                <dd>{finding.content.assignee || 'Belum diisi'}</dd>
                <dt>Severity</dt>
                <dd>
                  {finding.content.severity}: {finding.content.severity_reason || 'Belum dinilai'}
                </dd>
                <dt>CVSS 3.1 Base</dt>
                <dd>
                  {finding.content.cvss_score ?? 'Tidak dinilai'} · {finding.content.cvss_vector}
                  <br />
                  {finding.content.cvss_reason}
                </dd>
                <dt>Duplikat dari</dt>
                <dd>{finding.content.duplicate_of || 'Tidak ada'}</dd>
              </dl>
              <h4>Deskripsi kandidat</h4>
              <pre className="record-output">{finding.content.description}</pre>
              <h4>Interpretasi AI · belum diverifikasi</h4>
              <pre className="record-output">
                {finding.content.ai_interpretation ||
                  'Tidak ada interpretasi AI. Tidak ada model dipanggil.'}
              </pre>
              <h4>Keputusan analis · deklarasi lokal</h4>
              <pre className="record-output">
                {finding.review
                  ? `${finding.review.actor_label} · ${finding.review.at}\n${finding.review.analyst_assessment}`
                  : 'Belum ditinjau.'}
              </pre>
              <h4>Remediasi</h4>
              <pre className="record-output">{finding.content.remediation || 'Belum diisi'}</pre>
              <h4>Bukti terkait</h4>
              <ul>
                {[...finding.content.evidence_ids, ...finding.retest_evidence_ids].map((id) => {
                  const e = evidenceChoices.find((x) => x.id === id)
                  return (
                    <li key={id}>
                      {e?.title || id} · {e ? sourceLabels[e.source] : ''} · {id}
                      {finding.retest_evidence_ids.includes(id) ? ' · RETEST' : ''}
                    </li>
                  )
                })}
              </ul>
              <details>
                <summary>Riwayat snapshot finding ({finding.history?.length || 0})</summary>
                {finding.history?.map((h) => (
                  <details key={h.revision}>
                    <summary>
                      Revisi {h.revision} · {findingLabels[h.snapshot.status]}
                    </summary>
                    <p className="record-hash">{h.hash}</p>
                    <Json value={h.snapshot} />
                  </details>
                ))}
              </details>
            </article>
          )}
        </>
      )}
      {view === 'reports' && (
        <>
          <p>
            Snapshot laporan bersifat tetap. Perubahan finding berikutnya memerlukan laporan baru;
            versi lama dapat dibandingkan melalui hash dan revisi.
          </p>
          <div className="record-list">
            {records?.reports.map((r) => (
              <button
                key={r.id}
                disabled={busy}
                onClick={() =>
                  void operate(async () => setReport(await fetchRecord('/reports/' + r.id)))
                }
              >
                <strong>{r.title}</strong>
                <small>{r.created_at}</small>
                <small>{r.id}</small>
              </button>
            ))}
          </div>
          {report && (
            <article className="record-detail">
              <h4>{report.snapshot.title}</h4>
              <p>
                {report.snapshot.created_at} · {report.snapshot.author_declaration} (deklarasi
                lokal)
              </p>
              <pre className="record-output">{report.snapshot.summary}</pre>
              <p>
                {report.snapshot.evidence.length} evidence · {report.snapshot.findings.length}{' '}
                findings · RoE v{report.snapshot.roe_version}
              </p>
              <p className="record-hash">SHA-256 snapshot: {report.hash}</p>
              <div className="roe-decision-actions">
                <button
                  className="primary-button"
                  onClick={() =>
                    downloadFile(
                      'report-' + report.snapshot.id + '.md',
                      report.markdown,
                      'text/markdown'
                    )
                  }
                >
                  <Download size={14} />
                  Unduh laporan Markdown
                </button>
                <button
                  className="secondary-button"
                  onClick={() => exportJson(report, 'report-' + report.snapshot.id)}
                >
                  Ekspor laporan JSON
                </button>
              </div>
              <h4>Batas laporan</h4>
              <ul>
                {report.snapshot.limitations.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
              <h4>Temuan dalam snapshot</h4>
              {report.snapshot.findings.map((f) => (
                <article className="job-step-result" key={f.id}>
                  <strong>{f.content.title}</strong>
                  <p>
                    {findingLabels[f.status]} · {f.content.severity} · {f.content.target.value}
                  </p>
                  <p>
                    {f.content.evidence_ids.length} bukti · analis:{' '}
                    {f.review?.actor_label || 'belum ditinjau'}
                  </p>
                </article>
              ))}
              <details>
                <summary>Snapshot lengkap, termasuk bukti tersensor</summary>
                <Json value={report.snapshot} />
              </details>
            </article>
          )}
        </>
      )}
      {modal && (
        <Modal
          title={
            {
              import: 'Tambah evidence',
              finding: editing ? 'Edit finding · kembali Candidate' : 'Finding baru',
              review: 'Keputusan analis',
              report: 'Buat snapshot laporan',
              original: 'Unduh evidence asli tanpa sensor'
            }[modal]
          }
          onClose={() => {
            if (!busy) setModal(null)
          }}
          wide
        >
          <form
            className="record-form"
            onSubmit={(event) => {
              event.preventDefault()
              void operate(async () => {
                if (modal === 'import') {
                  const body = {
                    job_id: importDraft.job_id,
                    step_ordinal: importDraft.step_ordinal,
                    source: importDraft.source,
                    title: importDraft.title,
                    redaction_terms: terms
                      .split('\n')
                      .map((x) => x.trim())
                      .filter(Boolean),
                    acknowledge: ack,
                    ...(importDraft.source === 'offline_policy'
                      ? {}
                      : {
                          captured_at: importDraft.captured_at,
                          tool_name: importDraft.tool_name,
                          tool_version: importDraft.tool_version,
                          parameters: importDraft.parameters,
                          content: importDraft.content
                        })
                  }
                  setEvidence(await mutate('/evidence', body))
                }
                if (modal === 'finding') {
                  const content = { ...draft }
                  delete content.cvss_score
                  const body = {
                    ...content,
                    redaction_terms: terms
                      .split('\n')
                      .map((x) => x.trim())
                      .filter(Boolean)
                  }
                  setFinding(
                    editing
                      ? await mutate(
                          '/findings/' + editing.id,
                          { expected_revision: editing.revision, content: body },
                          'PUT'
                        )
                      : await mutate('/findings', body)
                  )
                }
                if (modal === 'review' && finding)
                  setFinding(
                    await mutate('/findings/' + finding.id + '/review', {
                      expected_revision: finding.revision,
                      status,
                      actor_label: actor,
                      analyst_assessment: note,
                      acknowledge: ack,
                      redaction_terms: terms
                        .split('\n')
                        .map((x) => x.trim())
                        .filter(Boolean),
                      retest_evidence_ids: status === 'retest_passed' ? retests : []
                    })
                  )
                if (modal === 'report')
                  setReport(
                    await mutate('/reports', {
                      redaction_terms: terms
                        .split('\n')
                        .map((x) => x.trim())
                        .filter(Boolean),
                      title: reportTitle,
                      summary: note,
                      actor_label: actor,
                      acknowledge: ack
                    })
                  )
                if (modal === 'original' && evidence) {
                  const original = await mutate<{ content: string }>(
                    '/evidence/' + evidence.id + '/original',
                    {
                      actor_label: actor,
                      note,
                      acknowledge_sensitive_export: ack
                    }
                  )
                  downloadFile(
                    'evidence-original-' + evidence.id + '.txt',
                    original.content,
                    'text/plain'
                  )
                }
                setModal(null)
              })
            }}
          >
            {modal === 'original' && (
              <p className="notice error">
                Teks asli didekripsi hanya untuk unduhan ini. Arsip menggunakan Windows DPAPI akun
                saat ini; unduhan tidak disensor dan akses dicatat. Tidak ada eksekusi tool.
              </p>
            )}
            {error && (
              <p className="notice error" role="alert">
                {error}
              </p>
            )}
            {modal === 'import' && (
              <>
                <p>
                  Evidence selalu terhubung ke run/hasil policy. Impor tidak menjalankan tool. Teks
                  asli baru diarsipkan terenkripsi pada Windows; tampilan dan laporan tetap
                  tersensor.
                </p>
                <Field label="Run sumber evidence">
                  <select
                    required
                    value={importDraft.job_id}
                    onChange={(e) => {
                      setJob(null)
                      setImportDraft({ ...importDraft, job_id: e.target.value, step_ordinal: 1 })
                    }}
                  >
                    <option value="">Pilih run dengan hasil tersimpan</option>
                    {readyJobs.map((j) => (
                      <option value={j.id} key={j.id}>
                        {j.plan.name} · {j.status} · {j.id.slice(0, 8)}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Langkah sumber evidence">
                  <select
                    required
                    value={importDraft.step_ordinal}
                    onChange={(e) =>
                      setImportDraft({ ...importDraft, step_ordinal: Number(e.target.value) })
                    }
                  >
                    {job?.results?.map((r) => (
                      <option value={r.ordinal} key={r.ordinal}>
                        Langkah {r.ordinal}: {job.plan.steps[r.ordinal - 1].target.value} · policy{' '}
                        {r.result.decision}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Asal evidence">
                  <select
                    value={importDraft.source}
                    onChange={(e) =>
                      setImportDraft({ ...importDraft, source: e.target.value as EvidenceSource })
                    }
                  >
                    {Object.entries(sourceLabels).map(([k, v]) => (
                      <option key={k} value={k}>
                        {v}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Judul evidence">
                  <input
                    required
                    maxLength={160}
                    value={importDraft.title}
                    onChange={(e) => setImportDraft({ ...importDraft, title: e.target.value })}
                  />
                </Field>
                {importDraft.source !== 'offline_policy' && (
                  <>
                    <Field label="Waktu pengambilan evidence (ISO dengan zona waktu)">
                      <input
                        required
                        value={importDraft.captured_at}
                        onChange={(e) =>
                          setImportDraft({ ...importDraft, captured_at: e.target.value })
                        }
                      />
                    </Field>
                    <div className="record-filters">
                      <Field label="Nama tool bukti (deklarasi)">
                        <input
                          required
                          maxLength={120}
                          value={importDraft.tool_name}
                          onChange={(e) =>
                            setImportDraft({ ...importDraft, tool_name: e.target.value })
                          }
                        />
                      </Field>
                      <Field label="Versi tool bukti (deklarasi)">
                        <input
                          required
                          maxLength={120}
                          value={importDraft.tool_version}
                          onChange={(e) =>
                            setImportDraft({ ...importDraft, tool_version: e.target.value })
                          }
                        />
                      </Field>
                    </div>
                    <Field label="Parameter bukti (tidak dieksekusi)">
                      <textarea
                        maxLength={4000}
                        value={importDraft.parameters}
                        onChange={(e) =>
                          setImportDraft({ ...importDraft, parameters: e.target.value })
                        }
                      />
                    </Field>
                    <Field label="Impor file teks UTF-8 (maksimal 64 KiB)">
                      <input
                        type="file"
                        accept=".txt,.json,.md,.log,.csv,text/plain,application/json"
                        onChange={(e) => {
                          const file = e.target.files?.[0]
                          if (!file) return
                          void operate(async () => {
                            if (file.size > 65536 || !/\.(txt|json|md|log|csv)$/i.test(file.name))
                              throw new Error('Gunakan file teks UTF-8 maksimal 64 KiB.')
                            const content = new TextDecoder('utf-8', {
                              fatal: true,
                              ignoreBOM: true
                            }).decode(await file.arrayBuffer())
                            if (
                              Array.from(content).some(
                                (c) => c.charCodeAt(0) < 32 && !'\t\r\n'.includes(c)
                              )
                            )
                              throw new Error('File mengandung karakter biner.')
                            setImportDraft((d) => ({ ...d, content }))
                          })
                        }}
                      />
                    </Field>
                    <Field label="Isi bukti teks sebelum sensor">
                      <textarea
                        required
                        rows={8}
                        maxLength={65536}
                        value={importDraft.content}
                        onChange={(e) =>
                          setImportDraft({ ...importDraft, content: e.target.value })
                        }
                      />
                    </Field>
                  </>
                )}
              </>
            )}
            {modal === 'finding' && (
              <>
                <p>
                  Setiap simpan membuat snapshot dan mengembalikan status ke Candidate. AI
                  interpretation tidak dianggap keputusan analis.
                </p>
                <Field label="Judul finding">
                  <input
                    required
                    maxLength={160}
                    value={draft.title}
                    onChange={(e) => change({ title: e.target.value })}
                  />
                </Field>
                <div className="record-filters">
                  <Field label="Jenis target finding">
                    <select
                      value={draft.target.kind}
                      onChange={(e) =>
                        change({ target: { ...draft.target, kind: e.target.value as ScopeKind } })
                      }
                    >
                      {['ip', 'cidr', 'domain', 'url'].map((k) => (
                        <option key={k}>{k}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Target finding">
                    <input
                      required
                      maxLength={1000}
                      value={draft.target.value}
                      onChange={(e) =>
                        change({ target: { ...draft.target, value: e.target.value } })
                      }
                    />
                  </Field>
                </div>
                <Field label="Kategori / CWE finding">
                  <input
                    required
                    maxLength={120}
                    value={draft.category}
                    onChange={(e) => change({ category: e.target.value })}
                  />
                </Field>
                <Field label="Deskripsi finding">
                  <textarea
                    required
                    maxLength={6000}
                    value={draft.description}
                    onChange={(e) => change({ description: e.target.value })}
                  />
                </Field>
                <Field label="Interpretasi AI (opsional, belum diverifikasi)">
                  <textarea
                    maxLength={6000}
                    value={draft.ai_interpretation}
                    onChange={(e) => change({ ai_interpretation: e.target.value })}
                  />
                </Field>
                <fieldset>
                  <legend>Evidence untuk finding · target harus sama</legend>
                  {evidenceChoices.map((e) => (
                    <label className="checkbox-field" key={e.id}>
                      <input
                        type="checkbox"
                        checked={draft.evidence_ids.includes(e.id)}
                        onChange={() => change({ evidence_ids: toggle(draft.evidence_ids, e.id) })}
                      />
                      {e.title} · {e.target.value} · {sourceLabels[e.source]}
                    </label>
                  ))}
                </fieldset>
                <div className="record-filters">
                  <Field label="Severity finding">
                    <select
                      value={draft.severity}
                      onChange={(e) => change({ severity: e.target.value })}
                    >
                      {['unrated', 'informational', 'low', 'medium', 'high', 'critical'].map(
                        (s) => (
                          <option key={s}>{s}</option>
                        )
                      )}
                    </select>
                  </Field>
                  <Field label="Penanggung jawab remediasi">
                    <input
                      maxLength={160}
                      value={draft.assignee}
                      onChange={(e) => change({ assignee: e.target.value })}
                    />
                  </Field>
                </div>
                <Field label="Dasar severity">
                  <textarea
                    required={draft.severity !== 'unrated'}
                    maxLength={3000}
                    value={draft.severity_reason}
                    onChange={(e) => change({ severity_reason: e.target.value })}
                  />
                </Field>
                <Field label="Vektor CVSS 3.1 Base (opsional)">
                  <input
                    maxLength={160}
                    placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                    value={draft.cvss_vector}
                    onChange={(e) => change({ cvss_vector: e.target.value })}
                  />
                </Field>
                <Field label="Dasar metrik CVSS">
                  <textarea
                    required={!!draft.cvss_vector}
                    maxLength={3000}
                    value={draft.cvss_reason}
                    onChange={(e) => change({ cvss_reason: e.target.value })}
                  />
                </Field>
                <small>
                  Skor dihitung backend dari delapan metrik Base. CVSS 4.0, Temporal dan
                  Environmental belum didukung.
                </small>
                <Field label="Rencana remediasi">
                  <textarea
                    maxLength={6000}
                    value={draft.remediation}
                    onChange={(e) => change({ remediation: e.target.value })}
                  />
                </Field>
                <Field label="Duplikat semantik dari finding utama">
                  <select
                    value={draft.duplicate_of || ''}
                    onChange={(e) => change({ duplicate_of: e.target.value || null })}
                  >
                    <option value="">Bukan duplikat</option>
                    {records?.findings
                      .filter((f) => f.id !== editing?.id && !f.content.duplicate_of)
                      .map((f) => (
                        <option value={f.id} key={f.id}>
                          {f.content.title} · {f.content.target.value}
                        </option>
                      ))}
                  </select>
                </Field>
              </>
            )}
            {modal === 'review' && (
              <>
                <p>
                  Nama analis merupakan deklarasi lokal. Validated memerlukan bukti observasi,
                  target yang sama, dasar severity, dan peninjauan manusia. Retest Passed memerlukan
                  job serta bukti baru setelah review sebelumnya.
                </p>
                <Field label="Status keputusan finding">
                  <select
                    value={status}
                    onChange={(e) => setStatus(e.target.value as FindingStatus)}
                  >
                    {Object.entries(findingLabels).map(([k, v]) => (
                      <option disabled={k === finding?.status} value={k} key={k}>
                        {v}
                      </option>
                    ))}
                  </select>
                </Field>
                {status === 'retest_passed' && (
                  <fieldset>
                    <legend>Bukti retest baru</legend>
                    {evidenceChoices
                      .filter(
                        (e) =>
                          e.source !== 'offline_policy' &&
                          !finding?.content.evidence_ids.includes(e.id)
                      )
                      .map((e) => (
                        <label className="checkbox-field" key={e.id}>
                          <input
                            type="checkbox"
                            checked={retests.includes(e.id)}
                            onChange={() => setRetests(toggle(retests, e.id))}
                          />
                          {e.title} · {e.job_id} · {e.captured_at}
                        </label>
                      ))}
                  </fieldset>
                )}
              </>
            )}
            {modal === 'report' && (
              <>
                <p>
                  Laporan menyertakan seluruh finding dan evidence tersensor pada saat ini. Snapshot
                  lama tidak ditimpa.
                </p>
                <Field label="Judul laporan">
                  <input
                    required
                    maxLength={160}
                    value={reportTitle}
                    onChange={(e) => setReportTitle(e.target.value)}
                  />
                </Field>
              </>
            )}
            {modal !== 'original' && (
              <Field label="Istilah sensor tambahan (satu per baris, maksimal 20)">
                <textarea
                  value={terms}
                  onChange={(e) => setTerms(e.target.value)}
                  placeholder="Nilai rahasia khusus yang harus diganti"
                />
              </Field>
            )}
            {(modal === 'review' || modal === 'report' || modal === 'original') && (
              <>
                <Field label="Nama analis / penyusun (deklarasi lokal)">
                  <input
                    required
                    maxLength={120}
                    value={actor}
                    onChange={(e) => setActor(e.target.value)}
                  />
                </Field>
                <Field
                  label={
                    modal === 'review'
                      ? 'Penilaian dan alasan keputusan analis'
                      : modal === 'original'
                        ? 'Alasan ekspor asli'
                        : 'Ringkasan eksekutif laporan'
                  }
                >
                  <textarea
                    required
                    maxLength={modal === 'original' ? 1000 : 6000}
                    rows={5}
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                  />
                </Field>
              </>
            )}
            {modal !== 'finding' && (
              <label className="checkbox-field">
                <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
                {modal === 'original'
                  ? 'Saya memahami bahwa unduhan asli dapat berisi rahasia dan PII tanpa sensor. Simpan di lokasi privat dan jangan membagikannya tanpa review.'
                  : 'Saya meninjau data, asal bukti, dan batas sensor. Ini deklarasi lokal; eksekusi pentest tetap dinonaktifkan.'}
              </label>
            )}
            <div className="roe-decision-actions">
              <button
                type="button"
                className="secondary-button"
                disabled={busy}
                onClick={() => setModal(null)}
              >
                Batal
              </button>
              <Save
                busy={busy}
                disabled={
                  (modal !== 'finding' && !ack) ||
                  (modal === 'import' && (!job || !job.results?.length))
                }
              >
                {modal === 'import'
                  ? 'Simpan evidence tersensor'
                  : modal === 'review'
                    ? 'Simpan keputusan analis'
                    : modal === 'report'
                      ? 'Simpan snapshot laporan'
                      : modal === 'original'
                        ? 'Unduh asli tanpa sensor'
                        : 'Simpan sebagai Candidate'}
              </Save>
            </div>
          </form>
        </Modal>
      )}
    </section>
  )
}
