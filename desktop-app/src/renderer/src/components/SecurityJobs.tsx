import { useEffect, useState, type JSX, type ReactNode } from 'react'
import { Plus, Square, Download, RefreshCw, X, ShieldCheck } from 'lucide-react'
import { apiFetch } from '../lib/api'
import {
  actionLabels,
  engagementPath,
  parsePorts,
  type Engagement,
  type ScopeKind
} from '../lib/engagements'
import {
  activeJob,
  jobStatusLabels,
  type JobsListing,
  type SecurityJob,
  type JobStep
} from '../lib/securityJobs'
import { downloadFile } from '../lib/preferences'
import { Modal } from './Modal'

type DraftStep = Omit<JobStep, 'ports'> & { portText: string }
function Field({ label, children }: { label: string; children: ReactNode }): JSX.Element {
  return (
    <label className="field-block">
      {label}
      {children}
    </label>
  )
}
const eventLabels: Record<string, string> = {
  created: 'Rencana dibuat',
  approved: 'Validasi disetujui',
  running: 'Validasi dimulai',
  step_validated: 'Policy langkah diperiksa',
  completed: 'Validasi selesai',
  failed: 'Job gagal',
  cancelled: 'Job dibatalkan',
  mcp_fixture_completed: 'MCP fixture selesai; evidence tersimpan',
  reapproval_required: 'Persetujuan ulang diperlukan',
  retry_created: 'Percobaan baru dibuat'
}

export function SecurityJobs({ engagement }: { engagement: Engagement }): JSX.Element {
  const head = engagement.versions[0]
  const path = engagementPath(engagement.project_id, engagement.id)
  const [listing, setListing] = useState<JobsListing | null>(null)
  const [selected, setSelected] = useState('')
  const [detail, setDetail] = useState<SecurityJob | null>(null)
  const [builder, setBuilder] = useState(false)
  const [name, setName] = useState('')
  const [steps, setSteps] = useState<DraftStep[]>([])
  const [timeout, setTimeoutValue] = useState(60)
  const [output, setOutput] = useState(64)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [fetchError, setFetchError] = useState('')
  const [refresh, setRefresh] = useState(0)
  const [decision, setDecision] = useState<'approve' | 'resume' | null>(null)
  const [actor, setActor] = useState('')
  const [note, setNote] = useState('')
  const [ack, setAck] = useState(false)
  const selectedRevision = listing?.items.find((j) => j.id === selected)?.revision
  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    const poll = async (): Promise<void> => {
      try {
        const data: JobsListing = await (
          await apiFetch(path + '/jobs', { signal: controller.signal })
        ).json()
        if (!controller.signal.aborted) {
          setListing(data)
          setSelected((id) => (data.items.some((j) => j.id === id) ? id : data.items[0]?.id || ''))
          setFetchError('')
        }
      } catch (e) {
        if (!controller.signal.aborted)
          setFetchError(e instanceof Error ? e.message : 'Antrean tidak dapat dimuat.')
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(poll, 1000)
      }
    }
    void poll()
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [path, refresh])
  useEffect(() => {
    if (!selected) return
    const controller = new AbortController()
    void apiFetch(path + '/jobs/' + selected, { signal: controller.signal })
      .then((r) => r.json())
      .then((data: SecurityJob) => {
        if (!controller.signal.aborted) setDetail(data)
      })
      .catch((e) => {
        if (!controller.signal.aborted) setFetchError(e.message)
      })
    return () => controller.abort()
  }, [path, selected, selectedRevision, refresh])
  const binding = {
    expected_roe_revision: engagement.revision,
    roe_version: head.version,
    content_hash: head.content_hash
  }
  const currentDetail = detail?.id === selected ? detail : null
  const time = (iso: string | null): string =>
    iso
      ? new Date(iso).toLocaleString('id-ID', { timeZone: head.content.timezone })
      : 'Belum dicatat'
  const request = async (endpoint: string, body: unknown): Promise<unknown> =>
    (
      await apiFetch(path + endpoint, {
        method: 'POST',
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
      setError(e instanceof Error ? e.message : 'Operasi job gagal.')
    } finally {
      setBusy(false)
    }
  }
  const adopt = (job: SecurityJob): void => {
    setDetail(job)
    setSelected(job.id)
    setBuilder(false)
    setDecision(null)
    setListing((prev) =>
      prev ? { ...prev, items: [job, ...prev.items.filter((j) => j.id !== job.id)] } : prev
    )
  }
  const addStep = (): void =>
    setSteps((prev) => [
      ...prev,
      {
        target: { kind: 'ip', value: '' },
        action: 'tcp_discovery',
        portText: head.content.ports.join(', '),
        max_http_rps: 1,
        max_concurrency: 1,
        max_duration_minutes: 1,
        test_account_ref: ''
      }
    ])
  const changeStep = (index: number, change: Partial<DraftStep>): void =>
    setSteps((prev) => prev.map((step, i) => (i === index ? { ...step, ...change } : step)))
  const openDecision = (value: 'approve' | 'resume'): void => {
    setDecision(value)
    setActor('')
    setNote('')
    setAck(false)
    setError('')
  }
  return (
    <section className="security-jobs" aria-label="Runs offline">
      <div className="section-title">
        <h3>
          <ShieldCheck size={18} /> Runs · validasi offline
        </h3>
        <span className="planning-badge">Pentest terkunci</span>
      </div>
      <p>
        Job biasa hanya memvalidasi policy. Job dengan binding MCP menjalankan fixture terkurasi
        dalam AppContainer dan menyimpan evidence. Tidak ada Nmap/TCP scan, request HTTP/DNS ke
        target, atau model yang dipanggil. Completed berarti validasi atau fixture offline selesai.
      </p>
      <div className="jobs-runtime-status">
        <span>{listing?.worker_active ? 'Worker offline aktif' : 'Menunggu worker offline'}</span>
        <span>Concurrency global 1 · maksimal 20 langkah · 300 detik · 64 KiB output</span>
      </div>
      {listing?.gate.stopped ? (
        <div className="notice error" role="status">
          <div>
            <strong>Engagement dihentikan</strong>
            <p>{listing.gate.note}</p>
            <small>
              {time(listing.gate.updated_at)} · {listing.gate.actor} (deklarasi lokal)
            </small>
            <p>
              Job baru dan persetujuan ditolak. Pembukaan kembali tidak menghidupkan job yang
              dibatalkan.
            </p>
          </div>
        </div>
      ) : null}
      <div className="roe-decision-actions">
        <button
          className="primary-button"
          disabled={busy || !listing || !!listing.gate.stopped || listing.items.length >= 100}
          onClick={() => {
            setBuilder(true)
            setName('')
            setSteps([])
            setTimeoutValue(60)
            setOutput(64)
            setError('')
          }}
        >
          <Plus size={14} /> Rencana job baru
        </button>
        <button
          className="secondary-button"
          disabled={busy}
          onClick={() => setRefresh((v) => v + 1)}
        >
          <RefreshCw size={14} /> Muat ulang job
        </button>
        {listing?.gate.stopped ? (
          <button
            className="secondary-button"
            disabled={busy}
            onClick={() => openDecision('resume')}
          >
            Buka kembali engagement
          </button>
        ) : (
          <button
            className="danger-button"
            disabled={busy || !listing}
            onClick={() =>
              void operate(async () => {
                setListing(
                  (await request('/stop', {
                    actor_label: 'operator-lokal',
                    note: 'Stop Engagement dari kontrol darurat UI.'
                  })) as JobsListing
                )
              })
            }
          >
            <Square size={14} /> Stop Engagement
          </button>
        )}
      </div>
      {(error || fetchError) && (
        <p className="notice error" role="alert">
          {error || fetchError}
        </p>
      )}
      {builder && (
        <form
          className="settings-card job-builder"
          onSubmit={(e) => {
            e.preventDefault()
            void operate(async () => {
              const normalized = steps.map(({ portText, ...step }) => ({
                ...step,
                ports: parsePorts(portText)
              }))
              adopt(
                (await request('/jobs', {
                  ...binding,
                  name: name.trim(),
                  steps: normalized,
                  wall_timeout_seconds: timeout,
                  max_output_kb: output
                })) as SecurityJob
              )
            })
          }}
        >
          <h4>Rencana validasi offline · RoE v{head.version}</h4>
          <p>
            Rencana dan batas dibekukan setelah disimpan. Antrean memerlukan persetujuan terpisah
            dan policy yang lolos. Target nama untuk rencana jaringan masih ditolak karena DNS tidak
            diverifikasi.
          </p>
          <fieldset disabled={busy || !!listing?.gate.stopped}>
            <div className="roe-grid">
              <Field label="Nama job">
                <input
                  required
                  maxLength={120}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </Field>
              <Field label="Durasi maksimal job (detik)">
                <input
                  required
                  type="number"
                  min={1}
                  max={300}
                  value={timeout}
                  onChange={(e) => setTimeoutValue(Number(e.target.value))}
                />
              </Field>
              <Field label="Batas output job (KiB)">
                <input
                  required
                  type="number"
                  min={1}
                  max={64}
                  value={output}
                  onChange={(e) => setOutput(Number(e.target.value))}
                />
              </Field>
            </div>
            {steps.map((step, index) => (
              <section className="job-step-editor" key={index}>
                <div className="section-title">
                  <h4>Langkah {index + 1}</h4>
                  <button
                    type="button"
                    className="icon-button"
                    aria-label={`Hapus langkah ${index + 1}`}
                    onClick={() => setSteps((prev) => prev.filter((_, i) => i !== index))}
                  >
                    <X size={15} />
                  </button>
                </div>
                <div className="roe-grid">
                  <Field label={`Jenis target langkah ${index + 1}`}>
                    <select
                      value={step.target.kind}
                      onChange={(e) =>
                        changeStep(index, {
                          target: { ...step.target, kind: e.target.value as ScopeKind }
                        })
                      }
                    >
                      {['ip', 'cidr', 'domain', 'url'].map((k) => (
                        <option key={k} value={k}>
                          {k.toUpperCase()}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label={`Target langkah ${index + 1}`}>
                    <input
                      required
                      maxLength={1000}
                      value={step.target.value}
                      placeholder="192.168.10.25"
                      onChange={(e) =>
                        changeStep(index, { target: { ...step.target, value: e.target.value } })
                      }
                    />
                  </Field>
                  <Field label={`Tindakan langkah ${index + 1}`}>
                    <select
                      value={step.action}
                      onChange={(e) => changeStep(index, { action: e.target.value })}
                    >
                      {Object.entries(actionLabels).map(([key, label]) => (
                        <option key={key} value={key}>
                          {label}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label={`Port langkah ${index + 1}`}>
                    <input
                      value={step.portText}
                      onChange={(e) => changeStep(index, { portText: e.target.value })}
                      placeholder="443; kosong untuk port dari URL HTTP"
                    />
                  </Field>
                  <Field label={`RPS langkah ${index + 1}`}>
                    <input
                      required
                      type="number"
                      min={1}
                      max={15}
                      value={step.max_http_rps}
                      onChange={(e) => changeStep(index, { max_http_rps: Number(e.target.value) })}
                    />
                  </Field>
                  <Field label={`Concurrency langkah ${index + 1}`}>
                    <input
                      required
                      type="number"
                      min={1}
                      max={4}
                      value={step.max_concurrency}
                      onChange={(e) =>
                        changeStep(index, { max_concurrency: Number(e.target.value) })
                      }
                    />
                  </Field>
                  <Field label={`Durasi rencana langkah ${index + 1} (menit)`}>
                    <input
                      required
                      type="number"
                      min={1}
                      max={240}
                      value={step.max_duration_minutes}
                      onChange={(e) =>
                        changeStep(index, { max_duration_minutes: Number(e.target.value) })
                      }
                    />
                  </Field>
                  <Field label={`Alias akun langkah ${index + 1}`}>
                    <select
                      value={step.test_account_ref}
                      onChange={(e) => changeStep(index, { test_account_ref: e.target.value })}
                    >
                      <option value="">Tanpa alias</option>
                      {head.content.test_account_refs.map((ref) => (
                        <option key={ref} value={ref}>
                          {ref}
                        </option>
                      ))}
                    </select>
                  </Field>
                </div>
              </section>
            ))}
            <div className="roe-decision-actions">
              <button
                type="button"
                className="secondary-button"
                disabled={steps.length >= 20}
                onClick={addStep}
              >
                <Plus size={14} /> Tambah langkah
              </button>
              <button type="submit" className="primary-button" disabled={!steps.length}>
                {busy ? 'Menyimpan…' : 'Simpan rencana job'}
              </button>
              <button type="button" className="secondary-button" onClick={() => setBuilder(false)}>
                Batal
              </button>
            </div>
          </fieldset>
        </form>
      )}
      <div className="job-list" aria-label="Daftar job">
        {listing?.items.map((job) => (
          <button
            className={selected === job.id ? 'selected' : ''}
            key={job.id}
            disabled={busy}
            onClick={() => {
              setSelected(job.id)
              setError('')
            }}
          >
            <strong>{job.plan.name}</strong>
            <span className={`roe-status job-${job.status}`}>{jobStatusLabels[job.status]}</span>
            <small>
              {job.progress}/{job.plan.steps.length} langkah · percobaan {job.attempt} ·{' '}
              {time(job.created_at)}
            </small>
          </button>
        ))}
        {listing && !listing.items.length && (
          <p className="muted-text">
            Belum ada job. Buat rencana, tinjau, lalu antrekan validasi offline.
          </p>
        )}
      </div>
      {currentDetail && (
        <section className="settings-card job-detail">
          <div className="section-title">
            <h4>{currentDetail.plan.name}</h4>
            <span className={`roe-status job-${currentDetail.status}`}>
              {jobStatusLabels[currentDetail.status]}
            </span>
          </div>
          <p className="roe-hash">ID: {currentDetail.id}</p>
          <p>
            Mode: {currentDetail.plan.mcp ? 'MCP fixture terisolasi' : 'validasi policy offline'} ·
            tidak memberikan izin eksekusi pentest.
          </p>
          {currentDetail.plan.mcp && (
            <>
              <h4>Binding MCP · terikat hash rencana</h4>
              <pre className="record-output">{JSON.stringify(currentDetail.plan.mcp, null, 2)}</pre>
            </>
          )}
          {currentDetail.mcp_result && (
            <>
              <h4>Hasil MCP fixture · output tidak dipercaya sebagai instruksi</h4>
              <p>Evidence otomatis: {currentDetail.mcp_result.evidence_id}</p>
              <pre className="record-output">
                {JSON.stringify(currentDetail.mcp_result, null, 2)}
              </pre>
            </>
          )}
          <div className="roe-decision-actions">
            {currentDetail.status === 'awaiting_approval' && (
              <button
                className="primary-button"
                disabled={busy || !!listing?.gate.stopped || !listing?.worker_active}
                onClick={() => openDecision('approve')}
              >
                Tinjau & antrekan validasi
              </button>
            )}
            {activeJob(currentDetail.status) && (
              <button
                className="danger-button"
                disabled={busy}
                onClick={() =>
                  void operate(async () =>
                    adopt(
                      (await request('/jobs/' + currentDetail.id + '/stop', {
                        actor_label: 'operator-lokal',
                        note: 'Stop Run dari kontrol job UI.'
                      })) as SecurityJob
                    )
                  )
                }
              >
                <Square size={14} /> Stop Run
              </button>
            )}
            {['failed', 'cancelled'].includes(currentDetail.status) &&
              currentDetail.attempt < 3 &&
              !currentDetail.retry_job_id && (
                <button
                  className="secondary-button"
                  disabled={busy || !!listing?.gate.stopped}
                  onClick={() =>
                    void operate(async () =>
                      adopt(
                        (await request('/jobs/' + currentDetail.id + '/retry', {
                          ...binding,
                          expected_revision: currentDetail.revision
                        })) as SecurityJob
                      )
                    )
                  }
                >
                  Ulangi validasi offline
                </button>
              )}
            <button
              className="secondary-button"
              disabled={busy}
              onClick={() =>
                downloadFile(`job-${currentDetail.id}.json`, JSON.stringify(currentDetail, null, 2))
              }
            >
              <Download size={14} /> Ekspor job
            </button>
          </div>
          {currentDetail.error_code && (
            <p className="notice error">
              {currentDetail.error_code}: {currentDetail.error_message}
            </p>
          )}
          <dl className="roe-summary roe-grid">
            <div>
              <dt>Snapshot RoE</dt>
              <dd>
                v{currentDetail.plan.roe_version} · revisi engagement{' '}
                {currentDetail.plan.expected_roe_revision}
              </dd>
            </div>
            <div>
              <dt>Progres</dt>
              <dd>
                {currentDetail.progress}/{currentDetail.plan.steps.length} langkah
              </dd>
            </div>
            <div>
              <dt>Batas job</dt>
              <dd>
                {currentDetail.plan.wall_timeout_seconds} detik · {currentDetail.plan.max_output_kb}{' '}
                KiB
              </dd>
            </div>
            <div>
              <dt>Output tersimpan</dt>
              <dd>{currentDetail.output_bytes} byte</dd>
            </div>
            <div>
              <dt>Mulai</dt>
              <dd>{time(currentDetail.started_at)}</dd>
            </div>
            <div>
              <dt>Selesai</dt>
              <dd>{time(currentDetail.finished_at)}</dd>
            </div>
            <div>
              <dt>Peninjau (deklarasi lokal)</dt>
              <dd>{currentDetail.approver || 'Belum disetujui'}</dd>
            </div>
            <div>
              <dt>Catatan persetujuan</dt>
              <dd>{currentDetail.approval_note || 'Belum dicatat'}</dd>
            </div>
          </dl>
          <p className="roe-hash">Hash rencana: {currentDetail.plan_hash}</p>
          <p className="roe-hash">Hash RoE: {currentDetail.plan.content_hash}</p>
          <h4>Langkah rencana · hanya dapat dibaca</h4>
          <ol className="job-plan">
            {currentDetail.plan.steps.map((step, i) => (
              <li key={i}>
                <strong>
                  {i + 1}. {actionLabels[step.action]}
                </strong>
                <code>
                  {step.target.kind.toUpperCase()} · {step.target.value}
                </code>
                <small>
                  Port: {step.ports.join(', ') || 'Dari URL HTTP'} · {step.max_http_rps} RPS ·{' '}
                  {step.max_concurrency} concurrent · {step.max_duration_minutes} menit · alias:{' '}
                  {step.test_account_ref || 'tidak ada'}
                </small>
              </li>
            ))}
          </ol>
          <h4>Hasil validasi · bukan bukti pemindaian</h4>
          {currentDetail.results?.map(({ ordinal, result }) => (
            <details className="job-step-result" key={ordinal}>
              <summary>
                Langkah {ordinal}: {result.decision === 'pass' ? 'policy lolos' : 'policy ditolak'}{' '}
                · tanpa eksekusi
              </summary>
              <p>
                {time(result.evaluated_at)} · {result.policy_version}
              </p>
              <ul className="policy-checks">
                {result.checks.map((check) => (
                  <li key={check.code} className={check.passed ? 'policy-pass' : 'policy-fail'}>
                    <strong>
                      {check.passed ? 'Lolos' : 'Ditolak'} · {check.code}
                    </strong>
                    <span>{check.message}</span>
                  </li>
                ))}
              </ul>
            </details>
          ))}
          {!currentDetail.results?.length && (
            <p className="muted-text">Belum ada hasil. Tidak ada tool yang dijalankan.</p>
          )}
          <details className="policy-history">
            <summary>Riwayat job ({currentDetail.events?.length || 0})</summary>
            <ol className="roe-audit">
              {currentDetail.events?.map((event) => (
                <li key={event.id}>
                  <strong>{eventLabels[event.action] || event.action}</strong>
                  <small>
                    {time(event.at)} · {event.actor}
                  </small>
                  <p>{event.note}</p>
                </li>
              ))}
            </ol>
          </details>
        </section>
      )}
      {decision && (
        <Modal
          title={
            decision === 'approve' ? 'Persetujuan validasi offline' : 'Buka kembali engagement'
          }
          onClose={() => {
            if (!busy) setDecision(null)
          }}
        >
          <div className="job-approval">
            <p>
              {decision === 'approve'
                ? 'Persetujuan terikat pada rencana, parameter, batas, dan snapshot di bawah. Ini tidak menjalankan pentest. Nama peninjau adalah deklarasi lokal, bukan identitas organisasi terverifikasi.'
                : 'Pembukaan kembali hanya mengizinkan rencana baru. Job yang dibatalkan tidak dilanjutkan otomatis; perlu persetujuan baru.'}
            </p>
            {decision === 'approve' && currentDetail && (
              <>
                <strong>
                  {currentDetail.plan.name} · {currentDetail.plan.steps.length} langkah ·{' '}
                  {currentDetail.plan.wall_timeout_seconds} detik
                </strong>
                <p className="roe-hash">Hash rencana: {currentDetail.plan_hash}</p>
                {currentDetail.plan.mcp && (
                  <>
                    <p>
                      Approval ini juga mengizinkan fixture MCP terisolasi berikut. Server, tool,
                      argumen, dan schema terikat pada hash rencana.
                    </p>
                    <pre className="record-output">
                      {JSON.stringify(currentDetail.plan.mcp, null, 2)}
                    </pre>
                  </>
                )}
                <ol className="job-plan">
                  {currentDetail.plan.steps.map((step, i) => (
                    <li key={i}>
                      {i + 1}. {actionLabels[step.action]} · {step.target.value} · port{' '}
                      {step.ports.join(', ') || 'dari URL'}
                    </li>
                  ))}
                </ol>
              </>
            )}
            {error && (
              <p role="alert" className="notice error">
                {error}
              </p>
            )}
            <Field label="Nama peninjau job (deklarasi)">
              <input maxLength={120} value={actor} onChange={(e) => setActor(e.target.value)} />
            </Field>
            <Field label="Catatan keputusan job">
              <textarea maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} />
            </Field>
            <label className="roe-ack">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              <span>
                Saya meninjau rencana dan memahami bahwa eksekusi pentest tetap dinonaktifkan.
              </span>
            </label>
            <div className="roe-decision-actions">
              <button
                className="secondary-button"
                disabled={busy}
                onClick={() => setDecision(null)}
              >
                Batal
              </button>
              <button
                className="primary-button"
                disabled={
                  busy ||
                  !ack ||
                  !actor.trim() ||
                  !note.trim() ||
                  (decision === 'approve' && !currentDetail)
                }
                onClick={() =>
                  void operate(async () => {
                    if (decision === 'approve' && currentDetail)
                      adopt(
                        (await request('/jobs/' + currentDetail.id + '/approve', {
                          expected_revision: currentDetail.revision,
                          actor_label: actor.trim(),
                          note: note.trim(),
                          acknowledge: ack
                        })) as SecurityJob
                      )
                    else if (listing) {
                      setListing(
                        (await request('/resume', {
                          ...binding,
                          expected_gate_revision: listing.gate.revision,
                          actor_label: actor.trim(),
                          note: note.trim(),
                          acknowledge: ack
                        })) as JobsListing
                      )
                      setDecision(null)
                    }
                  })
                }
              >
                {busy
                  ? 'Mencatat…'
                  : decision === 'approve'
                    ? 'Setujui & antrekan validasi'
                    : 'Buka kembali'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </section>
  )
}
