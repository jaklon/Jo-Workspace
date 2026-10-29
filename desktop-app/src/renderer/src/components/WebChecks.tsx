import { useEffect, useState, type JSX } from 'react'
import { apiFetch } from '../lib/api'
import type { Engagement } from '../lib/engagements'
import type { SecurityJob } from '../lib/securityJobs'

export function WebChecks({ engagement }: { engagement: Engagement }): JSX.Element {
  const [url, setUrl] = useState('')
  const [job, setJob] = useState<SecurityJob | null>(null)
  const [actor, setActor] = useState('')
  const [note, setNote] = useState('')
  const [ack, setAck] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [items, setItems] = useState<SecurityJob[]>([])
  const base = `/api/security/projects/${engagement.project_id}/engagements/${engagement.id}/jobs`
  const head = engagement.versions[0]
  const load = async (): Promise<void> => {
    const data = (await (await apiFetch(base)).json()) as { items: SecurityJob[] }
    setItems(data.items.filter((item) => Boolean(item.plan.web)))
  }
  useEffect(() => {
    void apiFetch(base)
      .then((r) => r.json())
      .then((data: { items: SecurityJob[] }) =>
        setItems(data.items.filter((item) => Boolean(item.plan.web)))
      )
      .catch((e) => setError(String(e)))
    if (!job || !['queued', 'running'].includes(job.status)) return
    const timer = window.setInterval(() => {
      void apiFetch(`${base}/${job.id}`)
        .then((r) => r.json())
        .then((value) => {
          setJob(value as SecurityJob)
          if (!['queued', 'running'].includes((value as SecurityJob).status)) void load()
        })
        .catch((e) => setError(String(e)))
    }, 1000)
    return () => window.clearInterval(timer)
  }, [engagement.id, job?.id, job?.status])
  const act = async (fn: () => Promise<void>): Promise<void> => {
    setBusy(true)
    setError('')
    try {
      await fn()
      await load()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }
  const create = (): Promise<void> =>
    act(async () => {
      const response = await apiFetch(base, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Pemeriksaan URL · HEAD/HTTPS',
          expected_roe_revision: engagement.revision,
          roe_version: head.version,
          content_hash: head.content_hash,
          wall_timeout_seconds: 20,
          max_output_kb: 64,
          web: { adapter: 'public-head-1.0' },
          steps: [
            {
              target: { kind: 'url', value: url.trim() },
              action: 'http_headers',
              ports: [],
              max_http_rps: 1,
              max_concurrency: 1,
              max_duration_minutes: 1,
              test_account_ref: ''
            }
          ]
        })
      })
      setJob((await response.json()) as SecurityJob)
      setAck(false)
    })
  const approve = (): Promise<void> =>
    act(async () => {
      if (!job) return
      const response = await apiFetch(`${base}/${job.id}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          expected_revision: job.revision,
          actor_label: actor.trim(),
          note: note.trim(),
          acknowledge: ack
        })
      })
      setJob((await response.json()) as SecurityJob)
    })
  const stop = (): Promise<void> =>
    act(async () => {
      if (!job) return
      const response = await apiFetch(`${base}/${job.id}/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor_label: actor.trim() || 'operator-lokal',
          note: 'Dihentikan oleh operator.'
        })
      })
      setJob((await response.json()) as SecurityJob)
    })
  const download = (): void => {
    if (!job?.web_result) return
    const payload = JSON.stringify(job.web_result, null, 2)
    const blob = new Blob([payload], { type: 'application/json' })
    const href = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = href
    link.download = `jo-url-check-${job.id}.json`
    link.click()
    URL.revokeObjectURL(href)
  }
  return (
    <section className="security-jobs" aria-label="Pemeriksaan URL project">
      <div className="section-title">
        <h3>Pemeriksaan URL project</h3>
        <span className="planning-badge">Satu HEAD · read-only</span>
      </div>
      <p>
        Periksa sertifikat HTTPS, status, dan keberadaan header keamanan. Satu request HEAD dikirim
        setelah persetujuan; redirect tidak diikuti, tanpa login atau pengambilan body. Hasil header
        bersifat informasi dan perlu tinjauan manusia.
      </p>
      <label className="field-block">
        URL project dalam scope RoE
        <input
          type="url"
          value={url}
          placeholder="https://project-anda.example/"
          maxLength={1000}
          onChange={(e) => setUrl(e.target.value)}
        />
      </label>
      <button
        className="primary-button"
        disabled={busy || !url.trim() || head.status !== 'approved'}
        onClick={() => void create()}
      >
        Siapkan rencana untuk persetujuan
      </button>
      {head.status !== 'approved' && (
        <p className="muted-text">
          Setujui RoE engagement terlebih dahulu. URL, port 80/443, dan tindakan http_headers harus
          masuk scope.
        </p>
      )}
      {error && (
        <p role="alert" className="notice error">
          {error}
        </p>
      )}
      <div className="section-title">
        <h4>Riwayat pemeriksaan</h4>
        <button
          className="secondary-button"
          onClick={() =>
            void act(async () => {
              await load()
            })
          }
        >
          Muat ulang
        </button>
      </div>
      <div className="job-plan">
        {items.map((item) => (
          <button
            key={item.id}
            className="secondary-button"
            onClick={() =>
              void act(async () => {
                setJob((await (await apiFetch(`${base}/${item.id}`)).json()) as SecurityJob)
              })
            }
          >
            {item.plan.steps[0].target.value} · {item.status}
          </button>
        ))}
      </div>
      {job && (
        <div className="security-card">
          <h4>{job.plan.steps[0].target.value}</h4>
          <p>
            Status: {job.status} · RoE v{job.plan.roe_version} · satu request HEAD · batas 20 detik
          </p>
          {job.status === 'awaiting_approval' && (
            <div className="job-approval">
              <p>
                Periksa URL, scope, waktu RoE, dan otorisasi sebelum memberi persetujuan. Nama
                peninjau adalah deklarasi lokal.
              </p>
              <label className="field-block">
                Nama peninjau
                <input maxLength={120} value={actor} onChange={(e) => setActor(e.target.value)} />
              </label>
              <label className="field-block">
                Catatan persetujuan
                <textarea maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} />
              </label>
              <label className="roe-ack">
                <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
                Saya menyetujui satu pemeriksaan HEAD pada URL ini sesuai RoE.
              </label>
              <button
                className="primary-button"
                disabled={busy || !actor.trim() || !note.trim() || !ack}
                onClick={() => void approve()}
              >
                Setujui dan antrekan
              </button>
            </div>
          )}
          {['awaiting_approval', 'queued', 'running'].includes(job.status) && (
            <button className="secondary-button" disabled={busy} onClick={() => void stop()}>
              Hentikan run
            </button>
          )}
          {job.error_code && (
            <p role="alert">
              {job.error_code}: {job.error_message}
            </p>
          )}
          {job.web_result && (
            <>
              <h4>Laporan pemeriksaan</h4>
              <pre className="record-output">{JSON.stringify(job.web_result, null, 2)}</pre>
              <button className="secondary-button" onClick={download}>
                Unduh laporan JSON
              </button>
              <p>Evidence otomatis tersimpan di tab Evidence. Temuan memerlukan review analis.</p>
            </>
          )}
        </div>
      )}
    </section>
  )
}
