import { useEffect, useState, type JSX } from 'react'
import { AlertTriangle, CheckCircle2, Info, RefreshCw, XCircle } from 'lucide-react'
import { apiFetch } from '../lib/api'

type Issue = { level: 'error' | 'warn' | 'info'; reason: string; action: string }
type ModelRow = {
  role: string
  name: string
  installed: boolean
  loaded: boolean
  size_mb?: number
  estimated_mb?: number
  fit?: 'gpu' | 'partial' | 'cpu'
  gpu_percent?: number
}
type Setting = 'context_tokens' | 'thinking_tokens' | 'model_timeout'
export type RuntimeStatus = {
  ollama: { reachable: boolean; version: string | null; url: string; error: string | null }
  gpu: { available: boolean; name: string; vram_used_mb: number; vram_total_mb: number }
  models: ModelRow[]
  queue: {
    active: number
    waiting: number
    max_pending: number
    current: { model: string; elapsed_seconds: number; thinking: boolean; images: boolean } | null
    completed: number
    failed: number
  }
  last: {
    model: string
    seconds: number
    output_tokens?: number
    tokens_per_second?: number | null
    load_seconds?: number
  } | null
  issues: Issue[]
  recommendation: Record<Setting, number> & {
    label: string
    note: string
    differs: Setting[]
    current: Record<Setting, number>
  }
}

const roleLabels: Record<string, string> = {
  reasoning: 'Penalaran',
  coding: 'Coding',
  security: 'Security',
  vision: 'Vision'
}
const fitLabels = {
  gpu: 'Muat penuh di GPU',
  partial: 'Sebagian di CPU',
  cpu: 'CPU saja'
}
const settingLabels: Record<Setting, string> = {
  context_tokens: 'Konteks',
  thinking_tokens: 'Token penalaran',
  model_timeout: 'Batas waktu (detik)'
}

const fetchStatus = async (): Promise<RuntimeStatus> =>
  (await apiFetch('/api/runtime/status')).json()

function IssueIcon({ level }: { level: Issue['level'] }): JSX.Element {
  if (level === 'error') return <XCircle size={14} />
  if (level === 'warn') return <AlertTriangle size={14} />
  return <Info size={14} />
}

/** Live view of Ollama, loaded models, memory fit and queue, with reasons and recovery steps. */
export function ModelRuntime(): JSX.Element {
  const [status, setStatus] = useState<RuntimeStatus | null>(null)
  const [error, setError] = useState('')
  const [tick, setTick] = useState(0)
  const busy = !!status && (status.queue.active > 0 || status.queue.waiting > 0)
  useEffect(() => {
    let cancelled = false
    void fetchStatus()
      .then((next) => {
        if (cancelled) return
        setStatus(next)
        setError('')
      })
      .catch((e) => !cancelled && setError(e instanceof Error ? e.message : String(e)))
    // Poll faster while a request runs so elapsed time and queue stay current.
    const timer = window.setTimeout(() => setTick((t) => t + 1), busy ? 3000 : 15000)
    return () => {
      cancelled = true
      window.clearTimeout(timer)
    }
  }, [tick, busy])
  if (!status)
    return (
      <section className="runtime-panel" aria-label="Status model lokal">
        <p className="muted-text">{error || 'Memeriksa model lokal…'}</p>
      </section>
    )
  const { ollama, gpu, models, queue, last, issues, recommendation } = status
  return (
    <section className="runtime-panel" aria-label="Status model lokal">
      <header>
        <strong>Status model lokal</strong>
        <button type="button" className="secondary-button" onClick={() => setTick((t) => t + 1)}>
          <RefreshCw size={13} /> Periksa ulang
        </button>
      </header>
      <dl className="runtime-facts">
        <div>
          <dt>Ollama</dt>
          <dd className={ollama.reachable ? 'ok' : 'bad'}>
            {ollama.reachable ? `Aktif · versi ${ollama.version}` : 'Tidak terhubung'}
          </dd>
        </div>
        <div>
          <dt>GPU</dt>
          <dd>
            {gpu.available
              ? `${gpu.name} · ${(gpu.vram_used_mb / 1024).toFixed(1)}/${(gpu.vram_total_mb / 1024).toFixed(1)} GB terpakai`
              : 'Tidak terdeteksi (inferensi di CPU)'}
          </dd>
        </div>
        <div>
          <dt>Antrean</dt>
          <dd>
            {queue.current
              ? `Memproses ${queue.current.model} · ${queue.current.elapsed_seconds} dtk${queue.current.thinking ? ' · dengan penalaran' : ''}`
              : 'Kosong'}
            {queue.waiting > 0 && ` · ${queue.waiting}/${queue.max_pending} menunggu`}
          </dd>
        </div>
        {last && (
          <div>
            <dt>Permintaan terakhir</dt>
            <dd>
              {last.model} · {last.seconds.toFixed(1)} dtk
              {last.tokens_per_second ? ` · ${last.tokens_per_second} token/dtk` : ''}
              {last.load_seconds ? ` · memuat ${last.load_seconds} dtk` : ''}
            </dd>
          </div>
        )}
      </dl>
      <table className="runtime-models">
        <thead>
          <tr>
            <th>Peran</th>
            <th>Model</th>
            <th>Status</th>
            <th>Perkiraan memori</th>
          </tr>
        </thead>
        <tbody>
          {models.map((m) => (
            <tr key={m.role}>
              <td>{roleLabels[m.role] || m.role}</td>
              <td>{m.name}</td>
              <td>
                {!m.installed
                  ? 'Belum terpasang'
                  : m.loaded
                    ? `Dimuat · ${m.gpu_percent}% GPU`
                    : 'Terpasang, belum dimuat'}
              </td>
              <td>
                {m.estimated_mb
                  ? `~${(m.estimated_mb / 1024).toFixed(1)} GB · ${m.fit ? fitLabels[m.fit] : ''}`
                  : '–'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {issues.length ? (
        <ul className="runtime-issues">
          {issues.map((issue) => (
            <li key={issue.reason} className={issue.level}>
              <IssueIcon level={issue.level} />
              <div>
                <p>{issue.reason}</p>
                <small>{issue.action}</small>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <p className="runtime-ok">
          <CheckCircle2 size={14} /> Tidak ada masalah terdeteksi.
        </p>
      )}
      <div className="runtime-recommendation">
        <strong>Rekomendasi untuk perangkat ini ({recommendation.label})</strong>
        <p className="muted-text">{recommendation.note}</p>
        {recommendation.differs.length ? (
          <ul>
            {recommendation.differs.map((key) => (
              <li key={key}>
                {settingLabels[key]}: saat ini {recommendation.current[key]}, disarankan{' '}
                {recommendation[key]}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted-text">Pengaturan saat ini sudah sesuai rekomendasi.</p>
        )}
        <small className="muted-text">
          Rekomendasi tidak diterapkan otomatis; ubah di formulir di bawah bila setuju.
        </small>
      </div>
      {error && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
    </section>
  )
}
