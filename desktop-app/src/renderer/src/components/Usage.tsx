import { useEffect, useState, type JSX } from 'react'
import { RefreshCw, Download, Activity, ArrowDownLeft, ArrowUpRight, Timer } from 'lucide-react'
import { apiFetch } from '../lib/api'
import { downloadFile } from '../lib/preferences'

export interface UsageRow {
  date: string
  model: string
  completed: number
  failed: number
  cancelled: number
  input_tokens: number
  output_tokens: number
  measured: number
  seconds: number
}
interface UsageData {
  rows: UsageRow[]
  active: number
  waiting: number
  persistence_error: boolean
}
const number = (n: number): string =>
  new Intl.NumberFormat('id-ID', { maximumFractionDigits: 1 }).format(n)

export function Usage(): JSX.Element {
  const [data, setData] = useState<UsageData | null>(null)
  const [days, setDays] = useState('7')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [version, setVersion] = useState(0)
  useEffect(() => {
    let alive = true
    const controller = new AbortController()
    const refresh = async (): Promise<void> => {
      setBusy(true)
      try {
        const result = await (await apiFetch('/api/usage', { signal: controller.signal })).json()
        if (alive) {
          setData(result)
          setError('')
        }
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : 'Usage tidak dapat dimuat.')
      } finally {
        if (alive) setBusy(false)
      }
    }
    void refresh()
    const timer = setInterval(() => void refresh(), 10000)
    return () => {
      alive = false
      controller.abort()
      clearInterval(timer)
    }
  }, [version])
  const cutoff = new Date()
  cutoff.setUTCDate(cutoff.getUTCDate() - Number(days) + 1)
  const rows = (data?.rows || []).filter((r) => r.date >= cutoff.toISOString().slice(0, 10))
  const totals = rows.reduce(
    (a, r) => ({
      completed: a.completed + r.completed,
      failed: a.failed + r.failed,
      cancelled: a.cancelled + r.cancelled,
      input: a.input + r.input_tokens,
      output: a.output + r.output_tokens,
      seconds: a.seconds + r.seconds,
      measured: a.measured + r.measured
    }),
    { completed: 0, failed: 0, cancelled: 0, input: 0, output: 0, seconds: 0, measured: 0 }
  )
  const models = [...new Set(rows.map((r) => r.model))].map((model) => ({
    model,
    rows: rows.filter((r) => r.model === model)
  }))
  const daily = Array.from({ length: Number(days) === 90 ? 30 : Number(days) }, (_, i) => {
    const date = new Date()
    date.setUTCDate(date.getUTCDate() - i)
    const key = date.toISOString().slice(0, 10)
    return {
      date: key,
      tokens: rows
        .filter((r) => r.date === key)
        .reduce((sum, r) => sum + r.input_tokens + r.output_tokens, 0)
    }
  }).reverse()
  const max = Math.max(1, ...daily.map((r) => r.tokens))
  return (
    <div className="usage-page">
      <div className="page-eyebrow">WORKSPACE ANALYTICS</div>
      <div className="page-title-row">
        <div>
          <h3>Usage</h3>
          <p>Pahami pemakaian model di komputer Anda.</p>
        </div>
        <button
          className="secondary-button"
          disabled={busy}
          onClick={() => setVersion((v) => v + 1)}
        >
          <RefreshCw size={15} className={busy ? 'animate-spin' : ''} /> Perbarui
        </button>
      </div>
      <div className="usage-toolbar">
        <div className="segmented">
          {[
            ['1', 'Hari ini'],
            ['7', '7 hari'],
            ['30', '30 hari'],
            ['90', '90 hari']
          ].map(([value, label]) => (
            <button
              key={value}
              className={days === value ? 'active' : ''}
              onClick={() => setDays(value)}
            >
              {label}
            </button>
          ))}
        </div>
        <button
          className="secondary-button"
          disabled={!data || !!error}
          onClick={() =>
            downloadFile(
              'jo-workspace-usage.json',
              JSON.stringify({ timezone: 'UTC', days: Number(days), rows }, null, 2)
            )
          }
        >
          <Download size={15} /> Ekspor
        </button>
      </div>
      {error && (
        <p role="alert" className="notice error">
          {error} Data di bawah mungkin belum diperbarui.
        </p>
      )}
      {data?.persistence_error && (
        <p className="notice error">
          Usage saat ini hanya tersimpan dalam memori; penulisan ke disk gagal.
        </p>
      )}
      <div className="usage-stats">
        {[
          {
            label: 'Inferensi selesai',
            value: number(totals.completed),
            icon: Activity,
            detail: `${number(totals.failed)} gagal · ${number(totals.cancelled)} dihentikan`
          },
          {
            label: 'Input tokens',
            value: number(totals.input),
            icon: ArrowDownLeft,
            detail: 'Prompt dan konteks yang diproses'
          },
          {
            label: 'Output tokens',
            value: number(totals.output),
            icon: ArrowUpRight,
            detail: 'Token yang dihasilkan model'
          },
          {
            label: 'Waktu inferensi',
            value: `${number(totals.seconds / 60)} m`,
            icon: Timer,
            detail: 'Termasuk waktu tunggu antrean'
          }
        ].map((s) => (
          <div className="stat-card" key={s.label}>
            <div>
              <span>{s.label}</span>
              <s.icon size={17} />
            </div>
            <strong>{data ? s.value : '—'}</strong>
            <small>{s.detail}</small>
          </div>
        ))}
      </div>
      <section className="settings-card">
        <div className="section-title">
          <h4>Aktivitas token</h4>
          <span>{days === '90' ? 'Grafik 30 hari terakhir' : 'Total input + output'} · UTC</span>
        </div>
        <div className="usage-chart" role="img" aria-label="Grafik pemakaian token harian">
          <div className="chart-bars">
            {daily.map((r) => (
              <div
                className="chart-column"
                key={r.date}
                title={`${r.date}: ${number(r.tokens)} token`}
              >
                <div
                  className={r.tokens ? 'bar filled' : 'bar'}
                  style={{ height: `${Math.max(2, (r.tokens / max) * 100)}%` }}
                />
              </div>
            ))}
          </div>
          <div className="chart-labels">
            <span>{daily[0]?.date}</span>
            <span>{daily[daily.length - 1]?.date}</span>
          </div>
        </div>
        {data && !totals.completed && (
          <p className="muted-text">
            Belum ada inferensi selesai pada periode ini. Data muncul setelah model digunakan.
          </p>
        )}
      </section>
      <section className="settings-card">
        <div className="section-title">
          <h4>Penggunaan per model</h4>
          <span>{data ? `${data.active} aktif · ${data.waiting} antre` : 'Menghubungkan…'}</span>
        </div>
        <div className="table-scroll">
          <table className="usage-table">
            <thead>
              <tr>
                <th>Model</th>
                <th>Selesai</th>
                <th>Input</th>
                <th>Output</th>
                <th>Gagal / stop</th>
              </tr>
            </thead>
            <tbody>
              {models.map(({ model, rows: modelRows }) => (
                <tr key={model}>
                  <td>{model}</td>
                  <td>{number(modelRows.reduce((n, r) => n + r.completed, 0))}</td>
                  <td>{number(modelRows.reduce((n, r) => n + r.input_tokens, 0))}</td>
                  <td>{number(modelRows.reduce((n, r) => n + r.output_tokens, 0))}</td>
                  <td>{number(modelRows.reduce((n, r) => n + r.failed + r.cancelled, 0))}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!models.length && (
            <p className="empty-table">{data ? 'Belum ada data model.' : 'Memuat data model…'}</p>
          )}
        </div>
      </section>
      <p className="muted-text">
        Data backend bersama, disimpan hingga 90 hari dalam UTC. Token berasal dari laporan Ollama (
        {totals.measured} inferensi memiliki hitungan token). Satu pesan dapat memicu beberapa
        inferensi, misalnya Vision atau agent. Inferensi selesai juga mencakup respons yang mencapai
        batas token. Tidak mencakup pemakaian sebelum fitur ini aktif; biaya listrik dan kuota cloud
        tidak dihitung.
      </p>
    </div>
  )
}
