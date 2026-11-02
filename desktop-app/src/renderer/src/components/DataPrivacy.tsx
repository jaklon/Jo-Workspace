import { useEffect, useState, type JSX } from 'react'
import { ArrowUpRight, HardDrive, ShieldCheck } from 'lucide-react'
import { apiFetch } from '../lib/api'
import type { OutboundDisclosure, OutboundLog } from '../lib/types'

type Location = {
  name: string
  path: string
  bytes: number
  files: number
  truncated: boolean
  exists: boolean
}
type Overview = {
  locations: Location[]
  attachments: { count: number; bytes: number; oldest_expires_in_days: number | null }
  retention: Array<{ item: string; rule: string }>
  exports: Array<{ name: string; includes: string[]; excludes: string[] }>
  browser_storage: string
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`
}

/** Shown on approval cards before a web search or recon job runs. */
export function OutboundCard({ info }: { info: OutboundDisclosure }): JSX.Element {
  return (
    <div className="outbound-card" aria-label="Data yang dikirim keluar">
      <strong>
        {info.leaves_device ? (
          <>
            <ArrowUpRight size={13} /> Data yang akan keluar dari laptop
          </>
        ) : (
          <>
            <ShieldCheck size={13} /> Tidak ada data yang keluar dari laptop
          </>
        )}
      </strong>
      <ul>
        {info.sent.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
      {!!info.destinations.length && <p>Tujuan: {info.destinations.join(' · ')}</p>}
      <p className="muted-text">Tidak dikirim: {info.not_sent.join(', ')}.</p>
    </div>
  )
}

/** After a web answer: the exact search terms and pages that were contacted. */
export function OutboundLogLine({ log }: { log: OutboundLog }): JSX.Element {
  return (
    <p className="outbound-log">
      Terkirim keluar: {log.query ? `kata kunci "${log.query}"` : 'tanpa kata kunci (URL langsung)'}
      {log.pages.length ? ` · ${log.pages.length} halaman dibuka` : ''}
    </p>
  )
}

/** Where data lives, how much space it uses, how long it is kept and what an export contains. */
export function DataOverview(): JSX.Element {
  const [overview, setOverview] = useState<Overview | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let cancelled = false
    void apiFetch('/api/data/overview')
      .then((r) => r.json())
      .then((data: Overview) => !cancelled && setOverview(data))
      .catch((e) => !cancelled && setError(e instanceof Error ? e.message : String(e)))
    return () => {
      cancelled = true
    }
  }, [])
  if (!overview) return <p className="muted-text">{error || 'Menghitung penggunaan ruang…'}</p>
  const { attachments } = overview
  return (
    <section className="data-overview" aria-label="Lokasi dan penggunaan data">
      <h4>
        <HardDrive size={14} /> Lokasi penyimpanan aktif
      </h4>
      <ul className="data-locations">
        {overview.locations.map((l) => (
          <li key={l.path}>
            <strong>{l.name}</strong>
            <code>{l.path}</code>
            <small>
              {l.exists
                ? `${formatBytes(l.bytes)} · ${l.files}${l.truncated ? '+' : ''} file`
                : 'Belum dibuat'}
            </small>
          </li>
        ))}
        <li>
          <strong>Penyimpanan aplikasi/browser</strong>
          <small>{overview.browser_storage}</small>
        </li>
      </ul>
      <p>
        Lampiran tersimpan: {attachments.count} ({formatBytes(attachments.bytes)} teks hasil
        ekstraksi)
        {attachments.oldest_expires_in_days !== null &&
          ` · lampiran tertua terhapus otomatis dalam ${attachments.oldest_expires_in_days} hari`}
      </p>
      <h4>Masa retensi</h4>
      <table className="runtime-models">
        <tbody>
          {overview.retention.map((r) => (
            <tr key={r.item}>
              <td>{r.item}</td>
              <td>{r.rule}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h4>Yang ikut diekspor</h4>
      {overview.exports.map((e) => (
        <div key={e.name} className="data-export">
          <strong>{e.name}</strong>
          <p>Termasuk: {e.includes.join(', ')}.</p>
          <p className="muted-text">Tidak termasuk: {e.excludes.join(', ')}.</p>
        </div>
      ))}
    </section>
  )
}
