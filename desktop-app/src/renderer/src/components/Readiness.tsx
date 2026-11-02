import { useCallback, useEffect, useState, type JSX } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { apiFetch } from '../lib/api'

type Status = 'ready' | 'limited' | 'action'
type Check = { status: Status; detail: string; action?: string; url?: string }
type Report = { checked_at: string; checks: Record<string, Check> }
const names: Record<string, string> = {
  backend: 'Backend',
  ollama: 'Ollama dan model',
  queue: 'Antrean inferensi',
  gpu: 'GPU / VRAM',
  storage: 'Penyimpanan runtime',
  search: 'SearXNG (opsional)',
  docker: 'Docker (opsional)',
  tailscale: 'Tailscale dan akses iPhone'
}
const labels: Record<Status, string> = {
  ready: 'Siap',
  limited: 'Terbatas',
  action: 'Perlu tindakan'
}

async function checkBrowserStorage(): Promise<void> {
  const name = 'jo-readiness-probe'
  await new Promise<void>((resolve, reject) => {
    const timeout = window.setTimeout(() => reject(new Error('timeout')), 3000)
    const request = indexedDB.open(name, 1)
    request.onupgradeneeded = () => request.result.createObjectStore('probe')
    request.onerror = () => {
      window.clearTimeout(timeout)
      reject(new Error('open'))
    }
    request.onsuccess = () => {
      const db = request.result
      const tx = db.transaction('probe', 'readwrite')
      tx.objectStore('probe').put('ok', 'test')
      tx.oncomplete = () => {
        db.close()
        indexedDB.deleteDatabase(name)
        window.clearTimeout(timeout)
        resolve()
      }
      tx.onabort = tx.onerror = () => {
        db.close()
        window.clearTimeout(timeout)
        reject(new Error('write'))
      }
    }
  })
}

export function Readiness(): JSX.Element {
  const [report, setReport] = useState<Report | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [browser, setBrowser] = useState('Memeriksa penyimpanan browser…')
  const refresh = useCallback(async (): Promise<void> => {
    setBusy(true)
    setError('')
    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), 12000)
    try {
      const response = await apiFetch('/api/readiness', { signal: controller.signal })
      setReport(await response.json())
    } catch {
      setReport(null)
      setError(
        'Backend tidak dapat diperiksa. Pastikan Jo Workspace berjalan dan sambungkan ulang.'
      )
    } finally {
      window.clearTimeout(timeout)
      setBusy(false)
    }
    try {
      if (!window.indexedDB) throw new Error()
      await checkBrowserStorage()
      const estimate = await navigator.storage?.estimate?.()
      const available =
        estimate?.quota && estimate?.usage != null
          ? `; digunakan sekitar ${Math.round(estimate.usage / 1024 ** 2)} MB dari ${Math.round(estimate.quota / 1024 ** 2)} MB`
          : ''
      setBrowser(
        `IndexedDB dapat ditulis${available}. Penyimpanan browser dapat dihapus oleh pengguna atau sistem.`
      )
    } catch {
      setBrowser('Penyimpanan browser tidak dapat diperiksa. Periksa izin penyimpanan Safari.')
    }
  }, [])
  useEffect(() => {
    const timer = window.setTimeout(() => void refresh(), 0)
    return () => window.clearTimeout(timer)
  }, [refresh])
  const tailscale = report?.checks.tailscale
  const url =
    tailscale?.status === 'ready' && /^https:\/\/[a-z0-9.-]+\.ts\.net$/.test(tailscale.url || '')
      ? tailscale.url
      : undefined
  const download = (): void => {
    if (!report) return
    // Whitelist only status codes and numeric capacity. Do not export URLs, names, paths or text from services.
    const checks = Object.fromEntries(
      Object.entries(report.checks).map(([key, value]) => [key, value.status])
    )
    const blob = new Blob(
      [JSON.stringify({ version: 1, checked_at: report.checked_at, checks }, null, 2)],
      { type: 'application/json' }
    )
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = 'jo-diagnostik.json'
    link.click()
    URL.revokeObjectURL(link.href)
  }
  return (
    <div>
      <div className="flex flex-wrap gap-2 mb-4">
        <button
          className="secondary-button"
          type="button"
          onClick={() => void refresh()}
          disabled={busy}
        >
          {busy ? 'Memeriksa…' : 'Periksa ulang'}
        </button>
        <button className="secondary-button" type="button" onClick={download} disabled={!report}>
          Ekspor diagnostik
        </button>
      </div>
      <p className="muted-text">
        Ekspor hanya berisi waktu dan status pemeriksaan; token, chat, alamat dan nama perangkat
        tidak disertakan.
      </p>
      {error && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
      {report && (
        <>
          <p className="muted-text">Diperiksa: {new Date(report.checked_at).toLocaleString()}</p>
          {Object.entries(names).map(([key, name]) => {
            const check = report.checks[key]
            if (!check) return null
            return (
              <div className="setting-row" key={key}>
                <div>
                  <strong>
                    {name}: {labels[check.status]}
                  </strong>
                  <p>{check.detail}</p>
                  {check.action && <p>{check.action}</p>}
                </div>
              </div>
            )
          })}
        </>
      )}
      <div className="setting-row">
        <div>
          <strong>Browser perangkat ini</strong>
          <p>{browser}</p>
        </div>
      </div>
      <h4>Akses Jo dari iPhone</h4>
      <ol className="muted-text" style={{ paddingLeft: 20 }}>
        <li>Di laptop, jalankan backend Jo dan Tailscale Serve pada backend yang sama.</li>
        <li>
          Di iPhone, masuk ke jaringan Tailscale yang sama, lalu buka alamat HTTPS berikut di
          Safari.
        </li>
        <li>
          Jika diminta, masukkan token akses secara langsung. Jangan memasukkan token ke alamat atau
          QR.
        </li>
        <li>
          Jika koneksi terputus, buka kembali aplikasi dan periksa status. Tindakan yang belum jelas
          hasilnya tidak diulang otomatis.
        </li>
      </ol>
      {url ? (
        <div>
          <p>
            <a href={url}>{url}</a>
          </p>
          <div style={{ background: '#fff', padding: 12, width: 'fit-content' }}>
            <QRCodeSVG value={url} size={180} title="QR alamat Jo Workspace" />
          </div>
          <p className="muted-text">
            QR hanya memuat alamat privat; token tidak disertakan. Status Serve bukan bukti bahwa
            iPhone dapat menjangkaunya.
          </p>
        </div>
      ) : (
        <p className="notice">
          Alamat iPhone belum terverifikasi untuk backend ini. Periksa status Tailscale dan Serve di
          laptop.
        </p>
      )}
    </div>
  )
}
