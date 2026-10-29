import { BrandMark } from './BrandMark'
import { useState } from 'react'
import type { JSX } from 'react'
import { connect } from '../lib/api'

export function Connection({ onConnected }: { onConnected: () => void }): JSX.Element {
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const desktop = Boolean(window.agentDesktop)
  const localBrowser =
    window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost'
  return (
    <form
      className="connection-overlay fixed inset-0 z-50 flex items-center justify-center bg-slate-950/95 p-6"
      onSubmit={(e) => {
        e.preventDefault()
        setBusy(true)
        const connection = window.agentDesktop
          ? window.agentDesktop.reconnect().then((ok) => {
              if (!ok) throw new Error('Koneksi desktop tidak tersedia. Buka ulang aplikasi.')
            })
          : connect(token.trim())
        void connection
          .then(() => {
            setToken('')
            onConnected()
          })
          .catch((e) => setError(String(e.message)))
          .finally(() => setBusy(false))
      }}
    >
      <div className="connection-card w-full max-w-md space-y-4 rounded-xl border border-slate-700 bg-slate-900 p-6 text-slate-100">
        <BrandMark large />
        <h1 className="text-xl">Hubungkan Jo Workspace</h1>
        <p className="text-sm text-slate-300">
          {desktop
            ? 'Sesi desktop berakhir. Hubungkan kembali untuk melanjutkan; token dikelola otomatis oleh aplikasi.'
            : localBrowser
              ? 'Buka aplikasi melalui shortcut Jo Workspace di Desktop untuk masuk otomatis. Jika membuka alamat server langsung, gunakan token milik server pada port ini; server preview dapat memakai token yang berbeda dari data/runtime/api-token.'
              : 'Masukkan token akses dari pemilik server.'}
        </p>
        {!desktop && <p className="text-xs text-slate-400">Server: {window.location.origin}</p>}
        {!desktop && (
          <input
            type="password"
            aria-label="Token akses"
            autoComplete="off"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            className="w-full rounded bg-slate-800 p-3"
          />
        )}
        {error && (
          <p role="alert" className="text-rose-300">
            {error}
          </p>
        )}
        <button
          disabled={busy || (!desktop && token.trim().length < 24)}
          className="primary-button"
        >
          {busy ? 'Menghubungkan...' : 'Hubungkan'}
        </button>
      </div>
    </form>
  )
}
