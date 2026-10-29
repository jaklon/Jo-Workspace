import { useEffect, useRef, useState } from 'react'
import type { JSX } from 'react'
import ReactMarkdown from 'react-markdown'
import type { Message } from '../lib/types'
import { RemoteImage } from './RemoteImage'

export function MessageImage({
  blob,
  fallback
}: {
  blob?: Blob
  fallback?: string
}): JSX.Element | null {
  const imageRef = useRef<HTMLImageElement>(null)
  useEffect(() => {
    if (!blob) return
    const next = URL.createObjectURL(blob)
    if (imageRef.current) imageRef.current.src = next
    return () => URL.revokeObjectURL(next)
  }, [blob])
  return blob || fallback ? (
    <img
      ref={imageRef}
      src={fallback}
      alt="Lampiran pengguna"
      className="mb-2 max-h-64 max-w-full rounded"
    />
  ) : null
}

export function MarkdownAnswer({ text }: { text: string }): JSX.Element {
  return (
    <div className="prose-answer">
      <ReactMarkdown
        components={{
          a: ({ children, href }) => (
            <a
              href={href}
              target="_blank"
              rel="noreferrer noopener"
              className="text-emerald-300 underline"
            >
              {children}
            </a>
          ),
          img: ({ alt }) => <span>{alt || 'Gambar eksternal'}</span>
        }}
      >
        {text}
      </ReactMarkdown>
    </div>
  )
}

const ENGAGEMENT_REF = /Engagement: ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i

export function MessageDetails({
  message,
  onProposal,
  onAction,
  onOpenSecurity
}: {
  message: Message
  onProposal: (id: string, approve: boolean) => Promise<void>
  onAction: (id: string, approve: boolean, sessionTokens?: string[]) => Promise<void>
  onOpenSecurity?: (engagementId: string) => void
}): JSX.Element {
  const engagementId =
    message.role === 'assistant' ? message.content.match(ENGAGEMENT_REF)?.[1] : undefined
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [firstToken, setFirstToken] = useState('')
  const [secondToken, setSecondToken] = useState('')
  return (
    <div className="space-y-3">
      {engagementId && onOpenSecurity && (
        <button
          type="button"
          className="rounded border border-emerald-400/40 px-3 py-1 text-sm text-emerald-200 hover:bg-emerald-400/10"
          onClick={() => onOpenSecurity(engagementId)}
        >
          Lihat Detail di Security Workspace
        </button>
      )}
      {message.action && (
        <section className="rounded border border-amber-400/40 p-3" aria-label="Rencana tindakan">
          <strong>Konfirmasi rencana</strong>
          <p>{message.action.summary}</p>
          <p>Target: {message.action.target}</p>
          {!!message.action.ports?.length && <p>Port: {message.action.ports.join(', ')}</p>}
          {message.action.environment && <p>Lingkungan: {message.action.environment}</p>}
          {!!message.action.account_refs?.length && (
            <div className="space-y-2">
              <p>Dua akun uji: {message.action.account_refs.join(' · ')}</p>
              {message.action.owner_json_pointer && (
                <p>Pointer pemilik: {message.action.owner_json_pointer}</p>
              )}
              {!message.action.state &&
                message.action.account_refs.map((alias, index) => (
                  <label key={alias} className="block text-sm">
                    Token JWT sementara untuk {alias}
                    <input
                      type="password"
                      autoComplete="off"
                      spellCheck={false}
                      className="w-full rounded bg-slate-950 p-2"
                      value={index === 0 ? firstToken : secondToken}
                      onChange={(e) =>
                        index === 0 ? setFirstToken(e.target.value) : setSecondToken(e.target.value)
                      }
                    />
                  </label>
                ))}
            </div>
          )}
          <p>Tool: {message.action.tools.join(', ')}</p>
          <p>Durasi: {message.action.duration}</p>
          {message.action.state ? (
            <p>{message.action.state === 'cancelled' ? 'Dibatalkan.' : 'Keputusan dikirim.'}</p>
          ) : (
            <div className="flex gap-3">
              {[true, false].map((approve) => (
                <button
                  key={String(approve)}
                  disabled={
                    !!busy ||
                    (approve &&
                      !!message.action?.account_refs?.length &&
                      (!firstToken || !secondToken))
                  }
                  className="rounded border px-3 py-1"
                  onClick={() => {
                    setBusy(message.action!.id)
                    setError('')
                    const tokens =
                      approve && message.action!.account_refs?.length
                        ? [firstToken, secondToken]
                        : undefined
                    setFirstToken('')
                    setSecondToken('')
                    void onAction(message.action!.id, approve, tokens)
                      .catch((e) => setError(e.message))
                      .finally(() => setBusy(''))
                  }}
                >
                  {approve ? 'Setuju & Jalankan' : 'Batalkan'}
                </button>
              ))}
            </div>
          )}
        </section>
      )}
      {message.coverage && (
        <p className="text-xs text-amber-200">
          {message.coverage.complete
            ? 'Seluruh bagian sumber tersedia untuk jawaban ini.'
            : `Cakupan terbatas: ${message.coverage.selected}/${message.coverage.total} bagian. Jawaban ini bukan pemeriksaan seluruh dokumen.`}
        </p>
      )}
      {!!message.sources?.length && (
        <details>
          <summary className="cursor-pointer text-xs text-emerald-300">
            Sumber yang digunakan ({message.sources.length})
          </summary>
          {message.sources.map((s, i) => (
            <div key={i} className="my-2 rounded bg-slate-950 p-3 text-xs">
              {s.kind === 'web' && s.url ? (
                <a
                  href={s.url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="text-emerald-300 underline"
                >
                  {s.label} {s.title || s.url}
                </a>
              ) : (
                <strong>{s.label}</strong>
              )}
              {s.kind === 'web' && (
                <p className="mt-1 text-slate-400">
                  {s.read_level === 'rendered'
                    ? 'Isi halaman JavaScript berhasil dibaca'
                    : s.read_level === 'metadata'
                      ? 'Hanya metadata halaman; isi aplikasi JavaScript belum terbaca'
                      : s.fetched
                        ? 'Isi halaman berhasil dibaca'
                        : 'Hanya cuplikan hasil pencarian; isi halaman belum terbaca'}
                </p>
              )}
              <pre className="mt-2 whitespace-pre-wrap">{s.text}</pre>
            </div>
          ))}
        </details>
      )}
      {!!message.webImages?.length && (
        <div
          className="grid grid-cols-2 gap-3 sm:grid-cols-3"
          aria-label="Gambar hasil pencarian web"
        >
          {message.webImages.map((item) => (
            <figure key={item.url} className="rounded border border-white/10 p-2">
              <RemoteImage
                url={item.url}
                ticket={item.ticket}
                alt={item.alt || 'Gambar hasil pencarian'}
                style={{ width: '100%', maxHeight: 170, objectFit: 'contain' }}
              />
              <figcaption className="mt-1 truncate text-xs text-slate-400">{item.alt}</figcaption>
              <a
                href={item.source_url}
                target="_blank"
                rel="noreferrer noopener"
                className="text-xs text-emerald-300 underline"
              >
                Buka sumber
              </a>
            </figure>
          ))}
        </div>
      )}
      {message.proposals?.map((proposal) => (
        <div key={proposal.id} className="rounded border border-amber-400/40 p-3">
          <p>Usulan perubahan: {proposal.path}</p>
          <pre className="my-2 max-h-72 overflow-auto whitespace-pre-wrap text-xs">
            {proposal.diff}
          </pre>
          {proposal.state ? (
            <p>{proposal.state === 'applied' ? 'Perubahan diterapkan.' : 'Usulan ditolak.'}</p>
          ) : (
            <div className="flex gap-3">
              {[true, false].map((approve) => (
                <button
                  key={String(approve)}
                  disabled={!!busy}
                  className="rounded border px-3 py-1"
                  onClick={() => {
                    setBusy(proposal.id)
                    setError('')
                    void onProposal(proposal.id, approve)
                      .catch((e) => setError(e.message))
                      .finally(() => setBusy(''))
                  }}
                >
                  {approve ? 'Setujui dan terapkan' : 'Tolak'}
                </button>
              ))}
            </div>
          )}
        </div>
      ))}
      {error && (
        <p role="alert" className="text-rose-300">
          {error}
        </p>
      )}
    </div>
  )
}
