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

export function MessageDetails({
  message,
  onProposal
}: {
  message: Message
  onProposal: (id: string, approve: boolean) => Promise<void>
}): JSX.Element {
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  return (
    <div className="space-y-3">
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
                    : s.fetched ? 'Isi halaman berhasil dibaca' : 'Hanya cuplikan hasil pencarian; isi halaman belum terbaca'}
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
