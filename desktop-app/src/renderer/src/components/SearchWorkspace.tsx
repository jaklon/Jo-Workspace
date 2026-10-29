import { useEffect, useState, type JSX } from 'react'
import { apiFetch } from '../lib/api'
import { RemoteImage } from './RemoteImage'

interface SearchResult {
  title: string
  url: string
  snippet: string
  image_url: string | null
  engine: string
}
interface PageImage {
  url: string
  alt: string
}

export function SearchWorkspace(): JSX.Element {
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState<'general' | 'images'>('general')
  const [results, setResults] = useState<SearchResult[]>([])
  const [images, setImages] = useState<PageImage[]>([])
  const [source, setSource] = useState('')
  const [endpoint, setEndpoint] = useState('SearXNG lokal')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    void apiFetch('/api/search/capabilities')
      .then((r) => r.json())
      .then((data) => setEndpoint(data.configured_url))
      .catch(() => {})
  }, [])
  const search = async (): Promise<void> => {
    setBusy(true)
    setError('')
    setImages([])
    setSource('')
    try {
      const response = await apiFetch('/api/search/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: query.trim(), category })
      })
      const data = (await response.json()) as { results: SearchResult[] }
      setResults(data.results)
    } catch (e) {
      setError(String(e))
      setResults([])
    } finally {
      setBusy(false)
    }
  }
  const extract = async (url: string): Promise<void> => {
    setBusy(true)
    setError('')
    setImages([])
    setSource(url)
    try {
      const response = await apiFetch('/api/search/extract-images', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      })
      const data = (await response.json()) as { images: PageImage[] }
      setImages(data.images)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <section className="security-workspace scrollbar-thin" aria-label="Pencarian web dan gambar">
      <div className="security-page-heading">
        <div>
          <p className="page-eyebrow">SEARCH ENGINE</p>
          <h2>Pencarian web & gambar</h2>
          <p>SearXNG mencari; Scrapling mengekstrak gambar dari halaman yang dipilih.</p>
        </div>
      </div>
      <p className="muted-text">
        Sumber: {endpoint}. Jalankan SearXNG lokal dengan keluaran JSON aktif. Hasil luar adalah
        konten tak tepercaya.
      </p>
      <form
        className="security-toolbar"
        onSubmit={(event) => {
          event.preventDefault()
          void search()
        }}
      >
        <input
          aria-label="Kata kunci pencarian"
          value={query}
          maxLength={200}
          minLength={2}
          placeholder="Cari di web…"
          onChange={(event) => setQuery(event.target.value)}
        />
        <select
          aria-label="Kategori pencarian"
          value={category}
          onChange={(event) => setCategory(event.target.value as 'general' | 'images')}
        >
          <option value="general">Web</option>
          <option value="images">Gambar</option>
        </select>
        <button className="primary-button" type="submit" disabled={busy || query.trim().length < 2}>
          Cari
        </button>
      </form>
      {error && (
        <p role="alert" className="notice error">
          {error}
        </p>
      )}
      {busy && <p role="status">Memuat hasil…</p>}
      <div className="search-results">
        {results.map((item) => (
          <article className="security-card" key={item.url}>
            {item.image_url && (
              <RemoteImage
                url={item.image_url}
                alt={item.title || 'Gambar hasil pencarian'}
                style={{ maxWidth: 240, maxHeight: 180, objectFit: 'contain' }}
              />
            )}
            <h3>{item.title || item.url}</h3>
            <p>{item.snippet}</p>
            <small>{item.engine}</small>
            <div className="roe-decision-actions">
              <a
                className="secondary-button"
                href={item.url}
                target="_blank"
                rel="noopener noreferrer"
              >
                Buka sumber
              </a>
              <button
                className="secondary-button"
                disabled={busy}
                onClick={() => void extract(item.url)}
              >
                Ekstrak gambar halaman
              </button>
            </div>
          </article>
        ))}
      </div>
      {source && (
        <div className="security-card">
          <h3>Gambar dari halaman yang dipilih</h3>
          <p>{source}</p>
          {!busy && !images.length && <p>Tidak ada gambar publik yang ditemukan.</p>}
          <div
            className="search-image-grid"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill,minmax(180px,1fr))',
              gap: 12
            }}
          >
            {images.map((item) => (
              <figure key={item.url}>
                <RemoteImage
                  url={item.url}
                  alt={item.alt || 'Gambar halaman'}
                  style={{ width: '100%', maxHeight: 180, objectFit: 'contain' }}
                />
                <figcaption>{item.alt}</figcaption>
              </figure>
            ))}
          </div>
        </div>
      )}
    </section>
  )
}
