import { useEffect, useState, type CSSProperties, type JSX } from 'react'
import { apiFetch } from '../lib/api'

export function RemoteImage({
  url,
  alt,
  style
}: {
  url: string
  alt: string
  style: CSSProperties
}): JSX.Element {
  const [src, setSrc] = useState('')
  const [error, setError] = useState(false)
  useEffect(() => {
    let active = true
    let objectUrl = ''
    void apiFetch(`/api/search/image?url=${encodeURIComponent(url)}`)
      .then((response) => response.blob())
      .then((blob) => {
        if (!active) return
        objectUrl = URL.createObjectURL(blob)
        setSrc(objectUrl)
      })
      .catch(() => {
        if (active) setError(true)
      })
    return () => {
      active = false
      if (objectUrl) URL.revokeObjectURL(objectUrl)
    }
  }, [url])
  if (error) return <span className="muted-text">Gambar tidak dapat dimuat.</span>
  if (!src) return <span className="muted-text">Memuat gambar…</span>
  return <img src={src} alt={alt} style={style} loading="lazy" />
}
