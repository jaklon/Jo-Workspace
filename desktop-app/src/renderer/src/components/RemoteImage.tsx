import { useEffect, useState, type CSSProperties, type JSX } from 'react'
import { apiFetch } from '../lib/api'

export function RemoteImage({
  url,
  alt,
  style,
  ticket
}: {
  url: string
  alt: string
  style: CSSProperties
  ticket?: string
}): JSX.Element {
  const [src, setSrc] = useState('')
  const [error, setError] = useState(false)
  useEffect(() => {
    let active = true
    let objectUrl = ''
    if (!ticket) return
    void apiFetch(
      `/api/search/image?url=${encodeURIComponent(url)}&ticket=${encodeURIComponent(ticket)}`
    )
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
  }, [url, ticket])
  if (!ticket || error) return <span className="muted-text">Gambar tidak dapat dimuat.</span>
  if (!src) return <span className="muted-text">Memuat gambar…</span>
  return <img src={src} alt={alt} style={style} loading="lazy" />
}
