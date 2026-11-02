import { useEffect, useState } from 'react'

export interface Preferences {
  name: string
  theme: 'dark' | 'light' | 'system'
  fontSize: 'small' | 'normal' | 'large'
  sendWithEnter: boolean
  reducedMotion: boolean
  showSuggestions: boolean
  autoScroll: boolean
  defaultMode: 'chat' | 'code' | 'vision' | 'docs' | 'pentest'
  customInstructions: string
  responseStyle: 'balanced' | 'concise' | 'detailed'
  responseLanguage: 'id' | 'en' | 'auto'
}

export const defaultPreferences: Preferences = {
  name: '',
  theme: 'dark',
  fontSize: 'normal',
  sendWithEnter: true,
  reducedMotion: false,
  showSuggestions: true,
  autoScroll: true,
  defaultMode: 'chat',
  customInstructions: '',
  responseStyle: 'balanced',
  responseLanguage: 'id'
}

export function normalizePreferences(value: unknown): Preferences {
  const result = { ...defaultPreferences }
  if (!value || typeof value !== 'object') return result
  const p = value as Record<string, unknown>
  for (const key of ['sendWithEnter', 'reducedMotion', 'showSuggestions', 'autoScroll'] as const) {
    if (typeof p[key] === 'boolean') result[key] = p[key]
  }
  for (const [key, options] of Object.entries({
    theme: ['dark', 'light', 'system'],
    fontSize: ['small', 'normal', 'large'],
    defaultMode: ['chat', 'code', 'vision', 'docs', 'pentest'],
    responseStyle: ['balanced', 'concise', 'detailed'],
    responseLanguage: ['id', 'en', 'auto']
  })) {
    if (options.includes(p[key] as string)) Object.assign(result, { [key]: p[key] })
  }
  if (typeof p.name === 'string') result.name = p.name.slice(0, 60)
  if (typeof p.customInstructions === 'string')
    result.customInstructions = p.customInstructions.slice(0, 1500)
  return result
}

export function usePreferences(): {
  preferences: Preferences
  setPreferences: React.Dispatch<React.SetStateAction<Preferences>>
  preferenceError: string
} {
  const [preferences, setPreferences] = useState(() => {
    try {
      return normalizePreferences(
        JSON.parse(localStorage.getItem('agent-os-preferences') || 'null')
      )
    } catch {
      return { ...defaultPreferences }
    }
  })
  const [preferenceError, setError] = useState('')
  useEffect(() => {
    const persist = setTimeout(() => {
      try {
        localStorage.setItem('agent-os-preferences', JSON.stringify(preferences))
        setError('')
      } catch {
        setError('Preferensi gagal disimpan di perangkat ini.')
      }
    }, 0)
    const media = window.matchMedia('(prefers-color-scheme: light)')
    const update = (): void => {
      document.documentElement.dataset.theme =
        preferences.theme === 'system' ? (media.matches ? 'light' : 'dark') : preferences.theme
    }
    update()
    media.addEventListener('change', update)
    document.documentElement.dataset.fontSize = preferences.fontSize
    document.documentElement.dataset.reducedMotion = String(preferences.reducedMotion)
    return () => {
      clearTimeout(persist)
      media.removeEventListener('change', update)
    }
  }, [preferences])
  return { preferences, setPreferences, preferenceError }
}

export function downloadFile(name: string, content: string, type = 'application/json'): void {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = name
  anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function personalizedPrompt(
  prompt: string,
  preferences: Preferences,
  projectInstructions = '',
  projectMemory = ''
): string {
  const parts = [
    preferences.responseLanguage === 'auto'
      ? 'Ikuti bahasa pesan pengguna.'
      : preferences.responseLanguage === 'en'
        ? 'Answer in English.'
        : 'Jawab dalam bahasa Indonesia.',
    preferences.responseStyle === 'concise'
      ? 'Berikan jawaban singkat dan langsung.'
      : preferences.responseStyle === 'detailed'
        ? 'Jelaskan secara terperinci dengan contoh bila membantu.'
        : '',
    preferences.customInstructions,
    projectInstructions ? `Instruksi project: ${projectInstructions}` : '',
    projectMemory
  ].filter(Boolean)
  return `${parts.join('\n')}\n\nPesan pengguna:\n${prompt}`
}
