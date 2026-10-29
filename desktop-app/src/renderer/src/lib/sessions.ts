import { useEffect, useRef, useState } from 'react'
import type { Dispatch, SetStateAction } from 'react'
import type { ActiveSessionMap, ChatSession, ChatSessionMap, TabType, Project } from './types'
export const TAB_TYPES: TabType[] = ['chat', 'code', 'vision', 'docs', 'pentest']
const LEGACY_KEY = 'agent_os_chat_history'
const MAX_SESSIONS_PER_TAB = 500
const MAX_MESSAGES_PER_SESSION = 100
type Saved = { sessions: ChatSessionMap; activeSessions: ActiveSessionMap; projects: Project[] }

export const createSession = (): ChatSession => ({
  id: crypto.randomUUID(),
  title: 'Percakapan baru',
  createdAt: Date.now(),
  updatedAt: Date.now(),
  messages: [],
  attachments: []
})

function initial(): Saved {
  const sessions = {} as ChatSessionMap
  const activeSessions = {} as ActiveSessionMap
  TAB_TYPES.forEach((tab) => {
    const s = createSession()
    sessions[tab] = [s]
    activeSessions[tab] = s.id
  })
  return { sessions, activeSessions, projects: [] }
}

export function validate(value: unknown): Saved {
  const fallback = initial()
  if (!value || typeof value !== 'object') return fallback
  const saved = value as Partial<Saved> & Partial<Record<TabType, ChatSession['messages']>>
  fallback.projects = (Array.isArray(saved.projects) ? saved.projects : [])
    .filter((p) => p && typeof p.id === 'string' && typeof p.name === 'string')
    .map((p) => ({
      id: p.id,
      name: p.name.slice(0, 80),
      instructions: typeof p.instructions === 'string' ? p.instructions.slice(0, 1500) : '',
      createdAt: Number(p.createdAt) || Date.now()
    }))
  for (const tab of TAB_TYPES) {
    const legacy = saved[tab]
    const rows =
      saved.sessions?.[tab] ??
      (Array.isArray(legacy) ? [{ ...createSession(), messages: legacy }] : [])
    const valid = (Array.isArray(rows) ? rows : [])
      .filter(
        (s) =>
          s && typeof s.id === 'string' && typeof s.title === 'string' && Array.isArray(s.messages)
      )
      .map((s) => ({
        ...s,
        pinned: s.pinned === true,
        archived: s.archived === true,
        projectId: fallback.projects.some((p) => p.id === s.projectId) ? s.projectId : undefined,
        attachments: (Array.isArray(s.attachments) ? s.attachments : [])
          .filter((a) => typeof a?.id === 'string')
          .slice(0, 4),
        messages: s.messages
          .filter(
            (m) => m && ['user', 'assistant'].includes(m.role) && typeof m.content === 'string'
          )
          .map((m) => ({
            ...m,
            image: undefined,
            imageBlob: undefined,
            analysisProgress: undefined
          }))
          .slice(-MAX_MESSAGES_PER_SESSION)
      }))
      .slice(0, MAX_SESSIONS_PER_TAB)
    if (valid.length) fallback.sessions[tab] = valid
    fallback.activeSessions[tab] = valid.some((s) => s.id === saved.activeSessions?.[tab])
      ? saved.activeSessions![tab]
      : fallback.sessions[tab][0].id
  }
  return fallback
}

async function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('agent-os', 1)
    request.onupgradeneeded = (): void => {
      request.result.createObjectStore('sessions')
    }
    request.onsuccess = (): void => resolve(request.result)
    request.onerror = (): void => reject(request.error)
  })
}

async function save(value: Saved): Promise<void> {
  const sessions = Object.fromEntries(
    TAB_TYPES.map((tab) => [
      tab,
      value.sessions[tab].map((session) => ({
        ...session,
        messages: session.messages.map((message) => ({
          ...message,
          image: undefined,
          imageBlob: undefined,
          analysisProgress: undefined
        }))
      }))
    ])
  ) as ChatSessionMap
  const serializable: Saved = {
    sessions,
    activeSessions: value.activeSessions,
    projects: value.projects
  }
  const db = await database()
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction('sessions', 'readwrite')
      transaction.objectStore('sessions').put(serializable, 'current')
      transaction.oncomplete = (): void => resolve()
      transaction.onerror = (): void => reject(transaction.error)
      transaction.onabort = (): void => reject(transaction.error)
    })
  } finally {
    db.close()
  }
}

async function load(): Promise<Saved> {
  const db = await database()
  let value: unknown
  try {
    value = await new Promise((resolve, reject) => {
      const request = db.transaction('sessions').objectStore('sessions').get('current')
      request.onsuccess = (): void => resolve(request.result)
      request.onerror = (): void => reject(request.error)
    })
  } finally {
    db.close()
  }
  if (value) return validate(value)
  const legacy = localStorage.getItem(LEGACY_KEY)
  const migrated = validate(legacy ? JSON.parse(legacy) : null)
  await save(migrated) // Remove old quota-sensitive data only after durable migration.
  if (legacy) localStorage.removeItem(LEGACY_KEY)
  return migrated
}

export function useSessions(): {
  sessionsByTab: ChatSessionMap
  setSessionsByTab: Dispatch<SetStateAction<ChatSessionMap>>
  activeSessions: ActiveSessionMap
  setActiveSessions: Dispatch<SetStateAction<ActiveSessionMap>>
  ready: boolean
  storageError: string
  projects: Project[]
  setProjects: Dispatch<SetStateAction<Project[]>>
} {
  const [defaults] = useState(initial)
  const [sessionsByTab, setSessionsByTab] = useState(defaults.sessions)
  const [activeSessions, setActiveSessions] = useState(defaults.activeSessions)
  const [projects, setProjects] = useState<Project[]>([])
  const [ready, setReady] = useState(false)
  const [storageError, setStorageError] = useState('')
  const writable = useRef(false)
  useEffect(() => {
    let alive = true
    load()
      .then((saved) => {
        if (!alive) return
        setSessionsByTab(saved.sessions)
        setActiveSessions(saved.activeSessions)
        setProjects(saved.projects)
        writable.current = true
      })
      .catch(() => {
        if (alive)
          setStorageError(
            'Riwayat tidak dapat dibuka. Sesi ini sementara; data lama tidak ditimpa.'
          )
      })
      .finally(() => {
        if (alive) setReady(true)
      })
    return () => {
      alive = false
    }
  }, [])
  useEffect(() => {
    if (!ready || !writable.current) return
    const timer = setTimeout(() => {
      void save({ sessions: sessionsByTab, activeSessions, projects }).catch(() =>
        setStorageError(
          'Riwayat gagal disimpan. Penyimpanan mungkin penuh; ekspor informasi penting sebelum menutup.'
        )
      )
    }, 500)
    return () => clearTimeout(timer)
  }, [sessionsByTab, activeSessions, projects, ready])
  return {
    sessionsByTab,
    setSessionsByTab,
    activeSessions,
    setActiveSessions,
    projects,
    setProjects,
    ready,
    storageError
  }
}
