import { useEffect, useRef, useState } from 'react'
import type { Dispatch, SetStateAction } from 'react'
import type { ActiveSessionMap, ChatSession, ChatSessionMap, TabType, Project } from './types'
import { apiFetch } from './api'
import { sanitizeMemory } from './project-memory'
import {
  acknowledge,
  conflictList,
  emptySync,
  mergeRecovery,
  pendingChanges,
  receiveRemote,
  resolveConflict,
  type SyncMeta,
  type WorkspaceData
} from './workspace-sync'
import type { SyncConflict, SyncRecord } from './sync-merge'
export const TAB_TYPES: TabType[] = ['chat', 'code', 'vision', 'docs', 'pentest']
const LEGACY_KEY = 'agent_os_chat_history'
const MAX_SESSIONS_PER_TAB = 500
const MAX_MESSAGES_PER_SESSION = 100
type Saved = WorkspaceData

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
  return { sessions, activeSessions, projects: [], sync: emptySync() }
}

export function validate(value: unknown): Saved {
  const fallback = initial()
  if (!value || typeof value !== 'object') return fallback
  const saved = value as Partial<Saved> & Partial<Record<TabType, ChatSession['messages']>>
  if (saved.sync !== undefined) {
    const sync = saved.sync as SyncMeta
    if (
      !sync ||
      (sync.workspaceId !== null && typeof sync.workspaceId !== 'string') ||
      !Number.isSafeInteger(sync.cursor) ||
      sync.cursor < 0 ||
      !sync.base ||
      typeof sync.base !== 'object' ||
      !sync.conflicts ||
      typeof sync.conflicts !== 'object'
    )
      throw new Error('Metadata sinkronisasi tidak valid.')
    fallback.sync = sync
  }
  fallback.projects = (Array.isArray(saved.projects) ? saved.projects : [])
    .filter((p) => p && typeof p.id === 'string' && typeof p.name === 'string')
    .map((p) => ({
      id: p.id,
      name: p.name.slice(0, 80),
      instructions: typeof p.instructions === 'string' ? p.instructions.slice(0, 1500) : '',
      memory: sanitizeMemory(p.memory),
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
            analysisProgress: undefined,
            // A stream cut off by closing the app must not leave a step spinning forever.
            trace: Array.isArray(m.trace)
              ? m.trace.map((s) => (s.endedAt ? s : { ...s, endedAt: s.startedAt }))
              : undefined,
            thinking: typeof m.thinking === 'string' ? m.thinking : undefined
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

const LEASE_MS = 30000

async function claimLease(owner: string): Promise<boolean> {
  const db = await database()
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction('sessions', 'readwrite')
      const store = tx.objectStore('sessions')
      const request = store.get('sync-lease')
      let acquired = false
      request.onsuccess = (): void => {
        const lease = request.result as { owner?: string; expires?: number } | undefined
        if (!lease || lease.owner === owner || !lease.expires || lease.expires <= Date.now()) {
          acquired = true
          store.put({ owner, expires: Date.now() + LEASE_MS }, 'sync-lease')
        }
      }
      tx.oncomplete = (): void => resolve(acquired)
      tx.onerror = (): void => reject(tx.error)
      tx.onabort = (): void => reject(tx.error)
    })
  } finally {
    db.close()
  }
}

async function releaseLease(owner: string): Promise<void> {
  const db = await database()
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('sessions', 'readwrite')
      const store = tx.objectStore('sessions')
      const request = store.get('sync-lease')
      request.onsuccess = (): void => {
        if (request.result?.owner === owner) store.delete('sync-lease')
      }
      tx.oncomplete = (): void => resolve()
      tx.onerror = (): void => reject(tx.error)
      tx.onabort = (): void => reject(tx.error)
    })
  } finally {
    db.close()
  }
}

async function save(value: Saved, owner: string): Promise<void> {
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
    projects: value.projects,
    sync: value.sync
  }
  const db = await database()
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction('sessions', 'readwrite')
      const store = transaction.objectStore('sessions')
      const lease = store.get('sync-lease')
      lease.onsuccess = (): void => {
        if (lease.result?.owner !== owner || lease.result.expires <= Date.now()) {
          transaction.abort()
          return
        }
        store.put(serializable, 'current')
      }
      transaction.oncomplete = (): void => resolve()
      transaction.onerror = (): void => reject(transaction.error)
      transaction.onabort = (): void => reject(transaction.error)
    })
  } finally {
    db.close()
  }
}

async function load(owner: string): Promise<Saved> {
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
  await save(migrated, owner) // Remove old quota-sensitive data only after durable migration.
  if (legacy) localStorage.removeItem(LEGACY_KEY)
  return migrated
}

export function useSessions(suspended = false): {
  sessionsByTab: ChatSessionMap
  setSessionsByTab: Dispatch<SetStateAction<ChatSessionMap>>
  activeSessions: ActiveSessionMap
  setActiveSessions: Dispatch<SetStateAction<ActiveSessionMap>>
  ready: boolean
  storageError: string
  projects: Project[]
  setProjects: Dispatch<SetStateAction<Project[]>>
  syncStatus: string
  syncConflicts: SyncConflict[]
  reviewSyncConflict: (key: string, choice: 'local' | 'remote') => void
  importSyncedRecovery: (
    recovery: Pick<WorkspaceData, 'sessions' | 'activeSessions' | 'projects'>
  ) => void
} {
  const [defaults] = useState(initial)
  const [state, setState] = useState(defaults)
  const [ready, setReady] = useState(false)
  const [storageError, setStorageError] = useState('')
  const [syncStatus, setSyncStatus] = useState('Menyiapkan sinkronisasi')
  const current = useRef(defaults)
  const writable = useRef(false)
  const [owner] = useState(() => crypto.randomUUID())
  const leaseGeneration = useRef(0)
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const saveChain = useRef<Promise<void>>(Promise.resolve())
  const flush = (): Promise<void> => {
    if (saveTimer.current) clearTimeout(saveTimer.current)
    saveTimer.current = null
    const snapshot = current.current
    const operation = saveChain.current.catch(() => {}).then(() => save(snapshot, owner))
    saveChain.current = operation
    return operation.catch((error) => {
      writable.current = false
      setReady(false)
      setStorageError(
        'Riwayat gagal disimpan atau dipakai tab lain. Ekspor data penting sebelum menutup tab ini.'
      )
      throw error
    })
  }
  const flushStable = async (): Promise<void> => {
    for (;;) {
      const snapshot = current.current
      await flush()
      if (snapshot === current.current) return
    }
  }
  const commit = (next: Saved): void => {
    current.current = next
    setState(next)
    if (!writable.current) return
    if (saveTimer.current) clearTimeout(saveTimer.current)
    saveTimer.current = setTimeout(() => {
      void flush().catch(() => {})
    }, 400)
  }
  const setSessionsByTab: Dispatch<SetStateAction<ChatSessionMap>> = (action) => {
    const previous = current.current
    commit({
      ...previous,
      sessions: typeof action === 'function' ? action(previous.sessions) : action
    })
  }
  const setActiveSessions: Dispatch<SetStateAction<ActiveSessionMap>> = (action) => {
    const previous = current.current
    commit({
      ...previous,
      activeSessions: typeof action === 'function' ? action(previous.activeSessions) : action
    })
  }
  const setProjects: Dispatch<SetStateAction<Project[]>> = (action) => {
    const previous = current.current
    commit({
      ...previous,
      projects: typeof action === 'function' ? action(previous.projects) : action
    })
  }
  useEffect(() => {
    let alive = true
    const generation = ++leaseGeneration.current
    const releaseIfCurrent = (): Promise<void> =>
      generation === leaseGeneration.current ? releaseLease(owner) : Promise.resolve()
    let retry: ReturnType<typeof setTimeout> | undefined
    let heartbeat: ReturnType<typeof setInterval> | undefined
    const start = async (): Promise<void> => {
      try {
        const acquired = await claimLease(owner)
        if (!alive) {
          if (acquired) void releaseIfCurrent()
          return
        }
        if (!acquired) {
          setStorageError(
            'Workspace sedang dibuka di tab lain. Tutup tab tersebut agar data tidak saling menimpa.'
          )
          retry = setTimeout(() => {
            void start()
          }, 5000)
          return
        }
        const saved = await load(owner)
        if (!alive) {
          void releaseIfCurrent()
          return
        }
        current.current = saved
        setState(saved)
        writable.current = true
        setStorageError('')
        setReady(true)
        heartbeat = setInterval(() => {
          if (!writable.current) {
            if (heartbeat) clearInterval(heartbeat)
            void releaseIfCurrent().catch(() => {})
            return
          }
          void claimLease(owner)
            .then((held) => {
              if (!alive || held) return
              if (heartbeat) clearInterval(heartbeat)
              writable.current = false
              setReady(false)
              setStorageError(
                'Tab lain mengambil akses penyimpanan. Ekspor perubahan lokal sebelum menutup tab ini.'
              )
            })
            .catch(() => {
              if (!alive) return
              if (heartbeat) clearInterval(heartbeat)
              writable.current = false
              setReady(false)
              setStorageError(
                'Penyimpanan tidak dapat diperiksa. Ekspor perubahan lokal sebelum menutup tab ini.'
              )
            })
        }, 5000)
      } catch {
        void releaseIfCurrent().catch(() => {})
        if (alive)
          setStorageError(
            'Riwayat tidak dapat dibuka. Sesi ini sementara; data lama tidak ditimpa.'
          )
      }
    }
    void start()
    const pagehide = (): void => {
      if (!writable.current) return
      writable.current = false
      void flush()
        .catch(() => {})
        .finally(() => releaseIfCurrent().catch(() => {}))
    }
    const pageshow = (event: PageTransitionEvent): void => {
      if (!event.persisted) return
      setReady(false)
      setStorageError(
        'Tab dilanjutkan dari keadaan tertidur. Ekspor perubahan lokal jika perlu, lalu muat ulang tab untuk menghindari konflik penyimpanan.'
      )
    }
    window.addEventListener('pagehide', pagehide)
    window.addEventListener('pageshow', pageshow)
    return () => {
      alive = false
      if (retry) clearTimeout(retry)
      if (heartbeat) clearInterval(heartbeat)
      if (saveTimer.current) clearTimeout(saveTimer.current)
      window.removeEventListener('pagehide', pagehide)
      window.removeEventListener('pageshow', pageshow)
      if (writable.current) {
        writable.current = false
        void flush()
          .catch(() => {})
          .finally(() => releaseIfCurrent().catch(() => {}))
      }
    }
  }, [owner])
  useEffect(() => {
    if (!ready || !writable.current || suspended) return
    let alive = true
    let timer: ReturnType<typeof setTimeout> | undefined
    const sendPending = async (): Promise<boolean> => {
      const pending = current.current.sync.pending
      if (!pending) return true
      try {
        const response = await apiFetch('/api/workspace-sync/changes', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ request_id: pending.requestId, changes: pending.changes })
        })
        const result = await response.json()
        if (!alive) return false
        const next = acknowledge(current.current, pending.changes, result.items)
        commit({ ...next, sync: { ...next.sync, pending: undefined } })
        await flushStable()
        return alive
      } catch (error) {
        if (alive && (error as { status?: number })?.status === 409) {
          const next = current.current
          commit({ ...next, sync: { ...next.sync, pending: undefined } })
          await flushStable()
          throw error
        }
        throw error
      }
    }
    const cycle = async (): Promise<void> => {
      try {
        await flushStable()
        if (!alive) return
        if (current.current.sync.pending) {
          const check = await apiFetch(
            `/api/workspace-sync/changes?after=${current.current.sync.cursor}`
          )
          const identity = await check.json()
          if (
            !current.current.sync.workspaceId ||
            identity.workspace_id !== current.current.sync.workspaceId
          )
            throw new Error(
              'Backend berbeda dari sinkronisasi sebelumnya. Data lokal dipertahankan; ekspor cadangan sebelum berganti backend.'
            )
          if (!alive) return
        }
        if (!(await sendPending())) return
        let cursor = current.current.sync.cursor
        let workspaceId = ''
        for (;;) {
          const response = await apiFetch(`/api/workspace-sync/changes?after=${cursor}`)
          const page: {
            items: SyncRecord[]
            cursor: number
            has_more: boolean
            workspace_id: string
          } = await response.json()
          if (!alive) return
          if (workspaceId && workspaceId !== page.workspace_id)
            throw new Error('Identitas backend berubah saat sinkronisasi.')
          workspaceId = page.workspace_id
          if (page.has_more && page.cursor <= cursor)
            throw new Error('Cursor sinkronisasi tidak bergerak.')
          cursor = page.cursor
          commit(receiveRemote(current.current, page.items, cursor, workspaceId))
          await flushStable()
          if (!alive) return
          if (!page.has_more) break
        }
        const changes = pendingChanges(current.current)
        const sent = [] as typeof changes
        let size = 0
        for (const change of changes) {
          const bytes = new TextEncoder().encode(JSON.stringify(change)).length
          if (sent.length && (sent.length >= 20 || size + bytes > 6_000_000)) break
          sent.push(change)
          size += bytes
        }
        if (sent.length) {
          const next = current.current
          commit({
            ...next,
            sync: { ...next.sync, pending: { requestId: crypto.randomUUID(), changes: sent } }
          })
          await flushStable()
          if (!alive || !(await sendPending())) return
        }
        if (alive)
          setSyncStatus(
            conflictList(current.current).length
              ? 'Ada konflik yang perlu ditinjau.'
              : changes.length > sent.length
                ? 'Menyinkronkan perubahan…'
                : 'Sinkron dengan backend'
          )
      } catch (error) {
        if (alive)
          setSyncStatus(
            error instanceof Error && error.message.includes('Backend berbeda')
              ? error.message
              : `Sinkronisasi tertunda${error instanceof Error && (error as Error & { status?: number }).status === 409 ? ': ' + error.message : ''}; perubahan tetap tersimpan di perangkat ini.`
          )
      } finally {
        if (alive)
          timer = setTimeout(() => {
            void cycle()
          }, 3000)
      }
    }
    void cycle()
    return () => {
      alive = false
      if (timer) clearTimeout(timer)
    }
  }, [ready, suspended])
  return {
    sessionsByTab: state.sessions,
    setSessionsByTab,
    activeSessions: state.activeSessions,
    setActiveSessions,
    projects: state.projects,
    setProjects,
    ready,
    storageError,
    syncStatus,
    syncConflicts: conflictList(state),
    reviewSyncConflict: (key, choice) => commit(resolveConflict(current.current, key, choice)),
    importSyncedRecovery: (recovery) => commit(mergeRecovery(current.current, recovery))
  }
}
