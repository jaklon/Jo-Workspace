import type { ActiveSessionMap, ChatSession, ChatSessionMap, Project, TabType } from './types'
import { sanitizeMemory } from './project-memory'
import {
  fingerprint,
  reconcileRemote,
  syncKey,
  type SyncBase,
  type SyncConflict,
  type SyncRecord
} from './sync-merge'

export const SYNC_TABS: TabType[] = ['chat', 'code', 'vision', 'docs', 'pentest']
export interface SyncMeta {
  workspaceId: string | null
  cursor: number
  base: Record<string, SyncBase>
  conflicts: Record<string, SyncRecord>
  restoreAllowed?: Record<string, number>
  pending?: { requestId: string; changes: SyncChange[] }
}
export interface WorkspaceData {
  sessions: ChatSessionMap
  activeSessions: ActiveSessionMap
  projects: Project[]
  sync: SyncMeta
}
export interface SyncChange {
  kind: 'project' | 'session'
  id: string
  expected: number
  deleted: boolean
  restore?: boolean
  data: Record<string, unknown> | null
}
export const emptySync = (): SyncMeta => ({ workspaceId: null, cursor: 0, base: {}, conflicts: {} })

function blank(session: ChatSession): boolean {
  return (
    session.title === 'Percakapan baru' &&
    !session.messages.length &&
    !session.attachments?.length &&
    !session.projectId &&
    !session.pinned &&
    !session.archived
  )
}

export function localRecords(state: WorkspaceData): Record<string, Record<string, unknown>> {
  const result: Record<string, Record<string, unknown>> = {}
  for (const project of state.projects) {
    result[syncKey('project', project.id)] = {
      id: project.id,
      name: project.name,
      instructions: project.instructions,
      // Omitted when empty so projects without memory keep their previous sync fingerprint.
      ...(project.memory?.length ? { memory: project.memory } : {}),
      createdAt: project.createdAt
    }
  }
  for (const tab of SYNC_TABS)
    for (const session of state.sessions[tab]) {
      const key = syncKey('session', session.id)
      if (blank(session) && !state.sync.base[key] && !state.sync.conflicts[key]) continue
      result[key] = {
        id: session.id,
        tab,
        title: session.title,
        createdAt: session.createdAt,
        updatedAt: session.updatedAt,
        projectId: session.projectId ?? null,
        pinned: !!session.pinned,
        archived: !!session.archived,
        attachments: session.attachments ?? [],
        messages: session.messages.map(
          ({ role, content, visualAnalysis, trace, thinking, sources, coverage }) => ({
            role,
            content,
            visualAnalysis,
            trace,
            thinking,
            sources,
            coverage
          })
        )
      }
    }
  return result
}

function applyRecord(state: WorkspaceData, record: SyncRecord): WorkspaceData {
  const next = {
    ...state,
    projects: [...state.projects],
    sessions: { ...state.sessions },
    activeSessions: { ...state.activeSessions }
  }
  if (record.kind === 'project') {
    if (
      !record.deleted &&
      !next.projects.some((item) => item.id === record.id) &&
      next.projects.length >= 500
    )
      throw new Error('Batas 500 project lokal tercapai. Ekspor data sebelum menyinkronkan.')
    next.projects = next.projects.filter((item) => item.id !== record.id)
    if (!record.deleted && record.data) {
      const project = record.data as unknown as Project
      next.projects.push({ ...project, memory: sanitizeMemory(project.memory) })
    }
    return next
  }
  const existingTab = SYNC_TABS.find((tab) => next.sessions[tab].some((s) => s.id === record.id))
  const existing = existingTab
    ? next.sessions[existingTab].find((s) => s.id === record.id)
    : undefined
  if (existingTab)
    next.sessions[existingTab] = next.sessions[existingTab].filter((s) => s.id !== record.id)
  if (!record.deleted && record.data) {
    const { tab, ...session } = record.data
    if (!SYNC_TABS.includes(tab as TabType)) throw new Error('Mode chat dari server tidak valid.')
    const target = tab as TabType
    if (next.sessions[target].length >= 500)
      throw new Error('Batas 500 chat lokal tercapai. Ekspor data sebelum menyinkronkan.')
    const incoming = session as unknown as ChatSession
    if (
      existing &&
      existing.messages.length === incoming.messages.length &&
      existing.messages.every(
        (m, i) => m.role === incoming.messages[i].role && m.content === incoming.messages[i].content
      )
    ) {
      incoming.messages = incoming.messages.map((m, i) => ({
        ...m,
        action: existing.messages[i].action,
        proposals: existing.messages[i].proposals,
        webImages: existing.messages[i].webImages,
        image: existing.messages[i].image,
        imageBlob: existing.messages[i].imageBlob
      }))
    }
    next.sessions[target] = [incoming, ...next.sessions[target]]
  }
  for (const tab of SYNC_TABS) {
    if (!next.sessions[tab].length) {
      const id = crypto.randomUUID()
      next.sessions[tab] = [
        {
          id,
          title: 'Percakapan baru',
          createdAt: Date.now(),
          updatedAt: Date.now(),
          messages: [],
          attachments: []
        }
      ]
    }
    if (!next.sessions[tab].some((s) => s.id === next.activeSessions[tab]))
      next.activeSessions[tab] = next.sessions[tab][0].id
  }
  return next
}

export function receiveRemote(
  state: WorkspaceData,
  records: SyncRecord[],
  cursor: number,
  workspaceId: string
): WorkspaceData {
  if (state.sync.workspaceId && state.sync.workspaceId !== workspaceId)
    throw new Error(
      'Backend berbeda dari sinkronisasi sebelumnya. Data lokal dipertahankan; ekspor cadangan sebelum berganti backend.'
    )
  const decisions = reconcileRemote(localRecords(state), state.sync.base, records)
  for (const record of [...decisions.updates]) {
    if (record.kind !== 'project' || !record.deleted) continue
    const depends = SYNC_TABS.flatMap((tab) => state.sessions[tab]).some((session) => {
      if (session.projectId !== record.id) return false
      const replacement = decisions.updates.find(
        (item) => item.kind === 'session' && item.id === session.id
      )
      return !replacement || (!replacement.deleted && replacement.data?.projectId === record.id)
    })
    if (depends) {
      decisions.updates = decisions.updates.filter((item) => item !== record)
      delete decisions.accepted[syncKey('project', record.id)]
      decisions.conflicts.push({
        key: syncKey('project', record.id),
        local: localRecords(state)[syncKey('project', record.id)] ?? null,
        remote: record
      })
    }
  }
  let next = state
  // Apply project changes first so session references remain meaningful.
  for (const record of [...decisions.updates].sort(
    (a, b) => Number(a.kind === 'session') - Number(b.kind === 'session')
  )) {
    next = applyRecord(next, record)
  }
  const conflicts = { ...state.sync.conflicts }
  for (const record of records) delete conflicts[syncKey(record.kind, record.id)]
  for (const conflict of decisions.conflicts) conflicts[conflict.key] = conflict.remote
  return {
    ...next,
    sync: {
      ...state.sync,
      workspaceId,
      cursor,
      base: { ...state.sync.base, ...decisions.accepted },
      conflicts
    }
  }
}

export function pendingChanges(state: WorkspaceData): SyncChange[] {
  const local = localRecords(state)
  const keys = new Set([...Object.keys(local), ...Object.keys(state.sync.base)])
  const changes: SyncChange[] = []
  for (const key of keys) {
    if (state.sync.conflicts[key]) continue
    const [kind, ...rest] = key.split(':')
    const id = rest.join(':')
    if (kind !== 'project' && kind !== 'session') continue
    const data = local[key] ?? null
    const previous = state.sync.base[key]
    const hash = data === null ? null : fingerprint(data)
    if (hash === (previous?.fingerprint ?? null)) continue
    if (
      data !== null &&
      previous?.fingerprint === null &&
      state.sync.restoreAllowed?.[key] !== previous.version
    )
      continue
    changes.push({
      kind,
      id,
      expected: previous?.version ?? 0,
      deleted: data === null,
      ...(data !== null && previous?.fingerprint === null ? { restore: true } : {}),
      data
    })
  }
  return changes.sort((a, b) => {
    const priority = (x: SyncChange): number =>
      x.kind === 'project' && !x.deleted ? 0 : x.kind === 'session' ? 1 : 2
    return priority(a) - priority(b)
  })
}

export function acknowledge(
  state: WorkspaceData,
  sent: SyncChange[],
  results: Array<{ kind: 'project' | 'session'; id: string; version: number }>
): WorkspaceData {
  const base = { ...state.sync.base }
  const restoreAllowed = { ...state.sync.restoreAllowed }
  for (const item of results) {
    const change = sent.find((c) => c.kind === item.kind && c.id === item.id)
    if (!change) throw new Error('Respons sinkronisasi tidak cocok dengan permintaan.')
    base[syncKey(item.kind, item.id)] = {
      version: item.version,
      fingerprint: change.deleted ? null : fingerprint(change.data)
    }
    delete restoreAllowed[syncKey(item.kind, item.id)]
  }
  return { ...state, sync: { ...state.sync, base, restoreAllowed } }
}

export function resolveConflict(
  state: WorkspaceData,
  key: string,
  choice: 'local' | 'remote'
): WorkspaceData {
  const remote =
    state.sync.conflicts[key] ?? conflictList(state).find((item) => item.key === key)?.remote
  if (!remote) return state
  if (
    choice === 'remote' &&
    remote.kind === 'project' &&
    remote.deleted &&
    SYNC_TABS.flatMap((tab) => state.sessions[tab]).some(
      (session) => session.projectId === remote.id
    )
  ) {
    throw new Error('Pindahkan chat dari project ini sebelum menerima penghapusan server.')
  }
  const next = choice === 'remote' ? applyRecord(state, remote) : state
  const conflicts = { ...state.sync.conflicts }
  delete conflicts[key]
  const restoreAllowed = { ...next.sync.restoreAllowed }
  if (choice === 'local' && remote.deleted) restoreAllowed[key] = remote.version
  else delete restoreAllowed[key]
  return {
    ...next,
    sync: {
      ...next.sync,
      conflicts,
      restoreAllowed,
      base: {
        ...next.sync.base,
        [key]: {
          version: remote.version,
          fingerprint: remote.deleted ? null : fingerprint(remote.data)
        }
      }
    }
  }
}

export function conflictList(state: WorkspaceData): SyncConflict[] {
  const local = localRecords(state)
  const result = Object.entries(state.sync.conflicts).map(([key, remote]) => ({
    key,
    local: local[key] ?? null,
    remote
  }))
  for (const [key, base] of Object.entries(state.sync.base)) {
    if (
      base.fingerprint !== null ||
      !local[key] ||
      state.sync.conflicts[key] ||
      state.sync.restoreAllowed?.[key] === base.version
    )
      continue
    const separator = key.indexOf(':')
    const kind = key.slice(0, separator)
    if (kind !== 'project' && kind !== 'session') continue
    result.push({
      key,
      local: local[key],
      remote: {
        kind,
        id: key.slice(separator + 1),
        version: base.version,
        deleted: true,
        data: null
      }
    })
  }
  return result
}

// Merge a browser recovery snapshot with already-pulled server records. Divergent
// records remain reviewable; neither copy is silently selected for the server.
export function mergeRecovery(
  state: WorkspaceData,
  recovery: Pick<WorkspaceData, 'sessions' | 'activeSessions' | 'projects'>
): WorkspaceData {
  if (
    !state.sync.workspaceId ||
    state.sync.pending ||
    pendingChanges(state).length ||
    conflictList(state).length
  )
    throw new Error(
      'Selesaikan sinkronisasi dan konflik yang ada sebelum mengimpor snapshot pemulihan.'
    )
  const previous = localRecords(state)
  const projectIds = new Set(recovery.projects.map((item) => item.id))
  const sessionIds = new Set(
    SYNC_TABS.flatMap((tab) => recovery.sessions[tab].map((item) => item.id))
  )
  const sessions = Object.fromEntries(
    SYNC_TABS.map((tab) => [
      tab,
      [
        ...recovery.sessions[tab],
        ...state.sessions[tab].filter((item) => !sessionIds.has(item.id) && !blank(item))
      ]
    ])
  ) as ChatSessionMap
  const projects = [
    ...recovery.projects,
    ...state.projects.filter((item) => !projectIds.has(item.id))
  ]
  if (projects.length > 500 || SYNC_TABS.some((tab) => sessions[tab].length > 500))
    throw new Error('Hasil impor melebihi batas 500 project atau 500 chat per mode.')
  for (const tab of SYNC_TABS) if (!sessions[tab].length) sessions[tab] = state.sessions[tab]
  const next: WorkspaceData = {
    ...state,
    sessions,
    projects,
    activeSessions: recovery.activeSessions
  }
  const incoming = localRecords(next)
  const conflicts = { ...state.sync.conflicts }
  for (const key of [...Object.keys(incoming)]) {
    const base = state.sync.base[key]
    if (!base || fingerprint(incoming[key]) === base.fingerprint) continue
    const separator = key.indexOf(':')
    const kind = key.slice(0, separator) as 'project' | 'session'
    conflicts[key] = {
      kind,
      id: key.slice(separator + 1),
      version: base.version,
      deleted: base.fingerprint === null,
      data: previous[key] ?? null
    }
  }
  return { ...next, sync: { ...state.sync, conflicts } }
}
