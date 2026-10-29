import type { ChatSessionMap, Project } from './types'
import { TAB_TYPES } from './sessions'
import type { Preferences } from './preferences'

export function exportBackup(
  sessions: ChatSessionMap,
  projects: Project[],
  preferences: Preferences
): string {
  return JSON.stringify(
    {
      format: 'agent-os-backup',
      version: 1,
      exportedAt: new Date().toISOString(),
      projects,
      preferences,
      sessions: Object.fromEntries(
        TAB_TYPES.map((tab) => [
          tab,
          sessions[tab].map((session) => ({
            ...session,
            attachments: [],
            messages: session.messages.map(({ role, content, sources, coverage }) => ({
              role,
              content,
              sources,
              coverage
            }))
          }))
        ])
      )
    },
    null,
    2
  )
}

export function importBackup(text: string): { sessions: ChatSessionMap; projects: Project[] } {
  const value = JSON.parse(text)
  if (
    value?.format !== 'agent-os-backup' ||
    value.version !== 1 ||
    !Array.isArray(value.projects) ||
    !value.sessions ||
    typeof value.sessions !== 'object'
  )
    throw new Error('Berkas bukan cadangan Jo Workspace versi 1.')
  if (value.projects.length > 500) throw new Error('Cadangan melebihi batas 500 project.')
  const mapping = new Map<string, string>()
  const projects = value.projects.map((p: Project) => {
    if (
      !p ||
      typeof p.id !== 'string' ||
      typeof p.name !== 'string' ||
      !p.name.trim() ||
      typeof p.instructions !== 'string'
    )
      throw new Error('Data project tidak valid.')
    const id = crypto.randomUUID()
    mapping.set(p.id, id)
    return {
      id,
      name: p.name.slice(0, 80),
      instructions: p.instructions.slice(0, 1500),
      createdAt: Date.now()
    }
  })
  const sessions = {} as ChatSessionMap
  for (const tab of TAB_TYPES) {
    const rows = value.sessions[tab]
    if (!Array.isArray(rows) || rows.length > 500)
      throw new Error('Data percakapan tidak valid atau terlalu besar.')
    sessions[tab] = rows.map((s) => {
      if (
        !s ||
        typeof s.title !== 'string' ||
        !Array.isArray(s.messages) ||
        s.messages.length > 100
      )
        throw new Error('Format percakapan tidak valid.')
      return {
        id: crypto.randomUUID(),
        title: s.title.slice(0, 100),
        createdAt: Number(s.createdAt) || Date.now(),
        updatedAt: Date.now(),
        projectId: mapping.get(s.projectId),
        pinned: s.pinned === true,
        archived: s.archived === true,
        attachments: [],
        messages: s.messages.map((m: { role: string; content: string }) => {
          if (
            !m ||
            !['user', 'assistant'].includes(m.role) ||
            typeof m.content !== 'string' ||
            m.content.length > 200000
          )
            throw new Error('Format pesan tidak valid.')
          return { role: m.role as 'user' | 'assistant', content: m.content }
        })
      }
    })
  }
  return { sessions, projects }
}
