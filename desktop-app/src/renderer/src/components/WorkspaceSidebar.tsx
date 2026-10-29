import { useState, type JSX } from 'react'
import {
  Search,
  SquarePen,
  FolderPlus,
  Folder,
  MessageSquare,
  MoreHorizontal,
  Settings2,
  ChartNoAxesCombined,
  PanelLeftClose,
  Archive,
  Pin,
  Layers,
  ChevronRight
} from 'lucide-react'
import type { ChatSession, ChatSessionMap, Project, TabType } from '../lib/types'
import { modeLabels } from '../lib/types'
import { TAB_TYPES } from '../lib/sessions'
import { BrandMark } from './BrandMark'

export interface SessionRow {
  tab: TabType
  session: ChatSession
}

export function WorkspaceSidebar({
  collapsed,
  onCollapse,
  sessions,
  currentId,
  projects,
  selectedProject,
  onProject,
  onNewProject,
  onEditProject,
  onSelect,
  onManage,
  onNewChat,
  onSettings,
  onUsage,
  onSecurity,
  onWebSearch,
  disabled,
  name,
  connection
}: {
  collapsed: boolean
  onCollapse: () => void
  sessions: ChatSessionMap
  currentId: string
  projects: Project[]
  selectedProject: string
  onProject: (id: string) => void
  onNewProject: () => void
  onEditProject: (project: Project) => void
  onSelect: (row: SessionRow) => void
  onManage: (row: SessionRow) => void
  onNewChat: () => void
  onSettings: () => void
  onUsage: () => void
  onSecurity: () => void
  onWebSearch: () => void
  disabled: boolean
  name: string
  connection: string
}): JSX.Element {
  const [query, setQuery] = useState('')
  const [archived, setArchived] = useState(false)
  const rows = TAB_TYPES.flatMap((tab) => sessions[tab].map((session) => ({ tab, session })))
    .filter(
      ({ session }) =>
        session.messages.length > 0 ||
        session.title !== 'Percakapan baru' ||
        session.id === currentId ||
        session.projectId ||
        session.archived ||
        session.pinned
    )
    .filter(
      ({ session }) =>
        Boolean(session.archived) === archived &&
        (selectedProject === 'all' ||
          (selectedProject === 'none' ? !session.projectId : session.projectId === selectedProject))
    )
    .filter(
      ({ session }) =>
        !query.trim() ||
        `${session.title} ${session.messages.map((m) => m.content).join(' ')}`
          .toLocaleLowerCase()
          .includes(query.trim().toLocaleLowerCase())
    )
    .sort(
      (a, b) =>
        Number(Boolean(b.session.pinned)) - Number(Boolean(a.session.pinned)) ||
        b.session.updatedAt - a.session.updatedAt
    )
  return (
    <>
      {!collapsed && (
        <button className="sidebar-scrim" aria-label="Tutup sidebar" onClick={onCollapse} />
      )}
      <aside
        className={`workspace-sidebar ${collapsed ? 'sidebar-collapsed' : ''}`}
        aria-label="Sidebar percakapan"
      >
        <div className="sidebar-brand">
          <BrandMark />
          <strong>
            Jo Workspace<span>Personal workspace</span>
          </strong>
          <button className="icon-button" onClick={onCollapse} aria-label="Ciutkan sidebar">
            <PanelLeftClose size={18} />
          </button>
        </div>
        <div className="sidebar-actions">
          <button className="nav-item" onClick={onWebSearch}>
            <Search size={18} />
            <span>Cari web melalui chat</span>
            <small>Chat</small>
          </button>
          <button className="nav-item" onClick={onSecurity}>
            <Folder size={18} />
            <span>Security Workspace</span>
            <small>Riwayat</small>
          </button>
          <button className="nav-item" onClick={onNewChat} disabled={disabled}>
            <SquarePen size={18} />
            <span>Chat baru</span>
            <kbd>Ctrl ⇧ O</kbd>
          </button>
          <label className="sidebar-search">
            <Search size={17} />
            <input
              id="chat-search"
              placeholder="Cari percakapan"
              aria-label="Cari percakapan"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <kbd>Ctrl K</kbd>
          </label>
        </div>
        <div className="sidebar-scroll scrollbar-thin">
          <div className="sidebar-heading">
            <span>PROJECTS</span>
            <button
              className="icon-button"
              disabled={disabled}
              onClick={onNewProject}
              aria-label="Buat project"
            >
              <FolderPlus size={16} />
            </button>
          </div>
          <button
            className={`nav-item ${selectedProject === 'all' ? 'selected' : ''}`}
            onClick={() => onProject('all')}
          >
            <Layers size={17} />
            <span>Semua percakapan</span>
            <small>
              {TAB_TYPES.reduce(
                (n, t) =>
                  n +
                  sessions[t].filter(
                    (s) =>
                      !s.archived &&
                      (s.messages.length ||
                        s.title !== 'Percakapan baru' ||
                        s.projectId ||
                        s.pinned ||
                        s.id === currentId)
                  ).length,
                0
              )}
            </small>
          </button>
          <button
            className={`nav-item ${selectedProject === 'none' ? 'selected' : ''}`}
            onClick={() => onProject('none')}
          >
            <MessageSquare size={17} />
            <span>Tanpa project</span>
          </button>
          {projects.map((project) => (
            <div
              className={`project-row ${selectedProject === project.id ? 'selected' : ''}`}
              key={project.id}
            >
              <button className="nav-item" onClick={() => onProject(project.id)}>
                <Folder size={17} />
                <span>{project.name}</span>
              </button>
              <button
                className="row-menu icon-button"
                disabled={disabled}
                aria-label={`Kelola project ${project.name}`}
                onClick={() => onEditProject(project)}
              >
                <MoreHorizontal size={16} />
              </button>
            </div>
          ))}
          {!projects.length && (
            <button className="project-invite" disabled={disabled} onClick={onNewProject}>
              Kelompokkan ide dan pekerjaan Anda dalam sebuah project.
              <span>
                Buat project <ChevronRight size={13} />
              </span>
            </button>
          )}
          <div className="sidebar-heading history-heading">
            <span>{archived ? 'ARSIP' : query ? 'HASIL PENCARIAN' : 'PERCAKAPAN'}</span>
            <button
              className={`icon-button ${archived ? 'active' : ''}`}
              onClick={() => setArchived(!archived)}
              aria-label={archived ? 'Lihat chat aktif' : 'Lihat arsip'}
              title={archived ? 'Lihat chat aktif' : 'Lihat arsip'}
            >
              <Archive size={15} />
            </button>
          </div>
          {rows.length === 0 && (
            <p className="sidebar-empty">
              {query
                ? 'Tidak ada percakapan yang cocok.'
                : archived
                  ? 'Belum ada chat di arsip.'
                  : 'Mulai percakapan di sini.'}
            </p>
          )}
          {rows.map((row) => (
            <div
              className={`session-row ${row.session.id === currentId ? 'selected' : ''}`}
              key={row.session.id}
            >
              <button disabled={disabled} className="session-select" onClick={() => onSelect(row)}>
                <span className="session-title">
                  {row.session.pinned && <Pin size={11} />}
                  {row.session.title}
                </span>
                <small>
                  {modeLabels[row.tab]}
                  {row.session.projectId && selectedProject === 'all'
                    ? ` · ${projects.find((p) => p.id === row.session.projectId)?.name || 'Project'}`
                    : ''}
                </small>
              </button>
              <button
                className="row-menu icon-button"
                disabled={disabled}
                aria-label={`Kelola ${row.session.title}`}
                onClick={() => onManage(row)}
              >
                <MoreHorizontal size={17} />
              </button>
            </div>
          ))}
        </div>
        <div className="sidebar-footer">
          <button className="nav-item" onClick={onUsage}>
            <ChartNoAxesCombined size={18} />
            <span>Usage</span>
            <small>Local</small>
          </button>
          <button className="profile-button" onClick={onSettings}>
            <span className="profile-avatar">{(name || 'A')[0].toUpperCase()}</span>
            <span>
              <strong>{name || 'Workspace saya'}</strong>
              <small>{connection} · Lokal</small>
            </span>
            <Settings2 size={18} />
          </button>
        </div>
      </aside>
    </>
  )
}
