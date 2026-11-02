import { useState, type JSX } from 'react'
import { Archive, Download, Pin, Trash2 } from 'lucide-react'
import { Modal } from './Modal'
import type { ChatSession, Project, ProjectFact } from '../lib/types'
import { ProjectMemoryList } from './ProjectMemory'
import { downloadFile } from '../lib/preferences'

export function ProjectEditor({
  project,
  onSave,
  onDelete,
  onClose
}: {
  project: Project | null
  onSave: (name: string, instructions: string, memory: ProjectFact[]) => void
  onDelete: () => Promise<void>
  onClose: () => void
}): JSX.Element {
  const [name, setName] = useState(project?.name || '')
  const [instructions, setInstructions] = useState(project?.instructions || '')
  const [memory, setMemory] = useState<ProjectFact[]>(project?.memory || [])
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  return (
    <Modal
      title={project ? 'Pengaturan project' : 'Project baru'}
      onClose={() => {
        if (!busy) onClose()
      }}
    >
      <form
        className="organize-form"
        onSubmit={(e) => {
          e.preventDefault()
          if (name.trim()) onSave(name.trim(), instructions.trim(), memory)
        }}
      >
        <p className="muted-text">
          Satukan percakapan untuk satu topik atau pekerjaan. Anda juga bisa chat tanpa project.
        </p>
        <label className="field-block">
          Nama project
          <input
            autoFocus
            required
            maxLength={80}
            placeholder="Misalnya: Aplikasi toko online"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label className="field-block">
          Instruksi project <small>Opsional</small>
          <textarea
            maxLength={1500}
            rows={5}
            placeholder="Apa yang perlu diketahui AI saat bekerja dalam project ini?"
            value={instructions}
            onChange={(e) => setInstructions(e.target.value)}
          />
          <small>{instructions.length}/1500 karakter · Dikirim bersama pesan di project ini.</small>
        </label>
        <ProjectMemoryList memory={memory} onChange={setMemory} />
        <p className="muted-text">
          Project mengelompokkan chat. Riwayat dan lampiran antarpercakapan tidak dibagikan
          otomatis; hanya instruksi dan memori project di atas yang ikut dikirim.
        </p>
        <div className="settings-form-actions">
          {project && (
            <button type="button" className="danger-button" onClick={() => setConfirm(true)}>
              <Trash2 size={14} /> Hapus project
            </button>
          )}
          <button className="primary-button" disabled={!name.trim() || busy}>
            {project ? 'Simpan perubahan' : 'Buat project'}
          </button>
        </div>
        {error && (
          <p className="notice error" role="alert">
            {error}
          </p>
        )}
        {confirm && (
          <div className="confirmation-box">
            <strong>Hapus project ini?</strong>
            <p>Semua chat di dalamnya akan dipindahkan ke Tanpa project.</p>
            <div className="settings-form-actions">
              <button type="button" className="secondary-button" onClick={() => setConfirm(false)}>
                Batal
              </button>
              <button
                type="button"
                className="danger-button"
                disabled={busy}
                onClick={() => {
                  setBusy(true)
                  setError('')
                  void onDelete()
                    .catch((e) => setError(e.message))
                    .finally(() => setBusy(false))
                }}
              >
                Hapus project
              </button>
            </div>
          </div>
        )}
      </form>
    </Modal>
  )
}

export function SessionEditor({
  session,
  projects,
  onSave,
  onDelete,
  onClose
}: {
  session: ChatSession
  projects: Project[]
  onSave: (change: Partial<ChatSession>) => void
  onDelete: () => Promise<void>
  onClose: () => void
}): JSX.Element {
  const [title, setTitle] = useState(session.title)
  const [projectId, setProjectId] = useState(session.projectId || '')
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  return (
    <Modal
      title="Kelola percakapan"
      onClose={() => {
        if (!busy) onClose()
      }}
    >
      <form
        className="organize-form"
        onSubmit={(e) => {
          e.preventDefault()
          if (title.trim()) onSave({ title: title.trim(), projectId: projectId || undefined })
        }}
      >
        <label className="field-block">
          Judul percakapan
          <input
            required
            maxLength={100}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
          />
        </label>
        <label className="field-block">
          Project
          <select value={projectId} onChange={(e) => setProjectId(e.target.value)}>
            <option value="">Tanpa project</option>
            {projects.map((p) => (
              <option value={p.id} key={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <div className="session-options">
          <button
            type="button"
            className="secondary-button"
            onClick={() => onSave({ pinned: !session.pinned })}
          >
            <Pin size={15} />
            {session.pinned ? 'Lepas pin' : 'Pin percakapan'}
          </button>
          <button
            type="button"
            className="secondary-button"
            onClick={() => onSave({ archived: !session.archived })}
          >
            <Archive size={15} />
            {session.archived ? 'Pulihkan dari arsip' : 'Arsipkan'}
          </button>
          <button
            type="button"
            className="secondary-button"
            onClick={() =>
              downloadFile(
                'percakapan.md',
                `# ${session.title}\n\n${session.messages.map((m) => `## ${m.role === 'user' ? 'Anda' : 'Jo Workspace'}\n\n${m.content}`).join('\n\n')}`,
                'text/markdown'
              )
            }
          >
            <Download size={15} />
            Ekspor Markdown
          </button>
        </div>
        <div className="settings-form-actions">
          <button
            type="button"
            className="danger-button"
            onClick={() => setConfirm(true)}
            disabled={busy}
          >
            <Trash2 size={14} />
            Hapus chat
          </button>
          <button className="primary-button" disabled={!title.trim() || busy}>
            Simpan
          </button>
        </div>
        {error && (
          <p className="notice error" role="alert">
            {error}
          </p>
        )}
        {confirm && (
          <div className="confirmation-box">
            <strong>Hapus percakapan ini?</strong>
            <p>
              Pesan dan lampiran yang dirujuk akan dihapus. Tindakan ini tidak dapat dibatalkan.
            </p>
            <div className="settings-form-actions">
              <button
                type="button"
                disabled={busy}
                className="secondary-button"
                onClick={() => setConfirm(false)}
              >
                Batal
              </button>
              <button
                type="button"
                className="danger-button"
                disabled={busy}
                onClick={() => {
                  setBusy(true)
                  void onDelete()
                    .catch((e) => setError(e.message))
                    .finally(() => setBusy(false))
                }}
              >
                {busy ? 'Menghapus…' : 'Hapus percakapan'}
              </button>
            </div>
          </div>
        )}
      </form>
    </Modal>
  )
}
