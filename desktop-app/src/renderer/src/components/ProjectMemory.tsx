import { useState, type JSX } from 'react'
import { Pencil, Plus, Trash2 } from 'lucide-react'
import { Modal } from './Modal'
import type { ProjectFact, ProjectFactKind } from '../lib/types'
import {
  FACT_KINDS,
  FACT_TEXT_LIMIT,
  MEMORY_LIMIT,
  createFact,
  memoryPrompt,
  removeFact,
  upsertFact
} from '../lib/project-memory'

function KindSelect({
  value,
  onChange
}: {
  value: ProjectFactKind
  onChange: (kind: ProjectFactKind) => void
}): JSX.Element {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value as ProjectFactKind)}>
      {(Object.keys(FACT_KINDS) as ProjectFactKind[]).map((kind) => (
        <option key={kind} value={kind}>
          {FACT_KINDS[kind]}
        </option>
      ))}
    </select>
  )
}

function sourceLabel(fact: ProjectFact): string {
  if (fact.source.kind === 'manual') return 'Ditambahkan manual'
  return `Dari chat "${fact.source.sessionTitle || 'tanpa judul'}"`
}

/** View, add, edit and delete project facts. Changes are held until the project is saved. */
export function ProjectMemoryList({
  memory,
  onChange
}: {
  memory: ProjectFact[]
  onChange: (memory: ProjectFact[]) => void
}): JSX.Element {
  const [kind, setKind] = useState<ProjectFactKind>('goal')
  const [text, setText] = useState('')
  const [editing, setEditing] = useState<ProjectFact | null>(null)
  const [error, setError] = useState('')
  const sent = memoryPrompt(memory).included
  const save = (fact: ProjectFact): void => {
    try {
      onChange(upsertFact(memory, fact))
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }
  return (
    <section className="project-memory" aria-label="Memori project">
      <header>
        <strong>Memori project</strong>
        <small>
          {memory.length}/{MEMORY_LIMIT} fakta
          {memory.length > sent ? ` · ${sent} dikirim (batas ruang prompt)` : ''}
        </small>
      </header>
      <p className="muted-text">
        Fakta di sini dikirim bersama setiap pesan dalam project. Tidak ada yang disimpan otomatis;
        Anda menambah, mengubah, dan menghapusnya sendiri.
      </p>
      {memory.length === 0 && <p className="muted-text">Belum ada fakta tersimpan.</p>}
      <ul>
        {memory.map((fact) =>
          editing?.id === fact.id ? (
            <li key={fact.id} className="memory-fact editing">
              <KindSelect
                value={editing.kind}
                onChange={(k) => setEditing({ ...editing, kind: k })}
              />
              <textarea
                rows={2}
                maxLength={FACT_TEXT_LIMIT}
                value={editing.text}
                onChange={(e) => setEditing({ ...editing, text: e.target.value })}
              />
              <div className="memory-actions">
                <button
                  type="button"
                  className="primary-button"
                  disabled={!editing.text.trim()}
                  onClick={() => {
                    save({ ...editing, text: editing.text.trim() })
                    setEditing(null)
                  }}
                >
                  Simpan
                </button>
                <button type="button" className="secondary-button" onClick={() => setEditing(null)}>
                  Batal
                </button>
              </div>
            </li>
          ) : (
            <li key={fact.id} className="memory-fact">
              <span className="memory-kind">{FACT_KINDS[fact.kind]}</span>
              <span className="memory-text">{fact.text}</span>
              <small
                className="memory-source"
                title={fact.source.kind === 'chat' ? fact.source.excerpt : ''}
              >
                {sourceLabel(fact)} · {new Date(fact.updatedAt).toLocaleDateString('id-ID')}
              </small>
              <div className="memory-actions">
                <button
                  type="button"
                  className="icon-button"
                  title="Ubah fakta"
                  aria-label={`Ubah fakta ${fact.text}`}
                  onClick={() => setEditing(fact)}
                >
                  <Pencil size={13} />
                </button>
                <button
                  type="button"
                  className="icon-button"
                  title="Hapus fakta"
                  aria-label={`Hapus fakta ${fact.text}`}
                  onClick={() => onChange(removeFact(memory, fact.id))}
                >
                  <Trash2 size={13} />
                </button>
              </div>
            </li>
          )
        )}
      </ul>
      <div className="memory-add">
        <KindSelect value={kind} onChange={setKind} />
        <input
          maxLength={FACT_TEXT_LIMIT}
          placeholder="Misalnya: Target rilis beta akhir Desember"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <button
          type="button"
          className="secondary-button"
          disabled={!text.trim()}
          onClick={() => {
            save(createFact(kind, text))
            setText('')
          }}
        >
          <Plus size={13} /> Tambah
        </button>
      </div>
      {error && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
    </section>
  )
}

/** Save a passage from a chat as a project fact; the user edits the wording before saving. */
export function SaveToMemoryDialog({
  projectName,
  excerpt,
  sessionId,
  sessionTitle,
  onSave,
  onClose
}: {
  projectName: string
  excerpt: string
  sessionId: string
  sessionTitle: string
  onSave: (fact: ProjectFact) => void
  onClose: () => void
}): JSX.Element {
  const [kind, setKind] = useState<ProjectFactKind>('decision')
  const [text, setText] = useState(excerpt.trim().slice(0, FACT_TEXT_LIMIT))
  return (
    <Modal title="Simpan ke memori project" onClose={onClose}>
      <form
        className="organize-form"
        onSubmit={(e) => {
          e.preventDefault()
          if (text.trim())
            onSave(createFact(kind, text, { kind: 'chat', sessionId, sessionTitle, excerpt }))
        }}
      >
        <p className="muted-text">
          Fakta akan dikirim bersama pesan berikutnya di project <strong>{projectName}</strong>.
          Ringkas menjadi satu pernyataan yang tetap benar.
        </p>
        <label className="field-block">
          Jenis
          <KindSelect value={kind} onChange={setKind} />
        </label>
        <label className="field-block">
          Fakta
          <textarea
            autoFocus
            rows={4}
            maxLength={FACT_TEXT_LIMIT}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <small>
            {text.length}/{FACT_TEXT_LIMIT} karakter · Sumber: chat &quot;{sessionTitle}&quot;
          </small>
        </label>
        <div className="settings-form-actions">
          <button type="button" className="secondary-button" onClick={onClose}>
            Batal
          </button>
          <button className="primary-button" disabled={!text.trim()}>
            Simpan fakta
          </button>
        </div>
      </form>
    </Modal>
  )
}
