import { useEffect, useState, type JSX, type ReactNode } from 'react'
import { Plus, Square, RefreshCw, Download, Workflow } from 'lucide-react'
import { apiFetch } from '../lib/api'
import { engagementPath, type Engagement, type ScopeKind } from '../lib/engagements'
import { downloadFile } from '../lib/preferences'
import {
  workflowLabels,
  type Orchestration,
  type WorkflowCatalog,
  type WorkflowListing
} from '../lib/orchestration'
import type { MCPCatalog, MCPServer } from '../lib/mcp'
import { Modal } from './Modal'
import { OrchestrationReview } from './OrchestrationReview'

function Field({ label, children }: { label: string; children: ReactNode }): JSX.Element {
  return (
    <label className="field-block">
      {label}
      {children}
    </label>
  )
}
function Json({ value }: { value: unknown }): JSX.Element {
  return <pre className="record-output">{JSON.stringify(value, null, 2)}</pre>
}
interface Draft {
  name: string
  objective: string
  model: string
  playbook_id: string
  server_id: string
  kind: ScopeKind
  target: string
  max_calls: number
  max_steps: number
  max_tokens: number
  output_tokens: number
  active_seconds: number
}
const emptyDraft = (): Draft => ({
  name: '',
  objective: '',
  model: '',
  playbook_id: '',
  server_id: '',
  kind: 'ip',
  target: '',
  max_calls: 6,
  max_steps: 2,
  max_tokens: 30000,
  output_tokens: 512,
  active_seconds: 300
})

export function SecurityOrchestration({
  engagement,
  onRuns,
  onMCP
}: {
  engagement: Engagement
  onRuns: () => void
  onMCP: () => void
}): JSX.Element {
  const path = engagementPath(engagement.project_id, engagement.id) + '/orchestrations'
  const [listing, setListing] = useState<WorkflowListing | null>(null)
  const [catalog, setCatalog] = useState<WorkflowCatalog | null>(null)
  const [servers, setServers] = useState<MCPServer[]>([])
  const [selected, setSelected] = useState('')
  const [detail, setDetail] = useState<Orchestration | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [error, setError] = useState('')
  const [catalogError, setCatalogError] = useState('')
  const [busy, setBusy] = useState(false)
  const [modal, setModal] = useState<'new' | 'approve' | 'resume' | null>(null)
  const [draft, setDraft] = useState<Draft>(emptyDraft)
  const [actor, setActor] = useState('')
  const [note, setNote] = useState('')
  const [ack, setAck] = useState(false)
  const [terms, setTerms] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    const poll = async (): Promise<void> => {
      try {
        const data: WorkflowListing = await (
          await apiFetch(path, { signal: controller.signal })
        ).json()
        if (controller.signal.aborted) return
        setListing(data)
        const next = data.items.some((x) => x.id === selected) ? selected : data.items[0]?.id || ''
        setSelected(next)
        if (next) {
          const record: Orchestration = await (
            await apiFetch(path + '/' + next, { signal: controller.signal })
          ).json()
          if (!controller.signal.aborted) setDetail(record)
        }
      } catch (e) {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : 'Checkpoint tidak dapat dimuat.')
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(poll, 1500)
      }
    }
    void poll()
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [path, selected, refresh])
  useEffect(() => {
    const controller = new AbortController()
    void Promise.allSettled([
      apiFetch('/api/security/orchestration/catalog', { signal: controller.signal }).then((r) =>
        r.json()
      ),
      apiFetch('/api/security/mcp/servers', { signal: controller.signal }).then((r) => r.json())
    ]).then((results) => {
      if (controller.signal.aborted) return
      if (results[0].status === 'fulfilled') {
        setCatalog(results[0].value as WorkflowCatalog)
        setCatalogError('')
      } else
        setCatalogError(
          results[0].reason instanceof Error
            ? results[0].reason.message
            : 'Katalog model lokal tidak tersedia.'
        )
      if (results[1].status === 'fulfilled')
        setServers((results[1].value as MCPCatalog).servers.filter((s) => s.state === 'approved'))
      else
        setCatalogError(
          results[1].reason instanceof Error
            ? results[1].reason.message
            : 'Profil MCP tidak tersedia.'
        )
    })
    return () => controller.abort()
  }, [refresh])
  const operate = async (action: () => Promise<void>): Promise<void> => {
    setBusy(true)
    setError('')
    try {
      await action()
      setRefresh((v) => v + 1)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Operasi gagal.')
    } finally {
      setBusy(false)
    }
  }
  const open = (value: typeof modal): void => {
    setModal(value)
    setActor('')
    setNote('')
    setTerms('')
    setAck(false)
    setError('')
  }
  const decide = async (action: string): Promise<void> => {
    if (!detail) return
    const result: Orchestration = await (
      await apiFetch(path + '/' + detail.id + '/' + action, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          expected_revision: detail.revision,
          actor_label: action === 'pause' ? 'operator-lokal' : actor,
          note:
            action === 'pause'
              ? 'Hentikan orkestrasi dari UI; pertahankan checkpoint dan evidence.'
              : note,
          acknowledge: action === 'pause' ? true : ack
        })
      })
    ).json()
    setDetail(result)
    setModal(null)
  }
  const approvedServer = servers.find((s) => s.id === draft.server_id)
  return (
    <section className="security-records" aria-label="Orkestrasi satu model">
      <div className="section-title">
        <h3>
          <Workflow size={18} />
          Orkestrasi satu model
        </h3>
        <span className="planning-badge">Fixture saja · pentest terkunci</span>
      </div>
      <p className="notice">
        Planner → review manusia → Executor → approval job di Runs → fixture terisolasi → Reviewer.
        Satu model Ollama lokal dipakai bergantian; state machine backend menentukan alur. Reviewer
        tidak dapat mengesahkan finding.
      </p>
      <p className="muted-text">
        Tidak ada model diunduh atau cloud berbayar. Spesialis tahap 7 tersedia di tab Agents.
        Checkpoint, bukti, dan anggaran tetap tersimpan saat dihentikan. Setelah restart perlu
        resume eksplisit; budget tidak direset.
      </p>
      <div className="roe-decision-actions">
        <button
          className="primary-button"
          disabled={busy || !catalog || !servers.length}
          onClick={() => {
            setDraft({
              ...emptyDraft(),
              model:
                catalog?.models.find((m) => m.name.startsWith('qwen-9b-reasoning'))?.name ||
                catalog?.models[0]?.name ||
                '',
              playbook_id: catalog?.playbooks[0]?.id || '',
              server_id: servers[0]?.id || ''
            })
            open('new')
          }}
        >
          <Plus size={14} />
          Orkestrasi baru
        </button>
        <button
          className="secondary-button"
          disabled={busy}
          onClick={() => {
            setError('')
            setRefresh((v) => v + 1)
          }}
        >
          <RefreshCw size={14} />
          Muat ulang orkestrasi
        </button>
        <button className="secondary-button" onClick={onMCP}>
          Profil MCP & izin tool
        </button>
        <small>
          {listing?.worker_active ? 'Worker orkestrasi aktif' : 'Menunggu worker'} ·{' '}
          {listing?.items.length || 0}/30 tugas
        </small>
      </div>
      {catalogError && (
        <p className="notice error" role="status">
          {catalogError} Catatan yang tersimpan tetap dapat dibaca/dihentikan.
        </p>
      )}
      {!servers.length && (
        <p>Siapkan profil MCP fixture yang disetujui sebelum membuat orkestrasi.</p>
      )}
      {error && !modal && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
      <div className="record-list">
        {listing?.items.map((r) => (
          <button
            key={r.id}
            className={r.id === selected ? 'selected' : ''}
            onClick={() => setSelected(r.id)}
          >
            <strong>{r.request.name}</strong>
            <span>{workflowLabels[r.status] || r.status}</span>
            <small>
              {r.request.model} · {r.model_calls}/{r.request.max_calls} panggilan · {r.jobs.length}{' '}
              job
            </small>
          </button>
        ))}
      </div>
      {detail && detail.id === selected && (
        <article className="record-detail">
          <h4>{detail.request.name}</h4>
          <p>
            {workflowLabels[detail.status]} · revisi {detail.revision} · {detail.id}
          </p>
          <div className="roe-decision-actions">
            {!['completed', 'paused'].includes(detail.status) && (
              <button
                className="danger-button"
                disabled={busy}
                onClick={() => void operate(() => decide('pause'))}
              >
                <Square size={14} />
                Hentikan orkestrasi
              </button>
            )}
            {detail.status === 'awaiting_approval' && (
              <button className="primary-button" disabled={busy} onClick={() => open('approve')}>
                Tinjau & setujui rencana
              </button>
            )}
            {detail.status === 'paused' && (
              <button className="primary-button" disabled={busy} onClick={() => open('resume')}>
                Lanjutkan dari checkpoint
              </button>
            )}
            <button className="secondary-button" onClick={onRuns}>
              Buka Runs & approval job
            </button>
            <button
              className="secondary-button"
              onClick={() =>
                downloadFile(
                  'orchestration-' + detail.id + '.json',
                  JSON.stringify(detail, null, 2)
                )
              }
            >
              <Download size={14} />
              Ekspor checkpoint
            </button>
          </div>
          {detail.error && (
            <p className="notice error" role="status">
              {detail.error}
            </p>
          )}
          <dl className="roe-grid">
            <div>
              <dt>Model tunggal</dt>
              <dd>{detail.request.model}</dd>
            </div>
            <div>
              <dt>Target RoE</dt>
              <dd>
                {detail.request.target.value} · v{detail.request.roe_version}
              </dd>
            </div>
            <div>
              <dt>Playbook</dt>
              <dd>
                {detail.request.playbook.title} · {detail.request.playbook.version}
              </dd>
            </div>
            <div>
              <dt>Budget panggilan</dt>
              <dd>
                {detail.model_calls}/{detail.request.max_calls}
              </dd>
            </div>
            <div>
              <dt>Reservasi token konservatif</dt>
              <dd>
                {detail.token_reserved}/{detail.request.max_tokens} · output per panggilan ≤{' '}
                {detail.request.output_tokens}
              </dd>
            </div>
            <div>
              <dt>Token terukur dari model</dt>
              <dd>
                {detail.measured_input_tokens} input / {detail.measured_output_tokens} output
              </dd>
            </div>
            <div>
              <dt>Waktu aktif tersimpan</dt>
              <dd>
                {detail.active_seconds.toFixed(1)}/{detail.request.active_seconds} detik · tidak
                termasuk menunggu approval/job
              </dd>
            </div>
            <div>
              <dt>Batch job</dt>
              <dd>{detail.batch}</dd>
            </div>
          </dl>
          <p className="record-hash">
            Model digest: {detail.request.model_digest}
            <br />
            Request hash: {detail.request_hash}
            <br />
            RoE hash: {detail.request.content_hash}
            <br />
            Playbook hash: {detail.request.playbook.hash}
          </p>
          <h4>Objektif</h4>
          <pre className="record-output">{detail.request.objective}</pre>
          <h4>Planner · rencana terstruktur</h4>
          {detail.planner ? (
            <>
              <p>{detail.planner.rationale}</p>
              <Json value={detail.planner.actions} />
            </>
          ) : (
            <p>Belum ada checkpoint Planner.</p>
          )}
          <h4>Executor · permintaan tindakan yang tersedia</h4>
          {detail.executor ? (
            <>
              <p>{detail.executor.reason}</p>
              <p>Indeks langkah disetujui: {detail.executor.action_indices.join(', ')}</p>
            </>
          ) : (
            <p>Menunggu rencana dan review manusia.</p>
          )}
          <h4>Job batch saat ini · approval terpisah di Runs</h4>
          <ul>
            {detail.jobs.map((j) => (
              <li key={j}>{j}</li>
            ))}
          </ul>
          <h4>Reviewer AI · bantuan untuk analis</h4>
          <OrchestrationReview reviewer={detail.reviewer} />
          <details>
            <summary>Riwayat checkpoint ({detail.checkpoints?.length || 0})</summary>
            {detail.checkpoints?.map((c) => (
              <details key={c.revision}>
                <summary>
                  r{c.revision} · {c.action} · {c.at}
                </summary>
                <p>
                  {c.actor} · {c.note}
                </p>
                <p className="record-hash">{c.hash}</p>
                <Json value={c.snapshot} />
              </details>
            ))}
          </details>
        </article>
      )}
      <details>
        <summary>Knowledge base playbook · sumber dan versi</summary>
        {catalog?.playbooks.map((p) => (
          <article key={p.id}>
            <h4>
              {p.title} · {p.version}
            </h4>
            <p>{p.instructions}</p>
            <ul>
              {p.sources.map((s) => (
                <li key={s.ref}>
                  {s.title.replace('Agent OS', 'Jo Workspace')} · {s.ref} · {s.version}
                </li>
              ))}
            </ul>
            <p className="record-hash">{p.hash}</p>
          </article>
        ))}
      </details>
      {modal && (
        <Modal
          title={
            {
              new: 'Orkestrasi satu model baru',
              approve: 'Review rencana Planner',
              resume: 'Lanjutkan dari checkpoint'
            }[modal]
          }
          onClose={() => {
            if (!busy) setModal(null)
          }}
          wide
        >
          <form
            className="record-form"
            onSubmit={(e) => {
              e.preventDefault()
              void operate(async () => {
                if (modal === 'new' && approvedServer) {
                  const head = engagement.versions[0]
                  const response: Orchestration = await (
                    await apiFetch(path, {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({
                        name: draft.name,
                        objective: draft.objective,
                        model: draft.model,
                        playbook_id: draft.playbook_id,
                        target: { kind: draft.kind, value: draft.target },
                        server_id: approvedServer.id,
                        server_revision: approvedServer.revision,
                        descriptor_hash: approvedServer.descriptor_hash,
                        expected_roe_revision: engagement.revision,
                        roe_version: head.version,
                        content_hash: head.content_hash,
                        max_calls: draft.max_calls,
                        max_steps: draft.max_steps,
                        max_tokens: draft.max_tokens,
                        output_tokens: draft.output_tokens,
                        active_seconds: draft.active_seconds,
                        acknowledge: ack,
                        redaction_terms: terms
                          .split('\n')
                          .map((x) => x.trim())
                          .filter(Boolean)
                      })
                    })
                  ).json()
                  setDetail(response)
                  setSelected(response.id)
                  setModal(null)
                } else await decide(modal === 'approve' ? 'approve' : 'resume')
              })
            }}
          >
            {error && (
              <p className="notice error" role="alert">
                {error}
              </p>
            )}
            {modal === 'new' ? (
              <>
                <p>
                  Membuat tugas langsung mengantrekan Planner pada model lokal. Rencana yang
                  dihasilkan tetap memerlukan review; setiap job fixture juga memerlukan approval
                  terpisah di Runs.
                </p>
                <Field label="Nama orkestrasi">
                  <input
                    required
                    maxLength={120}
                    value={draft.name}
                    onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                  />
                </Field>
                <Field label="Objektif orkestrasi">
                  <textarea
                    required
                    maxLength={800}
                    value={draft.objective}
                    onChange={(e) => setDraft({ ...draft, objective: e.target.value })}
                  />
                </Field>
                <Field label="Model Ollama tunggal">
                  <select
                    required
                    value={draft.model}
                    onChange={(e) => setDraft({ ...draft, model: e.target.value })}
                  >
                    {catalog?.models.map((m) => (
                      <option key={m.name}>{m.name}</option>
                    ))}
                  </select>
                </Field>
                <Field label="Playbook orkestrasi">
                  <select
                    value={draft.playbook_id}
                    onChange={(e) => setDraft({ ...draft, playbook_id: e.target.value })}
                  >
                    {catalog?.playbooks.map((p) => (
                      <option value={p.id} key={p.id}>
                        {p.title} · {p.version}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Profil MCP orkestrasi">
                  <select
                    value={draft.server_id}
                    onChange={(e) => setDraft({ ...draft, server_id: e.target.value })}
                  >
                    {servers.map((s) => (
                      <option value={s.id} key={s.id}>
                        {s.config.name} · r{s.revision} · {s.config.allowed_tools.join(', ')}
                      </option>
                    ))}
                  </select>
                </Field>
                <div className="record-filters">
                  <Field label="Jenis target orkestrasi">
                    <select
                      value={draft.kind}
                      onChange={(e) => setDraft({ ...draft, kind: e.target.value as ScopeKind })}
                    >
                      {['ip', 'cidr', 'domain', 'url'].map((k) => (
                        <option key={k}>{k}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Target orkestrasi">
                    <input
                      required
                      maxLength={1000}
                      value={draft.target}
                      onChange={(e) => setDraft({ ...draft, target: e.target.value })}
                    />
                  </Field>
                </div>
                <div className="record-filters">
                  {(
                    [
                      ['max_calls', 'Batas panggilan model', 3, 6],
                      ['max_steps', 'Batas langkah rencana', 1, 3],
                      ['max_tokens', 'Budget token konservatif', 6000, 60000],
                      ['output_tokens', 'Batas output token per panggilan', 128, 768],
                      ['active_seconds', 'Batas waktu aktif (detik)', 30, 900]
                    ] as const
                  ).map(([key, label, min, max]) => (
                    <Field key={key} label={label}>
                      <input
                        required
                        type="number"
                        min={min}
                        max={max}
                        value={draft[key]}
                        onChange={(e) => setDraft({ ...draft, [key]: Number(e.target.value) })}
                      />
                    </Field>
                  ))}
                </div>
                <Field label="Istilah sensor objektif (satu per baris)">
                  <textarea value={terms} onChange={(e) => setTerms(e.target.value)} />
                </Field>
              </>
            ) : (
              <>
                <p>
                  {modal === 'approve'
                    ? 'Tinjau rencana, target, versi playbook/profil, dan anggaran. Executor hanya dapat membuat job Awaiting Approval, bukan menyetujuinya.'
                    : 'Resume mempertahankan seluruh anggaran dan evidence. Jika job terdahulu dibatalkan, rencana harus disetujui ulang dan job baru perlu approval. RoE/profil/model yang berubah dapat menolak kelanjutan.'}
                </p>
                <Json value={{ plan: detail?.planner, request: detail?.request }} />
                <Field label="Nama peninjau orkestrasi (deklarasi lokal)">
                  <input
                    required
                    maxLength={120}
                    value={actor}
                    onChange={(e) => setActor(e.target.value)}
                  />
                </Field>
                <Field label="Catatan keputusan orkestrasi">
                  <textarea
                    required
                    maxLength={1000}
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                  />
                </Field>
              </>
            )}
            <label className="checkbox-field">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              Saya memahami penggunaan model lokal, batas fixture, review manusia, dan eksekusi
              pentest yang tetap terkunci.
            </label>
            <div className="roe-decision-actions">
              <button
                className="secondary-button"
                type="button"
                disabled={busy}
                onClick={() => setModal(null)}
              >
                Batal
              </button>
              <button
                className="primary-button"
                type="submit"
                disabled={busy || !ack || (modal === 'new' && !approvedServer)}
              >
                {busy
                  ? 'Menyimpan…'
                  : modal === 'new'
                    ? 'Mulai Planner lokal'
                    : modal === 'approve'
                      ? 'Setujui rencana untuk Executor'
                      : 'Lanjutkan dengan budget tersisa'}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </section>
  )
}
