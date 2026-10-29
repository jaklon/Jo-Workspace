import { useEffect, useState, type JSX, type ReactNode } from 'react'
import {
  ShieldCheck,
  Plus,
  RefreshCw,
  Download,
  LockKeyhole,
  Pencil,
  History,
  X
} from 'lucide-react'
import type { Project } from '../lib/types'
import { apiFetch } from '../lib/api'
import { downloadFile } from '../lib/preferences'
import {
  actionLabels,
  effectiveStatus,
  emptyContent,
  engagementPath,
  localDateTime,
  parsePorts,
  statusLabels,
  utcDateTime,
  type Engagement,
  type EngagementContent,
  type DecisionAction,
  type ScopeAsset,
  type ScopeKind
} from '../lib/engagements'
import { Modal } from './Modal'
import { PolicyGuard, ScopeFindings, ScopePreview } from './PolicyGuard'
import { SecurityJobs } from './SecurityJobs'
import { WebChecks } from './WebChecks'
import { SecurityRecords } from './SecurityRecords'
import { MCPIntegrations } from './MCPIntegrations'
import { SecurityOrchestration } from './SecurityOrchestration'
import { SecurityAgents } from './SecurityAgents'
import { DeepAnalysis } from './DeepAnalysis'
import { TCPScan } from './TCPScan'

const environments = {
  lab: 'Lab sintetis',
  development: 'Development',
  staging: 'Staging',
  uat: 'UAT',
  production_readonly: 'Production · read-only'
}
const decisionLabels: Record<DecisionAction, string> = {
  submit: 'Ajukan RoE',
  approve: 'Setujui secara lokal',
  request_changes: 'Minta perbaikan',
  revoke: 'Cabut RoE',
  revise: 'Buat revisi baru'
}
const eventLabels: Record<string, string> = {
  created: 'Engagement dibuat',
  draft_saved: 'Draft disimpan',
  submit: 'RoE diajukan',
  approve: 'Persetujuan lokal dicatat',
  request_changes: 'Perbaikan diminta',
  revoke: 'RoE dicabut',
  revise: 'Revisi baru dibuat'
}

function Field({
  label,
  children,
  hint
}: {
  label: string
  children: ReactNode
  hint?: string
}): JSX.Element {
  return (
    <label className="field-block">
      {label}
      {children}
      {hint && <small>{hint}</small>}
    </label>
  )
}
function ScopeEditor({
  label,
  value,
  onChange
}: {
  label: string
  value: ScopeAsset[]
  onChange: (assets: ScopeAsset[]) => void
}): JSX.Element {
  return (
    <div className="scope-editor">
      <div className="section-title">
        <h4>{label}</h4>
        <button
          type="button"
          className="secondary-button"
          disabled={value.length >= 100}
          onClick={() => onChange([...value, { kind: 'domain', value: '' }])}
        >
          <Plus size={13} />
          Tambah target {label === 'Dalam scope' ? 'scope' : 'pengecualian'}
        </button>
      </div>
      {!value.length && <p className="muted-text">Belum ada target.</p>}
      {value.map((asset, index) => (
        <div className="scope-input-row" key={index}>
          <select
            aria-label={`${label} jenis ${index + 1}`}
            value={asset.kind}
            onChange={(e) =>
              onChange(
                value.map((a, i) => (i === index ? { ...a, kind: e.target.value as ScopeKind } : a))
              )
            }
          >
            {['domain', 'ip', 'cidr', 'url'].map((kind) => (
              <option key={kind} value={kind}>
                {kind.toUpperCase()}
              </option>
            ))}
          </select>
          <input
            aria-label={`${label} target ${index + 1}`}
            value={asset.value}
            maxLength={1000}
            placeholder={
              asset.kind === 'domain'
                ? 'uat.example.test'
                : asset.kind === 'ip'
                  ? '127.0.0.1'
                  : asset.kind === 'cidr'
                    ? '192.168.10.0/24'
                    : 'https://uat.example.test/api/'
            }
            onChange={(e) =>
              onChange(value.map((a, i) => (i === index ? { ...a, value: e.target.value } : a)))
            }
          />
          <button
            type="button"
            className="icon-button"
            aria-label={`Hapus ${label} target ${index + 1}`}
            onClick={() => onChange(value.filter((_, i) => i !== index))}
          >
            <X size={15} />
          </button>
        </div>
      ))}
      <p className="muted-text">
        Tanpa DNS lookup, request HTTP, atau pemindaian. Domain exact-host; URL mengikuti scheme,
        port, dan batas segmen path. Wildcard, kredensial/query, encoding dan dot segment tidak
        didukung.
      </p>
    </div>
  )
}

export function SecurityWorkspace({
  projects,
  projectId,
  onProject,
  onCreateProject
}: {
  projects: Project[]
  projectId: string
  onProject: (id: string) => void
  onCreateProject: () => void
}): JSX.Element {
  const project = projects.find((p) => p.id === projectId)
  return (
    <div className="security-workspace scrollbar-thin">
      <div className="security-page-heading">
        <div>
          <p className="page-eyebrow">SECURITY WORKSPACE · TAHAP 7</p>
          <h2>
            <ShieldCheck size={25} />
            Engagement & RoE
          </h2>
          <p>
            Kelola RoE, policy guard, antrean offline, evidence, laporan, dan MCP fixture
            terisolasi.
          </p>
        </div>
        <span className="planning-badge">
          <LockKeyhole size={14} />
          Eksekusi sesuai adapter & persetujuan
        </span>
      </div>
      <div className="security-project-picker">
        <label>
          Project
          <select
            aria-label="Project Security Workspace"
            value={project?.id || ''}
            onChange={(e) => onProject(e.target.value)}
          >
            <option value="" disabled>
              Pilih project
            </option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <button className="secondary-button" onClick={onCreateProject}>
          <Plus size={14} />
          Project baru
        </button>
      </div>
      <div className="notice">
        <LockKeyhole size={16} />
        <span>
          Tahap perencanaan. Bahkan RoE yang disetujui tidak mengaktifkan pentest. Persetujuan di
          sini adalah deklarasi operator lokal, bukan verifikasi identitas peninjau atau pengganti
          surat otorisasi organisasi. Tidak ada kredensial yang perlu dimasukkan.
        </span>
      </div>
      {project ? (
        <EngagementPanel key={project.id} project={project} />
      ) : (
        <div className="security-empty">
          <ShieldCheck size={35} />
          <h3>Pilih project untuk memulai</h3>
          <p>
            Engagement dan seluruh versi RoE akan terikat pada ID project dan disimpan di backend.
            Chat tetap tersimpan pada perangkat ini.
          </p>
          {!projects.length && (
            <button className="primary-button" onClick={onCreateProject}>
              Buat project pertama
            </button>
          )}
        </div>
      )}
    </div>
  )
}

function EngagementPanel({ project }: { project: Project }): JSX.Element {
  const [items, setItems] = useState<Engagement[]>([])
  const [selected, setSelected] = useState('')
  const [detail, setDetail] = useState<Engagement | null>(null)
  const [viewVersion, setViewVersion] = useState<number | null>(null)
  const [engagementView, setEngagementView] = useState<
    | 'overview'
    | 'runs'
    | 'web'
    | 'deep'
    | 'scan'
    | 'evidence'
    | 'findings'
    | 'reports'
    | 'mcp'
    | 'orchestration'
    | 'agents'
  >('overview')
  const [draft, setDraft] = useState<EngagementContent>(emptyContent)
  const [starts, setStarts] = useState('')
  const [ends, setEnds] = useState('')
  const [ports, setPorts] = useState('')
  const [accountRefs, setAccountRefs] = useState('')
  const [editing, setEditing] = useState(false)
  const [busy, setBusy] = useState(false)
  const [fetching, setFetching] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [refresh, setRefresh] = useState(0)
  const [decision, setDecision] = useState<DecisionAction | null>(null)
  const [actor, setActor] = useState('')
  const [note, setNote] = useState('')
  const [ack, setAck] = useState(false)
  const [clock, setClock] = useState(Date.now)
  const head = detail?.versions[0]
  const version = detail?.versions.find((v) => v.version === viewVersion) || head
  const current = !!head && version?.version === head.version
  const status = version ? effectiveStatus(version, current, clock) : 'draft'
  const field = <K extends keyof EngagementContent>(key: K, value: EngagementContent[K]): void =>
    setDraft((p) => ({ ...p, [key]: value }))
  useEffect(() => {
    const timer = setInterval(() => setClock(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [])
  useEffect(() => {
    const controller = new AbortController()
    void apiFetch(engagementPath(project.id), { signal: controller.signal })
      .then((r) => r.json())
      .then((data) => {
        setItems(data.items)
        setSelected((id) =>
          data.items.some((item: Engagement) => item.id === id) ? id : data.items[0]?.id || ''
        )
        setError('')
        setFetching(false)
      })
      .catch((e) => {
        if (!controller.signal.aborted) {
          setError(e.message)
          setFetching(false)
        }
      })
    return () => controller.abort()
  }, [project.id, refresh])
  useEffect(() => {
    if (!selected || detail?.id === selected) return
    const controller = new AbortController()
    void apiFetch(engagementPath(project.id, selected), { signal: controller.signal })
      .then((r) => r.json())
      .then((data: Engagement) => {
        setDetail(data)
        setViewVersion(data.versions[0].version)
        setEditing(false)
        setError('')
      })
      .catch((e) => {
        if (!controller.signal.aborted) setError(e.message)
      })
    return () => controller.abort()
  }, [project.id, selected, refresh, detail?.id])
  const adopt = (data: Engagement): void => {
    document.querySelector('.security-workspace')?.scrollTo({ top: 0 })
    setDetail(data)
    setSelected(data.id)
    setViewVersion(data.versions[0].version)
    setItems((prev) => [data, ...prev.filter((p) => p.id !== data.id)])
    setEditing(false)
    setDecision(null)
    setClock(Date.now())
  }
  const edit = (content: EngagementContent): void => {
    setDraft(structuredClone(content))
    setStarts(localDateTime(content.starts_at, content.timezone))
    setEnds(localDateTime(content.ends_at, content.timezone))
    setPorts(content.ports.join(', '))
    setAccountRefs(content.test_account_refs.join('\n'))
    setEditing(true)
    setError('')
    setNotice('')
  }
  const run = async (action: () => Promise<void>): Promise<void> => {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await action()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Operasi gagal.')
    } finally {
      setBusy(false)
    }
  }
  const save = async (): Promise<void> => {
    const content = {
      ...draft,
      ports: parsePorts(ports),
      starts_at: utcDateTime(starts, draft.timezone),
      ends_at: utcDateTime(ends, draft.timezone),
      test_account_refs: accountRefs
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean)
    }
    const body = detail ? { content, expected_revision: detail.revision } : { content }
    const data = await (
      await apiFetch(engagementPath(project.id, detail?.id), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      })
    ).json()
    adopt(data)
    setNotice('Draft tersimpan di backend. Belum ada pengujian yang dijalankan.')
  }
  const decide = async (): Promise<void> => {
    if (!detail || !decision) return
    const result = await (
      await apiFetch(engagementPath(project.id, detail.id) + '/decisions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          expected_revision: detail.revision,
          action: decision,
          actor_label: actor.trim(),
          note: note.trim(),
          acknowledge: ack
        })
      })
    ).json()
    adopt(result)
    setNotice('Keputusan RoE dicatat. Setiap run memerlukan rencana dan persetujuan terpisah.')
  }
  const openDecision = (action: DecisionAction): void => {
    setDecision(action)
    setActor('')
    setNote('')
    setAck(false)
    setError('')
  }
  const time = (value: string | null, zone: string): string =>
    value
      ? new Intl.DateTimeFormat('id-ID', {
          dateStyle: 'medium',
          timeStyle: 'short',
          timeZone: zone
        }).format(new Date(value))
      : 'Belum diisi'
  const label = (title: string, value: ReactNode): JSX.Element => (
    <div>
      <dt>{title}</dt>
      <dd>{value || 'Belum diisi'}</dd>
    </div>
  )
  return (
    <>
      {error && (
        <p role="alert" className="notice error security-error">
          {error}
        </p>
      )}
      {notice && (
        <p role="status" className="notice success">
          {notice}
        </p>
      )}
      <div className="security-toolbar">
        <h3>
          {items.length} engagement · {project.name}
        </h3>
        <div>
          <button
            className="secondary-button"
            disabled={busy || editing}
            onClick={() => {
              setFetching(true)
              setNotice('')
              setError('')
              setDetail(null)
              setRefresh((v) => v + 1)
            }}
          >
            <RefreshCw size={14} />
            Muat ulang
          </button>
          <button
            className="primary-button"
            disabled={busy || editing || fetching || items.length >= 100}
            onClick={() => {
              setSelected('')
              setDetail(null)
              setViewVersion(null)
              edit(emptyContent())
            }}
          >
            <Plus size={14} />
            Engagement baru
          </button>
        </div>
      </div>
      {fetching && (
        <p className="muted-text" role="status">
          Memuat Engagement…
        </p>
      )}
      <div className="engagement-layout">
        <nav className="engagement-list" aria-label="Daftar engagement">
          {items.map((item) => {
            const row = item.versions[0]
            const rowStatus = effectiveStatus(row, true, clock)
            return (
              <button
                key={item.id}
                disabled={busy || editing}
                className={selected === item.id ? 'selected' : ''}
                onClick={() => {
                  setDetail(null)
                  setSelected(item.id)
                  setNotice('')
                  setError('')
                }}
              >
                <strong>{row.content.name}</strong>
                <small>
                  {environments[row.content.environment]} · RoE v{row.version}
                </small>
                <span className={`roe-status status-${rowStatus}`}>{statusLabels[rowStatus]}</span>
              </button>
            )
          })}
          {!items.length && !fetching && (
            <p className="muted-text">
              Belum ada engagement. Mulai dengan draft untuk project ini.
            </p>
          )}
        </nav>
        <div className="engagement-body">
          {editing ? (
            <form
              className="roe-editor"
              onSubmit={(e) => {
                e.preventDefault()
                void run(save)
              }}
            >
              <fieldset disabled={busy}>
                <div className="section-title">
                  <h3>{detail ? `Edit draft RoE v${head?.version}` : 'Draft engagement baru'}</h3>
                  <span className="roe-status status-draft">Belum disimpan</span>
                </div>
                <p className="muted-text">
                  Draft dapat disimpan sebagian. Data wajib dilengkapi sebelum pengajuan. Semua
                  bidang di bawah menjadi snapshot RoE setelah diajukan.
                </p>
                <h4>Identitas dan otorisasi</h4>
                <Field label="Nama engagement">
                  <input
                    autoFocus
                    required
                    maxLength={120}
                    value={draft.name}
                    onChange={(e) => field('name', e.target.value)}
                  />
                </Field>
                <Field label="Tujuan pengujian">
                  <textarea
                    rows={3}
                    maxLength={3000}
                    value={draft.objective}
                    onChange={(e) => field('objective', e.target.value)}
                  />
                </Field>
                <div className="roe-grid">
                  <Field label="Pemilik engagement">
                    <input
                      maxLength={120}
                      value={draft.owner}
                      onChange={(e) => field('owner', e.target.value)}
                    />
                  </Field>
                  <Field label="PIC / kontak operasional">
                    <input
                      maxLength={200}
                      value={draft.contact}
                      onChange={(e) => field('contact', e.target.value)}
                    />
                  </Field>
                  <Field label="Lingkungan">
                    <select
                      value={draft.environment}
                      onChange={(e) => {
                        field('environment', e.target.value as EngagementContent['environment'])
                        if (e.target.value === 'production_readonly') {
                          field('allowed_actions', ['http_headers'])
                          field('max_http_rps', 1)
                          field('max_concurrency', 1)
                        }
                      }}
                    >
                      {Object.entries(environments).map(([key, text]) => (
                        <option key={key} value={key}>
                          {text}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field
                    label="Referensi surat otorisasi"
                    hint="Nomor dokumen/lokasi dokumen; aplikasi tidak memverifikasi tanda tangan atau otorisasi organisasi."
                  >
                    <input
                      maxLength={500}
                      value={draft.authorization_ref}
                      onChange={(e) => field('authorization_ref', e.target.value)}
                    />
                  </Field>
                </div>
                <h4>Scope dan pengecualian</h4>
                <ScopeEditor
                  label="Dalam scope"
                  value={draft.in_scope}
                  onChange={(v) => field('in_scope', v)}
                />
                <ScopeEditor
                  label="Di luar scope"
                  value={draft.out_of_scope}
                  onChange={(v) => field('out_of_scope', v)}
                />
                <Field
                  label="Port yang direncanakan"
                  hint="Pisahkan dengan koma, misalnya 443, 8443. Port HTTP/TCP dan rate diperiksa policy guard; run memerlukan adapter dan persetujuan terpisah."
                >
                  <input value={ports} maxLength={700} onChange={(e) => setPorts(e.target.value)} />
                </Field>
                <h4>Periode dan zona waktu</h4>
                <Field
                  label="Zona waktu IANA"
                  hint="Contoh Asia/Jakarta atau UTC. Jam di bawah ditafsirkan pada zona yang dipilih, bukan zona komputer."
                >
                  <input
                    list="roe-timezones"
                    maxLength={100}
                    value={draft.timezone}
                    onChange={(e) => field('timezone', e.target.value)}
                  />
                  <datalist id="roe-timezones">
                    {['Asia/Jakarta', 'Asia/Makassar', 'Asia/Jayapura', 'UTC'].map((zone) => (
                      <option key={zone} value={zone} />
                    ))}
                  </datalist>
                </Field>
                <div className="roe-grid">
                  <Field label="Mulai (jam lokal)">
                    <input
                      type="datetime-local"
                      value={starts}
                      onChange={(e) => setStarts(e.target.value)}
                      onInput={(e) => setStarts(e.currentTarget.value)}
                    />
                  </Field>
                  <Field label="Berakhir (jam lokal)">
                    <input
                      type="datetime-local"
                      value={ends}
                      onChange={(e) => setEnds(e.target.value)}
                      onInput={(e) => setEnds(e.currentTarget.value)}
                    />
                  </Field>
                </div>
                <h4>Tindakan yang direncanakan</h4>
                <div className="roe-checkboxes">
                  {Object.entries(actionLabels).map(([key, text]) => (
                    <label key={key}>
                      <input
                        type="checkbox"
                        checked={draft.allowed_actions.includes(key)}
                        onChange={(e) =>
                          field(
                            'allowed_actions',
                            e.target.checked
                              ? [...draft.allowed_actions, key]
                              : draft.allowed_actions.filter((a) => a !== key)
                          )
                        }
                      />
                      {text}
                    </label>
                  ))}
                </div>
                <div className="roe-grid">
                  <Field label="Batas HTTP request/detik">
                    <input
                      type="number"
                      required
                      min={1}
                      max={15}
                      step={1}
                      value={draft.max_http_rps}
                      onChange={(e) => field('max_http_rps', Number(e.target.value))}
                    />
                  </Field>
                  <Field label="Batas concurrency">
                    <input
                      type="number"
                      required
                      min={1}
                      max={4}
                      step={1}
                      value={draft.max_concurrency}
                      onChange={(e) => field('max_concurrency', Number(e.target.value))}
                    />
                  </Field>
                  <Field label="Batas durasi (menit)">
                    <input
                      type="number"
                      required
                      min={1}
                      max={240}
                      step={1}
                      value={draft.max_duration_minutes}
                      onChange={(e) => field('max_duration_minutes', Number(e.target.value))}
                    />
                  </Field>
                </div>
                <Field
                  label="Alias akun uji"
                  hint="Satu alias per baris, maksimal 10. Contoh account-A dan account-B. Jangan isi password, JWT, PIN, atau API key."
                >
                  <textarea
                    rows={2}
                    maxLength={1210}
                    value={accountRefs}
                    onChange={(e) => setAccountRefs(e.target.value)}
                  />
                </Field>
                <h4>Penghentian dan larangan</h4>
                <Field label="Kontak darurat">
                  <input
                    maxLength={200}
                    value={draft.emergency_contact}
                    onChange={(e) => field('emergency_contact', e.target.value)}
                  />
                </Field>
                <Field label="Kondisi penghentian">
                  <textarea
                    rows={3}
                    maxLength={1500}
                    placeholder="Contoh: hentikan saat ada degradasi layanan atau instruksi STOP dari PIC."
                    value={draft.stop_conditions}
                    onChange={(e) => field('stop_conditions', e.target.value)}
                  />
                </Field>
                <p className="notice">
                  Production, DoS/stress testing, penghapusan/modifikasi data, pengambilan PII asli,
                  dan shell arbitrer tidak tersedia sebagai pilihan tahap ini.
                </p>
                <ScopePreview content={draft} portsText={ports} />
                <div className="settings-form-actions">
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => setEditing(false)}
                  >
                    Batal edit
                  </button>
                  <button type="submit" className="primary-button">
                    {busy ? 'Menyimpan…' : 'Simpan draft'}
                  </button>
                </div>
              </fieldset>
            </form>
          ) : detail && version ? (
            <>
              <div className="roe-detail-heading">
                <div>
                  <p className="page-eyebrow">ENGAGEMENT · ROE v{version.version}</p>
                  <h3>{version.content.name}</h3>
                  <span className={`roe-status status-${status}`}>{statusLabels[status]}</span>
                </div>
                <button
                  className="secondary-button"
                  disabled={busy}
                  onClick={() =>
                    downloadFile(
                      `engagement-${detail.id}.json`,
                      JSON.stringify(
                        {
                          format: 'agent-os-engagement-export',
                          schema_version: 1,
                          project: { id: project.id, name: project.name },
                          exported_at: new Date().toISOString(),
                          ...detail
                        },
                        null,
                        2
                      )
                    )
                  }
                >
                  <Download size={14} />
                  Ekspor riwayat
                </button>
              </div>
              <div
                className="security-engagement-tabs"
                role="tablist"
                aria-label="Halaman engagement"
              >
                <button
                  role="tab"
                  aria-selected={
                    engagementView === 'overview' || (!current && engagementView === 'runs')
                  }
                  onClick={() => setEngagementView('overview')}
                >
                  Scope, RoE & Policy
                </button>
                <button
                  role="tab"
                  aria-selected={engagementView === 'runs' && current}
                  disabled={!current}
                  onClick={() => setEngagementView('runs')}
                >
                  Runs · offline
                </button>
                <button
                  role="tab"
                  aria-selected={engagementView === 'web'}
                  disabled={!current}
                  onClick={() => setEngagementView('web')}
                >
                  Pemeriksaan URL
                </button>
                <button role="tab" aria-selected={engagementView === 'deep'} onClick={() => setEngagementView('deep')}>
                  Deep Analisis
                </button>
                <button role="tab" aria-selected={engagementView === 'scan'} onClick={() => setEngagementView('scan')}>Tools & monitoring</button>
                {(
                  ['evidence', 'findings', 'reports', 'mcp', 'orchestration', 'agents'] as const
                ).map((view) => (
                  <button
                    key={view}
                    role="tab"
                    aria-selected={engagementView === view}
                    onClick={() => setEngagementView(view)}
                  >
                    {
                      {
                        evidence: 'Evidence',
                        findings: 'Findings',
                        reports: 'Reports',
                        mcp: 'MCP Integrations',
                        orchestration: 'Orkestrasi',
                        agents: 'Agents'
                      }[view]
                    }
                  </button>
                ))}
              </div>
              {engagementView === 'scan' ? (
                <TCPScan key={detail.id} engagement={detail} />
              ) : engagementView === 'deep' ? (
                <DeepAnalysis key={detail.id} engagement={detail} />
              ) : engagementView === 'web' ? (
                <WebChecks key={detail.id} engagement={detail} />
              ) : engagementView === 'agents' ? (
                <SecurityAgents
                  key={detail.id}
                  engagement={detail}
                  onRuns={() => setEngagementView('runs')}
                />
              ) : engagementView === 'orchestration' ? (
                <SecurityOrchestration
                  key={detail.id}
                  engagement={detail}
                  onRuns={() => setEngagementView('runs')}
                  onMCP={() => setEngagementView('mcp')}
                />
              ) : engagementView === 'mcp' ? (
                <MCPIntegrations
                  key={detail.id}
                  engagement={detail}
                  onRuns={() => setEngagementView('runs')}
                />
              ) : ['evidence', 'findings', 'reports'].includes(engagementView) ? (
                <SecurityRecords
                  key={`${detail.id}:${engagementView}`}
                  engagement={detail}
                  view={engagementView as 'evidence' | 'findings' | 'reports'}
                />
              ) : engagementView === 'runs' && current ? (
                <SecurityJobs key={`${detail.id}:${detail.revision}`} engagement={detail} />
              ) : (
                <>
                  <div className="roe-decision-actions">
                    {current && status === 'draft' && (
                      <>
                        <button
                          className="secondary-button"
                          disabled={busy}
                          onClick={() => edit(version.content)}
                        >
                          <Pencil size={14} />
                          Edit draft
                        </button>
                        <button
                          className="primary-button"
                          disabled={busy || !!version.submission_errors.length}
                          onClick={() => openDecision('submit')}
                        >
                          Ajukan RoE
                        </button>
                      </>
                    )}
                    {current && status === 'pending_review' && (
                      <>
                        <button
                          className="primary-button"
                          disabled={busy}
                          onClick={() => openDecision('approve')}
                        >
                          Tinjau & setujui lokal
                        </button>
                        <button
                          className="secondary-button"
                          disabled={busy}
                          onClick={() => openDecision('request_changes')}
                        >
                          Minta perbaikan
                        </button>
                      </>
                    )}
                    {current && status !== 'draft' && (
                      <button
                        className="secondary-button"
                        disabled={busy}
                        onClick={() => openDecision('revise')}
                      >
                        Buat revisi baru
                      </button>
                    )}
                    {current && version.status !== 'revoked' && (
                      <button
                        className="danger-button"
                        disabled={busy}
                        onClick={() => openDecision('revoke')}
                      >
                        Cabut RoE
                      </button>
                    )}
                  </div>
                  {current && status === 'draft' && version.submission_errors.length > 0 && (
                    <div className="roe-checklist">
                      <strong>Lengkapi sebelum pengajuan</strong>
                      <ul>
                        {version.submission_errors.map((message) => (
                          <li key={message}>{message}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {!current && (
                    <p className="notice">
                      Snapshot versi terdahulu hanya dapat dibaca. Keputusan baru hanya berlaku pada
                      versi terkini.
                    </p>
                  )}
                  {version.scope_report && (
                    <section className="settings-card">
                      <ScopeFindings report={version.scope_report} />
                    </section>
                  )}
                  {current && (
                    <PolicyGuard key={`${detail.id}:${detail.revision}`} engagement={detail} />
                  )}
                  <dl className="roe-summary roe-grid">
                    {label('Tujuan', version.content.objective)}
                    {label('Lingkungan', environments[version.content.environment])}
                    {label('Pemilik', version.content.owner)}
                    {label('PIC', version.content.contact)}
                    {label('Referensi otorisasi', version.content.authorization_ref)}
                    {label('Zona waktu', version.content.timezone)}
                    {label('Mulai', time(version.content.starts_at, version.content.timezone))}
                    {label('Berakhir', time(version.content.ends_at, version.content.timezone))}
                    {label('Port rencana', version.content.ports.join(', '))}
                    {label(
                      'Batas rencana',
                      `${version.content.max_http_rps} HTTP RPS · ${version.content.max_concurrency} concurrent · ${version.content.max_duration_minutes} menit`
                    )}
                    {label('Kontak darurat', version.content.emergency_contact)}
                    {label('Kondisi stop', version.content.stop_conditions)}
                    {label('Alias akun uji', version.content.test_account_refs.join(', '))}
                    {label(
                      'Tindakan rencana',
                      version.content.allowed_actions.map((a) => actionLabels[a]).join(', ')
                    )}
                  </dl>
                  <div className="roe-grid">
                    {(['in_scope', 'out_of_scope'] as const).map((key) => (
                      <section className="settings-card" key={key}>
                        <h4>{key === 'in_scope' ? 'Dalam scope' : 'Di luar scope'}</h4>
                        {version.content[key].map((asset) => (
                          <p className="scope-display" key={asset.kind + asset.value}>
                            <small>{asset.kind.toUpperCase()}</small>
                            <code>{asset.value}</code>
                          </p>
                        ))}
                        {!version.content[key].length && <p>Belum diisi</p>}
                      </section>
                    ))}
                  </div>
                  <section className="settings-card">
                    <h4>Keputusan dan integritas snapshot</h4>
                    <p>
                      Mode: deklarasi lokal. Nama peninjau di bawah diisi oleh operator sesi yang
                      sama dan bukan identitas yang diverifikasi.
                    </p>
                    <dl className="roe-summary roe-grid">
                      {label('Diajukan', time(version.submitted_at, version.content.timezone))}
                      {label('Ditinjau', time(version.reviewed_at, version.content.timezone))}
                      {label('Nama peninjau (deklarasi)', version.reviewer)}
                      {label('Catatan peninjau', version.review_note)}
                      {label('Dicabut', time(version.revoked_at, version.content.timezone))}
                      {label('Alasan pencabutan', version.revoke_note)}
                    </dl>
                    <p className="roe-hash">SHA-256: {version.content_hash}</p>
                    <p>
                      Hash mengidentifikasi isi snapshot; bukan tanda tangan digital atau audit
                      tahan manipulasi.
                    </p>
                  </section>
                  <section className="settings-card">
                    <h4>
                      <History size={15} />
                      Riwayat versi RoE
                    </h4>
                    <div className="roe-versions">
                      {detail.versions.map((v) => (
                        <button
                          key={v.version}
                          className={`secondary-button ${version.version === v.version ? 'active' : ''}`}
                          onClick={() => {
                            setViewVersion(v.version)
                            setEngagementView('overview')
                          }}
                        >
                          v{v.version} ·{' '}
                          {statusLabels[effectiveStatus(v, v.version === head?.version, clock)]}
                        </button>
                      ))}
                    </div>
                    <p className="muted-text">
                      Snapshot terkunci setelah pengajuan. Membuat revisi baru mencabut persetujuan
                      versi sebelumnya.
                    </p>
                  </section>
                  <section className="settings-card">
                    <h4>Riwayat pencatatan</h4>
                    <ol className="roe-audit">
                      {detail.events
                        .slice(-30)
                        .reverse()
                        .map((event) => (
                          <li key={event.id}>
                            <strong>
                              {eventLabels[event.action] || event.action} · v{event.version}
                            </strong>
                            <small>
                              {time(event.at, version.content.timezone)} · {event.actor} (deklarasi
                              lokal)
                            </small>
                            {event.note && <p>{event.note}</p>}
                          </li>
                        ))}
                    </ol>
                    {detail.events.length > 30 && (
                      <p className="muted-text">
                        Menampilkan 30 catatan terakhir. Ekspor menyertakan seluruh riwayat.
                      </p>
                    )}
                  </section>
                </>
              )}
            </>
          ) : (
            !fetching && (
              <div className="security-empty">
                <h3>{selected ? 'Memuat detail engagement…' : 'Rencanakan engagement pertama'}</h3>
                <p>
                  Mulai dari nama engagement. Lengkapi RoE sebelum mengajukannya untuk ditinjau.
                </p>
              </div>
            )
          )}
        </div>
      </div>
      {decision && detail && head && (
        <Modal
          title={`${decisionLabels[decision]} · v${head.version}`}
          onClose={() => {
            if (!busy) setDecision(null)
          }}
        >
          <form
            className="organize-form"
            onSubmit={(e) => {
              e.preventDefault()
              void run(decide)
            }}
          >
            <p className="notice">
              {decision === 'revise'
                ? 'Versi lama dipertahankan untuk riwayat. Persetujuan lama dicabut dan revisi baru kembali menjadi Draft.'
                : 'Keputusan berlaku hanya pada versi dan isi RoE yang ditampilkan. Run memerlukan adapter yang tersedia dan persetujuan terpisah.'}
            </p>
            <Field label="Nama operator / peninjau (deklarasi)">
              <input
                required
                maxLength={120}
                value={actor}
                onChange={(e) => setActor(e.target.value)}
              />
            </Field>
            <Field
              label={
                decision === 'submit'
                  ? 'Catatan pengajuan (opsional)'
                  : 'Catatan / alasan keputusan'
              }
            >
              <textarea
                required={decision !== 'submit'}
                maxLength={1500}
                rows={3}
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </Field>
            {['approve', 'request_changes'].includes(decision) && (
              <label className="roe-ack">
                <input
                  type="checkbox"
                  required
                  checked={ack}
                  onChange={(e) => setAck(e.target.checked)}
                />
                Saya telah meninjau snapshot v{head.version}. Saya memahami ini pencatatan lokal,
                tidak memverifikasi otorisasi organisasi, dan tidak mengaktifkan pengujian.
              </label>
            )}
            <p className="roe-hash">Snapshot: {head.content_hash}</p>
            {error && (
              <p role="alert" className="notice error security-error">
                {error}
              </p>
            )}
            <div className="settings-form-actions">
              <button
                type="button"
                className="secondary-button"
                disabled={busy}
                onClick={() => setDecision(null)}
              >
                Batal
              </button>
              <button
                className="primary-button"
                disabled={
                  busy ||
                  !actor.trim() ||
                  (decision !== 'submit' && !note.trim()) ||
                  (['approve', 'request_changes'].includes(decision) && !ack)
                }
              >
                {busy ? 'Mencatat…' : decisionLabels[decision]}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </>
  )
}
