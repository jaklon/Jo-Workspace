import { BrandMark } from './BrandMark'
import {
  useEffect,
  useRef,
  useState,
  type Dispatch,
  type SetStateAction,
  type JSX,
  type ReactNode
} from 'react'
import {
  SlidersHorizontal,
  Palette,
  UserRound,
  Cpu,
  Plug,
  Database,
  ShieldCheck,
  Keyboard,
  Info,
  Download,
  Upload,
  RefreshCw,
  Save,
  Check,
  AlertCircle
} from 'lucide-react'
import { Modal } from './Modal'
import { apiFetch, API_BASE_URL } from '../lib/api'
import { defaultPreferences, type Preferences } from '../lib/preferences'
import { modeLabels } from '../lib/types'
import { Readiness } from './Readiness'
import { ModelRuntime } from './ModelRuntime'
import { DataOverview } from './DataPrivacy'

interface ServerSettings {
  models: Record<'reasoning' | 'coding' | 'vision' | 'security', string>
  inference: {
    context_tokens: number
    output_tokens: number
    thinking_tokens: number
    temperature: number
    model_timeout: number
    queue_timeout: number
  }
}
interface SettingsInfo {
  settings: ServerSettings
  defaults: ServerSettings
  ollama_url: string
  workspace: string
  max_upload_mb: number
  max_attachments: number
}
interface HealthInfo {
  status: string
  installed_models: string[]
  missing_models: string[]
  queue: { active: number; waiting: number }
}
const sections = [
  { id: 'general', label: 'Umum', icon: SlidersHorizontal },
  { id: 'appearance', label: 'Tampilan', icon: Palette },
  { id: 'personalization', label: 'Personalisasi', icon: UserRound },
  { id: 'models', label: 'Model & inferensi', icon: Cpu },
  { id: 'connection', label: 'Koneksi', icon: Plug },
  { id: 'readiness', label: 'Kesehatan & iPhone', icon: ShieldCheck },
  { id: 'data', label: 'Kontrol data', icon: Database },
  { id: 'privacy', label: 'Privasi & keamanan', icon: ShieldCheck },
  { id: 'shortcuts', label: 'Pintasan', icon: Keyboard },
  { id: 'about', label: 'Tentang', icon: Info }
]

function Row({
  title,
  description,
  children
}: {
  title: string
  description?: string
  children: ReactNode
}): JSX.Element {
  return (
    <div className="setting-row">
      <div>
        <strong>{title}</strong>
        {description && <p>{description}</p>}
      </div>
      <div className="setting-control">{children}</div>
    </div>
  )
}
function Toggle({
  label,
  value,
  onChange
}: {
  label: string
  value: boolean
  onChange: (value: boolean) => void
}): JSX.Element {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={value}
      aria-label={label}
      className={`toggle ${value ? 'on' : ''}`}
      onClick={() => onChange(!value)}
    >
      <span />
    </button>
  )
}

const modelFeatureMeta: Record<
  keyof ServerSettings['models'],
  { title: string; description: string }
> = {
  reasoning: { title: 'Chat & dokumen', description: 'Penalaran umum untuk chat dan analisis dokumen.' },
  coding: { title: 'Coding', description: 'Bantuan menulis dan meninjau kode.' },
  security: { title: 'Security', description: 'Analisis keamanan dan pentest.' },
  vision: {
    title: 'Vision',
    description: 'Harus mendukung gambar (mis. minicpm-v, llava, qwen2.5-vl).'
  }
}

const CUSTOM_MODEL = '__custom__'

/** Per-feature model picker: a dropdown of installed models, with an escape hatch
 * to type a model name that is not installed yet. */
function ModelSelect({
  feature,
  value,
  installed,
  onChange
}: {
  feature: keyof ServerSettings['models']
  value: string
  installed: string[]
  onChange: (value: string) => void
}): JSX.Element {
  const [custom, setCustom] = useState(false)
  const options = Array.from(new Set([...installed, value].filter(Boolean))).sort((a, b) =>
    a.localeCompare(b)
  )
  if (custom) {
    return (
      <div className="model-select-custom">
        <input
          aria-label={`Model ${feature}`}
          list="installed-models"
          required
          autoFocus
          maxLength={120}
          value={value}
          placeholder="mis. qwen2.5:7b-instruct"
          onChange={(e) => onChange(e.target.value)}
        />
        <button type="button" className="secondary-button" onClick={() => setCustom(false)}>
          Pilih dari daftar
        </button>
      </div>
    )
  }
  return (
    <select
      aria-label={`Model ${feature}`}
      value={options.includes(value) ? value : CUSTOM_MODEL}
      onChange={(e) => {
        if (e.target.value === CUSTOM_MODEL) setCustom(true)
        else onChange(e.target.value)
      }}
    >
      {!options.length && <option value="">Tidak ada model terpasang</option>}
      {options.map((m) => (
        <option key={m} value={m}>
          {m}
        </option>
      ))}
      <option value={CUSTOM_MODEL}>Model lain (ketik manual)…</option>
    </select>
  )
}

export function Settings({
  preferences,
  setPreferences,
  preferenceError,
  onClose,
  onDisconnect,
  onExport,
  onRecoveryExport,
  onImport,
  onArchiveAll,
  onClearAll,
  counts,
  disabled,
  exportDisabled
}: {
  preferences: Preferences
  setPreferences: Dispatch<SetStateAction<Preferences>>
  preferenceError: string
  onClose: () => void
  onDisconnect: () => void
  onExport: () => void
  onRecoveryExport: () => void
  onImport: (file: File) => Promise<void>
  onArchiveAll: () => void
  onClearAll: () => Promise<void>
  counts: { chats: number; projects: number; messages: number }
  disabled: boolean
  exportDisabled: boolean
}): JSX.Element {
  const [section, setSection] = useState('general')
  const [server, setServer] = useState<SettingsInfo | null>(null)
  const [draft, setDraft] = useState<ServerSettings | null>(null)
  const [health, setHealth] = useState<HealthInfo | null>(null)
  const [backendError, setBackendError] = useState('')
  const [healthError, setHealthError] = useState('')
  const [feedback, setFeedback] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState(false)
  const [confirm, setConfirm] = useState('')
  const [confirmText, setConfirmText] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)
  const [refresh, setRefresh] = useState(0)
  const update = <K extends keyof Preferences>(key: K, value: Preferences[K]): void =>
    setPreferences((p) => ({ ...p, [key]: value }))
  useEffect(() => {
    const controller = new AbortController()
    let alive = true
    void apiFetch('/api/settings', { signal: controller.signal })
      .then((r) => r.json())
      .then((value) => {
        if (alive) {
          setServer(value)
          setDraft(value.settings)
          setBackendError('')
        }
      })
      .catch((e) => {
        if (alive) setBackendError(e.message)
      })
    void apiFetch('/api/health', { signal: controller.signal })
      .then((r) => r.json())
      .then((value) => {
        if (alive) {
          setHealth(value)
          setHealthError('')
        }
      })
      .catch((e) => {
        if (alive) setHealthError(e.message)
      })
    return () => {
      alive = false
      controller.abort()
    }
  }, [refresh])
  const run = async (action: () => Promise<void>): Promise<void> => {
    setBusy(true)
    setError('')
    setFeedback('')
    try {
      await action()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Operasi gagal.')
    } finally {
      setBusy(false)
    }
  }
  const saveModels = async (): Promise<void> => {
    if (!draft) return
    await apiFetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(draft)
    })
    setFeedback('Model dan parameter tersimpan. Berlaku untuk permintaan berikutnya.')
    window.dispatchEvent(new Event('agent-settings-changed'))
    setRefresh((v) => v + 1)
  }
  const changeSection = (id: string): void => {
    setSection(id)
    setFeedback('')
    setError('')
    setConfirm('')
    setConfirmText('')
  }
  const confirmAction = async (): Promise<void> => {
    if (confirm === 'delete' && confirmText !== 'HAPUS') return
    if (confirm === 'delete') {
      await onClearAll()
      setFeedback(
        'Percakapan dan project pada perangkat ini dihapus. Referensi lampiran tidak lagi ditampilkan.'
      )
    }
    if (confirm === 'usage') {
      await apiFetch('/api/usage', { method: 'DELETE' })
      setFeedback('Statistik usage backend dihapus.')
    }
    if (confirm === 'archive') {
      onArchiveAll()
      setFeedback('Semua percakapan diarsipkan. Buka ikon Arsip di sidebar untuk memulihkan.')
    }
    if (confirm === 'reset') {
      setPreferences({ ...defaultPreferences })
      setFeedback('Preferensi perangkat dikembalikan ke bawaan.')
    }
    setConfirm('')
    setConfirmText('')
  }
  return (
    <Modal
      title="Settings"
      onClose={() => {
        if (!busy) onClose()
      }}
      wide
    >
      <div className="settings-layout">
        <nav className="settings-nav" aria-label="Kategori settings">
          {sections.map((s) => (
            <button
              key={s.id}
              className={section === s.id ? 'active' : ''}
              onClick={() => changeSection(s.id)}
            >
              <s.icon size={17} />
              <span>{s.label}</span>
            </button>
          ))}
          <p>Jo Workspace · Local workspace</p>
        </nav>
        <div className="settings-content scrollbar-thin">
          <div className="settings-section-heading">
            <h3>{sections.find((s) => s.id === section)?.label}</h3>
            <p>
              {(
                {
                  models:
                    'Konfigurasi backend bersama; perubahan berlaku untuk semua klien yang terhubung.',
                  connection: 'Periksa layanan backend, model lokal, dan sesi akses Anda.',
                  readiness: 'Periksa kesiapan layanan dan akses privat iPhone.',
                  data: 'Kelola riwayat perangkat dan statistik backend dengan cakupan yang jelas.',
                  privacy: 'Informasi penyimpanan, retensi, dan batas akses agent.',
                  shortcuts: 'Akses fitur yang sering dipakai langsung dari keyboard.',
                  about: 'Asisten AI untuk ruang kerja pribadi Anda.'
                } as Record<string, string>
              )[section] || 'Preferensi pribadi disimpan otomatis di perangkat dan browser ini.'}
            </p>
          </div>
          {preferenceError && (
            <p role="alert" className="notice error">
              {preferenceError}
            </p>
          )}
          {feedback && (
            <p role="status" className="notice success">
              <Check size={16} />
              {feedback}
            </p>
          )}
          {error && (
            <p role="alert" className="notice error">
              <AlertCircle size={16} />
              {error}
            </p>
          )}
          {section === 'general' && (
            <>
              <Row title="Nama panggilan" description="Ditampilkan pada profil dan sapaan awal.">
                <input
                  aria-label="Nama panggilan"
                  maxLength={60}
                  placeholder="Nama Anda"
                  value={preferences.name}
                  onChange={(e) => update('name', e.target.value)}
                />
              </Row>
              <Row
                title="Mode awal"
                description="Mode yang dibuka saat aplikasi dijalankan kembali."
              >
                <select
                  aria-label="Mode awal"
                  value={preferences.defaultMode}
                  onChange={(e) =>
                    update('defaultMode', e.target.value as Preferences['defaultMode'])
                  }
                >
                  {Object.entries(modeLabels).map(([id, label]) => (
                    <option value={id} key={id}>
                      {label}
                    </option>
                  ))}
                </select>
              </Row>
              <Row
                title="Enter untuk mengirim"
                description="Jika aktif, Shift + Enter membuat baris baru. Ctrl + Enter selalu mengirim."
              >
                <Toggle
                  label="Enter untuk mengirim"
                  value={preferences.sendWithEnter}
                  onChange={(v) => update('sendWithEnter', v)}
                />
              </Row>
              <Row
                title="Saran pertanyaan"
                description="Tampilkan inspirasi saat percakapan masih kosong."
              >
                <Toggle
                  label="Saran pertanyaan"
                  value={preferences.showSuggestions}
                  onChange={(v) => update('showSuggestions', v)}
                />
              </Row>
              <Row
                title="Gulir otomatis"
                description="Ikuti jawaban baru pada percakapan yang sedang dibuka."
              >
                <Toggle
                  label="Gulir otomatis"
                  value={preferences.autoScroll}
                  onChange={(v) => update('autoScroll', v)}
                />
              </Row>
              <Row
                title="Reset preferensi"
                description="Kembalikan profil, tampilan, dan personalisasi perangkat ke bawaan."
              >
                <button className="secondary-button" onClick={() => setConfirm('reset')}>
                  Reset
                </button>
              </Row>
            </>
          )}
          {section === 'appearance' && (
            <>
              <h4 className="field-heading">Tema</h4>
              <div className="theme-options">
                {[
                  ['dark', 'Gelap'],
                  ['light', 'Terang'],
                  ['system', 'Sistem']
                ].map(([id, label]) => (
                  <button
                    key={id}
                    className={`theme-preview ${id} ${preferences.theme === id ? 'chosen' : ''}`}
                    onClick={() => update('theme', id as Preferences['theme'])}
                  >
                    <span className="preview-window">
                      <i />
                      <span>
                        <b />
                        <b />
                        <b />
                      </span>
                    </span>
                    <strong>{label}</strong>
                    {preferences.theme === id && <Check size={14} />}
                  </button>
                ))}
              </div>
              <Row
                title="Ukuran teks jawaban"
                description="Sesuaikan kenyamanan membaca percakapan."
              >
                <select
                  aria-label="Ukuran teks jawaban"
                  value={preferences.fontSize}
                  onChange={(e) => update('fontSize', e.target.value as Preferences['fontSize'])}
                >
                  <option value="small">Kecil</option>
                  <option value="normal">Normal</option>
                  <option value="large">Besar</option>
                </select>
              </Row>
              <Row
                title="Kurangi animasi"
                description="Nonaktifkan transisi dan gulir halus. Preferensi aksesibilitas sistem juga dihormati."
              >
                <Toggle
                  label="Kurangi animasi"
                  value={preferences.reducedMotion}
                  onChange={(v) => update('reducedMotion', v)}
                />
              </Row>
              <div className="appearance-sample prose-answer">
                Pratinjau jawaban: ide yang jelas dimulai dari percakapan yang nyaman.
              </div>
            </>
          )}
          {section === 'personalization' && (
            <>
              <Row
                title="Bahasa jawaban"
                description="Preferensi dikirim bersama pesan berikutnya."
              >
                <select
                  aria-label="Bahasa jawaban"
                  value={preferences.responseLanguage}
                  onChange={(e) =>
                    update('responseLanguage', e.target.value as Preferences['responseLanguage'])
                  }
                >
                  <option value="id">Bahasa Indonesia</option>
                  <option value="en">English</option>
                  <option value="auto">Ikuti pesan</option>
                </select>
              </Row>
              <Row title="Gaya jawaban">
                <select
                  aria-label="Gaya jawaban"
                  value={preferences.responseStyle}
                  onChange={(e) =>
                    update('responseStyle', e.target.value as Preferences['responseStyle'])
                  }
                >
                  <option value="balanced">Seimbang</option>
                  <option value="concise">Ringkas</option>
                  <option value="detailed">Terperinci</option>
                </select>
              </Row>
              <label className="field-block">
                Instruksi khusus
                <textarea
                  rows={6}
                  maxLength={1500}
                  placeholder="Contoh: Saya developer pemula. Jelaskan istilah teknis dan sertakan contoh praktis."
                  value={preferences.customInstructions}
                  onChange={(e) => update('customInstructions', e.target.value)}
                />
                <small>
                  {preferences.customInstructions.length}/1500 karakter · Berlaku pada pesan
                  berikutnya di semua mode chat.
                </small>
              </label>
              <p className="notice">
                Instruksi dan memori project ditambahkan saat chat berada dalam project. Percakapan
                lain dalam project tidak otomatis menjadi konteks. Model lokal mungkin tidak selalu mengikuti
                semua preferensi.
              </p>
            </>
          )}
          {section === 'models' && (
            <>
              <ModelRuntime />
              {backendError && (
                <p role="alert" className="notice error">
                  {backendError}
                  <button className="secondary-button" onClick={() => setRefresh((v) => v + 1)}>
                    Coba lagi
                  </button>
                </p>
              )}
              {!draft && !backendError && <p className="muted-text">Memuat konfigurasi backend…</p>}
              {draft && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault()
                    void run(saveModels)
                  }}
                >
                  <p className="notice">
                    Pilih model untuk setiap fitur dari daftar model terpasang
                    {health ? ` (${health.installed_models.length} terpasang)` : ''}, atau pilih
                    “Model lain” untuk mengetik nama model Ollama. Model tidak diunduh otomatis.
                    Simpan saat antrean kosong.
                  </p>
                  <datalist id="installed-models">
                    {health?.installed_models.map((m) => (
                      <option key={m} value={m} />
                    ))}
                  </datalist>
                  {(Object.keys(draft.models) as Array<keyof ServerSettings['models']>).map(
                    (key) => (
                      <Row
                        key={key}
                        title={modelFeatureMeta[key].title}
                        description={modelFeatureMeta[key].description}
                      >
                        <ModelSelect
                          feature={key}
                          value={draft.models[key]}
                          installed={health?.installed_models ?? []}
                          onChange={(value) =>
                            setDraft({ ...draft, models: { ...draft.models, [key]: value } })
                          }
                        />
                      </Row>
                    )
                  )}
                  <h4 className="field-heading">Parameter inferensi</h4>
                  {(
                    [
                      [
                        'context_tokens',
                        'Context window',
                        '2048–32768 token. Konteks besar membutuhkan lebih banyak VRAM.',
                        2048,
                        32768,
                        256
                      ],
                      [
                        'output_tokens',
                        'Batas token jawaban',
                        '128–8192 token, maksimal sepertiga context window.',
                        128,
                        Math.min(8192, Math.floor(draft.inference.context_tokens / 3)),
                        1
                      ],
                      [
                        'thinking_tokens',
                        'Token penalaran',
                        '0 mematikan penalaran. Jawaban + penalaran maksimal dua pertiga context window; penalaran ditampilkan di chat.',
                        0,
                        Math.max(
                          0,
                          Math.min(
                            8192,
                            Math.floor((draft.inference.context_tokens * 2) / 3) -
                              draft.inference.output_tokens
                          )
                        ),
                        1
                      ],
                      [
                        'temperature',
                        'Temperature',
                        '0 lebih konsisten; 2 lebih bervariasi.',
                        0,
                        2,
                        0.1
                      ],
                      [
                        'model_timeout',
                        'Timeout model (detik)',
                        'Batas waktu pemrosesan satu inferensi.',
                        30,
                        600,
                        1
                      ],
                      [
                        'queue_timeout',
                        'Timeout antrean (detik)',
                        'Batas waktu menunggu giliran model.',
                        5,
                        120,
                        1
                      ]
                    ] as const
                  ).map(([key, label, description, min, max, step]) => (
                    <Row key={key} title={label} description={description}>
                      <input
                        type="number"
                        aria-label={label}
                        required
                        min={min}
                        max={max}
                        step={step}
                        value={Number.isNaN(draft.inference[key]) ? '' : draft.inference[key]}
                        onChange={(e) =>
                          setDraft({
                            ...draft,
                            inference: {
                              ...draft.inference,
                              [key]: e.target.value === '' ? NaN : Number(e.target.value)
                            }
                          })
                        }
                      />
                    </Row>
                  ))}
                  {server && JSON.stringify(draft) !== JSON.stringify(server.settings) && (
                    <p className="notice">Ada perubahan konfigurasi yang belum disimpan.</p>
                  )}
                  <div className="settings-form-actions">
                    <button
                      type="button"
                      disabled={busy}
                      className="secondary-button"
                      onClick={() => {
                        if (server) setDraft(structuredClone(server.defaults))
                      }}
                    >
                      Isi nilai bawaan
                    </button>
                    <button className="primary-button" disabled={busy || disabled}>
                      <Save size={15} />
                      {busy ? 'Menyimpan…' : 'Simpan konfigurasi'}
                    </button>
                  </div>
                </form>
              )}
            </>
          )}
          {section === 'readiness' && <Readiness />}
          {section === 'connection' && (
            <>
              <div className="connection-card">
                <span className={`connection-dot ${health && !healthError ? 'online' : ''}`} />
                <div>
                  <strong>
                    {healthError
                      ? 'Ollama tidak terhubung'
                      : health?.status === 'connected'
                        ? 'Semua model siap'
                        : health
                          ? 'Sebagian model belum tersedia'
                          : 'Memeriksa koneksi…'}
                  </strong>
                  <p>{healthError || `${health?.installed_models.length ?? 0} model terpasang`}</p>
                </div>
              </div>
              <Row title="Backend API">
                <code className="path-value">{API_BASE_URL}</code>
              </Row>
              <Row title="Server Ollama">
                <code className="path-value">{server?.ollama_url || 'Belum tersedia'}</code>
              </Row>
              <Row
                title="Uji koneksi"
                description="Periksa backend dan daftar model tanpa menjalankan inferensi."
              >
                <button
                  className="secondary-button"
                  disabled={testing}
                  onClick={() => {
                    setTesting(true)
                    setFeedback('')
                    setError('')
                    void apiFetch('/api/health')
                      .then((r) => r.json())
                      .then((h) => {
                        setHealth(h)
                        setHealthError('')
                        setFeedback(
                          h.status === 'connected'
                            ? 'Backend dan model siap digunakan.'
                            : `Model belum tersedia: ${h.missing_models.join(', ')}`
                        )
                      })
                      .catch((e) => {
                        setHealthError(e.message)
                        setError(e.message)
                      })
                      .finally(() => setTesting(false))
                  }}
                >
                  <RefreshCw size={15} />
                  {testing ? 'Memeriksa…' : 'Uji koneksi'}
                </button>
              </Row>
              {health?.missing_models.length ? (
                <p className="notice">
                  Model belum tersedia: {health.missing_models.join(', ')}. Instal melalui Ollama
                  atau ganti model pada pengaturan Model & inferensi.
                </p>
              ) : null}
              <Row
                title="Keluar / ganti token"
                description="Tutup sesi koneksi ini, lalu hubungkan kembali menggunakan token."
              >
                <button className="secondary-button" disabled={busy} onClick={onDisconnect}>
                  Putuskan koneksi
                </button>
              </Row>
              <p className="muted-text">
                Alamat backend desktop ditentukan oleh konfigurasi build. Alamat Ollama diatur
                melalui OLLAMA_URL saat server dimulai. Token disimpan sebagai cookie HttpOnly pada
                web; fallback desktop hanya di memori.
              </p>
            </>
          )}
          {section === 'data' && (
            <>
              <DataOverview />
              <div className="data-summary">
                <div>
                  <strong>{counts.chats}</strong>
                  <span>Percakapan</span>
                </div>
                <div>
                  <strong>{counts.projects}</strong>
                  <span>Project</span>
                </div>
                <div>
                  <strong>{counts.messages}</strong>
                  <span>Pesan tersimpan</span>
                </div>
              </div>
              <Row
                title="Ekspor data"
                description="Unduh chat, project, dan preferensi sebagai JSON. Lampiran dan token akses tidak disertakan."
              >
                <button className="secondary-button" disabled={exportDisabled} onClick={onExport}>
                  <Download size={15} />
                  Ekspor
                </button>
              </Row>
              <Row
                title="Snapshot browser untuk pemulihan"
                description="Simpan ID chat, project, dan referensi lampiran untuk digabungkan dengan cadangan backend. Berkas ini berisi data pribadi."
              >
                <button
                  className="secondary-button"
                  disabled={exportDisabled}
                  onClick={onRecoveryExport}
                >
                  <Download size={15} /> Snapshot browser
                </button>
              </Row>
              <Row
                title="Impor data"
                description="Gabungkan ekspor JSON atau pulihkan snapshot browser. Snapshot mempertahankan ID dan memerlukan backend yang sesuai."
              >
                <button
                  className="secondary-button"
                  disabled={busy || disabled}
                  onClick={() => fileRef.current?.click()}
                >
                  <Upload size={15} />
                  Impor
                </button>
                <input
                  ref={fileRef}
                  type="file"
                  accept=".json,application/json"
                  hidden
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file)
                      void run(async () => {
                        await onImport(file)
                        setFeedback(
                          'Berkas berhasil diimpor. Snapshot pemulihan juga mengembalikan preferensi perangkat.'
                        )
                      })
                    e.target.value = ''
                  }}
                />
              </Row>
              <Row
                title="Arsipkan semua chat"
                description="Sembunyikan dari daftar utama; chat tetap bisa dipulihkan."
              >
                <button
                  className="secondary-button"
                  disabled={disabled || busy}
                  onClick={() => setConfirm('archive')}
                >
                  Arsipkan
                </button>
              </Row>
              <Row
                title="Hapus seluruh chat & project"
                description="Hapus chat dan project dari workspace bersama. Lampiran yang tidak lagi dirujuk mengikuti batas retensi backend."
              >
                <button
                  className="danger-button"
                  disabled={disabled || busy}
                  onClick={() => setConfirm('delete')}
                >
                  Hapus data
                </button>
              </Row>
              <Row
                title="Reset statistik usage"
                description="Hapus catatan usage pada backend bersama untuk semua perangkat."
              >
                <button
                  className="danger-button"
                  disabled={disabled || busy}
                  onClick={() => setConfirm('usage')}
                >
                  Reset usage
                </button>
              </Row>
              <p className="muted-text">
                Chat tersimpan di IndexedDB, preferensi di localStorage. Riwayat tidak tersinkron
                otomatis antarbrowser/perangkat. Maksimal 500 chat per mode dan 100 pesan terbaru
                per chat; gambar asli tidak disimpan dalam riwayat.
              </p>
            </>
          )}
          {section === 'privacy' && (
            <>
              <div className="notice success">
                <ShieldCheck size={20} />
                <span>
                  Inferensi diarahkan ke Ollama yang dikonfigurasi. Aplikasi ini tidak mengirim
                  percakapan ke layanan analitik.
                </span>
              </div>
              <Row title="Penyimpanan chat">
                <span className="status-tag">Per perangkat</span>
              </Row>
              <Row
                title="Persetujuan perubahan kode"
                description="Proposal berkas dari agent harus disetujui sebelum diterapkan."
              >
                <span className="status-tag">Selalu aktif</span>
              </Row>
              <Row
                title="Eksekusi shell bebas"
                description="Model tidak dapat menjalankan perintah shell arbitrer."
              >
                <span className="status-tag">Dinonaktifkan</span>
              </Row>
              <Row
                title="Workspace agent"
                description="Project di sidebar hanya mengelompokkan chat; batas akses berkas agent tetap mengikuti workspace backend."
              >
                <code className="path-value">{server?.workspace || 'Belum tersedia'}</code>
              </Row>
              <div className="settings-card">
                <h4>Retensi & batasan</h4>
                <ul className="privacy-list">
                  <li>Sesi web berlaku 12 jam.</li>
                  <li>
                    Lampiran dibersihkan saat unggahan baru jika berusia lebih dari 30 hari; dapat
                    dihapus melalui chip lampiran.
                  </li>
                  <li>
                    Usage menyimpan jumlah token dan durasi, tanpa isi percakapan, selama hingga 90
                    hari.
                  </li>
                  <li>Maksimal 4 lampiran per sesi, 8 MB per berkas.</li>
                  <li>
                    Ekspor dapat memuat informasi pribadi dari chat Anda. Simpan cadangan dengan
                    aman.
                  </li>
                </ul>
              </div>
            </>
          )}
          {section === 'shortcuts' && (
            <>
              {[
                ['Chat baru', 'Ctrl / ⌘ + Shift + O'],
                ['Cari percakapan', 'Ctrl / ⌘ + K'],
                ['Buka Settings', 'Ctrl / ⌘ + ,'],
                [
                  'Kirim pesan',
                  preferences.sendWithEnter ? 'Enter atau Ctrl / ⌘ + Enter' : 'Ctrl / ⌘ + Enter'
                ],
                ['Baris baru', preferences.sendWithEnter ? 'Shift + Enter' : 'Enter'],
                ['Tutup dialog', 'Esc']
              ].map(([label, key]) => (
                <Row key={label} title={label}>
                  <kbd>{key}</kbd>
                </Row>
              ))}
              <p className="muted-text">Pintasan memakai ⌘ di macOS dan Ctrl di Windows/Linux.</p>
            </>
          )}
          {section === 'about' && (
            <>
              <div className="about-brand">
                <BrandMark />
                <h3>Jo Workspace</h3>
                <p>Personal AI workspace · v1.0.0</p>
              </div>
              <div className="settings-card">
                <h4>Ruang untuk berpikir dan bekerja</h4>
                <p>
                  Chat, coding, gambar, dokumen, dan lab keamanan dalam satu aplikasi lokal.
                  Dibangun dengan React, Electron, FastAPI, dan Ollama.
                </p>
              </div>
              <p className="muted-text">
                Aplikasi ini merupakan project mandiri. Kemampuan model, kualitas jawaban, dan
                kecepatan bergantung pada model Ollama serta perangkat yang digunakan.
              </p>
            </>
          )}
          {confirm && (
            <div className="confirmation-box" role="alert">
              <strong>
                {confirm === 'delete'
                  ? 'Hapus data perangkat ini?'
                  : confirm === 'usage'
                    ? 'Reset usage untuk semua perangkat?'
                    : confirm === 'archive'
                      ? 'Arsipkan semua percakapan?'
                      : 'Reset preferensi perangkat?'}
              </strong>
              <p>
                {confirm === 'delete'
                  ? 'Tindakan ini tidak dapat dibatalkan. Ekspor cadangan terlebih dahulu bila diperlukan. Ketik HAPUS untuk melanjutkan.'
                  : confirm === 'archive'
                    ? 'Chat tetap tersimpan dan dapat dipulihkan dari Arsip.'
                    : confirm === 'usage'
                      ? 'Statistik yang tersimpan akan dihapus. Percakapan tetap tersedia.'
                      : 'Preferensi umum, tampilan, dan instruksi pribadi dikembalikan ke bawaan.'}
              </p>
              {confirm === 'delete' && (
                <input
                  aria-label="Ketik HAPUS"
                  value={confirmText}
                  placeholder="HAPUS"
                  onChange={(e) => setConfirmText(e.target.value)}
                />
              )}
              <div className="settings-form-actions">
                <button className="secondary-button" disabled={busy} onClick={() => setConfirm('')}>
                  Batal
                </button>
                <button
                  className="danger-button"
                  disabled={busy || (confirm === 'delete' && confirmText !== 'HAPUS')}
                  onClick={() => void run(confirmAction)}
                >
                  {busy ? 'Memproses…' : 'Konfirmasi'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </Modal>
  )
}
