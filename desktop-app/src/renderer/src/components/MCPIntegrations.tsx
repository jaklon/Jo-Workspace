import { useEffect, useState, type JSX, type ReactNode } from 'react'
import { Plus, Plug, RefreshCw, Download, ShieldCheck } from 'lucide-react'
import { apiFetch } from '../lib/api'
import { engagementPath, type Engagement, type ScopeKind } from '../lib/engagements'
import { downloadFile } from '../lib/preferences'
import { fixtureNames, mcpTools, type MCPCatalog, type MCPConfig, type MCPServer } from '../lib/mcp'
import { Modal } from './Modal'
import type { SecurityJob } from '../lib/securityJobs'

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
const defaultConfig = (): MCPConfig => ({
  name: '',
  adapter: 'bundled_fixture',
  allowed_tools: ['fixture.inspect'],
  max_wall_seconds: 10,
  max_output_kb: 32
})
const states = {
  draft: 'Draft · belum diizinkan',
  approved: 'Disetujui secara lokal',
  disabled: 'Dinonaktifkan'
}

export function MCPIntegrations({
  engagement,
  onRuns
}: {
  engagement: Engagement
  onRuns: () => void
}): JSX.Element {
  const [catalog, setCatalog] = useState<MCPCatalog | null>(null)
  const [selected, setSelected] = useState<MCPServer | null>(null)
  const [modal, setModal] = useState<'config' | 'approve' | 'disable' | 'job' | null>(null)
  const [config, setConfig] = useState<MCPConfig>(defaultConfig)
  const [editing, setEditing] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [refresh, setRefresh] = useState(0)
  const [actor, setActor] = useState('')
  const [note, setNote] = useState('')
  const [ack, setAck] = useState(false)
  const [jobName, setJobName] = useState('')
  const [kind, setKind] = useState<ScopeKind>('ip')
  const [target, setTarget] = useState('')
  const [tool, setTool] = useState('fixture.inspect')
  const [fixture, setFixture] = useState('headers_missing')
  const [after, setAfter] = useState('headers_present')
  const [wall, setWall] = useState(10)
  const [output, setOutput] = useState(32)
  const [createdJob, setCreatedJob] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    void apiFetch('/api/security/mcp/servers', { signal: controller.signal })
      .then((r) => r.json())
      .then((data: MCPCatalog) => {
        if (!controller.signal.aborted) setCatalog(data)
      })
      .catch((e) => {
        if (!controller.signal.aborted) setError(e.message)
      })
    return () => controller.abort()
  }, [refresh])
  const request = async <T,>(path: string, body?: unknown, method = 'POST'): Promise<T> =>
    (
      await apiFetch(
        '/api/security/mcp' + path,
        body === undefined
          ? {}
          : { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
      )
    ).json()
  const operate = async (action: () => Promise<void>): Promise<void> => {
    setBusy(true)
    setError('')
    try {
      await action()
      setRefresh((v) => v + 1)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Operasi MCP gagal.')
    } finally {
      setBusy(false)
    }
  }
  const open = (next: typeof modal): void => {
    setModal(next)
    setAck(false)
    setActor('')
    setNote('')
    setError('')
  }
  const head = engagement.versions[0]
  return (
    <section className="security-records" aria-label="MCP Integrations">
      <div className="section-title">
        <h3>
          <Plug size={18} />
          MCP Integrations
        </h3>
        <span className="planning-badge">Fixture terisolasi · pentest terkunci</span>
      </div>
      <p className="notice">
        Hanya server fixture yang dibundel dan ditinjau dapat digunakan. Tidak ada URL, command,
        environment, token eksternal, atau server MCP pihak ketiga yang dapat dijalankan. Model dan
        pentest tetap dinonaktifkan.
      </p>
      <p className="muted-text">
        Windows AppContainer tanpa kapabilitas jaringan · satu proses · 256 MiB · CPU 3 detik ·
        waktu maksimal 15 detik · output maksimal 64 KiB. Workspace pribadi, token aplikasi, dan
        Docker socket tidak diteruskan. Jika isolasi gagal, permintaan ditolak.
      </p>
      <p>
        {catalog?.runner_supported
          ? 'Dukungan AppContainer tersedia. Gunakan Periksa koneksi untuk menguji handshake nyata.'
          : 'Runner terisolasi belum tersedia pada runtime ini. Profil tetap dapat ditinjau; fixture tidak dapat dijalankan.'}
      </p>
      <div className="roe-decision-actions">
        <button
          className="primary-button"
          disabled={busy || !catalog}
          onClick={() => {
            setConfig(defaultConfig())
            setEditing(false)
            open('config')
          }}
        >
          <Plus size={14} />
          Profil MCP baru
        </button>
        <button
          className="secondary-button"
          disabled={busy}
          onClick={() => {
            setError('')
            setSelected(null)
            setRefresh((v) => v + 1)
          }}
        >
          <RefreshCw size={14} />
          Muat ulang MCP
        </button>
        <small>{catalog?.servers.length || 0}/20 profil global workspace</small>
      </div>
      {error && !modal && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
      {createdJob && (
        <div className="notice">
          <p>
            Job {createdJob} tersimpan sebagai Awaiting Approval. Tidak ada tool dipanggil sebelum
            review job.
          </p>
          <button className="secondary-button" onClick={onRuns}>
            Buka Runs untuk review job
          </button>
        </div>
      )}
      <div className="record-list">
        {catalog?.servers.map((s) => (
          <button
            className={selected?.id === s.id ? 'selected' : ''}
            key={s.id}
            disabled={busy}
            onClick={() => void operate(async () => setSelected(await request('/servers/' + s.id)))}
          >
            <strong>{s.config.name}</strong>
            <span>
              {states[s.state]} · revisi {s.revision}
            </span>
            <small>
              {s.config.allowed_tools.join(', ')} · {s.config.max_wall_seconds} detik ·{' '}
              {s.config.max_output_kb} KiB
            </small>
          </button>
        ))}
      </div>
      {!catalog?.servers.length && (
        <p>
          Belum ada profil. Tambahkan adapter fixture dari katalog, tinjau schema dan izin tool,
          lalu catat persetujuan lokal.
        </p>
      )}
      {selected && (
        <article className="record-detail">
          <h4>{selected.config.name}</h4>
          <p>
            {states[selected.state]} · {selected.id} · revisi {selected.revision}
          </p>
          <p>
            Autentikasi transport: managed local stdio. Backend memiliki proses/handle fixture;
            tidak ada kredensial server eksternal yang disimpan atau diwariskan.
          </p>
          <p className="record-hash">
            Hash konfigurasi: {selected.config_hash}
            <br />
            Hash adapter/schema: {selected.descriptor_hash}
          </p>
          <div className="roe-decision-actions">
            <button
              className="secondary-button"
              disabled={busy}
              onClick={() => {
                setConfig(selected.config)
                setEditing(true)
                open('config')
              }}
            >
              Edit profil & cabut approval
            </button>
            {selected.state !== 'approved' && (
              <button className="primary-button" disabled={busy} onClick={() => open('approve')}>
                <ShieldCheck size={14} />
                Tinjau profil MCP
              </button>
            )}
            {selected.state === 'approved' && (
              <>
                <button
                  className="secondary-button"
                  disabled={busy || !catalog?.runner_supported}
                  onClick={() =>
                    void operate(async () => {
                      await request('/servers/' + selected.id + '/check', {
                        expected_revision: selected.revision
                      })
                      setSelected(await request('/servers/' + selected.id))
                    })
                  }
                >
                  Periksa koneksi MCP
                </button>
                <button
                  className="primary-button"
                  disabled={busy || !catalog?.runner_supported}
                  onClick={() => {
                    setJobName('Fixture MCP ' + selected.config.name)
                    setTarget('')
                    setKind('ip')
                    setTool(selected.config.allowed_tools[0])
                    setFixture('headers_missing')
                    setAfter('headers_present')
                    setWall(selected.config.max_wall_seconds)
                    setOutput(selected.config.max_output_kb)
                    open('job')
                  }}
                >
                  Rencana job fixture MCP
                </button>
                <button className="danger-button" disabled={busy} onClick={() => open('disable')}>
                  Nonaktifkan server MCP
                </button>
              </>
            )}
            <button
              className="secondary-button"
              onClick={() =>
                downloadFile(
                  'mcp-server-' + selected.id + '.json',
                  JSON.stringify(selected, null, 2)
                )
              }
            >
              <Download size={14} />
              Ekspor profil MCP
            </button>
          </div>
          {selected.review && (
            <p>
              Review lokal: {selected.review.actor_label} · {selected.review.at}
              <br />
              {selected.review.note}
            </p>
          )}
          <details>
            <summary>Descriptor, versi, dan schema tool</summary>
            <Json value={selected.descriptor} />
          </details>
          <h4>Pemeriksaan koneksi (initialize + tools/list; tanpa tools/call)</h4>
          {!selected.checks?.length && <p>Belum diuji.</p>}
          {selected.checks?.map((c) => (
            <details key={c.id}>
              <summary>
                {c.at} · {String(c.result.status)} · revisi {c.server_revision}
              </summary>
              <Json value={c.result} />
            </details>
          ))}
          <details>
            <summary>Riwayat MCP ({selected.events?.length || 0})</summary>
            <ul>
              {selected.events?.map((e) => (
                <li key={e.id}>
                  {e.at} · r{e.revision} · {e.action} · {e.actor}
                  <p>{e.note}</p>
                </li>
              ))}
            </ul>
          </details>
        </article>
      )}
      <details>
        <summary>Katalog adapter terkurasi · protokol dipin</summary>
        <Json value={catalog?.catalog} />
      </details>
      {modal && (
        <Modal
          title={
            {
              config: editing ? 'Edit profil MCP' : 'Profil MCP baru',
              approve: 'Review profil MCP',
              disable: 'Nonaktifkan server MCP',
              job: 'Rencana fixture MCP'
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
                if (modal === 'config') {
                  setSelected(
                    editing && selected
                      ? await request(
                          '/servers/' + selected.id,
                          { expected_revision: selected.revision, config },
                          'PUT'
                        )
                      : await request('/servers', config)
                  )
                }
                if ((modal === 'approve' || modal === 'disable') && selected)
                  setSelected(
                    await request('/servers/' + selected.id + '/decisions', {
                      expected_revision: selected.revision,
                      action: modal === 'approve' ? 'approve' : 'disable',
                      actor_label: actor,
                      note,
                      acknowledge: ack
                    })
                  )
                if (modal === 'job' && selected) {
                  const response: SecurityJob = await (
                    await apiFetch(engagementPath(engagement.project_id, engagement.id) + '/jobs', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({
                        name: jobName,
                        expected_roe_revision: engagement.revision,
                        roe_version: head.version,
                        content_hash: head.content_hash,
                        steps: [
                          {
                            target: { kind, value: target },
                            action: 'configuration_review',
                            ports: [],
                            max_http_rps: 1,
                            max_concurrency: 1,
                            max_duration_minutes: 1,
                            test_account_ref: ''
                          }
                        ],
                        wall_timeout_seconds: wall,
                        max_output_kb: output,
                        mcp: {
                          server_id: selected.id,
                          server_revision: selected.revision,
                          descriptor_hash: selected.descriptor_hash,
                          tool,
                          arguments:
                            tool === 'fixture.inspect' ? { fixture } : { before: fixture, after }
                        }
                      })
                    })
                  ).json()
                  setCreatedJob(response.id)
                }
                setModal(null)
              })
            }}
          >
            {error && (
              <p className="notice error" role="alert">
                {error}
              </p>
            )}
            {modal === 'config' && (
              <>
                <p>
                  Adapter tetap bundled_fixture. Perubahan konfigurasi mencabut approval dan
                  membatalkan semua job aktif yang terikat ke profil ini.
                </p>
                <Field label="Nama profil MCP">
                  <input
                    required
                    maxLength={120}
                    value={config.name}
                    onChange={(e) => setConfig({ ...config, name: e.target.value })}
                  />
                </Field>
                <fieldset>
                  <legend>Izin per tool MCP</legend>
                  {mcpTools.map((t) => (
                    <label className="checkbox-field" key={t}>
                      <input
                        type="checkbox"
                        checked={config.allowed_tools.includes(t)}
                        onChange={() =>
                          setConfig({
                            ...config,
                            allowed_tools: config.allowed_tools.includes(t)
                              ? config.allowed_tools.filter((x) => x !== t)
                              : [...config.allowed_tools, t]
                          })
                        }
                      />
                      {t}
                    </label>
                  ))}
                </fieldset>
                <div className="record-filters">
                  <Field label="Batas waktu profil MCP (detik)">
                    <input
                      required
                      type="number"
                      min={1}
                      max={15}
                      value={config.max_wall_seconds}
                      onChange={(e) =>
                        setConfig({ ...config, max_wall_seconds: Number(e.target.value) })
                      }
                    />
                  </Field>
                  <Field label="Batas output profil MCP (KiB)">
                    <input
                      required
                      type="number"
                      min={1}
                      max={64}
                      value={config.max_output_kb}
                      onChange={(e) =>
                        setConfig({ ...config, max_output_kb: Number(e.target.value) })
                      }
                    />
                  </Field>
                </div>
              </>
            )}
            {(modal === 'approve' || modal === 'disable') && selected && (
              <>
                <p>
                  {modal === 'approve'
                    ? 'Tinjau versi, schema, izin tool, batas, dan isolasi. Approval hanya mengizinkan fixture; setiap job masih memerlukan RoE dan review terpisah.'
                    : 'Server dinonaktifkan dan job aktif terkait dibatalkan. Worker akan menghentikan seluruh proses runner. Pembukaan kembali memerlukan review baru.'}
                </p>
                <Json
                  value={{
                    config: selected.config,
                    descriptor: selected.descriptor,
                    descriptor_hash: selected.descriptor_hash
                  }}
                />
                <Field label="Nama peninjau MCP (deklarasi lokal)">
                  <input
                    required
                    maxLength={120}
                    value={actor}
                    onChange={(e) => setActor(e.target.value)}
                  />
                </Field>
                <Field label="Catatan keputusan MCP">
                  <textarea
                    required
                    maxLength={1000}
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                  />
                </Field>
                <label className="checkbox-field">
                  <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
                  Saya meninjau konfigurasi MCP dan memahami bahwa pentest serta server eksternal
                  tetap dinonaktifkan.
                </label>
              </>
            )}
            {modal === 'job' && selected && (
              <>
                <p>
                  Hanya review konfigurasi fixture. Target harus berada dalam scope RoE, tetapi
                  tidak dikirim ke subprocess dan tidak dihubungi. Job baru berstatus Awaiting
                  Approval; review lanjutan ada di Runs.
                </p>
                <Field label="Nama job MCP">
                  <input
                    required
                    maxLength={120}
                    value={jobName}
                    onChange={(e) => setJobName(e.target.value)}
                  />
                </Field>
                <div className="record-filters">
                  <Field label="Jenis target MCP">
                    <select value={kind} onChange={(e) => setKind(e.target.value as ScopeKind)}>
                      {['ip', 'cidr', 'domain', 'url'].map((k) => (
                        <option key={k}>{k}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Target scope MCP">
                    <input
                      required
                      maxLength={1000}
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                    />
                  </Field>
                </div>
                <Field label="Tool MCP fixture">
                  <select value={tool} onChange={(e) => setTool(e.target.value)}>
                    {selected.config.allowed_tools.map((t) => (
                      <option key={t}>{t}</option>
                    ))}
                  </select>
                </Field>
                <Field label={tool === 'fixture.inspect' ? 'Fixture MCP' : 'Fixture sebelum'}>
                  <select value={fixture} onChange={(e) => setFixture(e.target.value)}>
                    {fixtureNames.map((f) => (
                      <option key={f}>{f}</option>
                    ))}
                  </select>
                </Field>
                {tool === 'fixture.compare' && (
                  <Field label="Fixture sesudah">
                    <select value={after} onChange={(e) => setAfter(e.target.value)}>
                      {fixtureNames.map((f) => (
                        <option key={f}>{f}</option>
                      ))}
                    </select>
                  </Field>
                )}
                <div className="record-filters">
                  <Field label="Batas waktu job MCP (detik)">
                    <input
                      required
                      type="number"
                      min={1}
                      max={selected.config.max_wall_seconds}
                      value={wall}
                      onChange={(e) => setWall(Number(e.target.value))}
                    />
                  </Field>
                  <Field label="Batas output job MCP (KiB)">
                    <input
                      required
                      type="number"
                      min={1}
                      max={selected.config.max_output_kb}
                      value={output}
                      onChange={(e) => setOutput(Number(e.target.value))}
                    />
                  </Field>
                </div>
                <p className="record-hash">
                  Binding: {selected.id} · revisi {selected.revision} · {selected.descriptor_hash}
                </p>
              </>
            )}
            <div className="roe-decision-actions">
              <button
                type="button"
                className="secondary-button"
                disabled={busy}
                onClick={() => setModal(null)}
              >
                Batal
              </button>
              <button
                type="submit"
                className="primary-button"
                disabled={
                  busy ||
                  ((modal === 'approve' || modal === 'disable') && !ack) ||
                  (modal === 'config' && !config.allowed_tools.length)
                }
              >
                {busy
                  ? 'Menyimpan…'
                  : modal === 'config'
                    ? 'Simpan profil Draft'
                    : modal === 'approve'
                      ? 'Setujui profil fixture'
                      : modal === 'disable'
                        ? 'Nonaktifkan dan hentikan job'
                        : 'Simpan rencana MCP tanpa eksekusi'}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </section>
  )
}
