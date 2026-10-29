import { useEffect, useState, type JSX } from 'react'
import { apiFetch } from '../lib/api'
import { downloadFile } from '../lib/preferences'
import { engagementPath, type Engagement, type ScopeKind } from '../lib/engagements'
import {
  defaultAgent,
  agentLabels,
  type AgentBudget,
  type SpecialistCatalog,
  type SpecialistListing,
  type SpecialistTeam
} from '../lib/agents'
import { Modal } from './Modal'
import { SpecialistResults } from './SpecialistResults'

export function SecurityAgents({
  engagement,
  onRuns
}: {
  engagement: Engagement
  onRuns: () => void
}): JSX.Element {
  const path = engagementPath(engagement.project_id, engagement.id)
  const version = engagement.versions[0]
  const binding = {
    expected_roe_revision: engagement.revision,
    roe_version: version.version,
    content_hash: version.content_hash
  }
  const [listing, setListing] = useState<SpecialistListing | null>(null)
  const [catalog, setCatalog] = useState<SpecialistCatalog | null>(null)
  const [selected, setSelected] = useState('')
  const [detail, setDetail] = useState<SpecialistTeam | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [modal, setModal] = useState<'lab' | 'team' | 'approve' | 'resume' | 'disable' | null>(null)
  const [ack, setAck] = useState(false)
  const [actor, setActor] = useState('')
  const [note, setNote] = useState('')
  const [name, setName] = useState('')
  const [objective, setObjective] = useState('')
  const [model, setModel] = useState('')
  const [labId, setLabId] = useState('')
  const [kind, setKind] = useState<ScopeKind>('ip')
  const [target, setTarget] = useState('')
  const [accounts, setAccounts] = useState<string[]>([])
  const [agents, setAgents] = useState<AgentBudget[]>([])
  const [calls, setCalls] = useState(5)
  const [tokens, setTokens] = useState(60000)
  const [seconds, setSeconds] = useState(600)
  const [terms, setTerms] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    const poll = async (): Promise<void> => {
      try {
        const data: SpecialistListing = await (
          await apiFetch(path + '/agents', { signal: controller.signal })
        ).json()
        if (controller.signal.aborted) return
        setListing(data)
        const next = data.items.some((x) => x.id === selected) ? selected : data.items[0]?.id || ''
        setSelected(next)
        if (next) {
          const value: SpecialistTeam = await (
            await apiFetch(path + '/agents/' + next, { signal: controller.signal })
          ).json()
          if (!controller.signal.aborted)
            setDetail({
              ...value,
              repeatability: data.items.find((x) => x.id === next)?.repeatability
            })
        }
      } catch (e) {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : 'Data agent tidak tersedia.')
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
    void apiFetch('/api/security/agents/catalog', { signal: controller.signal })
      .then((r) => r.json())
      .then((data: SpecialistCatalog) => {
        if (!controller.signal.aborted) setCatalog(data)
      })
      .catch((e) => {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : 'Katalog tidak tersedia.')
      })
    return () => controller.abort()
  }, [refresh])
  const operate = async (fn: () => Promise<void>): Promise<void> => {
    setBusy(true)
    setError('')
    try {
      await fn()
      setModal(null)
      setRefresh((x) => x + 1)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Operasi ditolak.')
    } finally {
      setBusy(false)
    }
  }
  const post = async (suffix: string, body: unknown): Promise<unknown> =>
    (
      await apiFetch(path + suffix, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      })
    ).json()
  const open = (value: typeof modal): void => {
    setModal(value)
    setAck(false)
    setActor('')
    setNote('')
    setError('')
  }
  const decision = (action: string): Promise<unknown> =>
    detail
      ? post(`/agents/${detail.id}/${action}`, {
          expected_revision: detail.revision,
          actor_label: action === 'pause' ? 'operator-lokal' : actor,
          note:
            action === 'pause' ? 'Stop seluruh agent dan job; simpan checkpoint/evidence.' : note,
          acknowledge: action === 'pause' || ack
        })
      : Promise.resolve()
  const updateAgent = (
    index: number,
    field: keyof Omit<AgentBudget, 'role' | 'permissions'>,
    value: number
  ): void => setAgents((v) => v.map((a, i) => (i === index ? { ...a, [field]: value } : a)))
  const totals = agents.reduce(
    (v, a) => ({
      calls: v.calls + a.max_calls,
      tokens: v.tokens + a.max_tokens,
      seconds: v.seconds + a.active_seconds
    }),
    { calls: 0, tokens: 0, seconds: 0 }
  )
  return (
    <section className="security-records" aria-label="Agent spesialis">
      <div className="section-title">
        <h3>Agents · multi-agent spesialis</h3>
        <span className="planning-badge">Tahap 7 · pentest terkunci</span>
      </div>
      <p className="notice">
        Recon, Web/API, Auth/BOLA, LLM Security dan Reporting berbagi satu model lokal secara
        bergantian. Maksimal satu agent aktif; konteks, izin dan anggarannya terpisah. Gratis, tanpa
        download model atau layanan cloud.
      </p>
      <p className="muted-text">
        Daftarkan lab sintetis → review rencana tim → approval setiap job di Runs → observasi
        fixture → interpretasi AI. Target hanya label scope; tidak dihubungi. Auth memakai dua alias
        RoE dengan sesi memori terpisah. LLM Security memakai toy target lab dengan indikator
        canary, bukan serangan ke layanan nyata.
      </p>
      {error && (
        <p role="alert" className="error-banner">
          {error}
        </p>
      )}
      <div className="roe-decision-actions">
        <button
          className="secondary-button"
          disabled={busy}
          onClick={() => {
            setName('')
            setTarget('')
            setAccounts([])
            open('lab')
          }}
        >
          Daftarkan lab
        </button>
        <button
          className="primary-button"
          disabled={busy || !catalog?.models.length || !listing?.labs.some((l) => !l.disabled)}
          onClick={() => {
            setName('')
            setObjective('')
            setTerms('')
            setModel(
              catalog?.models.find((m) => m.name === 'qwen2.5:3b-instruct')?.name ||
                catalog?.models[0]?.name ||
                ''
            )
            setLabId(listing?.labs.find((l) => !l.disabled)?.id || '')
            setAgents(catalog?.profiles.map(defaultAgent) || [])
            setCalls(5)
            setTokens(60000)
            setSeconds(600)
            open('team')
          }}
        >
          Buat tim spesialis
        </button>
        <button className="secondary-button" onClick={onRuns}>
          Buka Runs & approval job
        </button>
        <button className="secondary-button" onClick={() => setRefresh((v) => v + 1)}>
          Muat ulang
        </button>
      </div>
      <p>Worker: {listing?.worker_active ? 'aktif' : 'belum tersedia'} · concurrency global: 1</p>
      <details>
        <summary>Lab terdaftar ({listing?.labs.length || 0})</summary>
        {listing?.labs.map((l) => (
          <p key={l.id}>
            {l.name} · {l.target.value} · {l.disabled ? 'Dinonaktifkan' : 'Aktif'} · alias:{' '}
            {l.account_aliases.join(', ') || 'Tidak ada'}
            {l.events?.map((event, index) => (
              <small key={index}>
                {' '}
                · {event.action} {event.at} ({event.actor}: {event.note})
              </small>
            ))}
            {!l.disabled && (
              <button
                className="secondary-button"
                disabled={busy}
                onClick={() => {
                  setLabId(l.id)
                  open('disable')
                }}
              >
                Nonaktifkan lab
              </button>
            )}
          </p>
        ))}
      </details>
      <div className="roe-decision-actions">
        {listing?.items.map((t) => (
          <button
            className={selected === t.id ? 'primary-button' : 'secondary-button'}
            key={t.id}
            onClick={() => setSelected(t.id)}
          >
            {t.request.name} · {agentLabels[t.status] || t.status}
          </button>
        ))}
      </div>
      {!!listing?.items.length && (
        <details>
          <summary>Bandingkan cakupan dan konsumsi antar tim</summary>
          <table>
            <thead>
              <tr>
                <th>Tim</th>
                <th>Spesialis</th>
                <th>Kasus</th>
                <th>False positive</th>
                <th>Token terukur</th>
              </tr>
            </thead>
            <tbody>
              {listing.items.map((t) => (
                <tr key={t.id}>
                  <td>{t.request.name}</td>
                  <td>{t.agents.map((a) => a.profile.title).join(', ')}</td>
                  <td>{t.metrics.case_count}/8</td>
                  <td>{t.metrics.false_positives}</td>
                  <td>{t.metrics.measured_input_tokens + t.metrics.measured_output_tokens}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
      {!detail && (
        <p className="muted-text">
          Belum ada tim. Buat Engagement lab dengan RoE disetujui dan tindakan sesuai profil agent.
        </p>
      )}
      {detail && (
        <>
          <h3>
            {detail.request.name} · {agentLabels[detail.status] || detail.status}
          </h3>
          <p>{detail.request.objective}</p>
          <p>
            Model: {detail.request.model} · lab: {detail.request.lab.name} · checkpoint{' '}
            {detail.revision}
          </p>
          {detail.error && <p className="error-banner">{detail.error}</p>}
          <div className="roe-decision-actions">
            {detail.status === 'awaiting_approval' && (
              <button
                className="primary-button"
                disabled={busy || !listing?.worker_active}
                onClick={() => open('approve')}
              >
                Review & setujui rencana tim
              </button>
            )}
            {detail.status === 'paused' && (
              <button
                className="primary-button"
                disabled={busy || !listing?.worker_active}
                onClick={() => open('resume')}
              >
                Review & lanjutkan
              </button>
            )}
            {!['paused', 'completed'].includes(detail.status) && (
              <button
                className="danger-button"
                disabled={busy}
                onClick={() =>
                  void operate(async () => {
                    await decision('pause')
                  })
                }
              >
                Stop semua agent
              </button>
            )}
            <button
              className="secondary-button"
              onClick={() =>
                downloadFile(
                  `agents-${detail.id}.json`,
                  JSON.stringify(detail, null, 2),
                  'application/json'
                )
              }
            >
              Ekspor checkpoint & hasil
            </button>
          </div>
          <SpecialistResults team={detail} />
          <p>
            Keterulangan pada model, lab, RoE, tujuan, profil dan anggaran sama:{' '}
            {detail.repeatability?.identical_classifications || 0}/
            {detail.repeatability?.comparable_runs || 0} run pembanding mempunyai klasifikasi
            identik. Belum ada pembanding berarti belum terukur.
          </p>
          <details>
            <summary>Audit checkpoint ({detail.checkpoints?.length || 0})</summary>
            {detail.checkpoints?.map((c) => (
              <p key={c.revision}>
                #{c.revision} {c.at} · {c.action} · {c.actor} · {c.note}
                <br />
                <code>{c.hash}</code>
              </p>
            ))}
          </details>
        </>
      )}
      {catalog && (
        <details>
          <summary>Katalog izin dan konteks spesialis</summary>
          {catalog.profiles.map((p) => (
            <p key={p.id}>
              <strong>{p.title}</strong> · {p.permission} · RoE: {p.action}
              <br />
              {p.context}
              <br />
              <code>{p.hash}</code>
            </p>
          ))}
          <p>
            Lab v{catalog.lab.version} · {catalog.lab.hash}
          </p>
        </details>
      )}
      {modal && (
        <Modal
          title={
            {
              lab: 'Daftarkan lab sintetis',
              team: 'Konfigurasi tim spesialis',
              approve: 'Review rencana tim',
              resume: 'Resume dari checkpoint',
              disable: 'Nonaktifkan lab'
            }[modal]
          }
          onClose={() => !busy && setModal(null)}
          wide
        >
          <form
            className="record-form specialist-form"
            onSubmit={(e) => {
              e.preventDefault()
              void operate(async () => {
                if (modal === 'lab')
                  await post('/agent-labs', {
                    ...binding,
                    name,
                    target: { kind, value: target },
                    account_aliases: accounts,
                    acknowledge: ack
                  })
                else if (modal === 'team') {
                  const data = (await post('/agents', {
                    ...binding,
                    name,
                    objective,
                    model,
                    lab_id: labId,
                    agents,
                    max_calls: calls,
                    max_tokens: tokens,
                    active_seconds: seconds,
                    max_parallel: 1,
                    acknowledge: ack,
                    redaction_terms: terms
                      .split('\n')
                      .map((t) => t.trim())
                      .filter(Boolean)
                  })) as SpecialistTeam
                  setSelected(data.id)
                } else if (modal === 'disable')
                  await post(`/agent-labs/${labId}/disable`, {
                    expected_revision: 1,
                    actor_label: actor,
                    note,
                    acknowledge: ack
                  })
                else await decision(modal)
              })
            }}
          >
            {error && (
              <p role="alert" className="error-banner">
                {error}
              </p>
            )}
            {(modal === 'lab' || modal === 'team') && (
              <label className="field-block">
                Nama
                <input
                  required
                  maxLength={120}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </label>
            )}
            {modal === 'lab' && (
              <>
                <p>
                  Hanya bundled-security-lab-v1, tidak menerima URL koneksi/credential. Engagement
                  harus berjenis Lab sintetis.
                </p>
                <label className="field-block">
                  Jenis label target
                  <select value={kind} onChange={(e) => setKind(e.target.value as ScopeKind)}>
                    {['ip', 'domain', 'url'].map((k) => (
                      <option key={k}>{k}</option>
                    ))}
                  </select>
                </label>
                <label className="field-block">
                  Target dalam scope
                  <input
                    required
                    value={target}
                    maxLength={1000}
                    onChange={(e) => setTarget(e.target.value)}
                  />
                </label>
                <p>Pilih dua alias akun sintetis di RoE untuk Auth/BOLA:</p>
                {version.content.test_account_refs.map((a) => (
                  <label className="field-block" key={a}>
                    <input
                      type="checkbox"
                      checked={accounts.includes(a)}
                      disabled={!accounts.includes(a) && accounts.length >= 2}
                      onChange={(e) =>
                        setAccounts((v) =>
                          e.target.checked ? [...v, a] : v.filter((x) => x !== a)
                        )
                      }
                    />
                    {a}
                  </label>
                ))}
              </>
            )}
            {modal === 'team' && (
              <>
                <label className="field-block">
                  Tujuan
                  <textarea
                    required
                    value={objective}
                    maxLength={600}
                    onChange={(e) => setObjective(e.target.value)}
                  />
                </label>
                <label className="field-block">
                  Model Ollama lokal
                  <select required value={model} onChange={(e) => setModel(e.target.value)}>
                    {catalog?.models.map((m) => (
                      <option key={m.name}>{m.name}</option>
                    ))}
                  </select>
                </label>
                <label className="field-block">
                  Lab terdaftar
                  <select required value={labId} onChange={(e) => setLabId(e.target.value)}>
                    {listing?.labs
                      .filter((l) => !l.disabled)
                      .map((l) => (
                        <option key={l.id} value={l.id}>
                          {l.name} · {l.target.value}
                        </option>
                      ))}
                  </select>
                </label>
                <div className="form-grid">
                  <label className="field-block">
                    Batas panggilan tim
                    <input
                      type="number"
                      required
                      min={1}
                      max={15}
                      value={calls}
                      onChange={(e) => setCalls(+e.target.value)}
                    />
                  </label>
                  <label className="field-block">
                    Token tim
                    <input
                      type="number"
                      required
                      min={4000}
                      max={120000}
                      value={tokens}
                      onChange={(e) => setTokens(+e.target.value)}
                    />
                  </label>
                  <label className="field-block">
                    Waktu aktif tim (detik)
                    <input
                      type="number"
                      required
                      min={30}
                      max={900}
                      value={seconds}
                      onChange={(e) => setSeconds(+e.target.value)}
                    />
                  </label>
                </div>
                {catalog?.profiles.map((p) => (
                  <label className="field-block" key={p.id}>
                    <input
                      type="checkbox"
                      checked={agents.some((a) => a.role === p.id)}
                      onChange={(e) =>
                        setAgents((v) =>
                          e.target.checked
                            ? [...v, defaultAgent(p)]
                            : v.filter((a) => a.role !== p.id)
                        )
                      }
                    />
                    {p.title} · {p.permission} · {p.action}
                  </label>
                ))}
                {agents.map((a, i) => (
                  <fieldset key={a.role}>
                    <legend>
                      {catalog?.profiles.find((p) => p.id === a.role)?.title} · {a.permissions[0]}
                    </legend>
                    <div className="form-grid">
                      {(
                        [
                          ['max_calls', 'Panggilan', 1, 3],
                          ['max_tokens', 'Token', 4000, 24000],
                          ['context_tokens', 'Konteks token', 3000, 12000],
                          ['output_tokens', 'Output token', 128, 768],
                          ['active_seconds', 'Waktu aktif detik', 30, 180]
                        ] as const
                      ).map(([key, label, min, max]) => (
                        <label className="field-block" key={key}>
                          {label}
                          <input
                            required
                            type="number"
                            min={min}
                            max={max}
                            value={a[key]}
                            onChange={(e) => updateAgent(i, key, +e.target.value)}
                          />
                        </label>
                      ))}
                    </div>
                  </fieldset>
                ))}
                <p>
                  Alokasi: {totals.calls}/{calls} panggilan · {totals.tokens}/{tokens} token ·{' '}
                  {totals.seconds}/{seconds} detik. Maksimum global dan RoE tetap berlaku.
                </p>
                <label className="field-block">
                  Istilah sensor tambahan (satu per baris)
                  <textarea value={terms} onChange={(e) => setTerms(e.target.value)} />
                </label>
              </>
            )}
            {(modal === 'approve' || modal === 'resume') && detail && (
              <>
                <p>
                  Model {detail.request.model} · lab {detail.request.lab.name} · target{' '}
                  {detail.request.lab.target.value}. Budget tidak direset saat resume; agent selesai
                  tidak diulang. Setiap job baru memerlukan persetujuan terpisah di Runs.
                </p>
                {detail.agents.map((a) => (
                  <p key={a.role}>
                    {a.profile.title}: {a.permissions.join(', ')} · {a.max_calls} panggilan /{' '}
                    {a.max_tokens} token / {a.active_seconds_limit} detik · target{' '}
                    {detail.request.plans[a.role]?.steps[0]?.target.value} · port{' '}
                    {detail.request.plans[a.role]?.steps[0]?.ports.join(', ') ||
                      'mengikuti URL / tidak berlaku'}
                  </p>
                ))}
              </>
            )}
            {['approve', 'resume', 'disable'].includes(modal) && (
              <>
                <label className="field-block">
                  Nama peninjau lokal
                  <input
                    required
                    maxLength={120}
                    value={actor}
                    onChange={(e) => setActor(e.target.value)}
                  />
                </label>
                <label className="field-block">
                  Catatan review
                  <textarea
                    required
                    maxLength={1000}
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                  />
                </label>
              </>
            )}
            <label className="field-block">
              <input
                required
                type="checkbox"
                checked={ack}
                onChange={(e) => setAck(e.target.checked)}
              />
              Saya meninjau scope, izin dan budget. Hanya fixture sintetis; tidak mengaktifkan
              pentest atau mengesahkan finding.
            </label>
            <button
              className="primary-button"
              disabled={
                busy ||
                (modal === 'team' &&
                  (!agents.length ||
                    totals.calls > calls ||
                    totals.tokens > tokens ||
                    totals.seconds > seconds))
              }
            >
              {busy ? 'Menyimpan…' : 'Simpan keputusan'}
            </button>
          </form>
        </Modal>
      )}
    </section>
  )
}
