import { useEffect, useState, type JSX, type ReactNode } from 'react'
import { ShieldCheck, Download } from 'lucide-react'
import { apiFetch } from '../lib/api'
import {
  actionLabels,
  engagementPath,
  parsePorts,
  type Engagement,
  type EngagementContent,
  type ScopeKind
} from '../lib/engagements'
import { downloadFile } from '../lib/preferences'
import {
  policyDecisionLabel,
  scopeFingerprint,
  type PolicyResult,
  type ScopeReport
} from '../lib/policy'

export function ScopeFindings({ report }: { report: ScopeReport }): JSX.Element {
  return (
    <div className="scope-findings">
      <strong>
        {report.valid ? 'Struktur scope memenuhi policy statis' : 'Scope perlu diperbaiki'}
      </strong>
      <small>{report.policy_version} · tanpa akses jaringan</small>
      {report.findings.length ? (
        <ul>
          {report.findings.map((f, index) => (
            <li key={index} className={f.severity === 'error' ? 'policy-fail' : ''}>
              <b>
                {f.severity === 'error' ? 'Blokir' : 'Catatan'} · {f.code}
              </b>
              <span>{f.message}</span>
              <small>{f.location}</small>
            </li>
          ))}
        </ul>
      ) : (
        <p>
          Tidak ada konflik struktural yang ditemukan. Ini belum menyatakan target aman atau
          diizinkan untuk dijalankan.
        </p>
      )}
    </div>
  )
}

export function ScopePreview({
  content,
  portsText
}: {
  content: EngagementContent
  portsText: string
}): JSX.Element {
  const [busy, setBusy] = useState(false)
  const [response, setResponse] = useState<{
    fingerprint: string
    report?: ScopeReport
    error?: string
  } | null>(null)
  const fingerprint = scopeFingerprint({ ...content, ports_text: portsText })
  const visible = response?.fingerprint === fingerprint ? response : null
  return (
    <section className="settings-card">
      <h4>Validasi hubungan scope</h4>
      <p>
        Periksa overlap CIDR/IP, pengecualian, host, dan batas path URL. Domain tidak mencakup
        subdomain secara otomatis.
      </p>
      <button
        type="button"
        className="secondary-button"
        disabled={busy}
        onClick={async () => {
          setBusy(true)
          try {
            const report = await (
              await apiFetch('/api/security/scope-validation', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: { ...content, ports: parsePorts(portsText) } })
              })
            ).json()
            setResponse({ fingerprint, report })
          } catch (e) {
            setResponse({ fingerprint, error: e instanceof Error ? e.message : 'Validasi gagal.' })
          } finally {
            setBusy(false)
          }
        }}
      >
        {busy ? 'Memvalidasi…' : 'Validasi scope draft'}
      </button>
      {visible?.error && (
        <p role="alert" className="policy-fail">
          {visible.error}
        </p>
      )}
      {visible?.report && <ScopeFindings report={visible.report} />}
      {response && !visible && (
        <p role="status">Draft berubah. Jalankan validasi lagi untuk data terbaru.</p>
      )}
    </section>
  )
}

function Field({ name, children }: { name: string; children: ReactNode }): JSX.Element {
  return (
    <label className="field-block">
      {name}
      {children}
    </label>
  )
}

export function PolicyGuard({ engagement }: { engagement: Engagement }): JSX.Element {
  const head = engagement.versions[0]
  const [kind, setKind] = useState<ScopeKind>('ip')
  const [target, setTarget] = useState('')
  const [action, setAction] = useState('tcp_discovery')
  const [ports, setPorts] = useState('')
  const [rps, setRps] = useState(1)
  const [concurrency, setConcurrency] = useState(1)
  const [duration, setDuration] = useState(1)
  const [account, setAccount] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<PolicyResult | null>(null)
  const [resultInput, setResultInput] = useState('')
  const [history, setHistory] = useState<PolicyResult[]>([])
  const [total, setTotal] = useState(0)
  const [historyError, setHistoryError] = useState('')
  const [refresh, setRefresh] = useState(0)
  const path = engagementPath(engagement.project_id, engagement.id) + '/policy-checks'
  const fingerprint = JSON.stringify([
    kind,
    target,
    action,
    ports,
    rps,
    concurrency,
    duration,
    account,
    engagement.revision
  ])
  const visibleResult = resultInput === fingerprint ? result : null
  useEffect(() => {
    const controller = new AbortController()
    void apiFetch(path, { signal: controller.signal })
      .then((r) => r.json())
      .then((data) => {
        setHistory(data.items)
        setTotal(data.total)
        setHistoryError('')
      })
      .catch((e) => {
        if (!controller.signal.aborted) setHistoryError(e.message)
      })
    return () => controller.abort()
  }, [path, refresh])
  return (
    <section className="settings-card policy-guard" aria-label="Policy guard">
      <h4>
        <ShieldCheck size={17} /> Policy guard · evaluasi tanpa eksekusi
      </h4>
      <p>
        Server mengevaluasi snapshot RoE terkini, status persetujuan, jadwal, scope, pengecualian,
        tindakan, port, dan batas rencana. Tidak ada DNS lookup atau request ke target.
      </p>
      <p className="notice">
        Hasil lolos hanya berlaku pada saat evaluasi dan tidak memberikan izin eksekusi. Target nama
        untuk tindakan jaringan tetap ditolak sampai DNS/pinning terpercaya tersedia.
      </p>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          setBusy(true)
          setError('')
          setResult(null)
          try {
            const proposal = {
              expected_revision: engagement.revision,
              roe_version: head.version,
              content_hash: head.content_hash,
              target: { kind, value: target.trim() },
              action,
              ports: parsePorts(ports),
              max_http_rps: rps,
              max_concurrency: concurrency,
              max_duration_minutes: duration,
              test_account_ref: account.trim()
            }
            const data = await (
              await apiFetch(path, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(proposal)
              })
            ).json()
            setResult(data)
            setResultInput(fingerprint)
            setRefresh((v) => v + 1)
          } catch (e) {
            setError(e instanceof Error ? e.message : 'Evaluasi gagal.')
          } finally {
            setBusy(false)
          }
        }}
      >
        <fieldset disabled={busy}>
          <div className="roe-grid">
            <Field name="Jenis target policy">
              <select value={kind} onChange={(e) => setKind(e.target.value as ScopeKind)}>
                {['ip', 'cidr', 'domain', 'url'].map((k) => (
                  <option key={k} value={k}>
                    {k.toUpperCase()}
                  </option>
                ))}
              </select>
            </Field>
            <Field name="Target policy">
              <input
                required
                maxLength={1000}
                value={target}
                placeholder="192.168.10.25"
                onChange={(e) => setTarget(e.target.value)}
              />
            </Field>
            <Field name="Tindakan rencana policy">
              <select value={action} onChange={(e) => setAction(e.target.value)}>
                {Object.entries(actionLabels).map(([key, label]) => (
                  <option key={key} value={key}>
                    {label}
                  </option>
                ))}
              </select>
            </Field>
            <Field name="Port policy">
              <input
                value={ports}
                placeholder="443,8443 — HTTP mengikuti port URL"
                onChange={(e) => setPorts(e.target.value)}
              />
            </Field>
            <Field name="HTTP RPS policy">
              <input
                required
                type="number"
                min={1}
                max={15}
                value={rps}
                onChange={(e) => setRps(Number(e.target.value))}
              />
            </Field>
            <Field name="Concurrency policy">
              <input
                required
                type="number"
                min={1}
                max={4}
                value={concurrency}
                onChange={(e) => setConcurrency(Number(e.target.value))}
              />
            </Field>
            <Field name="Durasi policy (menit)">
              <input
                required
                type="number"
                min={1}
                max={240}
                value={duration}
                onChange={(e) => setDuration(Number(e.target.value))}
              />
            </Field>
            <Field name="Alias akun uji policy">
              <select value={account} onChange={(e) => setAccount(e.target.value)}>
                <option value="">Tanpa alias</option>
                {head.content.test_account_refs.map((ref) => (
                  <option key={ref} value={ref}>
                    {ref}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <button className="primary-button" type="submit" disabled={total >= 500}>
            {busy ? 'Mengevaluasi…' : 'Evaluasi policy tanpa eksekusi'}
          </button>
        </fieldset>
      </form>
      {error && (
        <p className="policy-fail" role="alert">
          {error}
        </p>
      )}
      {result && !visibleResult && (
        <p role="status">
          Input berubah; hasil sebelumnya tidak berlaku untuk input ini. Evaluasi ulang.
        </p>
      )}
      {visibleResult && (
        <div className="policy-result" role="status">
          <h4 className={visibleResult.decision === 'deny' ? 'policy-fail' : 'policy-pass'}>
            {policyDecisionLabel(visibleResult.decision)}
          </h4>
          <p>
            Eksekusi tetap dinonaktifkan ·{' '}
            {new Date(visibleResult.evaluated_at).toLocaleString('id-ID')} · RoE v
            {visibleResult.roe_version} · revisi {visibleResult.revision}
          </p>
          <ul className="policy-checks">
            {visibleResult.checks
              .filter((check) => !check.passed)
              .map((check) => (
                <li key={check.code} className="policy-fail">
                  <b>Ditolak · {check.code}</b>
                  <span>{check.message}</span>
                </li>
              ))}
          </ul>
          <details>
            <summary>
              Pemeriksaan lolos ({visibleResult.checks.filter((check) => check.passed).length})
            </summary>
            <ul className="policy-checks">
              {visibleResult.checks
                .filter((check) => check.passed)
                .map((check) => (
                  <li key={check.code} className="policy-pass">
                    <b>Lolos · {check.code}</b>
                    <span>{check.message}</span>
                  </li>
                ))}
            </ul>
          </details>
          <p className="roe-hash">Snapshot SHA-256: {visibleResult.content_hash}</p>
          <button
            type="button"
            className="secondary-button"
            onClick={() =>
              downloadFile(
                `policy-${visibleResult.id}.json`,
                JSON.stringify(visibleResult, null, 2)
              )
            }
          >
            <Download size={14} /> Ekspor hasil policy
          </button>
        </div>
      )}
      <details className="policy-history">
        <summary>Riwayat evaluasi policy · {total}/500</summary>
        <p>
          20 hasil terbaru. Ini catatan evaluasi saat itu, bukan status izin saat ini. RoE dapat
          berubah atau kedaluwarsa.
        </p>
        <button
          type="button"
          className="secondary-button"
          disabled={busy || !total}
          onClick={async () => {
            setBusy(true)
            setError('')
            try {
              const all = await (await apiFetch(path + '?all_records=true')).json()
              downloadFile(`policy-history-${engagement.id}.json`, JSON.stringify(all, null, 2))
            } catch (e) {
              setError(e instanceof Error ? e.message : 'Ekspor gagal.')
            } finally {
              setBusy(false)
            }
          }}
        >
          Ekspor seluruh riwayat policy
        </button>
        {historyError && <p role="alert">{historyError}</p>}
        {history.map((item) => (
          <article key={item.id}>
            <strong>
              {policyDecisionLabel(item.decision)} · RoE v{item.roe_version}
            </strong>
            <small>
              {new Date(item.evaluated_at).toLocaleString('id-ID')} · {item.proposal.target.value}
            </small>
            <p>
              {item.checks
                .filter((c) => !c.passed)
                .map((c) => c.code)
                .join(', ') || 'Semua pemeriksaan statis lolos; eksekusi tetap terkunci.'}
            </p>
            <button
              className="secondary-button"
              type="button"
              onClick={() => downloadFile(`policy-${item.id}.json`, JSON.stringify(item, null, 2))}
            >
              Ekspor catatan ini
            </button>
          </article>
        ))}
      </details>
    </section>
  )
}
