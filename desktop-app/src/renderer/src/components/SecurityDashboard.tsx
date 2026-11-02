import { useEffect, useState, type JSX } from 'react'
import { apiFetch } from '../lib/api'
import { downloadFile } from '../lib/preferences'
import type { Project } from '../lib/types'
import type { Engagement } from '../lib/engagements'
import type { SecurityJob } from '../lib/securityJobs'

type RecordItem = Record<string, unknown> & { id: string }
type Records = { evidence: RecordItem[]; findings: RecordItem[]; reports: RecordItem[] }

function analysisMarkdown(item: RecordItem): string {
  const content = JSON.stringify(item.output || {}, null, 2)
  const longest = Math.max(2, ...Array.from(content.matchAll(/~+/g), (match) => match[0].length))
  const fence = '~'.repeat(longest + 1)
  return `# Deep Analysis\n\nID: ${item.id}\n\n${fence}json\n${content}\n${fence}\n`
}

export function SecurityDashboard({
  projects,
  projectId,
  onProject,
  engagementId = ''
}: {
  projects: Project[]
  projectId: string
  onProject: (id: string) => void
  engagementId?: string
}): JSX.Element {
  const [engagements, setEngagements] = useState<Engagement[]>([])
  const [loadedProject, setLoadedProject] = useState('')
  const [loadedBase, setLoadedBase] = useState('')
  const [selected, setSelected] = useState('')
  const [engagement, setEngagement] = useState<Engagement | null>(null)
  const [jobs, setJobs] = useState<SecurityJob[]>([])
  const [records, setRecords] = useState<Records>({ evidence: [], findings: [], reports: [] })
  const [analyses, setAnalyses] = useState<RecordItem[]>([])
  const [specialists, setSpecialists] = useState<RecordItem[]>([])
  const [detail, setDetail] = useState<unknown>(null)
  const [tab, setTab] = useState<'jobs' | 'evidence' | 'reports'>('jobs')
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)
  useEffect(() => {
    const refresh = (): void => setRevision((value) => value + 1)
    const resumed = (): void => {
      if (document.visibilityState === 'visible') refresh()
    }
    window.addEventListener('online', refresh)
    document.addEventListener('visibilitychange', resumed)
    return () => {
      window.removeEventListener('online', refresh)
      document.removeEventListener('visibilitychange', resumed)
    }
  }, [])
  const project = projects.some((p) => p.id === projectId) ? projectId : ''
  const base =
    project && project === loadedProject && selected
      ? `/api/security/projects/${encodeURIComponent(project)}/engagements/${encodeURIComponent(selected)}`
      : ''

  useEffect(() => {
    let live = true
    if (project)
      void apiFetch(`/api/security/projects/${encodeURIComponent(project)}/engagements`)
        .then((r) => r.json())
        .then((data) => {
          if (live) {
            setEngagements(data.items)
            setLoadedProject(project)
            setSelected((previous) =>
              engagementId && data.items.some((item: Engagement) => item.id === engagementId)
                ? engagementId
                : data.items.some((item: Engagement) => item.id === previous)
                  ? previous
                  : data.items[0]?.id || ''
            )
          }
        })
        .catch((e) => {
          if (live) setError(e.message)
        })
    return () => {
      live = false
    }
  }, [project, revision, engagementId])

  useEffect(() => {
    let live = true
    if (base)
      void Promise.all(
        [
          base,
          `${base}/jobs`,
          `${base}/records`,
          `${base}/deep-analysis`,
          `${base}/evidence-specialists`
        ].map(async (path) => (await apiFetch(path)).json())
      )
        .then(([eng, jobData, recordData, analysisData, specialistData]) => {
          if (live) {
            setDetail(null)
            setEngagement(eng)
            setJobs(jobData.items)
            setRecords(recordData)
            setAnalyses(analysisData.items)
            setSpecialists(specialistData.items)
            setLoadedBase(base)
            setError('')
          }
        })
        .catch((e) => {
          if (live) setError(e.message)
        })
    return () => {
      live = false
    }
  }, [base, revision])

  const show = async (path: string): Promise<void> => {
    try {
      setDetail(await (await apiFetch(path)).json())
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Gagal membaca catatan.')
    }
  }
  const stop = async (job: SecurityJob): Promise<void> => {
    try {
      await apiFetch(`${base}/jobs/${job.id}/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      })
      setRevision((n) => n + 1)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Gagal menghentikan job.')
    }
  }
  return (
    <div className="usage-scroll scrollbar-thin p-6 space-y-4">
      <h2>Security Workspace · Riwayat dan audit</h2>
      <div className="flex flex-wrap gap-3">
        <label>
          Project{' '}
          <select
            value={project}
            onChange={(e) => onProject(e.target.value)}
            className="bg-slate-900 p-2"
          >
            <option value="">Pilih project</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Engagement{' '}
          <select
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
            className="bg-slate-900 p-2"
          >
            <option value="">Pilih engagement</option>
            {engagements.map((e) => (
              <option key={e.id} value={e.id}>
                {e.versions[0]?.content.name || e.id}
              </option>
            ))}
          </select>
        </label>
        <button className="secondary-button" onClick={() => setRevision((n) => n + 1)}>
          Muat ulang
        </button>
      </div>
      {error && (
        <p role="alert" className="text-rose-300">
          {error}
        </p>
      )}
      <nav className="flex flex-wrap gap-2" aria-label="Bagian riwayat security">
        {(
          [
            ['jobs', 'Riwayat Job'],
            ['evidence', 'Evidence & Findings'],
            ['reports', 'Laporan & Audit RoE']
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            className="secondary-button"
            aria-pressed={tab === key}
            onClick={() => {
              setTab(key)
              setDetail(null)
            }}
          >
            {label}
          </button>
        ))}
      </nav>
      {base &&
        base === loadedBase &&
        tab === 'jobs' &&
        jobs.map((job) => (
          <section key={job.id} className="settings-card">
            <strong>
              {job.plan.name} · {job.status}
            </strong>
            <p>
              {job.id} · {job.created_at}
            </p>
            <button
              className="secondary-button"
              onClick={() => void show(`${base}/jobs/${job.id}`)}
            >
              Lihat log
            </button>{' '}
            {['queued', 'running', 'awaiting_approval'].includes(job.status) && (
              <button className="danger-button" onClick={() => void stop(job)}>
                Stop Run
              </button>
            )}
          </section>
        ))}
      {base && base === loadedBase && tab === 'evidence' && (
        <>
          {records.evidence.map((item) => (
            <section key={item.id} className="settings-card">
              <strong>Evidence · {String(item.title || item.id)}</strong>
              <p>{item.id}</p>
              <button
                className="secondary-button"
                onClick={() => void show(`${base}/evidence/${item.id}`)}
              >
                Lihat bukti tersensor
              </button>
            </section>
          ))}
          {records.findings.map((item) => (
            <section key={item.id} className="settings-card">
              <strong>Finding · {item.id}</strong>
              <button
                className="secondary-button"
                onClick={() => void show(`${base}/findings/${item.id}`)}
              >
                Lihat temuan
              </button>
            </section>
          ))}
        </>
      )}
      {base && base === loadedBase && tab === 'reports' && (
        <>
          {engagement && (
            <section className="settings-card">
              <strong>Audit RoE</strong>
              <button className="secondary-button" onClick={() => setDetail(engagement)}>
                Lihat snapshot dan riwayat
              </button>
            </section>
          )}
          {analyses.map((item) => (
            <section key={item.id} className="settings-card">
              <strong>Deep Analysis · {item.id}</strong>
              <div className="flex gap-2">
                <button className="secondary-button" onClick={() => setDetail(item)}>
                  Lihat
                </button>
                <button
                  className="secondary-button"
                  onClick={() =>
                    downloadFile(`analysis-${item.id}.json`, JSON.stringify(item, null, 2))
                  }
                >
                  Unduh JSON
                </button>
                <button
                  className="secondary-button"
                  onClick={() =>
                    downloadFile(`analysis-${item.id}.md`, analysisMarkdown(item), 'text/markdown')
                  }
                >
                  Unduh Markdown
                </button>
              </div>
            </section>
          ))}
          {specialists.map((item) => (
            <section key={item.id} className="settings-card">
              <strong>Spesialis {String(item.role)} · review evidence</strong>
              <div className="flex gap-2">
                <button className="secondary-button" onClick={() => setDetail(item)}>
                  Lihat
                </button>
                <button
                  className="secondary-button"
                  onClick={() =>
                    downloadFile(`specialist-${item.id}.json`, JSON.stringify(item, null, 2))
                  }
                >
                  Unduh JSON
                </button>
              </div>
            </section>
          ))}
          {records.reports.map((item) => (
            <section key={item.id} className="settings-card">
              <strong>Laporan · {String(item.title || item.id)}</strong>
              <button
                className="secondary-button"
                onClick={() => void show(`${base}/reports/${item.id}`)}
              >
                Lihat laporan
              </button>
            </section>
          ))}
        </>
      )}
      {base && base === loadedBase && detail !== null && (
        <section className="settings-card">
          <div className="flex gap-2">
            <strong>Detail</strong>
            <button
              className="secondary-button"
              onClick={() => downloadFile('security-detail.json', JSON.stringify(detail, null, 2))}
            >
              Unduh JSON
            </button>
          </div>
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap text-xs">
            {JSON.stringify(detail, null, 2)}
          </pre>
        </section>
      )}
    </div>
  )
}
