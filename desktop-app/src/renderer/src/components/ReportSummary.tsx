import type { JSX } from 'react'
import type { ReportFindingView, ReportView } from '../lib/securityEvidence'

function formatWhen(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'short' })
}

function FindingRow({ f }: { f: ReportFindingView }): JSX.Element {
  return (
    <li className="report-finding">
      <div className="report-finding-head">
        <strong>{f.title}</strong>
        <span className="source-chip">{f.severity_label}</span>
        <span
          className={`source-chip confidence-${f.confidence.toLowerCase().replace(/\s+/g, '-')}`}
        >
          Keyakinan {f.confidence}
        </span>
      </div>
      <small>
        {f.status_label} · target {f.target}
      </small>
      <small>{f.confidence_reason}</small>
      {f.review && (
        <small>
          Review {f.review.actor}: {f.review.assessment}
        </small>
      )}
    </li>
  )
}

/** Owner-facing summary of a report snapshot: what is open, how sure, what changed, what next. */
export function ReportSummary({ view }: { view: ReportView }): JSX.Element {
  const { owner_summary: owner, comparison } = view
  return (
    <section className="report-summary" aria-label="Ringkasan laporan untuk pemilik sistem">
      <h4>Ringkasan untuk pemilik sistem</h4>
      <p className="report-headline">{owner.headline}</p>
      <p className="muted-text">
        {Object.entries(owner.open_by_severity)
          .map(([label, count]) => `${label} ${count}`)
          .join(' · ')}
        {Object.keys(owner.open_by_severity).length ? ' · ' : ''}
        Diperbaiki {owner.fixed} · Belum direview {owner.unreviewed} · Bukan masalah{' '}
        {owner.dismissed}
      </p>
      {comparison && (
        <>
          <h4>Dibandingkan laporan sebelumnya</h4>
          <p className="muted-text">
            {comparison.previous_title} · {formatWhen(comparison.previous_created_at)}
          </p>
          <ul className="report-changes">
            {comparison.changed.map((c) => (
              <li key={c.title} className={c.resolved ? 'resolved' : undefined}>
                {c.resolved ? 'Diperbaiki' : 'Berubah'}: {c.title} ({c.from} → {c.to})
              </li>
            ))}
            {comparison.new.map((t) => (
              <li key={'new-' + t}>Baru: {t}</li>
            ))}
            {comparison.still_open.map((t) => (
              <li key={'open-' + t}>Masih terbuka: {t}</li>
            ))}
            {comparison.removed.map((t) => (
              <li key={'gone-' + t}>Tidak lagi tercatat: {t}</li>
            ))}
            <li>Evidence baru: {comparison.evidence_added}</li>
          </ul>
        </>
      )}
      <h4>Temuan yang telah direview ({view.reviewed.length})</h4>
      {view.reviewed.length ? (
        <ul className="report-findings">
          {view.reviewed.map((f) => (
            <FindingRow key={f.id} f={f} />
          ))}
        </ul>
      ) : (
        <p className="muted-text">Belum ada temuan yang direview analis.</p>
      )}
      {!!view.unreviewed.length && (
        <>
          <h4>Kandidat belum direview ({view.unreviewed.length})</h4>
          <ul className="report-findings">
            {view.unreviewed.map((f) => (
              <FindingRow key={f.id} f={f} />
            ))}
          </ul>
        </>
      )}
      <h4>Tindak lanjut</h4>
      {view.follow_ups.length ? (
        <ol className="report-follow-ups">
          {view.follow_ups.map((item) => (
            <li key={item.title}>
              <strong>{item.title}</strong>: {item.action}
            </li>
          ))}
        </ol>
      ) : (
        <p className="muted-text">Tidak ada tindak lanjut.</p>
      )}
    </section>
  )
}
