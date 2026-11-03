import { useState, type JSX } from 'react'
import { AlertTriangle, FileCode2, FilePlus2, Gauge, Zap, Clock, Layers } from 'lucide-react'
import type { Proposal } from '../lib/types'
import { blastRadiusLabel, type PlanSimulation } from '../lib/policy'

/** Dry-run blast-radius projection shown before the operator approves a run. */
export function DryRunPanel({ simulation }: { simulation: PlanSimulation }): JSX.Element {
  const score = Math.max(0, Math.min(100, simulation.blast_radius))
  const tierClass = `blast-tier blast-tier-${simulation.risk_tier}`
  return (
    <section className="dry-run-panel" aria-label="Simulasi dry-run sebelum eksekusi">
      <header>
        <Gauge size={14} /> <strong>Simulasi Dry-Run · proyeksi beban</strong>
        <span className={tierClass}>{simulation.risk_label}</span>
      </header>
      <p className="dry-run-note">
        Estimasi sebelum eksekusi; tidak ada request yang dikirim. Lingkungan: {simulation.environment}
        {simulation.job_count > 1 && ` · ${simulation.job_count} job`}.
      </p>
      <div className="dry-run-metrics">
        <div className="dry-run-metric">
          <Zap size={13} />
          <b>{simulation.total_requests}</b>
          <span>estimasi HTTP request</span>
        </div>
        <div className="dry-run-metric">
          <Layers size={13} />
          <b>{simulation.max_concurrency}</b>
          <span>konkurensi maks</span>
        </div>
        <div className="dry-run-metric">
          <Clock size={13} />
          <b>~{simulation.estimated_seconds}s</b>
          <span>perkiraan durasi</span>
        </div>
        <div className="dry-run-metric">
          <Gauge size={13} />
          <b>{score}/100</b>
          <span>blast-radius · {blastRadiusLabel(score)}</span>
        </div>
      </div>
      <div className="blast-meter" role="meter" aria-valuenow={score} aria-valuemin={0} aria-valuemax={100}>
        <div className={`blast-meter-fill ${tierClass}`} style={{ width: `${score}%` }} />
      </div>
      {simulation.jobs.length > 1 && (
        <ul className="dry-run-jobs">
          {simulation.jobs.map((job, index) => (
            <li key={index}>
              <span>{job.tool || job.action}</span>
              <small>
                {job.estimated_requests} req · {job.target_addresses} alamat · blast {job.blast_radius}
                {job.passive && ' · pasif'}
              </small>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function DiffLines({ diff }: { diff: string }): JSX.Element {
  return (
    <pre className="diff-view">
      {diff
        .replace(/\n$/, '')
        .split('\n')
        .map((line, i) => (
          <span
            key={i}
            className={
              line.startsWith('@@')
                ? 'diff-hunk'
                : line.startsWith('+')
                  ? 'diff-add'
                  : line.startsWith('-')
                    ? 'diff-del'
                    : undefined
            }
          >
            {line + '\n'}
          </span>
        ))}
    </pre>
  )
}

function reviewTotals(proposals: Proposal[]): {
  files: number
  added: number
  removed: number
  risky: number
} {
  return proposals.reduce(
    (total, p) => ({
      files: total.files + 1,
      added: total.added + (p.review?.added ?? 0),
      removed: total.removed + (p.review?.removed ?? 0),
      risky: total.risky + (p.review?.risks.length ? 1 : 0)
    }),
    { files: 0, added: 0, removed: 0, risky: 0 }
  )
}

function ProposalCard({
  proposal,
  disabled,
  onDecide
}: {
  proposal: Proposal
  disabled: boolean
  onDecide: (approve: boolean, hunks?: number[]) => void
}): JSX.Element {
  const hunks = proposal.hunks ?? []
  const [selected, setSelected] = useState<Set<number>>(() => new Set(hunks.map((h) => h.index)))
  const review = proposal.review
  const partialAllowed = hunks.length > 1 && !review?.new_file
  const decided = proposal.state
  return (
    <article className="proposal-card" aria-label={`Usulan perubahan ${proposal.path}`}>
      <header>
        {review?.new_file ? <FilePlus2 size={15} /> : <FileCode2 size={15} />}
        <strong>{proposal.path}</strong>
        {review && (
          <span className="proposal-stats">
            <span className="diff-add">+{review.added}</span>{' '}
            <span className="diff-del">−{review.removed}</span> · {review.hunk_count} bagian
          </span>
        )}
      </header>
      {!!review?.risks.length && (
        <ul className="proposal-risks">
          {review.risks.map((risk) => (
            <li key={risk}>
              <AlertTriangle size={12} /> {risk}
            </li>
          ))}
        </ul>
      )}
      {hunks.length ? (
        hunks.map((hunk) => {
          const skipped =
            decided === 'partial' &&
            !!proposal.appliedHunks &&
            !proposal.appliedHunks.includes(hunk.index)
          return (
            <div key={hunk.index} className={skipped ? 'proposal-hunk skipped' : 'proposal-hunk'}>
              {decided === 'partial' && proposal.appliedHunks && (
                <p className="hunk-result">
                  Bagian {hunk.index + 1}: {skipped ? 'dilewati' : 'diterapkan'}
                </p>
              )}
              {partialAllowed && !decided && (
                <label className="hunk-toggle">
                  <input
                    type="checkbox"
                    checked={selected.has(hunk.index)}
                    onChange={(e) =>
                      setSelected((prev) => {
                        const next = new Set(prev)
                        if (e.target.checked) next.add(hunk.index)
                        else next.delete(hunk.index)
                        return next
                      })
                    }
                  />
                  Terapkan bagian {hunk.index + 1} (+{hunk.added} −{hunk.removed})
                </label>
              )}
              <DiffLines diff={hunk.diff} />
            </div>
          )
        })
      ) : (
        <DiffLines diff={proposal.diff} />
      )}
      {proposal.simulation && !decided && <DryRunPanel simulation={proposal.simulation} />}
      {decided ? (
        <p className="proposal-state">
          {decided === 'applied'
            ? 'Perubahan diterapkan.'
            : decided === 'partial'
              ? 'Sebagian perubahan diterapkan; bagian lain dilewati.'
              : 'Usulan ditolak.'}
        </p>
      ) : (
        <div className="proposal-actions">
          <button className="primary-button" disabled={disabled} onClick={() => onDecide(true)}>
            Terapkan semua
          </button>
          {partialAllowed && (
            <button
              className="secondary-button"
              disabled={disabled || selected.size === 0 || selected.size === hunks.length}
              onClick={() =>
                onDecide(
                  true,
                  [...selected].sort((a, b) => a - b)
                )
              }
            >
              Terapkan {selected.size} bagian terpilih
            </button>
          )}
          <button className="secondary-button" disabled={disabled} onClick={() => onDecide(false)}>
            Tolak
          </button>
        </div>
      )}
    </article>
  )
}

/** Per-file review of coding-agent proposals with a summary of what and how risky. */
export function ProposalReview({
  proposals,
  busy,
  onDecide,
  simulation
}: {
  proposals: Proposal[]
  busy: string
  onDecide: (id: string, approve: boolean, hunks?: number[]) => void
  simulation?: PlanSimulation
}): JSX.Element {
  const totals = reviewTotals(proposals)
  return (
    <section className="proposal-review" aria-label="Tinjauan perubahan kode">
      <p className="proposal-summary">
        {totals.files} file terdampak · <span className="diff-add">+{totals.added}</span>{' '}
        <span className="diff-del">−{totals.removed}</span> baris
        {totals.risky > 0 && ` · ${totals.risky} file perlu perhatian khusus`}. Tidak ada yang
        ditulis sebelum Anda menyetujui.
      </p>
      {simulation && <DryRunPanel simulation={simulation} />}
      {proposals.map((proposal) => (
        <ProposalCard
          key={proposal.id}
          proposal={proposal}
          disabled={!!busy}
          onDecide={(approve, hunks) => onDecide(proposal.id, approve, hunks)}
        />
      ))}
    </section>
  )
}
