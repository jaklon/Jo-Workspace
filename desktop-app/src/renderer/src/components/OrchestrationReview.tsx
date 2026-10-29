import type { JSX } from 'react'
import type { Orchestration } from '../lib/orchestration'

export function OrchestrationReview({
  reviewer
}: {
  reviewer: Orchestration['reviewer']
}): JSX.Element {
  if (!reviewer) return <p>Reviewer menunggu seluruh job selesai dan evidence tersimpan.</p>
  return (
    <>
      <p className="notice">
        Interpretasi AI belum diverifikasi. Perlu tinjauan manusia · candidate_only. AI tidak
        mengubah status finding atau severity.
      </p>
      <pre className="record-output">{reviewer.summary}</pre>
      <h4>Ketidakpastian</h4>
      <ul>
        {reviewer.uncertainties.map((u, i) => (
          <li key={i}>{u}</li>
        ))}
      </ul>
      <h4>Evidence yang dirujuk</h4>
      <ul>
        {reviewer.evidence_ids.map((e) => (
          <li key={e}>{e}</li>
        ))}
      </ul>
    </>
  )
}
