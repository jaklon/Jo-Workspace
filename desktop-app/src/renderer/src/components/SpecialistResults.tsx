import type { JSX } from 'react'
import { agentLabels, type SpecialistTeam } from '../lib/agents'

export function SpecialistResults({ team }: { team: SpecialistTeam }): JSX.Element {
  const m = team.metrics
  return (
    <div>
      <p className="notice">
        Benchmark lab sintetis, bukan hasil pentest target. Interpretasi AI belum diverifikasi.
        Finding tetap candidate_only; status dan severity hanya melalui tinjauan manusia.
      </p>
      <div className="record-grid">
        <p>
          Cakupan:{' '}
          <strong>
            {m.case_count}/8 kasus ({m.coverage_percent}%)
          </strong>
        </p>
        <p>
          False positive: <strong>{m.false_positives}</strong> · true positive: {m.true_positives}
        </p>
        <p>
          Akurasi: {m.accuracy === null ? 'Belum tersedia' : `${Math.round(m.accuracy * 100)}%`} ·
          inconclusive: {m.inconclusive}
        </p>
        <p>
          Evidence unik: {m.evidence_count} · agent selesai: {m.completed_agents}/
          {team.agents.length} · kelengkapan {Math.round(m.evidence_completeness * 100)}%
        </p>
        <p>
          Token terukur: {m.measured_input_tokens} input / {m.measured_output_tokens} output
        </p>
        <p>
          Reservasi: {m.token_reserved}/{team.request.max_tokens} · panggilan: {m.calls}/
          {team.request.max_calls}
        </p>
        <p>
          Waktu aktif: {m.active_seconds.toFixed(1)}/{team.request.active_seconds} detik
        </p>
      </div>
      <p className="muted-text">
        Pembanding: satu spesialis observasi mencakup 2/8 kasus; empat spesialis mencakup 8/8.
        Indikator benar/salah dihitung backend dari kontrol positif/negatif tetap, bukan narasi
        model.
      </p>
      {team.agents.map((a) => (
        <article className="record-card" key={a.role}>
          <h4>
            {a.profile.title} · {agentLabels[a.status] || a.status}
          </h4>
          <p>{a.profile.context}</p>
          <p>
            Target rencana: {team.request.plans[a.role]?.steps[0]?.target.value} · port{' '}
            {team.request.plans[a.role]?.steps[0]?.ports.join(', ') ||
              'mengikuti URL / tidak berlaku'}
          </p>
          <p>
            Izin: <code>{a.permissions.join(', ')}</code> · konteks ≤{a.context_tokens} · output ≤
            {a.output_tokens}
          </p>
          <p>
            Panggilan {a.calls}/{a.max_calls} · reservasi {a.token_reserved}/{a.max_tokens} · waktu{' '}
            {a.active_seconds.toFixed(1)}/{a.active_seconds_limit} detik
          </p>
          {a.job_id && (
            <p>
              Job: <code>{a.job_id}</code>
            </p>
          )}
          {a.error && <p className="error-banner">{a.error}</p>}
          {a.output ? (
            <>
              <p>{a.output.summary}</p>
              <table>
                <thead>
                  <tr>
                    <th>Kasus</th>
                    <th>Interpretasi AI</th>
                    <th>Kontrol lab</th>
                    <th>Dasar AI</th>
                  </tr>
                </thead>
                <tbody>
                  {a.output.assessments.map((x) => (
                    <tr key={x.case_id}>
                      <td>{x.case_id}</td>
                      <td>{x.assessment}</td>
                      <td>
                        {a.lab_result?.find((c) => c.case_id === x.case_id)?.expected_assessment ||
                          '—'}
                      </td>
                      <td>{x.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p>Ketidakpastian: {a.output.uncertainties.join(' · ')}</p>
              <p>Evidence: {a.output.evidence_ids.join(', ')}</p>
            </>
          ) : (
            <p className="muted-text">
              Belum ada interpretasi AI. Bukti yang sudah tersimpan tetap dipertahankan.
            </p>
          )}
          {a.lab_result && (
            <details>
              <summary>Observasi mentah sintetis dan indikator yang dapat diperiksa</summary>
              <pre className="record-output">{JSON.stringify(a.lab_result, null, 2)}</pre>
            </details>
          )}
          <small>
            Profil v{a.profile.version} · {a.profile.hash}
          </small>
        </article>
      ))}
    </div>
  )
}
