import type { ScopeAsset } from './engagements'
export interface ScopeReport {
  policy_version: string
  valid: boolean
  findings: { code: string; severity: 'error' | 'warning'; message: string; location: string }[]
  execution_enabled: false
}
export interface PolicyProposal {
  expected_revision: number
  roe_version: number
  content_hash: string
  target: ScopeAsset
  action: string
  ports: number[]
  max_http_rps: number
  max_concurrency: number
  max_duration_minutes: number
  test_account_ref: string
}
export interface PolicyResult {
  id: string
  policy_version: string
  decision: 'pass' | 'deny'
  evaluated_at: string
  project_id: string
  engagement_id: string
  revision: number
  roe_version: number
  content_hash: string
  proposal_hash: string
  proposal: PolicyProposal
  checks: { code: string; passed: boolean; message: string }[]
  scope_report: ScopeReport
  execution_enabled: false
  grants_execution: false
  execution_blockers: string[]
}
export const policyDecisionLabel = (decision: PolicyResult['decision']): string =>
  decision === 'pass' ? 'Lolos evaluasi statis' : 'Ditolak policy'
export function scopeFingerprint(content: unknown): string {
  return JSON.stringify(content)
}
