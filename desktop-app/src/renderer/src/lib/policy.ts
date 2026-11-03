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

// --- Dynamic approval threshold (mirrors backend auto_governance.classify_risk) ---
export type RiskTier = 'low' | 'medium' | 'high'
export type RiskRequirement = 'auto' | 'one_click' | 'session_pin'
export interface RiskClass {
  tier: RiskTier
  requires: RiskRequirement
  label: string
  autoExecute: boolean
}
const PASSIVE_ACTIONS = new Set([
  'passive_recon',
  'configuration_review',
  'document_review',
  'monitoring_read'
])
const MEDIUM_ACTIONS = new Set([
  'tcp_discovery',
  'http_headers',
  'unauthenticated_access_check',
  'service_inventory'
])
const HIGH_ACTIONS = new Set(['scoped_spider', 'active_reflection', 'authenticated_api_review'])
const TIER_LABELS: Record<RiskTier, string> = {
  low: 'Low / pasif',
  medium: 'Medium',
  high: 'High / intrusif'
}
export function classifyRisk(action: string): RiskClass {
  let tier: RiskTier
  let requires: RiskRequirement
  if (HIGH_ACTIONS.has(action)) {
    tier = 'high'
    requires = 'session_pin'
  } else if (MEDIUM_ACTIONS.has(action)) {
    tier = 'medium'
    requires = 'one_click'
  } else if (PASSIVE_ACTIONS.has(action)) {
    tier = 'low'
    requires = 'auto'
  } else {
    // Fail safe: anything unrecognized needs the strictest confirmation.
    tier = 'high'
    requires = 'session_pin'
  }
  return { tier, requires, label: TIER_LABELS[tier], autoExecute: tier === 'low' }
}
export const riskRequirementLabel: Record<RiskRequirement, string> = {
  auto: 'Eksekusi otomatis tanpa interupsi',
  one_click: 'Perlu satu klik persetujuan',
  session_pin: 'Perlu konfirmasi eksplisit + PIN sesi lokal'
}

export interface JobSimulation {
  tool: string
  action: string
  target: string
  estimated_requests: number
  target_addresses: number
  concurrency: number
  estimated_seconds: number
  blast_radius: number
  risk_tier: RiskTier
  passive: boolean
}
export interface PlanSimulation {
  environment: string
  jobs: JobSimulation[]
  job_count: number
  total_requests: number
  max_concurrency: number
  estimated_seconds: number
  blast_radius: number
  risk_tier: RiskTier
  risk_label: string
  requires: RiskRequirement
  requires_pin: boolean
  execution_enabled: false
}
export function blastRadiusLabel(score: number): string {
  if (score >= 70) return 'Tinggi'
  if (score >= 40) return 'Sedang'
  if (score >= 15) return 'Rendah'
  return 'Minimal'
}
