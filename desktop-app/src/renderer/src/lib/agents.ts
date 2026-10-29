import type { ScopeAsset } from './engagements'

export type SpecialistRole = 'recon' | 'web_api' | 'auth_bola' | 'llm_security' | 'reporting'
export interface SpecialistProfile {
  id: SpecialistRole
  title: string
  permission: string
  action: string
  context: string
  version: string
  hash: string
}
export interface AgentBudget {
  role: SpecialistRole
  permissions: string[]
  max_calls: number
  max_tokens: number
  context_tokens: number
  output_tokens: number
  active_seconds: number
}
export const defaultAgent = (profile: SpecialistProfile): AgentBudget => ({
  role: profile.id,
  permissions: [profile.permission],
  max_calls: 1,
  max_tokens: 12000,
  context_tokens: 6000,
  output_tokens: 512,
  active_seconds: 120
})
export interface AgentLab {
  id: string
  name: string
  target: ScopeAsset
  account_aliases: string[]
  descriptor_hash: string
  disabled?: boolean
  events?: { action: string; at: string; actor: string; note: string }[]
}
export interface SpecialistAgent extends Omit<AgentBudget, 'active_seconds'> {
  profile: SpecialistProfile
  status: string
  job_id: string | null
  evidence_ids: string[]
  calls: number
  token_reserved: number
  active_seconds_limit: number
  active_seconds: number
  error: string | null
  lab_result:
    { case_id: string; observed: unknown; indicator: boolean; expected_assessment: string }[] | null
  output: {
    summary: string
    assessments: { case_id: string; assessment: string; reason: string }[]
    evidence_ids: string[]
    uncertainties: string[]
    needs_human_review: true
    finding_status: 'candidate_only'
  } | null
}
export interface TeamMetrics {
  case_count: number
  coverage_percent: number
  true_positives: number
  false_positives: number
  false_positive_rate: number | null
  inconclusive: number
  accuracy: number | null
  false_negatives: number
  true_negatives: number
  evidence_completeness: number
  evidence_count: number
  completed_agents: number
  calls: number
  token_reserved: number
  active_seconds: number
  measured_input_tokens: number
  measured_output_tokens: number
  classification_hash: string | null
}
export interface SpecialistTeam {
  id: string
  revision: number
  status: string
  request: {
    name: string
    objective: string
    model: string
    model_digest: string
    lab: AgentLab
    max_calls: number
    max_tokens: number
    active_seconds: number
    plans: Record<
      SpecialistRole,
      { steps: { target: ScopeAsset; action: string; ports: number[] }[] }
    >
  }
  agents: SpecialistAgent[]
  metrics: TeamMetrics
  repeatability?: { comparable_runs: number; identical_classifications: number }
  error: string | null
  checkpoints?: {
    revision: number
    action: string
    at: string
    actor: string
    note: string
    hash: string
  }[]
}
export interface SpecialistListing {
  items: SpecialistTeam[]
  labs: AgentLab[]
  worker_active: boolean
}
export interface SpecialistCatalog {
  profiles: SpecialistProfile[]
  models: { name: string; digest: string }[]
  lab: { id: string; version: string; hash: string }
}
export const agentLabels: Record<string, string> = {
  pending: 'Menunggu giliran',
  waiting_job: 'Menunggu approval/hasil job',
  running: 'Berjalan',
  completed: 'Selesai · tinjauan analis',
  paused: 'Dihentikan',
  awaiting_approval: 'Menunggu review rencana'
}
