import type { ScopeAsset } from './engagements'
export interface Playbook {
  id: string
  version: string
  title: string
  hash: string
  instructions: string
  allowed_fixtures: string[]
  sources: { title: string; ref: string; version: string }[]
}
export interface WorkflowRequest {
  name: string
  objective: string
  model: string
  model_digest: string
  playbook: Playbook
  target: ScopeAsset
  server_id: string
  server_revision: number
  descriptor_hash: string
  roe_version: number
  content_hash: string
  max_calls: number
  max_steps: number
  max_tokens: number
  output_tokens: number
  active_seconds: number
}
export interface Orchestration {
  id: string
  revision: number
  status: string
  request: WorkflowRequest
  request_hash?: string
  planner: { rationale: string; actions: { fixture: string; compare_to: string | null }[] } | null
  executor: { reason: string; action_indices: number[] } | null
  reviewer: {
    summary: string
    evidence_ids: string[]
    uncertainties: string[]
    needs_human_review: true
    finding_status: 'candidate_only'
  } | null
  jobs: string[]
  batch: number
  model_calls: number
  token_reserved: number
  measured_input_tokens: number
  measured_output_tokens: number
  active_seconds: number
  created_at: string
  updated_at: string
  error: string | null
  checkpoints?: {
    revision: number
    at: string
    action: string
    actor: string
    note: string
    hash: string
    snapshot: unknown
  }[]
}
export const workflowLabels: Record<string, string> = {
  queued_planner: 'Planner mengantre',
  planning: 'Planner berpikir',
  awaiting_approval: 'Review rencana manusia',
  queued_executor: 'Executor mengantre',
  executing: 'Executor menyusun permintaan',
  waiting_jobs: 'Menunggu approval/hasil job',
  queued_reviewer: 'Reviewer mengantre',
  reviewing: 'Reviewer memeriksa bukti',
  completed: 'Selesai · perlu tinjauan analis',
  paused: 'Dihentikan · checkpoint tersimpan'
}
export interface WorkflowListing {
  items: Orchestration[]
  worker_active: boolean
}
export interface WorkflowCatalog {
  playbooks: Playbook[]
  models: { name: string; digest: string }[]
}
