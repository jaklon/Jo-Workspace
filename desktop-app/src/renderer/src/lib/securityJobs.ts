import type { MCPBinding } from './mcp'
import type { ScopeAsset } from './engagements'
import type { PolicyResult } from './policy'
export type JobStatus =
  'awaiting_approval' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
export const jobStatusLabels: Record<JobStatus, string> = {
  awaiting_approval: 'Awaiting Approval',
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled'
}
export const activeJob = (status: JobStatus): boolean =>
  ['awaiting_approval', 'queued', 'running'].includes(status)
export interface JobStep {
  target: ScopeAsset
  action: string
  ports: number[]
  max_http_rps: number
  max_concurrency: number
  max_duration_minutes: number
  test_account_ref: string
}
export interface JobPlan {
  scan?: { tool: 'nmap' | 'tcp-connect' | 'monitoring-local' | 'nuclei-head' | 'zap-head' | 'auth-unauthenticated-get' | 'auth-two-session' | 'inventory-html' | 'js-bundle-inventory' | 'scoped-spider' | 'active-reflection' | 'subfinder-passive' | 'amass-passive'; binary_sha256: string; provider_disclosure?: boolean; account_refs?: string[]; owner_json_pointer?: string } | null
  web?: { adapter: string } | null
  mcp?: MCPBinding | null
  name: string
  expected_roe_revision: number
  roe_version: number
  content_hash: string
  steps: JobStep[]
  wall_timeout_seconds: number
  max_output_kb: number
}
export interface SecurityJob {
  id: string
  project_id: string
  engagement_id: string
  plan: JobPlan
  plan_hash: string
  status: JobStatus
  revision: number
  created_at: string
  updated_at: string
  approved_at: string | null
  approver: string | null
  approval_note: string | null
  started_at: string | null
  finished_at: string | null
  progress: number
  output_bytes: number
  error_code: string | null
  error_message: string | null
  attempt: number
  retry_of: string | null
  retry_job_id: string | null
  mode: 'offline_policy_validation' | 'isolated_mcp_fixture' | 'approved_public_url_head' | 'approved_tcp_scan'
  scan_result?: { evidence_id: string; [key: string]: unknown } | null
  web_result?: { evidence_id: string; [key: string]: unknown } | null
  mcp_result?: { evidence_id: string; [key: string]: unknown } | null
  execution_enabled: boolean
  grants_execution: false
  results?: { ordinal: number; result: PolicyResult & { tool_executed: false } }[]
  events?: { id: number; at: string; action: string; actor: string; note: string }[]
}
export interface JobsListing {
  items: SecurityJob[]
  gate: {
    stopped: boolean | number
    revision: number
    updated_at: string | null
    actor: string | null
    note: string
  }
  worker_active: boolean
  limits: {
    max_jobs: number
    max_steps: number
    max_concurrency: number
    max_wall_seconds: number
    max_output_kb: number
    max_attempts: number
  }
  execution_enabled: false
}
