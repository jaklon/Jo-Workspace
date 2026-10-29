import type { ScopeAsset } from './engagements'
export type EvidenceSource = 'offline_policy' | 'synthetic_fixture' | 'external_import'
export const sourceLabels: Record<EvidenceSource, string> = {
  offline_policy: 'Policy offline · bukan bukti kerentanan',
  synthetic_fixture: 'Fixture sintetis · bukan target nyata',
  external_import: 'Impor eksternal · deklarasi operator'
}
export type FindingStatus =
  'candidate' | 'validated' | 'false_positive' | 'inconclusive' | 'retest_passed'
export const findingLabels: Record<FindingStatus, string> = {
  candidate: 'Candidate',
  validated: 'Validated',
  false_positive: 'False Positive',
  inconclusive: 'Inconclusive',
  retest_passed: 'Retest Passed'
}
export interface Evidence {
  provenance?: string
  mcp?: unknown
  tool_executed_by_agent_os?: boolean
  original_available: boolean
  original_archive?: string
  id: string
  title: string
  job_id: string
  step_ordinal: number
  source: EvidenceSource
  target: ScopeAsset
  captured_at: string
  received_at: string
  tool_name: string
  tool_version: string
  parameters: string
  original_hash: string
  artifact_hash: string
  record_hash: string
  artifact_bytes: number
  original_bytes: number
  redactions: number
  roe_version: number
  roe_hash: string
  content?: string
  policy?: { decision: string }
  integrity: string
}
export interface FindingContent {
  title: string
  target: ScopeAsset
  category: string
  description: string
  ai_interpretation: string
  evidence_ids: string[]
  severity: string
  severity_reason: string
  cvss_vector: string
  cvss_reason: string
  cvss_score?: number | null
  remediation: string
  assignee: string
  duplicate_of: string | null
}
export interface Finding {
  id: string
  revision: number
  status: FindingStatus
  created_at: string
  updated_at: string
  content: FindingContent
  retest_evidence_ids: string[]
  review: { actor_label: string; analyst_assessment: string; at: string } | null
  history?: { revision: number; snapshot: Finding; hash: string }[]
}
export interface RecordsListing {
  evidence: Evidence[]
  findings: Finding[]
  reports: { id: string; title: string; created_at: string; hash: string }[]
  execution_enabled: false
}
export interface SecurityReport {
  hash: string
  markdown: string
  snapshot: {
    id: string
    title: string
    summary: string
    created_at: string
    author_declaration: string
    limitations: string[]
    findings: Finding[]
    evidence: Evidence[]
    roe_version: number
    roe_hash: string
  }
}
export const emptyFinding = (): FindingContent => ({
  title: '',
  target: { kind: 'ip', value: '' },
  category: '',
  description: '',
  ai_interpretation: '',
  evidence_ids: [],
  severity: 'unrated',
  severity_reason: '',
  cvss_vector: '',
  cvss_reason: '',
  remediation: '',
  assignee: '',
  duplicate_of: null
})
