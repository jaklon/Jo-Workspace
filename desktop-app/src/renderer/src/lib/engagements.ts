import type { ScopeReport } from './policy'
export type ScopeKind = 'ip' | 'cidr' | 'domain' | 'url'
export interface ScopeAsset {
  kind: ScopeKind
  value: string
}
export type RoeStatus =
  'draft' | 'pending_review' | 'approved' | 'revoked' | 'expired' | 'superseded'
export type DecisionAction = 'submit' | 'approve' | 'request_changes' | 'revoke' | 'revise'
export const statusLabels: Record<RoeStatus, string> = {
  draft: 'Draft',
  pending_review: 'Menunggu persetujuan',
  approved: 'Disetujui secara lokal',
  revoked: 'Dicabut',
  expired: 'Kedaluwarsa',
  superseded: 'Versi terdahulu'
}
export const actionLabels: Record<string, string> = {
  tcp_discovery: 'Discovery TCP',
  monitoring_read: 'Baca monitoring lokal (Prometheus/Grafana)',
  passive_recon: 'Recon pasif (mengirim domain ke sumber eksternal)',
  http_headers: 'Pemeriksaan header HTTP',
  unauthenticated_access_check: 'Pemeriksaan GET tanpa sesi',
  service_inventory: 'Inventaris tautan HTML tanpa sesi',
  scoped_spider: 'Spider terbatas dalam scope',
  active_reflection: 'Uji aktif marker aman',
  configuration_review: 'Review konfigurasi',
  document_review: 'Review dokumen',
  authenticated_api_review: 'Review API dengan akun uji'
}
export interface EngagementContent {
  name: string
  objective: string
  owner: string
  contact: string
  environment: 'lab' | 'development' | 'staging' | 'uat' | 'production_readonly'
  authorization_ref: string
  in_scope: ScopeAsset[]
  out_of_scope: ScopeAsset[]
  ports: number[]
  allowed_actions: string[]
  starts_at: string | null
  ends_at: string | null
  timezone: string
  max_http_rps: number
  max_concurrency: number
  max_duration_minutes: number
  emergency_contact: string
  stop_conditions: string
  test_account_refs: string[]
}
export interface RoeVersion {
  version: number
  status: RoeStatus
  effective_status: RoeStatus
  content: EngagementContent
  content_hash: string
  submitted_at: string | null
  reviewed_at: string | null
  reviewer: string | null
  review_note: string | null
  revoked_at: string | null
  revoke_note: string | null
  submission_errors: string[]
  scope_report: ScopeReport
}
export interface Engagement {
  id: string
  project_id: string
  created_at: string
  updated_at: string
  revision: number
  versions: RoeVersion[]
  events: {
    id: number
    version: number
    at: string
    action: string
    actor: string
    note: string
    content_hash: string
  }[]
  execution_enabled: false
  forbidden_actions: string[]
  approval_mode: 'local_attestation'
}
export const emptyContent = (): EngagementContent => ({
  name: '',
  objective: '',
  owner: '',
  contact: '',
  environment: 'lab',
  authorization_ref: '',
  in_scope: [],
  out_of_scope: [],
  ports: [],
  allowed_actions: [],
  starts_at: null,
  ends_at: null,
  timezone: 'Asia/Jakarta',
  max_http_rps: 5,
  max_concurrency: 1,
  max_duration_minutes: 60,
  emergency_contact: '',
  stop_conditions: '',
  test_account_refs: []
})
export function localDateTime(iso: string | null, zone: string): string {
  if (!iso) return ''
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: zone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23'
  }).formatToParts(new Date(iso))
  const get = (key: string): string => parts.find((p) => p.type === key)?.value || ''
  return `${get('year')}-${get('month')}-${get('day')}T${get('hour')}:${get('minute')}`
}
export function utcDateTime(value: string, zone: string): string | null {
  if (!value) return null
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) throw new Error('Tanggal/jam tidak valid.')
  const desired = Date.parse(value + ':00Z')
  if (!Number.isFinite(desired) || new Date(desired).toISOString().slice(0, 16) !== value)
    throw new Error('Tanggal/jam tidak valid.')
  let guess = desired
  for (let i = 0; i < 4; i++) {
    const formatted = localDateTime(new Date(guess).toISOString(), zone)
    guess += desired - Date.parse(formatted + ':00Z')
  }
  const result = new Date(guess).toISOString()
  if (localDateTime(result, zone) !== value)
    throw new Error('Waktu tidak ada pada zona waktu ini. Pilih waktu lain atau UTC.')
  if (
    [-7200000, -3600000, -1800000, 1800000, 3600000, 7200000].some(
      (offset) => localDateTime(new Date(guess + offset).toISOString(), zone) === value
    )
  )
    throw new Error('Waktu ambigu akibat DST. Gunakan zona UTC untuk periode ini.')
  return result
}
export function parsePorts(value: string): number[] {
  if (!value.trim()) return []
  const tokens = value.split(',').map((s) => s.trim())
  if (
    tokens.length > 100 ||
    tokens.some((s) => !/^\d+$/.test(s) || Number(s) < 1 || Number(s) > 65535)
  )
    throw new Error('Port harus berupa angka 1–65535 dipisahkan koma (maksimal 100).')
  return [...new Set(tokens.map(Number))].sort((a, b) => a - b)
}
export function effectiveStatus(version: RoeVersion, current = true, now = Date.now()): RoeStatus {
  if (!current) return 'superseded'
  if (
    ['pending_review', 'approved'].includes(version.status) &&
    version.content.ends_at &&
    Date.parse(version.content.ends_at) <= now
  )
    return 'expired'
  return version.status
}
export function engagementPath(projectId: string, id?: string): string {
  return `/api/security/projects/${encodeURIComponent(projectId)}/engagements${id ? '/' + encodeURIComponent(id) : ''}`
}
