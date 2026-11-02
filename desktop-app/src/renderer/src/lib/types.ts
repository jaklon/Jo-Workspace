export type TabType = 'chat' | 'code' | 'vision' | 'docs' | 'pentest'
export const modeLabels: Record<TabType, string> = {
  chat: 'Chat',
  code: 'Code',
  docs: 'Dokumen',
  vision: 'Vision',
  pentest: 'Security'
}
export interface Attachment {
  id: string
  filename: string
  kind: string
}
export interface Source {
  label: string
  text: string
  filename?: string
  line_start?: number
  line_end?: number
  section?: number
  location?: string
  matched?: boolean
  cited?: boolean
  kind?: 'web'
  title?: string
  url?: string
  fetched?: boolean
  read_level?: 'page' | 'rendered' | 'metadata' | 'snippet'
}
export interface WebImage {
  url: string
  alt: string
  source_url: string
  ticket?: string
}
export interface Coverage {
  selected: number
  total: number
  complete: boolean
  matched?: number
  cited?: number
  unreadable_pages?: number[]
}
export interface ProposalHunk {
  index: number
  header: string
  added: number
  removed: number
  diff: string
}
export interface Proposal {
  id: string
  path: string
  diff: string
  hunks?: ProposalHunk[]
  review?: {
    new_file: boolean
    added: number
    removed: number
    hunk_count: number
    risks: string[]
  }
  state?: 'applied' | 'partial' | 'rejected'
  appliedHunks?: number[]
}
export interface ActionProposal {
  id: string
  intent: string
  target: string
  tools: string[]
  duration: string
  summary: string
  ports?: number[]
  environment?: string
  account_refs?: string[]
  owner_json_pointer?: string
  project_id?: string
  project_is_new?: boolean
  outbound?: OutboundDisclosure
  state?: 'submitted' | 'cancelled'
}
export interface OutboundDisclosure {
  leaves_device: boolean
  sent: string[]
  destinations: string[]
  not_sent: string[]
}
export interface OutboundLog {
  query: string | null
  pages: string[]
}
export interface AnalysisProgress {
  step: string
  label: string
  detail?: string
  completedSteps: string[]
}
export interface TraceStep {
  step: string
  label: string
  detail?: string
  startedAt: number
  endedAt?: number
}
export interface PentestFinding {
  check: string
  status: string
  severity?: string
  endpoint?: string
  remediation?: string
}
export interface PentestReport {
  id: string
  target_id: string
  status: string
  seconds: number
  evidence: PentestFinding[]
  discovery: { engine?: string; open_ports?: Array<{ port: number; service: string }> }
  analysis?: string
}
export interface Message {
  role: 'user' | 'assistant'
  content: string
  image?: string
  imageBlob?: Blob
  visualAnalysis?: string
  analysisProgress?: AnalysisProgress
  trace?: TraceStep[]
  thinking?: string
  sources?: Source[]
  webImages?: WebImage[]
  coverage?: Coverage
  proposals?: Proposal[]
  action?: ActionProposal
  outbound?: OutboundLog
}
export interface ChatSession {
  id: string
  title: string
  createdAt: number
  updatedAt: number
  messages: Message[]
  attachments?: Attachment[]
  projectId?: string
  pinned?: boolean
  archived?: boolean
}
export type ProjectFactKind = 'goal' | 'decision' | 'term' | 'note'
export interface ProjectFact {
  id: string
  kind: ProjectFactKind
  text: string
  source:
    | { kind: 'manual' }
    | { kind: 'chat'; sessionId?: string; sessionTitle?: string; excerpt?: string }
  createdAt: number
  updatedAt: number
}
export interface Project {
  id: string
  name: string
  instructions: string
  memory?: ProjectFact[]
  createdAt: number
}
export type ChatSessionMap = Record<TabType, ChatSession[]>
export type ActiveSessionMap = Record<TabType, string>
export interface StreamEvent {
  type:
    | 'status'
    | 'token'
    | 'thinking'
    | 'attachment'
    | 'sources'
    | 'result'
    | 'error'
    | 'done'
    | 'action_proposal'
  token?: string
  result?: string
  step?: string
  label?: string
  detail?: string | null
  attachment?: Attachment
  sources?: Source[]
  images?: WebImage[]
  outbound?: OutboundLog | null
  coverage?: Coverage
  visual_analysis?: string | null
  proposals?: Proposal[]
  action?: ActionProposal
  report?: PentestReport
}
