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
}
export interface Coverage {
  selected: number
  total: number
  complete: boolean
}
export interface Proposal {
  id: string
  path: string
  diff: string
  state?: 'applied' | 'rejected'
}
export interface AnalysisProgress {
  step: string
  label: string
  detail?: string
  completedSteps: string[]
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
  sources?: Source[]
  webImages?: WebImage[]
  coverage?: Coverage
  proposals?: Proposal[]
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
export interface Project {
  id: string
  name: string
  instructions: string
  createdAt: number
}
export type ChatSessionMap = Record<TabType, ChatSession[]>
export type ActiveSessionMap = Record<TabType, string>
export interface StreamEvent {
  type: 'status' | 'token' | 'attachment' | 'sources' | 'result' | 'error' | 'done'
  token?: string
  result?: string
  step?: string
  label?: string
  detail?: string
  attachment?: Attachment
  sources?: Source[]
  images?: WebImage[]
  coverage?: Coverage
  proposals?: Proposal[]
  report?: PentestReport
}
