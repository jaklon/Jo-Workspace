import { BrandMark } from './components/BrandMark'
import { useState, useRef, useEffect, JSX, ChangeEvent, ClipboardEvent } from 'react'
import {
  MessageSquare,
  Code2,
  FileText,
  Image,
  ShieldAlert,
  Loader2,
  Bot,
  User,
  Copy,
  Check,
  ChevronDown,
  Paperclip,
  X,
  Menu,
  Plus,
  Zap,
  HardDrive,
  Command,
  ArrowUpRight,
  Settings2,
  ChartNoAxesCombined,
  Folder,
  Square,
  ArrowUp
} from 'lucide-react'

import type {
  Message,
  TabType,
  StreamEvent,
  Attachment,
  AnalysisProgress,
  ChatSession,
  Project
} from './lib/types'
import { apiFetch, consumeStream, disconnect } from './lib/api'
import { createSession, useSessions, TAB_TYPES } from './lib/sessions'
import { downloadFile, personalizedPrompt, usePreferences } from './lib/preferences'
import { exportBackup, importBackup } from './lib/backup'
import { modeLabels } from './lib/types'
import { WorkspaceSidebar, type SessionRow } from './components/WorkspaceSidebar'
import { Settings } from './components/Settings'
import { Usage } from './components/Usage'
import { ProjectEditor, SessionEditor } from './components/OrganizeDialogs'
import { Connection } from './components/Connection'
import { MarkdownAnswer, MessageDetails, MessageImage } from './components/MessageDetails'
import { SecurityWorkspace } from './components/SecurityWorkspace'
import { SearchWorkspace } from './components/SearchWorkspace'

const MOBILE_TAB_LABELS: Record<TabType, string> = {
  chat: 'Chat',
  code: 'Code',
  vision: 'Vision',
  docs: 'Dokumen',
  pentest: 'Security'
}

export default function App(): JSX.Element {
  const { preferences, setPreferences, preferenceError } = usePreferences()
  const [activeTab, setActiveTab] = useState<TabType>(preferences.defaultMode)
  const [view, setView] = useState<'chat' | 'usage' | 'security' | 'search'>(
    preferences.defaultMode === 'pentest' ? 'security' : 'chat'
  )
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [selectedProject, setSelectedProject] = useState('all')
  const [projectEditor, setProjectEditor] = useState<Project | 'new' | null>(null)
  const [sessionEditor, setSessionEditor] = useState<SessionRow | null>(null)
  const [prompt, setPrompt] = useState('')
  const {
    sessionsByTab,
    setSessionsByTab,
    activeSessions,
    setActiveSessions,
    ready,
    storageError,
    projects,
    setProjects
  } = useSessions()
  const [needsAuth, setNeedsAuth] = useState(false)
  const [connectionVersion, setConnectionVersion] = useState(0)
  const [connectionState, setConnectionState] = useState('Memeriksa koneksi')
  const [agentMode, setAgentMode] = useState(false)
  const [securityView, setSecurityView] = useState<'pentest' | 'chat'>('pentest')
  const [gpuName, setGpuName] = useState('GPU belum terdeteksi')
  const [modelNames, setModelNames] = useState<Record<string, string>>({})
  const abortRef = useRef<AbortController | null>(null)
  const [loading, setLoading] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => window.innerWidth < 1024)
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null)
  const [gpuStats, setGpuStats] = useState({ used: 0, total: 0, percent: 0 })
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState('')
  const [imageFile, setImageFile] = useState<File | null>(null)
  const [webMode, setWebMode] = useState<'auto' | 'on' | 'off'>('auto')
  const [imagePreviewUrl, setImagePreviewUrl] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const imageUrlsRef = useRef<Set<string>>(new Set())
  const currentSession =
    sessionsByTab[activeTab].find((session) => session.id === activeSessions[activeTab]) ??
    sessionsByTab[activeTab][0]
  const currentMessages = currentSession.messages
  const currentProject = projects.find((p) => p.id === currentSession.projectId)
  const [workspaceNotice, setWorkspaceNotice] = useState('')

  const appendMessageToActiveTab = (message: Message): void => {
    setSessionsByTab((prev) => ({
      ...prev,
      [activeTab]: prev[activeTab].map((session) =>
        session.id === currentSession.id
          ? {
              ...session,
              title:
                session.messages.length === 0 && message.role === 'user'
                  ? message.content.trim().split('\n')[0].slice(0, 40) || 'Percakapan baru'
                  : session.title,
              updatedAt: Date.now(),
              messages: [...session.messages, message].slice(-100)
            }
          : session
      )
    }))
  }

  const replacePendingMessageInActiveTab = (message: Message): void => {
    setMessagesInActiveSession((previous) => [...previous.slice(0, -1), message])
  }

  const setMessagesInActiveSession = (updater: (previous: Message[]) => Message[]): void => {
    setSessionsByTab((prev) => ({
      ...prev,
      [activeTab]: prev[activeTab].map((session) =>
        session.id === currentSession.id
          ? { ...session, updatedAt: Date.now(), messages: updater(session.messages).slice(-100) }
          : session
      )
    }))
  }

  const handleRemoveImage = (): void => {
    if (imagePreviewUrl) {
      URL.revokeObjectURL(imagePreviewUrl)
      imageUrlsRef.current.delete(imagePreviewUrl)
    }
    setImageFile(null)
    setImagePreviewUrl(null)
  }

  const selectTab = (tab: TabType): void => {
    if (loading) return
    handleRemoveImage()
    setSelectedFile(null)
    setFileError('')
    setActiveTab(tab)
    setView(tab === 'pentest' ? 'security' : 'chat')
  }

  const handleNewChat = (): void => {
    if (loading || !ready) return
    if (sessionsByTab[activeTab].length >= 500) {
      setWorkspaceNotice(
        'Batas 500 chat per mode tercapai. Ekspor dan hapus chat lama terlebih dahulu.'
      )
      return
    }
    const session = createSession()
    if (projects.some((p) => p.id === selectedProject)) session.projectId = selectedProject
    setSessionsByTab((prev) => ({
      ...prev,
      [activeTab]: [session, ...prev[activeTab]]
    }))
    setActiveSessions((prev) => ({ ...prev, [activeTab]: session.id }))
    setPrompt('')
    setView('chat')
    setSecurityView('chat')
    handleRemoveImage()
    setSelectedFile(null)
    setFileError('')
  }

  const selectSession = ({ tab, session }: SessionRow): void => {
    if (loading) return
    selectTab(tab)
    setActiveSessions((prev) => ({ ...prev, [tab]: session.id }))
    setView('chat')
    setSecurityView('chat')
    setPrompt('')
    if (window.innerWidth < 1024) setSidebarCollapsed(true)
  }

  const editSession = (change: Partial<ChatSession>): void => {
    if (!sessionEditor) return
    const { tab, session } = sessionEditor
    setSessionsByTab((prev) => ({
      ...prev,
      [tab]: prev[tab].map((s) =>
        s.id === session.id ? { ...s, ...change, updatedAt: Date.now() } : s
      )
    }))
    setSessionEditor(null)
  }

  const removeSessionAttachments = async (session: ChatSession): Promise<void> => {
    await Promise.all(
      (session.attachments || []).map((a) =>
        apiFetch(
          `/api/attachments/${encodeURIComponent(a.id)}?session_id=${encodeURIComponent(session.id)}`,
          { method: 'DELETE' }
        )
      )
    )
  }

  const deleteSession = async (): Promise<void> => {
    if (!sessionEditor) return
    const { tab, session } = sessionEditor
    await removeSessionAttachments(session)
    const remaining = sessionsByTab[tab].filter((s) => s.id !== session.id)
    if (!remaining.length) remaining.push(createSession())
    setSessionsByTab((prev) => ({ ...prev, [tab]: remaining }))
    if (activeSessions[tab] === session.id)
      setActiveSessions((prev) => ({ ...prev, [tab]: remaining[0].id }))
    setSessionEditor(null)
  }

  const assertProjectsRemovable = async (ids: string[]): Promise<void> => {
    if (!ids.length) return
    const result = await (
      await apiFetch('/api/security/project-retention', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_ids: ids })
      })
    ).json()
    if (result.protected_project_ids.length)
      throw new Error(
        'Project memiliki Engagement/RoE yang harus dipertahankan. Ekspor riwayat di Security Workspace; penghapusan project dengan catatan keamanan belum tersedia.'
      )
  }

  const clearAll = async (): Promise<void> => {
    await assertProjectsRemovable(projects.map((p) => p.id))
    await Promise.all(TAB_TYPES.flatMap((tab) => sessionsByTab[tab]).map(removeSessionAttachments))
    const fresh = Object.fromEntries(
      TAB_TYPES.map((tab) => [tab, [createSession()]])
    ) as typeof sessionsByTab
    setSessionsByTab(fresh)
    setActiveSessions(
      Object.fromEntries(TAB_TYPES.map((tab) => [tab, fresh[tab][0].id])) as typeof activeSessions
    )
    setProjects([])
    setSelectedProject('all')
    setPrompt('')
    handleRemoveImage()
    setSelectedFile(null)
    setFileError('')
  }

  const importData = async (file: File): Promise<void> => {
    if (file.size > 10 * 1024 * 1024) throw new Error('Batas cadangan 10 MB.')
    const backup = importBackup(await file.text())
    if (
      projects.length + backup.projects.length > 500 ||
      TAB_TYPES.some((tab) => sessionsByTab[tab].length + backup.sessions[tab].length > 500)
    )
      throw new Error('Hasil impor melebihi batas 500 project atau 500 chat per mode.')
    setProjects((prev) => [...prev, ...backup.projects])
    setSessionsByTab(
      (prev) =>
        Object.fromEntries(
          TAB_TYPES.map((tab) => [tab, [...backup.sessions[tab], ...prev[tab]]])
        ) as typeof prev
    )
  }

  const disconnectSession = (): void => {
    abortRef.current?.abort()
    setSettingsOpen(false)
    void disconnect().finally(() => setNeedsAuth(true))
  }

  const shortcutActions = useRef({
    newChat: handleNewChat,
    search: (): void => {
      setSidebarCollapsed(false)
      setTimeout(() => document.getElementById('chat-search')?.focus(), 100)
    }
  })
  useEffect(() => {
    shortcutActions.current.newChat = handleNewChat
  })
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (!(e.ctrlKey || e.metaKey) || e.altKey) return
      if (e.key === ',') {
        e.preventDefault()
        setSettingsOpen((open) => !open)
        return
      }
      if (document.querySelector('[role="dialog"]')) return
      if (e.key.toLowerCase() === 'k') {
        e.preventDefault()
        shortcutActions.current.search()
      }
      if (e.key.toLowerCase() === 'o' && e.shiftKey) {
        e.preventDefault()
        shortcutActions.current.newChat()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const tabDetails = {
    chat: {
      title: 'Chat & Reasoning',
      desc: 'Ruang kerja untuk berpikir, merencanakan, dan mengeksekusi.',
      target: 'reasoning',
      icon: MessageSquare,
      color: 'text-emerald-400',
      badge: modelNames.reasoning || 'Reasoning',
      accent: 'from-emerald-400 to-teal-400',
      suggestions: [
        'Buat rencana kerja untuk proyek baru',
        'Jelaskan konsep ini secara sederhana',
        'Bandingkan dua pendekatan teknis'
      ]
    },
    code: {
      title: 'Coding Assistant',
      desc: 'Buat, review, dan debug kode dengan konteks yang jelas.',
      target: 'coding',
      icon: Code2,
      color: 'text-cyan-400',
      badge: modelNames.coding || 'Coding',
      accent: 'from-cyan-400 to-blue-500',
      suggestions: [
        'Review fungsi ini dan temukan bug-nya',
        'Buatkan REST API yang aman',
        'Refactor kode agar lebih mudah diuji'
      ]
    },
    vision: {
      title: 'Vision Analysis',
      desc: 'Pahami screenshot, gambar, dan detail visual secara lokal.',
      target: 'vision',
      icon: Image,
      color: 'text-violet-400',
      badge: modelNames.vision || 'Vision Engine',
      accent: 'from-violet-400 to-fuchsia-500',
      suggestions: [
        'Jelaskan elemen pada gambar ini',
        'Temukan masalah UI dari screenshot',
        'Ekstrak informasi visual penting'
      ]
    },
    docs: {
      title: 'Document Parser',
      desc: 'Ekstrak, pahami, dan rangkum isi dokumen Anda.',
      target: 'reasoning',
      icon: FileText,
      color: 'text-amber-400',
      badge: 'Document Engine',
      accent: 'from-amber-300 to-orange-500',
      suggestions: [
        'Ringkas dokumen dalam lima poin',
        'Cari risiko dan keputusan penting',
        'Buat daftar tindak lanjut'
      ]
    },
    pentest: {
      title: 'Security & Pentest',
      desc: 'Audit keamanan dan temukan potensi kerentanan.',
      target: 'security',
      icon: ShieldAlert,
      color: 'text-rose-400',
      badge: modelNames.security || 'Audit Engine',
      accent: 'from-rose-400 to-orange-400',
      suggestions: [
        'Audit potensi kerentanan endpoint',
        'Buat checklist security review',
        'Analisis risiko dari konfigurasi ini'
      ]
    }
  }

  const scrollToBottom = (): void => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    if (preferences.autoScroll) scrollToBottom()
  }, [activeTab, currentMessages, preferences.autoScroll])

  useEffect(() => {
    const requireAuth = (): void => setNeedsAuth(true)
    window.addEventListener('agent-auth-required', requireAuth)
    const refresh = (): void => setConnectionVersion((v) => v + 1)
    window.addEventListener('agent-settings-changed', refresh)
    return () => {
      window.removeEventListener('agent-auth-required', requireAuth)
      window.removeEventListener('agent-settings-changed', refresh)
    }
  }, [])

  useEffect(() => {
    let alive = true
    const controller = new AbortController()
    const poll = async (): Promise<void> => {
      try {
        const health = await (await apiFetch('/api/health', { signal: controller.signal })).json()
        if (!alive) return
        setModelNames(health.models || {})
        setConnectionState(health.status === 'connected' ? 'Terhubung' : 'Model belum lengkap')
        const data = await (await apiFetch('/api/gpu-status', { signal: controller.signal })).json()
        if (!alive) return
        setGpuName(data.name)
        setGpuStats({
          used: data.vram_used_mb,
          total: data.vram_total_mb,
          percent: data.usage_percent
        })
      } catch {
        if (alive) setConnectionState('Tidak terhubung')
      }
    }
    void poll()
    const timer = setInterval(() => {
      void poll()
    }, 10000)
    return () => {
      alive = false
      controller.abort()
      clearInterval(timer)
    }
  }, [connectionVersion])

  useEffect(() => () => abortRef.current?.abort(), [])

  useEffect(() => {
    const imageUrls = imageUrlsRef.current
    return () => {
      imageUrls.forEach((url) => URL.revokeObjectURL(url))
      imageUrls.clear()
    }
  }, [])

  const copyToClipboard = (text: string, index: number): void => {
    void navigator.clipboard
      .writeText(text)
      .then(() => {
        setCopiedIndex(index)
        setTimeout(() => setCopiedIndex(null), 2000)
      })
      .catch(() =>
        setFileError('Salin otomatis tidak tersedia. Pilih teks jawaban dan salin secara manual.')
      )
  }

  const canUploadFile = activeTab === 'vision' || activeTab === 'docs'
  const fileAccept =
    activeTab === 'vision'
      ? '.png,.jpg,.jpeg,.webp'
      : '.pdf,.docx,.xlsx,.txt,.csv,.md,.json,.py,.ts,.js'

  const isAllowedFile = (file: File): boolean => {
    const extension = file.name.toLowerCase().split('.').pop()
    const allowedExtensions =
      activeTab === 'vision'
        ? ['png', 'jpg', 'jpeg', 'webp']
        : ['pdf', 'docx', 'xlsx', 'txt', 'csv', 'md', 'json', 'py', 'ts', 'js']
    return (
      file.size <= 8 * 1024 * 1024 &&
      canUploadFile &&
      extension !== undefined &&
      allowedExtensions.includes(extension)
    )
  }

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>): void => {
    const file = event.target.files?.[0]
    if (!file) return

    if (!isAllowedFile(file)) {
      setSelectedFile(null)
      setFileError(
        !canUploadFile
          ? 'Pilih tab Vision atau Document Parser untuk melampirkan file.'
          : activeTab === 'vision'
            ? 'Mode Vision hanya menerima file PNG, JPG, atau WEBP.'
            : 'Document Parser hanya menerima file PDF, DOCX, XLSX, atau TXT.'
      )
      event.target.value = ''
      return
    }

    setFileError('')
    setSelectedFile(file)
    setImageFile(null)
    setImagePreviewUrl(null)
  }

  const triggerFileSelect = (): void => {
    fileInputRef.current?.click()
  }

  const removeFile = (): void => {
    setSelectedFile(null)
    setFileError('')
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handlePaste = (event: ClipboardEvent<HTMLTextAreaElement>): void => {
    if (activeTab !== 'vision' || loading) return

    const imageItem = Array.from(event.clipboardData.items).find((item) =>
      item.type.startsWith('image/')
    )
    if (!imageItem) return

    event.preventDefault()
    const file = imageItem.getAsFile()
    if (!file) return
    if (file.size > 8 * 1024 * 1024) {
      setFileError('Gambar maksimal 8 MB.')
      return
    }

    setSelectedFile(null)
    if (imagePreviewUrl) {
      URL.revokeObjectURL(imagePreviewUrl)
      imageUrlsRef.current.delete(imagePreviewUrl)
    }
    setImageFile(file)
    const previewUrl = URL.createObjectURL(file)
    imageUrlsRef.current.add(previewUrl)
    setImagePreviewUrl(previewUrl)
    setFileError('')
  }

  const handleSend = async (): Promise<void> => {
    if (!ready || needsAuth || abortRef.current || (!prompt.trim() && !selectedFile && !imageFile))
      return
    const upload = imageFile || selectedFile
    if (upload && (currentSession.attachments?.length || 0) >= 4) {
      setFileError('Maksimal 4 lampiran per sesi. Lepas salah satu lampiran terlebih dahulu.')
      return
    }
    if (upload && !isAllowedFile(upload)) {
      setFileError('Format file tidak didukung atau melebihi 8 MB.')
      return
    }
    if (activeTab === 'vision' && !upload && !currentSession.attachments?.length) {
      setFileError('Unggah gambar terlebih dahulu untuk memulai analisis Vision.')
      return
    }
    const controller = new AbortController()
    abortRef.current = controller
    setLoading(true)
    const sessionId = currentSession.id
    const history = currentMessages
      .filter((m) => m.content.trim() && !m.content.startsWith('⚠️'))
      .slice(-12)
      .map(({ role, content }) => ({ role, content }))
    const userText =
      prompt.trim() || (activeTab === 'vision' ? 'Jelaskan gambar ini.' : 'Ringkas dokumen ini.')
    const requestPrompt = personalizedPrompt(userText, preferences, currentProject?.instructions)
    if (requestPrompt.length > 6000) {
      setFileError(
        'Pesan beserta instruksi pribadi/project maksimal 6000 karakter. Persingkat pesan atau instruksi.'
      )
      abortRef.current = null
      setLoading(false)
      return
    }
    setPrompt('')
    setFileError('')
    appendMessageToActiveTab({
      role: 'user',
      content: upload ? upload.name + '\n' + userText : userText,
      imageBlob: activeTab === 'vision' && upload ? upload : undefined
    })
    appendMessageToActiveTab({ role: 'assistant', content: '' })
    setSelectedFile(null)
    handleRemoveImage()
    let pending: Message = {
      role: 'assistant',
      content: '',
      analysisProgress: {
        step: 'queued',
        label: upload ? 'Mengunggah dan memproses lampiran' : 'Menunggu giliran model',
        completedSteps: []
      }
    }
    replacePendingMessageInActiveTab(pending)
    const rememberAttachment = (attachment: Attachment): void => {
      setSessionsByTab((prev) => ({
        ...prev,
        [activeTab]: prev[activeTab].map((s) =>
          s.id === sessionId
            ? {
                ...s,
                attachments: [
                  ...(s.attachments || []).filter((a) => a.id !== attachment.id),
                  attachment
                ].slice(-4)
              }
            : s
        )
      }))
    }
    const onEvent = (event: StreamEvent): void => {
      if (event.attachment) rememberAttachment(event.attachment)
      if (event.type === 'status')
        pending = {
          ...pending,
          analysisProgress: {
            step: event.step || 'running',
            label: event.label || 'Memproses',
            completedSteps: []
          }
        }
      if (event.type === 'token')
        pending = {
          ...pending,
          content: pending.content + (event.token || ''),
          analysisProgress: undefined
        }
      if (event.sources || event.images)
        pending = {
          ...pending,
          sources: event.sources || pending.sources,
          coverage: event.coverage,
          webImages: event.images || pending.webImages
        }
      if (event.type === 'result')
        pending = {
          ...pending,
          content: event.result || '',
          proposals: event.proposals,
          analysisProgress: undefined
        }
      replacePendingMessageInActiveTab({ ...pending })
    }
    try {
      if (upload) {
        const vision = activeTab === 'vision'
        const data = new FormData()
        data.append(vision ? 'image' : 'file', upload)
        data.append('prompt', requestPrompt)
        data.append('history', JSON.stringify(history))
        data.append('session_id', sessionId)
        const response = await apiFetch(
          vision ? '/api/vision/analyze' : '/api/document/analyze-stream',
          { method: 'POST', body: data, signal: controller.signal }
        )
        if (vision) {
          const result = await response.json()
          if (result.attachment) rememberAttachment(result.attachment)
          pending = {
            role: 'assistant',
            content: result.result,
            visualAnalysis: result.visual_analysis,
            sources: result.sources,
            coverage: result.coverage
          }
          replacePendingMessageInActiveTab(pending)
        } else await consumeStream(response, onEvent)
      } else if (activeTab === 'code' && agentMode) {
        const response = await apiFetch('/api/agent/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          signal: controller.signal,
          body: JSON.stringify({ prompt: requestPrompt, session_id: sessionId, max_iterations: 5 })
        })
        const result = await response.json()
        pending = { role: 'assistant', content: result.result, proposals: result.proposals }
        replacePendingMessageInActiveTab(pending)
      } else {
        const response = await apiFetch('/api/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          signal: controller.signal,
          body: JSON.stringify({
            prompt: requestPrompt,
            target: tabDetails[activeTab].target,
            history,
            session_id: sessionId,
            project_id: currentSession.projectId || null,
            attachment_ids: (currentSession.attachments || []).map((a) => a.id),
            web_mode: activeTab === 'chat' ? webMode : 'off'
          })
        })
        await consumeStream(response, onEvent)
      }
    } catch (error) {
      const reason = controller.signal.aborted
        ? 'Dihentikan oleh pengguna.'
        : error instanceof Error
          ? error.message
          : 'Permintaan gagal.'
      replacePendingMessageInActiveTab({
        ...pending,
        analysisProgress: undefined,
        content: (pending.content ? pending.content + '\n\n' : '') + '⚠️ ' + reason
      })
    } finally {
      abortRef.current = null
      setLoading(false)
    }
  }

  const handleProposal = async (id: string, approve: boolean): Promise<void> => {
    await apiFetch('/api/agent/proposals/' + id, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: currentSession.id, approve })
    })
    setMessagesInActiveSession((messages) =>
      messages.map((m) => ({
        ...m,
        proposals: m.proposals?.map((p) =>
          p.id === id ? { ...p, state: approve ? 'applied' : 'rejected' } : p
        )
      }))
    )
  }

  const renderAssistantMessage = (raw: string): JSX.Element => <MarkdownAnswer text={raw} />

  const renderAnalysisProgress = (progress: AnalysisProgress): JSX.Element => (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center gap-2 py-2 text-sm text-emerald-300"
    >
      <Loader2 size={15} className="animate-spin" />
      <span>
        {progress.label}
        {progress.detail ? ': ' + progress.detail : ''}
      </span>
    </div>
  )

  const detachAttachment = async (id: string): Promise<void> => {
    await apiFetch(
      '/api/attachments/' + id + '?session_id=' + encodeURIComponent(currentSession.id),
      { method: 'DELETE' }
    )
    setSessionsByTab((prev) => ({
      ...prev,
      [activeTab]: prev[activeTab].map((s) =>
        s.id === currentSession.id
          ? { ...s, attachments: s.attachments?.filter((a) => a.id !== id) }
          : s
      )
    }))
  }

  const activeDetail = tabDetails[activeTab]

  return (
    <div className="agent-shell flex h-[100dvh] w-screen flex-col overflow-hidden bg-[#080b12] font-sans text-slate-100 antialiased lg:flex-row">
      {needsAuth && (
        <Connection
          onConnected={() => {
            setNeedsAuth(false)
            setConnectionVersion((v) => v + 1)
          }}
        />
      )}
      <WorkspaceSidebar
        collapsed={sidebarCollapsed}
        onCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        sessions={sessionsByTab}
        currentId={currentSession.id}
        projects={projects}
        selectedProject={selectedProject}
        onProject={(id) => {
          setSelectedProject(id)
          setView('chat')
        }}
        onNewProject={() => {
          if (projects.length < 500) setProjectEditor('new')
          else setWorkspaceNotice('Batas 500 project tercapai.')
        }}
        onEditProject={setProjectEditor}
        onSelect={selectSession}
        onManage={setSessionEditor}
        onNewChat={handleNewChat}
        onSettings={() => setSettingsOpen(true)}
        onSecurity={() => {
          setView('security')
          if (window.innerWidth < 1024) setSidebarCollapsed(true)
        }}
        onWebSearch={() => {
          setView('search')
          if (window.innerWidth < 1024) setSidebarCollapsed(true)
        }}
        onUsage={() => {
          setView('usage')
          if (window.innerWidth < 1024) setSidebarCollapsed(true)
        }}
        disabled={loading || !ready}
        name={preferences.name}
        connection={connectionState}
      />
      <main className="workspace-main relative flex min-h-0 min-w-0 flex-1 flex-col">
        <header className="workspace-header">
          <div className="header-left">
            <button
              className="icon-button"
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              aria-label={sidebarCollapsed ? 'Buka sidebar' : 'Tutup sidebar'}
            >
              <Menu size={20} />
            </button>
            {view === 'chat' ? (
              <div className="model-picker">
                <span>Jo Workspace</span>
                <select
                  aria-label="Pilih mode"
                  value={activeTab}
                  disabled={loading}
                  onChange={(e) => selectTab(e.target.value as TabType)}
                >
                  {(Object.keys(tabDetails) as TabType[]).map((key) => (
                    <option key={key} value={key}>
                      {modeLabels[key]}
                    </option>
                  ))}
                </select>
                <span className="model-label">{activeDetail.badge}</span>
              </div>
            ) : (
              <button
                className="secondary-button"
                onClick={() => {
                  setView('chat')
                  if (activeTab === 'pentest') setActiveTab('chat')
                }}
              >
                <MessageSquare size={16} />
                Kembali ke chat
              </button>
            )}
          </div>
          <div className="header-actions">
            <span
              className={`connection-indicator ${connectionState === 'Terhubung' ? 'online' : ''}`}
              title={`${connectionState} · ${gpuName} · ${gpuStats.used}/${gpuStats.total} MB VRAM`}
            >
              <i />
              {connectionState}
            </span>
            <button
              className="icon-button"
              onClick={() => setView(view === 'usage' ? 'chat' : 'usage')}
              aria-label="Buka Usage"
            >
              <ChartNoAxesCombined size={18} />
            </button>
            <button
              className="icon-button"
              onClick={() => setSettingsOpen(true)}
              aria-label="Buka Settings"
            >
              <Settings2 size={18} />
            </button>
            <button
              className="icon-button"
              disabled={loading || !ready}
              onClick={handleNewChat}
              aria-label="Chat baru"
            >
              <Plus size={20} />
            </button>
          </div>
        </header>
        {view === 'security' ? (
          <SecurityWorkspace
            key={connectionVersion}
            projects={projects}
            projectId={selectedProject}
            onProject={setSelectedProject}
            onCreateProject={() => setProjectEditor('new')}
          />
        ) : view === 'search' ? (
          <SearchWorkspace />
        ) : view === 'usage' ? (
          <div className="usage-scroll scrollbar-thin">
            <Usage />
          </div>
        ) : (
          <>
            <div className="conversation-breadcrumb">
              <span>
                {currentProject ? (
                  <>
                    <Folder size={14} />
                    {currentProject.name}
                  </>
                ) : (
                  'Tanpa project'
                )}
                <span>/</span>
                <strong>{currentSession.title}</strong>
              </span>
              <button
                className="text-button"
                disabled={loading || !ready}
                onClick={() => setSessionEditor({ tab: activeTab, session: currentSession })}
              >
                Kelola chat
              </button>
            </div>
            {selectedProject !== 'all' &&
              selectedProject !== (currentSession.projectId || 'none') && (
                <div className="project-context-notice">
                  Sidebar difilter:{' '}
                  {projects.find((p) => p.id === selectedProject)?.name || 'Tanpa project'}. Chat
                  baru akan dibuat dalam kelompok ini.
                  <button onClick={handleNewChat} disabled={loading || !ready}>
                    Buat chat di sini
                  </button>
                </div>
              )}
            {workspaceNotice && (
              <div className="notice" role="status">
                {workspaceNotice}
                <button
                  className="icon-button"
                  aria-label="Tutup pemberitahuan"
                  onClick={() => setWorkspaceNotice('')}
                >
                  <X size={14} />
                </button>
              </div>
            )}
            {activeTab === 'pentest' ||
            activeTab === 'code' ||
            currentSession.attachments?.length ||
            loading ||
            storageError ? (
              <div className="conversation-toolbar flex min-h-12 flex-wrap items-center justify-between gap-3 border-b border-white/[.04] px-4 py-2 text-xs text-slate-300 sm:px-8">
                {activeTab === 'pentest' ? (
                  <div className="flex rounded-xl border border-white/[.07] bg-black/20 p-1">
                    {(
                      [
                        ['pentest', 'Pentest otomatis'],
                        ['chat', 'Konsultasi AI']
                      ] as const
                    ).map(([view, label]) => (
                      <button
                        key={view}
                        type="button"
                        onClick={() => setSecurityView(view)}
                        className={`rounded-lg px-3 py-2 font-medium transition sm:px-4 ${
                          securityView === view
                            ? 'bg-rose-400/15 text-rose-200'
                            : 'text-slate-500 hover:text-slate-300'
                        }`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                ) : (
                  <span />
                )}
                {activeTab === 'code' && (
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={agentMode}
                      disabled={loading}
                      onChange={(e) => setAgentMode(e.target.checked)}
                    />
                    Gunakan tools workspace (perubahan perlu persetujuan)
                  </label>
                )}
                {(currentSession.attachments || []).map((a) => (
                  <span
                    key={a.id}
                    className="flex items-center gap-2 rounded border border-slate-600 px-2 py-1"
                  >
                    {a.filename}
                    <button
                      disabled={loading}
                      aria-label={'Lepas ' + a.filename}
                      onClick={() => {
                        void detachAttachment(a.id).catch((e) => setFileError(e.message))
                      }}
                    >
                      ×
                    </button>
                  </span>
                ))}
                {loading && (
                  <button
                    className="rounded bg-rose-700 px-3 py-1 text-white"
                    onClick={() => abortRef.current?.abort()}
                  >
                    Stop
                  </button>
                )}
                {storageError && (
                  <p role="alert" className="text-amber-200">
                    {storageError}
                  </p>
                )}
              </div>
            ) : null}
            {activeTab === 'pentest' && securityView === 'pentest' && !needsAuth ? (
              <SecurityWorkspace
                key={connectionVersion}
                projects={projects}
                projectId={selectedProject}
                onProject={setSelectedProject}
                onCreateProject={() => setProjectEditor('new')}
              />
            ) : (
              <>
                {/* Message Thread */}
                <div className="scrollbar-thin min-h-0 flex-1 space-y-5 overflow-y-auto overscroll-contain px-3 py-4 sm:space-y-6 sm:px-8 sm:py-8">
                  {currentMessages.length === 0 ? (
                    <div className="mx-auto flex min-h-full max-w-3xl flex-col items-center justify-center py-5 text-center sm:pb-12">
                      <BrandMark large />
                      <p className="welcome-eyebrow">RUANG UNTUK IDE ANDA</p>
                      <h3 className="welcome-title">
                        {preferences.name
                          ? `Apa yang ingin Anda kerjakan, ${preferences.name}?`
                          : 'Apa yang ingin Anda kerjakan?'}
                      </h3>
                      <p className="welcome-description">
                        {currentProject
                          ? `Bersama membangun ${currentProject.name}.`
                          : activeDetail.desc}
                      </p>
                      {preferences.showSuggestions && (
                        <div className="suggestion-grid scrollbar-hidden mt-5 flex w-full snap-x snap-mandatory gap-2 overflow-x-auto pb-2 text-left sm:mt-7 sm:grid sm:grid-cols-3 sm:overflow-visible sm:pb-0">
                          {activeDetail.suggestions.map((suggestion, index) => (
                            <button
                              key={suggestion}
                              type="button"
                              onClick={(): void => setPrompt(suggestion)}
                              className="group min-w-[82%] snap-center rounded-2xl border border-white/[.08] bg-white/[.035] p-4 transition hover:-translate-y-0.5 hover:border-white/[.14] hover:bg-white/[.055] sm:min-w-0 sm:rounded-xl"
                            >
                              <span className="mb-4 flex items-center justify-between text-xs text-slate-600 sm:mb-5">
                                <span>0{index + 1}</span>
                                <ArrowUpRight
                                  size={13}
                                  className="opacity-0 transition group-hover:opacity-100"
                                />
                              </span>
                              <span className="block text-sm leading-5 text-slate-300 group-hover:text-white">
                                {suggestion}
                              </span>
                            </button>
                          ))}
                        </div>
                      )}
                      <div className="mt-4 flex gap-4 text-xs text-slate-600 sm:mt-6">
                        <span className="flex items-center gap-1.5">
                          <HardDrive size={13} /> Data tetap lokal
                        </span>
                        <span className="flex items-center gap-1.5">
                          <Zap size={13} /> {gpuStats.total ? 'GPU accelerated' : 'Ollama runtime'}
                        </span>
                      </div>
                    </div>
                  ) : (
                    currentMessages.map((msg, idx) => (
                      <div
                        key={idx}
                        className={`mx-auto flex max-w-4xl gap-3 sm:gap-4 ${
                          msg.role === 'user' ? 'justify-end' : 'justify-start'
                        }`}
                      >
                        {msg.role === 'assistant' && (
                          <div className="mt-1 hidden h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 sm:flex">
                            <Bot size={16} />
                          </div>
                        )}

                        <div className="group relative max-w-[94%] sm:max-w-[85%]">
                          <div
                            className={`rounded-2xl px-4 py-3 text-[15px] leading-6 sm:px-5 sm:py-3.5 sm:text-base ${
                              msg.role === 'user'
                                ? 'message-user whitespace-pre-wrap'
                                : 'message-assistant'
                            }`}
                          >
                            <MessageImage blob={msg.imageBlob} fallback={msg.image} />
                            {msg.role === 'assistant' ? (
                              <>
                                {msg.visualAnalysis && (
                                  <details className="group mb-2 rounded-lg border border-violet-500/15 bg-violet-500/5 text-[11px] font-sans">
                                    <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2 text-violet-300/70 hover:text-violet-200">
                                      <span className="flex items-center gap-2">
                                        <Image size={13} />
                                        Analisis visual — MiniCPM-V
                                      </span>
                                      <ChevronDown
                                        size={13}
                                        className="transition-transform group-open:rotate-180"
                                      />
                                    </summary>
                                    <div className="max-h-40 overflow-y-auto border-t border-violet-500/10 px-3 py-2 whitespace-pre-wrap text-[10px] leading-relaxed text-slate-400">
                                      {msg.visualAnalysis}
                                    </div>
                                  </details>
                                )}
                                {msg.analysisProgress
                                  ? renderAnalysisProgress(msg.analysisProgress)
                                  : msg.content
                                    ? renderAssistantMessage(msg.content)
                                    : loading && idx === currentMessages.length - 1
                                      ? 'Menunggu respons model...'
                                      : ''}
                                <MessageDetails message={msg} onProposal={handleProposal} />
                              </>
                            ) : (
                              msg.content && <div>{msg.content}</div>
                            )}
                          </div>

                          {msg.role === 'assistant' && msg.content && (
                            <button
                              onClick={(): void => copyToClipboard(msg.content, idx)}
                              className="absolute right-2 top-2 grid h-8 w-8 place-items-center rounded-lg border border-slate-700/60 bg-slate-800/90 text-slate-400 opacity-100 transition-opacity hover:text-white sm:opacity-0 sm:group-hover:opacity-100"
                              title="Salin Pesan"
                            >
                              {copiedIndex === idx ? (
                                <Check size={12} className="text-emerald-400" />
                              ) : (
                                <Copy size={12} />
                              )}
                            </button>
                          )}
                        </div>

                        {msg.role === 'user' && (
                          <div className="mt-1 hidden h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-slate-700 bg-slate-800 text-slate-300 sm:flex">
                            <User size={16} />
                          </div>
                        )}
                      </div>
                    ))
                  )}
                  <div ref={messagesEndRef} />
                </div>

                {/* Input Bar */}
                <div className="composer-area shrink-0 border-t border-white/[.06] bg-[#0b0f17]/90 p-3 backdrop-blur-xl sm:p-5">
                  {activeTab === 'chat' && (
                    <div className="mx-auto mb-2 flex max-w-4xl items-center gap-2 px-2 text-xs text-slate-400">
                      <span>Web</span>
                      <select
                        aria-label="Mode pencarian web chat"
                        value={webMode}
                        onChange={(event) =>
                          setWebMode(event.target.value as 'auto' | 'on' | 'off')
                        }
                        disabled={loading}
                        className="rounded border border-white/10 bg-slate-900 px-2 py-1 text-slate-200"
                      >
                        <option value="auto">Otomatis</option>
                        <option value="on">Selalu cari</option>
                        <option value="off">Mati</option>
                      </select>
                      <span>Hasil dan gambar tampil bersama jawaban dengan sumbernya.</span>
                    </div>
                  )}
                  <div className="composer mx-auto flex max-w-4xl items-end gap-2 rounded-2xl border border-white/[.09] bg-white/[.04] p-1.5 shadow-[0_10px_35px_rgba(0,0,0,.17)] transition-colors focus-within:border-emerald-400/45 focus-within:bg-white/[.055] sm:items-center sm:gap-3 sm:p-2">
                    <div className="flex-1 min-w-0">
                      {imagePreviewUrl && (
                        <div className="flex items-center gap-2 px-3 pt-1 text-[11px] text-slate-300">
                          <img
                            src={imagePreviewUrl}
                            alt="Pasted screenshot"
                            className="h-14 w-14 rounded object-cover"
                          />
                          <span className="text-slate-400">Screenshot terlampir</span>
                          <button
                            type="button"
                            onClick={handleRemoveImage}
                            className="text-slate-500 hover:text-rose-400"
                            title="Hapus screenshot"
                          >
                            <X size={14} />
                          </button>
                        </div>
                      )}
                      {selectedFile && (
                        <div className="flex items-center gap-2 px-3 pt-1 text-[11px] text-slate-300">
                          <span className="truncate">📄 {selectedFile.name}</span>
                          <button
                            type="button"
                            onClick={removeFile}
                            className="shrink-0 text-slate-500 hover:text-rose-400"
                            title="Hapus lampiran"
                          >
                            <X size={14} />
                          </button>
                        </div>
                      )}
                      {fileError && (
                        <div className="px-3 text-[10px] text-rose-400">{fileError}</div>
                      )}
                      <div className="flex items-center">
                        <input
                          type="file"
                          ref={fileInputRef}
                          onChange={handleFileChange}
                          className="hidden"
                          accept={canUploadFile ? fileAccept : undefined}
                        />
                        <button
                          type="button"
                          onClick={triggerFileSelect}
                          disabled={!canUploadFile || loading}
                          aria-label={canUploadFile ? 'Lampirkan file' : 'Lampiran tidak tersedia'}
                          className="grid h-11 w-11 shrink-0 place-items-center rounded-xl text-slate-400 transition-colors hover:bg-white/[.05] hover:text-emerald-400 disabled:opacity-30 disabled:hover:text-slate-400"
                          title={
                            canUploadFile ? 'Lampirkan file' : 'Pilih Vision atau Document Parser'
                          }
                        >
                          <Paperclip size={16} />
                        </button>
                        <textarea
                          rows={1}
                          value={prompt}
                          onChange={(e): void => {
                            setPrompt(e.target.value)
                            e.target.style.height = 'auto'
                            e.target.style.height = Math.min(e.target.scrollHeight, 160) + 'px'
                          }}
                          onPaste={handlePaste}
                          aria-label="Pesan untuk AI"
                          onKeyDown={(e): void => {
                            if (
                              e.key === 'Enter' &&
                              !e.nativeEvent.isComposing &&
                              (e.ctrlKey || e.metaKey || (preferences.sendWithEnter && !e.shiftKey))
                            ) {
                              e.preventDefault()
                              void handleSend()
                            }
                          }}
                          placeholder={`Tanyakan apa saja · ${modeLabels[activeTab]}`}
                          className="min-h-11 min-w-0 flex-1 resize-none bg-transparent px-1 py-2.5 text-base leading-6 text-slate-100 placeholder-slate-500 focus:outline-none sm:max-h-28 sm:px-2 sm:text-sm"
                        />
                      </div>
                    </div>
                    <button
                      onClick={(): void => {
                        if (loading) abortRef.current?.abort()
                        else void handleSend()
                      }}
                      disabled={
                        !ready ||
                        needsAuth ||
                        (!loading && !prompt.trim() && !selectedFile && !imageFile)
                      }
                      aria-label={loading ? 'Hentikan respons' : 'Kirim pesan'}
                      className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-emerald-400 font-semibold text-slate-950 shadow-md shadow-emerald-950/30 transition-all hover:bg-emerald-300 disabled:opacity-40 disabled:hover:bg-emerald-400 sm:flex sm:w-auto sm:gap-2 sm:px-4 sm:text-sm"
                    >
                      {loading ? (
                        <Square size={16} fill="currentColor" />
                      ) : (
                        <>
                          <ArrowUp size={20} />
                        </>
                      )}
                    </button>
                  </div>
                  <div className="mx-auto mt-2 hidden max-w-4xl items-center justify-between px-2 text-xs text-slate-600 sm:flex">
                    <span>
                      {canUploadFile
                        ? 'Lampiran diaktifkan untuk mode ini'
                        : 'AI dapat keliru. Periksa kembali informasi penting.'}
                    </span>
                    <span className="hidden sm:flex items-center gap-1">
                      <Command size={11} />{' '}
                      {preferences.sendWithEnter
                        ? 'Enter kirim · Shift + Enter baris baru'
                        : 'Ctrl + Enter untuk kirim'}
                    </span>
                  </div>
                </div>
              </>
            )}
          </>
        )}
      </main>

      <nav
        className="mobile-tabbar flex shrink-0 items-stretch border-t border-white/[.07] bg-[#0b0f17]/95 px-1 pt-1 backdrop-blur-xl lg:hidden"
        aria-label="Navigasi modul"
      >
        {(Object.keys(tabDetails) as TabType[]).map((key) => {
          const item = tabDetails[key]
          const ItemIcon = item.icon
          const isActive = activeTab === key

          return (
            <button
              key={key}
              type="button"
              onClick={(): void => selectTab(key)}
              aria-current={isActive ? 'page' : undefined}
              className={`flex min-h-14 min-w-0 flex-1 flex-col items-center justify-center gap-1 rounded-xl px-1 text-xs font-medium transition-colors ${
                isActive
                  ? 'bg-white/[.06] text-white'
                  : 'text-slate-500 hover:bg-white/[.035] hover:text-slate-300'
              }`}
            >
              <ItemIcon size={19} className={isActive ? item.color : 'text-slate-500'} />
              <span className="w-full truncate">{MOBILE_TAB_LABELS[key]}</span>
            </button>
          )
        })}
      </nav>
      {settingsOpen && (
        <Settings
          preferences={preferences}
          setPreferences={setPreferences}
          preferenceError={preferenceError}
          onClose={() => setSettingsOpen(false)}
          onDisconnect={disconnectSession}
          onExport={() =>
            downloadFile(
              'jo-workspace-backup.json',
              exportBackup(sessionsByTab, projects, preferences)
            )
          }
          onImport={importData}
          onClearAll={clearAll}
          onArchiveAll={() =>
            setSessionsByTab(
              (prev) =>
                Object.fromEntries(
                  TAB_TYPES.map((tab) => [
                    tab,
                    prev[tab].map((session) => ({ ...session, archived: true }))
                  ])
                ) as typeof prev
            )
          }
          counts={{
            chats: TAB_TYPES.reduce(
              (n, tab) =>
                n +
                sessionsByTab[tab].filter(
                  (s) =>
                    s.messages.length ||
                    s.title !== 'Percakapan baru' ||
                    s.projectId ||
                    s.pinned ||
                    s.archived ||
                    s.id === currentSession.id
                ).length,
              0
            ),
            projects: projects.length,
            messages: TAB_TYPES.reduce(
              (n, tab) =>
                n + sessionsByTab[tab].reduce((sum, session) => sum + session.messages.length, 0),
              0
            )
          }}
          disabled={loading || !ready}
        />
      )}
      {projectEditor && (
        <ProjectEditor
          project={projectEditor === 'new' ? null : projectEditor}
          onClose={() => setProjectEditor(null)}
          onSave={(name, instructions) => {
            const project =
              projectEditor === 'new'
                ? { id: crypto.randomUUID(), createdAt: Date.now(), name, instructions }
                : { ...projectEditor, name, instructions }
            setProjects((prev) =>
              projectEditor === 'new'
                ? [...prev, project]
                : prev.map((p) => (p.id === project.id ? project : p))
            )
            setSelectedProject(project.id)
            setProjectEditor(null)
          }}
          onDelete={async () => {
            if (projectEditor === 'new') return
            const id = projectEditor.id
            await assertProjectsRemovable([id])
            setProjects((prev) => prev.filter((p) => p.id !== id))
            setSessionsByTab(
              (prev) =>
                Object.fromEntries(
                  TAB_TYPES.map((tab) => [
                    tab,
                    prev[tab].map((s) => (s.projectId === id ? { ...s, projectId: undefined } : s))
                  ])
                ) as typeof prev
            )
            setSelectedProject('all')
            setProjectEditor(null)
          }}
        />
      )}
      {sessionEditor && (
        <SessionEditor
          session={sessionEditor.session}
          projects={projects}
          onClose={() => setSessionEditor(null)}
          onSave={editSession}
          onDelete={deleteSession}
        />
      )}
    </div>
  )
}
