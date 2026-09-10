import { useState, useRef, useEffect, JSX, ChangeEvent, ClipboardEvent } from 'react'
import {
  MessageSquare,
  Code2,
  FileText,
  Image,
  ShieldAlert,
  Send,
  Loader2,
  Cpu,
  Terminal,
  Sparkles,
  Bot,
  User,
  Copy,
  Check,
  ChevronDown,
  Paperclip,
  X,
  Menu,
  PanelLeftClose,
  Plus,
  Trash2,
  Zap,
  HardDrive,
  Command,
  ArrowUpRight
} from 'lucide-react'

interface AnalysisProgress {
  step: string
  label: string
  detail?: string
  completedSteps: string[]
}

interface Message {
  role: 'user' | 'assistant'
  content: string
  image?: string
  visualAnalysis?: string
  analysisProgress?: AnalysisProgress
}

type TabType = 'chat' | 'code' | 'vision' | 'docs' | 'pentest'
interface ChatSession {
  id: string
  title: string
  createdAt: number
  updatedAt: number
  messages: Message[]
}

type ChatSessionMap = Record<TabType, ChatSession[]>
type ActiveSessionMap = Record<TabType, string>

const CHAT_HISTORY_STORAGE_KEY = 'agent_os_chat_history'
const TAB_TYPES: TabType[] = ['chat', 'code', 'vision', 'docs', 'pentest']
const MOBILE_TAB_LABELS: Record<TabType, string> = {
  chat: 'Chat',
  code: 'Code',
  vision: 'Vision',
  docs: 'Dokumen',
  pentest: 'Security'
}

// When the renderer is served by FastAPI, API requests use the same HTTPS
// origin exposed by Tailscale Serve. Electron continues to use local FastAPI.
const configuredApiBaseUrl = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '')
const API_BASE_URL =
  configuredApiBaseUrl ||
  (window.location.protocol === 'http:' || window.location.protocol === 'https:'
    ? window.location.origin
    : 'http://127.0.0.1:8000')

const apiUrl = (path: string): string => `${API_BASE_URL}${path}`

const createSession = (): ChatSession => {
  const now = Date.now()
  return {
    id: `${now}-${Math.random().toString(36).slice(2, 8)}`,
    title: 'Percakapan baru',
    createdAt: now,
    updatedAt: now,
    messages: []
  }
}

const createInitialSessions = (): {
  sessions: ChatSessionMap
  activeSessions: ActiveSessionMap
} => {
  const sessions = {} as ChatSessionMap
  const activeSessions = {} as ActiveSessionMap
  TAB_TYPES.forEach((tab) => {
    const session = createSession()
    sessions[tab] = [session]
    activeSessions[tab] = session.id
  })
  return { sessions, activeSessions }
}

const loadChatSessions = (): { sessions: ChatSessionMap; activeSessions: ActiveSessionMap } => {
  const initial = createInitialSessions()
  try {
    const saved = localStorage.getItem(CHAT_HISTORY_STORAGE_KEY)
    if (!saved) return initial

    const parsed = JSON.parse(saved) as {
      sessions?: Partial<ChatSessionMap>
      activeSessions?: Partial<ActiveSessionMap>
    } & Partial<Record<TabType, Message[]>>
    const sessions = {} as ChatSessionMap
    const activeSessions = {} as ActiveSessionMap

    TAB_TYPES.forEach((tab) => {
      const storedSessions = parsed.sessions?.[tab]
      const legacyMessages = parsed[tab]
      const tabSessions = Array.isArray(storedSessions)
        ? storedSessions.filter((session) => Array.isArray(session.messages))
        : Array.isArray(legacyMessages) && legacyMessages.length > 0
          ? [{ ...createSession(), title: 'Riwayat sebelumnya', messages: legacyMessages }]
          : initial.sessions[tab]
      sessions[tab] = tabSessions.length > 0 ? tabSessions : initial.sessions[tab]
      activeSessions[tab] = sessions[tab].some(
        (session) => session.id === parsed.activeSessions?.[tab]
      )
        ? parsed.activeSessions![tab]!
        : sessions[tab][0].id
    })

    return { sessions, activeSessions }
  } catch {
    return initial
  }
}

export default function App(): JSX.Element {
  const [activeTab, setActiveTab] = useState<TabType>('chat')
  const [prompt, setPrompt] = useState('')
  const [storedChatSessions] = useState(loadChatSessions)
  const [sessionsByTab, setSessionsByTab] = useState<ChatSessionMap>(storedChatSessions.sessions)
  const [activeSessions, setActiveSessions] = useState<ActiveSessionMap>(
    storedChatSessions.activeSessions
  )
  const [loading, setLoading] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => window.innerWidth < 1024)
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null)
  const [gpuStats, setGpuStats] = useState({ used: 0, total: 6144, percent: 0 })
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState('')
  const [imageFile, setImageFile] = useState<File | null>(null)
  const [imagePreviewUrl, setImagePreviewUrl] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const imageUrlsRef = useRef<Set<string>>(new Set())
  const currentSession =
    sessionsByTab[activeTab].find((session) => session.id === activeSessions[activeTab]) ??
    sessionsByTab[activeTab][0]
  const currentMessages = currentSession.messages

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
              messages: [...session.messages, message]
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
          ? { ...session, updatedAt: Date.now(), messages: updater(session.messages) }
          : session
      )
    }))
  }

  const handleClearCurrentChat = (): void => {
    setMessagesInActiveSession(() => [])
  }

  const handleNewChat = (): void => {
    if (loading) return
    const session = createSession()
    setSessionsByTab((prev) => ({ ...prev, [activeTab]: [session, ...prev[activeTab]] }))
    setActiveSessions((prev) => ({ ...prev, [activeTab]: session.id }))
    setPrompt('')
  }

  const tabDetails = {
    chat: {
      title: 'Chat & Reasoning',
      desc: 'Ruang kerja untuk berpikir, merencanakan, dan mengeksekusi.',
      target: 'reasoning',
      icon: MessageSquare,
      color: 'text-emerald-400',
      badge: 'Qwen 9B',
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
      badge: 'Qwen 9B',
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
      badge: 'Vision Engine',
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
      badge: 'Audit Engine',
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
    scrollToBottom()
  }, [activeTab, currentMessages])

  useEffect(() => {
    localStorage.setItem(
      CHAT_HISTORY_STORAGE_KEY,
      JSON.stringify({ sessions: sessionsByTab, activeSessions })
    )
  }, [sessionsByTab, activeSessions])

  useEffect(() => {
    const fetchGpu = async (): Promise<void> => {
      try {
        const res = await fetch(apiUrl('/api/gpu-status'))
        const data = await res.json()
        setGpuStats({
          used: data.vram_used_mb,
          total: data.vram_total_mb,
          percent: data.usage_percent
        })
      } catch {
        // Abaikan jika server belum terhubung
      }
    }

    void fetchGpu()
    const interval = setInterval(() => {
      void fetchGpu()
    }, 3000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const imageUrls = imageUrlsRef.current
    return () => {
      imageUrls.forEach((url) => URL.revokeObjectURL(url))
      imageUrls.clear()
    }
  }, [])

  const copyToClipboard = (text: string, index: number): void => {
    void navigator.clipboard.writeText(text)
    setCopiedIndex(index)
    setTimeout(() => setCopiedIndex(null), 2000)
  }

  const canUploadFile = activeTab === 'vision' || activeTab === 'docs'
  const fileAccept = activeTab === 'vision' ? '.png,.jpg,.webp' : '.pdf,.docx,.xlsx,.txt'

  const isAllowedFile = (file: File): boolean => {
    const extension = file.name.toLowerCase().split('.').pop()
    const allowedExtensions =
      activeTab === 'vision' ? ['png', 'jpg', 'webp'] : ['pdf', 'docx', 'xlsx', 'txt']
    return canUploadFile && extension !== undefined && allowedExtensions.includes(extension)
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
    if (activeTab !== 'vision') return

    const imageItem = Array.from(event.clipboardData.items).find((item) =>
      item.type.startsWith('image/')
    )
    if (!imageItem) return

    event.preventDefault()
    const file = imageItem.getAsFile()
    if (!file) return

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

  const handleRemoveImage = (): void => {
    if (imagePreviewUrl) {
      URL.revokeObjectURL(imagePreviewUrl)
      imageUrlsRef.current.delete(imagePreviewUrl)
    }
    setImageFile(null)
    setImagePreviewUrl(null)
  }

  const fileToBase64 = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.readAsDataURL(file)
      reader.onload = (): void => resolve(reader.result as string)
      reader.onerror = reject
    })
  }

  const handleSend = async (): Promise<void> => {
    if ((!prompt.trim() && !selectedFile && !imageFile) || loading) return
    const conversationHistory = currentMessages
      .filter((message) => message.content.trim())
      .slice(-12)
      .map(({ role, content }) => ({ role, content }))

    if (imageFile) {
      const imageToSend = imageFile
      const userText = prompt.trim()
      let base64Image: string

      try {
        base64Image = await fileToBase64(imageToSend)
      } catch {
        setFileError('Gagal membaca screenshot dari clipboard.')
        return
      }

      const formData = new FormData()
      formData.append('image', imageToSend)
      formData.append('prompt', userText || 'Jelaskan screenshot ini secara detail.')
      formData.append('history', JSON.stringify(conversationHistory))

      setPrompt('')
      handleRemoveImage()
      appendMessageToActiveTab({
        role: 'user',
        content: userText,
        image: base64Image
      })
      appendMessageToActiveTab({ role: 'assistant', content: '' })
      setLoading(true)

      try {
        const response = await fetch(apiUrl('/api/vision/analyze'), {
          method: 'POST',
          body: formData
        })
        if (!response.ok) throw new Error(`Vision upload failed with HTTP ${response.status}`)

        const data: { result?: string; detail?: string; visual_analysis?: string } =
          await response.json()
        replacePendingMessageInActiveTab({
          role: 'assistant',
          content: data.result ?? data.detail ?? 'Tidak ada hasil analisis.',
          visualAnalysis: data.visual_analysis
        })
      } catch {
        setMessagesInActiveSession((prev) => [
          ...prev.slice(0, -1),
          {
            role: 'assistant',
            content: '⚠️ Gagal menganalisis screenshot melalui backend FastAPI.'
          }
        ])
      } finally {
        setLoading(false)
      }
      return
    }

    if (selectedFile) {
      const fileToSend = selectedFile
      if (!isAllowedFile(fileToSend)) {
        setFileError(
          !canUploadFile
            ? 'Pilih tab Vision atau Document Parser untuk melampirkan file.'
            : activeTab === 'vision'
              ? 'Mode Vision hanya menerima file PNG, JPG, atau WEBP.'
              : 'Document Parser hanya menerima file PDF, DOCX, XLSX, atau TXT.'
        )
        return
      }
      const userText = prompt.trim()
      const isVisionFile = activeTab === 'vision'
      const formData = new FormData()
      formData.append(isVisionFile ? 'image' : 'file', fileToSend)
      formData.append(
        'prompt',
        userText ||
          (isVisionFile
            ? 'Jelaskan file gambar ini secara detail.'
            : 'Tolong analisis isi dokumen ini.')
      )
      formData.append('history', JSON.stringify(conversationHistory))

      setPrompt('')
      removeFile()
      appendMessageToActiveTab({
        role: 'user',
        content: `${fileToSend.name}${userText ? `\n${userText}` : ''}`
      })
      appendMessageToActiveTab({
        role: 'assistant',
        content: '',
        analysisProgress: isVisionFile
          ? undefined
          : {
              step: 'uploading',
              label: 'Mengunggah dokumen',
              detail: 'Menyiapkan file untuk diproses.',
              completedSteps: []
            }
      })
      setLoading(true)

      try {
        const targetUrl = isVisionFile
          ? apiUrl('/api/vision/analyze')
          : apiUrl('/api/document/analyze-stream')
        const response = await fetch(targetUrl, {
          method: 'POST',
          body: formData
        })

        if (!response.ok) throw new Error(`Upload failed with HTTP ${response.status}`)

        if (isVisionFile) {
          const data: { result?: string; detail?: string; visual_analysis?: string } =
            await response.json()
          replacePendingMessageInActiveTab({
            role: 'assistant',
            content: data.result ?? data.detail ?? 'Tidak ada hasil dari backend.',
            visualAnalysis: data.visual_analysis
          })
        } else {
          if (!response.body) throw new Error('No document stream body')

          const reader = response.body.getReader()
          const decoder = new TextDecoder()
          const completedSteps: string[] = []
          let buffer = ''
          let result = ''

          const processDocumentStreamLine = (line: string): void => {
            const trimmed = line.trim()
            if (!trimmed.startsWith('data:')) return

            const payload = JSON.parse(trimmed.slice(5).trim()) as {
              type?: 'status' | 'result' | 'error'
              step?: string
              label?: string
              detail?: string
              result?: string
            }

            if (payload.type === 'error') {
              throw new Error(payload.detail || 'Document analysis failed')
            }

            if (payload.type === 'result') {
              result = payload.result || ''
              replacePendingMessageInActiveTab({
                role: 'assistant',
                content: result || 'Tidak ada hasil dari backend.'
              })
              return
            }

            if (payload.type === 'status' && payload.step && payload.label) {
              const previousStep = completedSteps.at(-1)
              if (previousStep && !completedSteps.includes(previousStep)) {
                completedSteps.push(previousStep)
              }
              if (!completedSteps.includes(payload.step)) completedSteps.push(payload.step)
              replacePendingMessageInActiveTab({
                role: 'assistant',
                content: '',
                analysisProgress: {
                  step: payload.step,
                  label: payload.label,
                  detail: payload.detail,
                  completedSteps: completedSteps.slice(0, -1)
                }
              })
            }
          }

          while (true) {
            const { value, done } = await reader.read()
            if (done) break
            buffer += decoder.decode(value, { stream: true })
            const lines = buffer.split('\n')
            buffer = lines.pop() || ''
            for (const line of lines) processDocumentStreamLine(line)
          }

          processDocumentStreamLine(buffer)
          if (!result) throw new Error('Backend tidak mengirim hasil analisis dokumen')
        }
      } catch (error) {
        const reason = error instanceof Error ? error.message : 'Kesalahan tidak diketahui'
        setMessagesInActiveSession((prev) => [
          ...prev.slice(0, -1),
          {
            role: 'assistant',
            content: `⚠️ Gagal memproses file melalui backend FastAPI.\n\nDetail: ${reason}`
          }
        ])
      } finally {
        setLoading(false)
      }
      return
    }

    const userText = prompt
    setPrompt('')
    appendMessageToActiveTab({ role: 'user', content: userText })
    appendMessageToActiveTab({ role: 'assistant', content: '' })
    setLoading(true)

    try {
      const response = await fetch(apiUrl('/api/chat'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: tabDetails[activeTab].target,
          prompt: userText,
          history: conversationHistory
        })
      })

      if (!response.body) throw new Error('No stream body')

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      let accumulatedText = '' // Variabel penampung murni (mencegah duplikasi React)

      const processStreamLine = (line: string): void => {
        const trimmed = line.trim()
        if (!trimmed.startsWith('data:')) return

        const payload = trimmed.slice(5).trim()
        let token = ''

        try {
          const parsed = JSON.parse(payload)
          token = parsed.token ?? ''
        } catch {
          token = payload
        }

        if (token) {
          accumulatedText += token
          const snapshot = accumulatedText
          replacePendingMessageInActiveTab({ role: 'assistant', content: snapshot })
        }
      }

      while (true) {
        const { value, done } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() || ''

        for (const line of lines) processStreamLine(line)
      }

      processStreamLine(buffer)
      if (!accumulatedText) {
        setMessagesInActiveSession((prev) => [
          ...prev.slice(0, -1),
          { role: 'assistant', content: '⚠️ Backend tidak mengirim respons.' }
        ])
      }
    } catch {
      setMessagesInActiveSession((prev) => [
        ...prev.slice(0, -1),
        {
          role: 'assistant',
          content: `⚠️ Gagal terhubung ke backend FastAPI (${API_BASE_URL}).`
        }
      ])
    } finally {
      setLoading(false)
    }
  }

  // Tampilkan penalaran sebagai detail opsional agar jawaban akhir tetap menjadi fokus.
  const renderAssistantMessage = (raw: string): JSX.Element => {
    const renderThinkingPanel = (thinking: string, isStreaming = false): JSX.Element => (
      <details
        open={isStreaming}
        className="group mb-2 rounded-lg border border-slate-800 bg-slate-950/40 text-[11px] font-sans"
      >
        <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2 text-slate-500 hover:text-slate-300">
          <span className="flex items-center gap-2">
            <span
              className={`h-1.5 w-1.5 rounded-full ${isStreaming ? 'bg-emerald-500 animate-pulse' : 'bg-slate-600'}`}
            />
            {isStreaming ? 'Menganalisis...' : 'Proses analisis'}
          </span>
          <ChevronDown size={13} className="transition-transform group-open:rotate-180" />
        </summary>
        <div className="max-h-32 overflow-y-auto border-t border-slate-800/80 px-3 py-2 whitespace-pre-wrap text-[10px] leading-relaxed text-slate-500">
          {thinking}
        </div>
      </details>
    )

    const hasOpeningThinkTag = raw.includes('<think>')
    const hasClosingThinkTag = raw.includes('</think>')

    // Beberapa model hanya mengirim tag penutup. Perlakukan seluruh teks sebelum
    // penutup tersebut sebagai reasoning agar tidak memenuhi bubble jawaban.
    if (!hasOpeningThinkTag && hasClosingThinkTag) {
      const [thinking, ...answerParts] = raw.split('</think>')
      const answer = answerParts.join('</think>').trim()
      return (
        <div className="space-y-3 w-full">
          {thinking.trim() && renderThinkingPanel(thinking.trim())}
          {answer && <div className="text-slate-100 whitespace-pre-wrap">{answer}</div>}
        </div>
      )
    }

    if (!hasOpeningThinkTag) {
      // Fallback untuk model yang mengirim heading thinking tanpa tag <think>.
      if (/^\s*(?:#+\s*)?(?:thinking process|proses berpikir)\s*:/i.test(raw)) {
        return renderThinkingPanel(raw)
      }
      return <div className="text-slate-100 whitespace-pre-wrap">{raw}</div>
    }

    // Jika tag </think> sudah ditutup
    if (raw.includes('</think>')) {
      const parts = raw.split('</think>')
      const thinking = parts[0].replace(/<think>/g, '').trim()
      const answer = parts.slice(1).join('').trim()

      return (
        <div className="space-y-3 w-full">
          {thinking && renderThinkingPanel(thinking)}
          <div className="text-slate-100 whitespace-pre-wrap">{answer}</div>
        </div>
      )
    }

    // Selama proses model masih berpikir (tag </think> belum muncul)
    const currentThinking = raw.replace(/<think>/g, '').trim()
    return renderThinkingPanel(currentThinking, true)
  }

  const renderAnalysisProgress = (progress: AnalysisProgress): JSX.Element => {
    const steps = [
      { id: 'received', label: 'Dokumen diterima' },
      { id: 'extracting', label: 'Ekstraksi konten' },
      { id: 'analyzing', label: 'Analisis AI' },
      { id: 'finalizing', label: 'Penyusunan jawaban' }
    ]

    return (
      <div
        className="min-w-[260px] space-y-3 py-0.5 sm:min-w-[340px]"
        role="status"
        aria-live="polite"
      >
        <div className="flex items-center gap-2 text-sm font-medium text-emerald-300">
          <Loader2 size={15} className="animate-spin" />
          {progress.label}
        </div>
        {progress.detail && <p className="text-xs leading-5 text-slate-500">{progress.detail}</p>}
        <div className="grid grid-cols-4 gap-1.5" aria-label="Tahapan analisis dokumen">
          {steps.map((step) => {
            const isActive = step.id === progress.step
            const isComplete = progress.completedSteps.includes(step.id)
            return (
              <div key={step.id} className="min-w-0">
                <div
                  className={`h-1 rounded-full transition-colors duration-300 ${
                    isActive
                      ? 'bg-emerald-400 animate-pulse'
                      : isComplete
                        ? 'bg-emerald-500/70'
                        : 'bg-slate-800'
                  }`}
                />
                <span
                  className={`mt-1.5 hidden truncate text-[9px] sm:block ${
                    isActive ? 'text-emerald-300' : 'text-slate-600'
                  }`}
                >
                  {step.label}
                </span>
              </div>
            )
          })}
        </div>
        <p className="text-[10px] leading-4 text-slate-600">
          Menampilkan status kerja, bukan penalaran internal model.
        </p>
      </div>
    )
  }

  const CurrentIcon = tabDetails[activeTab].icon
  const activeDetail = tabDetails[activeTab]

  return (
    <div className="agent-shell flex h-[100dvh] w-screen flex-col overflow-hidden bg-[#080b12] font-sans text-slate-100 antialiased lg:flex-row">
      {/* SIDEBAR */}
      <aside
        className={`${sidebarCollapsed ? 'w-[76px]' : 'w-72'} relative z-10 hidden shrink-0 flex-col justify-between border-r border-white/[0.07] bg-[#0d111a]/95 transition-[width] duration-300 lg:flex`}
      >
        <div className="p-5">
          {/* Header Brand */}
          <div
            className={`flex items-center gap-3 px-2 py-2 mb-6 ${sidebarCollapsed ? 'justify-center' : ''}`}
          >
            <div className="p-2.5 rounded-xl bg-gradient-to-tr from-emerald-600 to-teal-400 text-slate-950 shadow-lg shadow-emerald-500/20">
              <Terminal size={20} strokeWidth={2.5} />
            </div>
            {!sidebarCollapsed && (
              <div>
                <h1 className="font-bold text-sm tracking-wide text-white">AGENT OS</h1>
                <p className="text-[10px] font-medium tracking-wider text-slate-500">
                  LOCAL INTELLIGENCE
                </p>
              </div>
            )}
            {!sidebarCollapsed && (
              <button
                type="button"
                onClick={(): void => setSidebarCollapsed(true)}
                className="ml-auto grid h-7 w-7 place-items-center rounded-lg text-slate-500 transition hover:bg-white/[.06] hover:text-white"
                title="Ciutkan sidebar"
              >
                <PanelLeftClose size={15} />
              </button>
            )}
          </div>

          {sidebarCollapsed && (
            <button
              type="button"
              onClick={(): void => setSidebarCollapsed(false)}
              className="absolute right-2 top-14 grid h-7 w-7 place-items-center rounded-lg border border-white/[.07] bg-slate-900 text-slate-400 transition hover:text-white"
              title="Buka sidebar"
            >
              <Menu size={15} />
            </button>
          )}

          {/* Navigasi Modul */}
          <div className="space-y-1.5">
            {(Object.keys(tabDetails) as Array<keyof typeof tabDetails>).map((key) => {
              const item = tabDetails[key]
              const ItemIcon = item.icon
              const isActive = activeTab === key

              return (
                <button
                  key={key}
                  onClick={(): void => setActiveTab(key)}
                  title={sidebarCollapsed ? item.title : undefined}
                  className={`w-full flex items-center ${sidebarCollapsed ? 'justify-center px-2' : 'gap-3.5 px-3.5'} py-3 rounded-xl text-xs font-medium transition-all text-left ${
                    isActive
                      ? 'bg-slate-800/90 text-white shadow-sm border border-slate-700/60'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  }`}
                >
                  <ItemIcon size={18} className={isActive ? item.color : 'text-slate-500'} />
                  {!sidebarCollapsed && (
                    <div className="flex-1 overflow-hidden">
                      <div className="truncate font-semibold">{item.title}</div>
                      <div className="text-[10px] text-slate-500 truncate">{item.badge}</div>
                    </div>
                  )}
                </button>
              )
            })}
          </div>

          {!sidebarCollapsed && (
            <div className="mt-6 border-t border-slate-800 pt-4">
              <div className="mb-2 flex items-center justify-between px-2">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Riwayat chat
                </span>
                <button
                  type="button"
                  onClick={handleNewChat}
                  disabled={loading}
                  className="text-[11px] text-emerald-400 hover:text-emerald-300 disabled:opacity-40"
                >
                  + Baru
                </button>
              </div>
              <div className="max-h-40 space-y-1 overflow-y-auto pr-1">
                {sessionsByTab[activeTab].map((session) => (
                  <button
                    key={session.id}
                    type="button"
                    onClick={(): void =>
                      setActiveSessions((prev) => ({ ...prev, [activeTab]: session.id }))
                    }
                    className={`w-full truncate rounded-lg px-2.5 py-2 text-left text-[11px] transition-colors ${
                      session.id === currentSession.id
                        ? 'bg-slate-800 text-slate-200'
                        : 'text-slate-500 hover:bg-slate-800/50 hover:text-slate-300'
                    }`}
                    title={session.title}
                  >
                    {session.title}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Hardware Status Panel */}
        <div className="p-4 m-3 rounded-xl bg-white/[.025] border border-white/[.07] text-xs">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="flex items-center gap-1.5 font-medium text-[11px]">
              <Cpu size={14} className="text-emerald-400" />{' '}
              {!sidebarCollapsed && 'NVIDIA RTX 3060'}
            </span>
            {!sidebarCollapsed && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                6GB VRAM
              </span>
            )}
          </div>
          {!sidebarCollapsed && (
            <>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div
                  className="bg-gradient-to-r from-emerald-500 to-teal-400 h-full transition-all duration-500"
                  style={{ width: `${gpuStats.percent}%` }}
                />
              </div>
              <div className="flex justify-between items-center mt-2 text-[10px] text-slate-500">
                <span>CUDA Accelerate</span>
                <span className="text-emerald-400 font-medium">Ready</span>
              </div>
            </>
          )}
        </div>
      </aside>

      {/* MAIN VIEW */}
      <main className="relative flex min-h-0 min-w-0 flex-1 flex-col bg-[#090c13]">
        {/* Top Navigation Bar */}
        <header className="flex h-16 shrink-0 items-center justify-between border-b border-white/[.06] bg-[#0b0f17]/85 px-4 backdrop-blur-xl sm:h-[74px] sm:px-8">
          <div className="flex min-w-0 items-center gap-3">
            <div
              className={`grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-gradient-to-br sm:h-10 sm:w-10 ${activeDetail.accent} text-slate-950`}
            >
              <CurrentIcon size={18} />
            </div>
            <div className="min-w-0">
              <h2 className="truncate text-base font-semibold text-slate-100">
                {activeDetail.title}
              </h2>
              <p className="hidden truncate text-sm text-slate-500 sm:block">{activeDetail.desc}</p>
            </div>
          </div>
          <div className="ml-3 flex shrink-0 items-center gap-2 sm:gap-3">
            <button
              type="button"
              onClick={handleNewChat}
              disabled={loading}
              className="hidden sm:flex items-center gap-1.5 rounded-lg border border-white/[.08] px-2.5 py-1.5 text-[11px] text-slate-400 transition hover:border-emerald-400/30 hover:text-emerald-300 disabled:opacity-40"
            >
              <Plus size={13} /> Baru
            </button>
            {currentMessages.length > 0 && (
              <button
                type="button"
                onClick={handleClearCurrentChat}
                disabled={loading}
                className="grid h-10 w-10 place-items-center overflow-hidden rounded-xl border border-white/[.07] text-slate-500 transition hover:border-rose-400/30 hover:text-rose-300 disabled:cursor-not-allowed disabled:opacity-40 sm:h-8 sm:w-8 sm:rounded-lg"
                title="Bersihkan percakapan ini"
              >
                <Trash2 size={14} className="shrink-0" />
              </button>
            )}
            <div className="flex items-center gap-2 rounded-full border border-emerald-400/15 bg-emerald-400/[.06] px-2.5 py-2 text-xs font-medium text-emerald-300 sm:px-3 sm:py-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_currentColor]" />
              <span className="hidden sm:inline">System online</span>
              <span className="sm:hidden">Online</span>
            </div>
          </div>
        </header>

        {/* Message Thread */}
        <div className="scrollbar-thin min-h-0 flex-1 space-y-5 overflow-y-auto overscroll-contain px-3 py-4 sm:space-y-6 sm:px-8 sm:py-8">
          {currentMessages.length === 0 ? (
            <div className="mx-auto flex min-h-full max-w-3xl flex-col items-center justify-center py-5 text-center sm:pb-12">
              <div
                className={`mb-4 grid h-12 w-12 place-items-center rounded-2xl border border-white/10 bg-gradient-to-br sm:mb-5 sm:h-14 sm:w-14 ${activeDetail.accent} text-slate-950 shadow-[0_12px_40px_rgba(16,185,129,.16)]`}
              >
                <Sparkles size={23} />
              </div>
              <p className="mb-2 text-xs font-semibold tracking-[.16em] text-emerald-300 sm:mb-3">
                PRIVATE · LOCAL
              </p>
              <h3 className="text-2xl font-semibold tracking-tight text-white sm:text-4xl">
                Mulai dari sebuah
                <br />
                <span className="text-slate-500">pertanyaan yang jelas.</span>
              </h3>
              <p className="mt-3 max-w-xl text-[15px] leading-6 text-slate-500 sm:mt-4 sm:text-base">
                {activeDetail.desc} Semua proses tetap berjalan di perangkat Anda.
              </p>
              <div className="scrollbar-hidden mt-5 flex w-full snap-x snap-mandatory gap-2 overflow-x-auto pb-2 text-left sm:mt-7 sm:grid sm:grid-cols-3 sm:overflow-visible sm:pb-0">
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
              <div className="mt-4 flex gap-4 text-xs text-slate-600 sm:mt-6">
                <span className="flex items-center gap-1.5">
                  <HardDrive size={13} /> Data tetap lokal
                </span>
                <span className="flex items-center gap-1.5">
                  <Zap size={13} /> GPU accelerated
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
                        ? 'bg-emerald-600 text-white rounded-tr-none shadow-md shadow-emerald-900/20 whitespace-pre-wrap'
                        : 'border border-slate-800/80 bg-slate-900/90 text-slate-200 rounded-tl-none'
                    }`}
                  >
                    {msg.image && (
                      <img
                        src={msg.image}
                        alt="User upload"
                        className="mb-2 block max-h-[260px] max-w-[min(520px,70vw)] rounded-lg object-contain"
                      />
                    )}
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
                            ? 'Sedang menganalisis gambar...'
                            : ''}
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
        <div className="shrink-0 border-t border-white/[.06] bg-[#0b0f17]/90 p-3 backdrop-blur-xl sm:p-5">
          <div className="mx-auto flex max-w-4xl items-end gap-2 rounded-2xl border border-white/[.09] bg-white/[.04] p-1.5 shadow-[0_10px_35px_rgba(0,0,0,.17)] transition-colors focus-within:border-emerald-400/45 focus-within:bg-white/[.055] sm:items-center sm:gap-3 sm:p-2">
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
              {fileError && <div className="px-3 text-[10px] text-rose-400">{fileError}</div>}
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
                  title={canUploadFile ? 'Lampirkan file' : 'Pilih Vision atau Document Parser'}
                >
                  <Paperclip size={16} />
                </button>
                <textarea
                  rows={1}
                  value={prompt}
                  onChange={(e): void => setPrompt(e.target.value)}
                  onPaste={handlePaste}
                  aria-label="Pesan untuk AI"
                  onKeyDown={(e): void => {
                    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                      e.preventDefault()
                      void handleSend()
                    }
                  }}
                  placeholder="Tulis pesan..."
                  className="min-h-11 min-w-0 flex-1 resize-none bg-transparent px-1 py-2.5 text-base leading-6 text-slate-100 placeholder-slate-500 focus:outline-none sm:max-h-28 sm:px-2 sm:text-sm"
                />
              </div>
            </div>
            <button
              onClick={(): void => {
                void handleSend()
              }}
              disabled={loading || (!prompt.trim() && !selectedFile && !imageFile)}
              aria-label="Kirim pesan"
              className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-emerald-400 font-semibold text-slate-950 shadow-md shadow-emerald-950/30 transition-all hover:bg-emerald-300 disabled:opacity-40 disabled:hover:bg-emerald-400 sm:flex sm:w-auto sm:gap-2 sm:px-4 sm:text-sm"
            >
              {loading ? (
                <Loader2 size={15} className="animate-spin" />
              ) : (
                <>
                  <span className="hidden sm:inline">Kirim</span>
                  <Send size={16} />
                </>
              )}
            </button>
          </div>
          <div className="mx-auto mt-2 hidden max-w-4xl items-center justify-between px-2 text-xs text-slate-600 sm:flex">
            <span>
              {canUploadFile
                ? 'Lampiran diaktifkan untuk mode ini'
                : 'Pilih Vision atau Dokumen untuk melampirkan file'}
            </span>
            <span className="hidden sm:flex items-center gap-1">
              <Command size={11} /> Ctrl + Enter untuk kirim
            </span>
          </div>
        </div>
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
              onClick={(): void => setActiveTab(key)}
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
    </div>
  )
}
