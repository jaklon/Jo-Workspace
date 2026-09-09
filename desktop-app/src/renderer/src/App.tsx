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
  X
} from 'lucide-react'

interface Message {
  role: 'user' | 'assistant'
  content: string
  image?: string
}

export default function App(): JSX.Element {
  const [activeTab, setActiveTab] = useState<'chat' | 'code' | 'vision' | 'docs' | 'pentest'>('chat')
  const [prompt, setPrompt] = useState('')
  const [messages, setMessages] = useState<Message[]>([])
  const [loading, setLoading] = useState(false)
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null)
  const [gpuStats, setGpuStats] = useState({ used: 0, total: 6144, percent: 0 })
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState('')
  const [imageFile, setImageFile] = useState<File | null>(null)
  const [imagePreviewUrl, setImagePreviewUrl] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const imageUrlsRef = useRef<Set<string>>(new Set())

  const tabDetails = {
    chat: {
      title: 'Chat & Reasoning',
      desc: 'DeepSeek R1 Distill 7B (Thinking Engine)',
      target: 'reasoning',
      icon: MessageSquare,
      color: 'text-emerald-400',
      badge: 'DeepSeek R1'
    },
    code: {
      title: 'Coding Assistant',
      desc: 'Qwen 2.5 Coder 7B (Code Generator & Debugger)',
      target: 'coding',
      icon: Code2,
      color: 'text-cyan-400',
      badge: 'Qwen Coder'
    },
    vision: {
      title: 'Vision Analysis',
      desc: 'Analisis gambar dengan model vision lokal',
      target: 'vision',
      icon: Image,
      color: 'text-violet-400',
      badge: 'Vision Engine'
    },
    docs: {
      title: 'Document Parser',
      desc: 'Ekstraksi PDF, DOCX, & Ringkasan Dokumen',
      target: 'reasoning',
      icon: FileText,
      color: 'text-amber-400',
      badge: 'Document Engine'
    },
    pentest: {
      title: 'Security & Pentest',
      desc: 'Static Scanner & Audit Vulnerability',
      target: 'reasoning',
      icon: ShieldAlert,
      color: 'text-rose-400',
      badge: 'Audit Engine'
    }
  }

  const scrollToBottom = (): void => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  useEffect(() => {
    const fetchGpu = async (): Promise<void> => {
      try {
        const res = await fetch('http://127.0.0.1:8000/api/gpu-status')
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
      imageUrls.forEach(url => URL.revokeObjectURL(url))
      imageUrls.clear()
    }
  }, [])

  const copyToClipboard = (text: string, index: number): void => {
    void navigator.clipboard.writeText(text)
    setCopiedIndex(index)
    setTimeout(() => setCopiedIndex(null), 2000)
  }

  const canUploadFile = activeTab === 'vision' || activeTab === 'docs'
  const fileAccept = activeTab === 'vision' ? '.png,.jpg,.webp' : '.json,.md,.ts,.py'

  const isAllowedFile = (file: File): boolean => {
    const extension = file.name.toLowerCase().split('.').pop()
    const allowedExtensions = activeTab === 'vision' ? ['png', 'jpg', 'webp'] : ['json', 'md', 'ts', 'py']
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
            : 'Document Parser hanya menerima file JSON, MD, TS, atau PY.'
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

  const handlePaste = (event: ClipboardEvent<HTMLInputElement>): void => {
    if (activeTab !== 'vision') return

    const imageItem = Array.from(event.clipboardData.items).find(item =>
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

      setPrompt('')
      handleRemoveImage()
      setMessages(prev => [
        ...prev,
        {
          role: 'user',
          content: userText,
          image: base64Image
        },
        { role: 'assistant', content: '' }
      ])
      setLoading(true)

      try {
        const response = await fetch('http://127.0.0.1:8000/api/vision/analyze', {
          method: 'POST',
          body: formData
        })
        if (!response.ok) throw new Error(`Vision upload failed with HTTP ${response.status}`)

        const data: { result?: string; detail?: string } = await response.json()
        setMessages(prev => [
          ...prev.slice(0, -1),
          { role: 'assistant', content: data.result ?? data.detail ?? 'Tidak ada hasil analisis.' }
        ])
      } catch {
        setMessages(prev => [
          ...prev.slice(0, -1),
          { role: 'assistant', content: '⚠️ Gagal menganalisis screenshot melalui backend FastAPI.' }
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
              : 'Document Parser hanya menerima file JSON, MD, TS, atau PY.'
        )
        return
      }
      const userText = prompt.trim()
      const isVisionFile = activeTab === 'vision'
      const formData = new FormData()
      formData.append(isVisionFile ? 'image' : 'file', fileToSend)
      formData.append('prompt', userText || 'Analisis file ini secara detail.')

      setPrompt('')
      removeFile()
      setMessages(prev => [
        ...prev,
        {
          role: 'user',
          content: `${fileToSend.name}${userText ? `\n${userText}` : ''}`
        },
        { role: 'assistant', content: '' }
      ])
      setLoading(true)

      try {
        const targetUrl = isVisionFile
          ? 'http://127.0.0.1:8000/api/vision/analyze'
          : 'http://127.0.0.1:8000/api/document/parse'
        const response = await fetch(targetUrl, {
          method: 'POST',
          body: formData
        })

        if (!response.ok) throw new Error(`Upload failed with HTTP ${response.status}`)

        const data: { result?: string; detail?: string } = await response.json()
        setMessages(prev => [
          ...prev.slice(0, -1),
          { role: 'assistant', content: data.result ?? data.detail ?? 'Tidak ada hasil dari backend.' }
        ])
      } catch {
        setMessages(prev => [
          ...prev.slice(0, -1),
          { role: 'assistant', content: '⚠️ Gagal memproses file melalui backend FastAPI.' }
        ])
      } finally {
        setLoading(false)
      }
      return
    }

    const userText = prompt
    setPrompt('')
    setMessages(prev => [
      ...prev,
      { role: 'user', content: userText },
      { role: 'assistant', content: '' }
    ])
    setLoading(true)

    try {
      const response = await fetch('http://127.0.0.1:8000/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: tabDetails[activeTab].target,
          prompt: userText
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
          setMessages(prev => [
            ...prev.slice(0, -1),
            { role: 'assistant', content: snapshot }
          ])
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
        setMessages(prev => [
          ...prev.slice(0, -1),
          { role: 'assistant', content: '⚠️ Backend tidak mengirim respons.' }
        ])
      }
    } catch {
      setMessages(prev => [
        ...prev.slice(0, -1),
        { role: 'assistant', content: '⚠️ Gagal terhubung ke backend FastAPI (http://127.0.0.1:8000).' }
      ])
    } finally {
      setLoading(false)
    }
  }

  // Helper untuk memisahkan blok <think> DeepSeek-R1 dari teks respon utama
  const renderAssistantMessage = (raw: string): JSX.Element => {
    if (!raw.includes('<think>')) {
      return <div className="text-slate-100 whitespace-pre-wrap">{raw}</div>
    }

    // Jika tag </think> sudah ditutup
    if (raw.includes('</think>')) {
      const parts = raw.split('</think>')
      const thinking = parts[0].replace(/<think>/g, '').trim()
      const answer = parts.slice(1).join('').trim()

      return (
        <div className="space-y-3 w-full">
          {thinking && (
            <details className="group bg-slate-950/70 rounded-xl p-3 border border-slate-800/80 text-xs font-sans">
              <summary className="cursor-pointer font-medium text-emerald-400 flex items-center justify-between list-none">
                <span className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                  Thinking Process
                </span>
                <ChevronDown size={14} className="group-open:rotate-180 transition-transform text-slate-400" />
              </summary>
              <div className="mt-2.5 whitespace-pre-wrap pl-3 border-l-2 border-emerald-500/30 text-slate-400 leading-relaxed text-[11px] font-mono">
                {thinking}
              </div>
            </details>
          )}
          <div className="text-slate-100 whitespace-pre-wrap">{answer}</div>
        </div>
      )
    }

    // Selama proses model masih berpikir (tag </think> belum muncul)
    const currentThinking = raw.replace(/<think>/g, '').trim()
    return (
      <details open className="group bg-slate-950/70 rounded-xl p-3 border border-slate-800/80 text-xs font-sans">
        <summary className="cursor-pointer font-medium text-emerald-400 flex items-center justify-between list-none">
          <span className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            Sedang Menganalisis & Berpikir...
          </span>
          <ChevronDown size={14} className="group-open:rotate-180 transition-transform text-slate-400" />
        </summary>
        <div className="mt-2.5 whitespace-pre-wrap pl-3 border-l-2 border-emerald-500/30 text-slate-400 leading-relaxed text-[11px] font-mono">
          {currentThinking}
        </div>
      </details>
    )
  }

  const CurrentIcon = tabDetails[activeTab].icon

  return (
    <div className="flex h-screen w-screen bg-[#0b0f17] text-slate-100 font-sans antialiased overflow-hidden select-none">
      {/* SIDEBAR */}
      <aside className="w-72 bg-[#0f172a]/95 border-r border-slate-800/80 flex flex-col justify-between shrink-0">
        <div className="p-5">
          {/* Header Brand */}
          <div className="flex items-center gap-3 px-2 py-2 mb-6">
            <div className="p-2.5 rounded-xl bg-gradient-to-tr from-emerald-600 to-teal-400 text-slate-950 shadow-lg shadow-emerald-500/20">
              <Terminal size={20} strokeWidth={2.5} />
            </div>
            <div>
              <h1 className="font-bold text-sm tracking-wide text-white">AGENT OS</h1>
              <p className="text-[11px] text-slate-400">Offline Multi-Model System</p>
            </div>
          </div>

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
                  className={`w-full flex items-center gap-3.5 px-3.5 py-3 rounded-xl text-xs font-medium transition-all text-left ${
                    isActive
                      ? 'bg-slate-800/90 text-white shadow-sm border border-slate-700/60'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  }`}
                >
                  <ItemIcon size={18} className={isActive ? item.color : 'text-slate-500'} />
                  <div className="flex-1 overflow-hidden">
                    <div className="truncate font-semibold">{item.title}</div>
                    <div className="text-[10px] text-slate-500 truncate">{item.badge}</div>
                  </div>
                </button>
              )
            })}
          </div>
        </div>

        {/* Hardware Status Panel */}
        <div className="p-4 m-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="flex items-center gap-1.5 font-medium text-[11px]">
              <Cpu size={14} className="text-emerald-400" /> NVIDIA RTX 3060
            </span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              6GB VRAM
            </span>
          </div>
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
        </div>
      </aside>

      {/* MAIN VIEW */}
      <main className="flex-1 flex flex-col h-full bg-[#090d16] min-w-0">
        {/* Top Navigation Bar */}
        <header className="h-16 border-b border-slate-800/80 flex items-center justify-between px-8 bg-[#0b111e]/60 backdrop-blur-md">
          <div className="flex items-center gap-3">
            <CurrentIcon size={20} className={tabDetails[activeTab].color} />
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                {tabDetails[activeTab].title}
              </h2>
              <p className="text-[11px] text-slate-400">{tabDetails[activeTab].desc}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/60 border border-slate-700/50 text-[11px] text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>Port: 8000</span>
            </div>
          </div>
        </header>

        {/* Message Thread */}
        <div className="flex-1 overflow-y-auto p-8 space-y-6">
          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center max-w-md mx-auto">
              <div className="p-4 rounded-2xl bg-slate-800/40 border border-slate-800 mb-4 text-emerald-400">
                <Sparkles size={32} />
              </div>
              <h3 className="text-base font-medium text-slate-200 mb-1">
                Local AI Agent Siap Digunakan
              </h3>
              <p className="text-xs text-slate-500 leading-relaxed">
                Inferensi diproses secara lokal pada GPU laptop Anda tanpa mengirim data ke cloud.
                Masukkan instruksi di kolom bawah.
              </p>
            </div>
          ) : (
            messages.map((msg, idx) => (
              <div
                key={idx}
                className={`flex gap-4 max-w-4xl mx-auto ${
                  msg.role === 'user' ? 'justify-end' : 'justify-start'
                }`}
              >
                {msg.role === 'assistant' && (
                  <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0 mt-1">
                    <Bot size={16} />
                  </div>
                )}

                <div className="relative group max-w-[85%]">
                  <div
                    className={`rounded-2xl px-5 py-3.5 text-xs leading-relaxed ${
                      msg.role === 'user'
                        ? 'bg-emerald-600 text-white rounded-tr-none shadow-md shadow-emerald-900/20 whitespace-pre-wrap'
                        : 'bg-slate-900/90 border border-slate-800/80 text-slate-200 rounded-tl-none font-mono'
                    }`}
                  >
                    {msg.image && (
                      <img
                        src={msg.image}
                        alt="User upload"
                        className="mb-2 block max-h-[260px] max-w-[min(520px,70vw)] rounded-lg object-contain"
                      />
                    )}
                    {msg.role === 'assistant'
                      ? msg.content
                        ? renderAssistantMessage(msg.content)
                        : loading && idx === messages.length - 1
                          ? 'Sedang berpikir...'
                          : ''
                      : msg.content && <div>{msg.content}</div>}
                  </div>

                  {msg.role === 'assistant' && msg.content && (
                    <button
                      onClick={(): void => copyToClipboard(msg.content, idx)}
                      className="absolute top-2 right-2 p-1 rounded bg-slate-800/80 border border-slate-700/60 text-slate-400 opacity-0 group-hover:opacity-100 transition-opacity hover:text-white"
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
                  <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 flex items-center justify-center shrink-0 mt-1">
                    <User size={16} />
                  </div>
                )}
              </div>
            ))
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <div className="p-5 border-t border-slate-800/80 bg-[#0b111e]/40 backdrop-blur-md">
          <div className="max-w-4xl mx-auto flex items-center gap-3 bg-slate-900/80 border border-slate-800 rounded-2xl p-2 focus-within:border-emerald-500/50 transition-colors shadow-inner">
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
                  className="p-2 text-slate-400 hover:text-emerald-400 disabled:opacity-30 disabled:hover:text-slate-400 transition-colors"
                  title={canUploadFile ? 'Lampirkan file' : 'Pilih Vision atau Document Parser'}
                >
                  <Paperclip size={16} />
                </button>
                <input
                  type="text"
                  value={prompt}
                  onChange={(e): void => setPrompt(e.target.value)}
                  onPaste={handlePaste}
                  onKeyDown={(e): void => {
                    if (e.key === 'Enter') void handleSend()
                  }}
                  placeholder={
                    activeTab === 'vision'
                      ? 'Ketik instruksi atau paste screenshot dengan Ctrl+V...'
                      : `Ketik instruksi untuk ${tabDetails[activeTab].title}...`
                  }
                  className="flex-1 min-w-0 bg-transparent px-2 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none"
                />
              </div>
            </div>
            <button
              onClick={(): void => {
                void handleSend()
              }}
              disabled={loading || (!prompt.trim() && !selectedFile && !imageFile)}
              className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:hover:bg-emerald-600 text-white px-4 py-2.5 rounded-xl flex items-center gap-2 text-xs font-medium transition-all shadow-md shadow-emerald-900/30"
            >
              {loading ? (
                <Loader2 size={15} className="animate-spin" />
              ) : (
                <>
                  <span>Kirim</span>
                  <Send size={13} />
                </>
              )}
            </button>
          </div>
        </div>
      </main>
    </div>
  )
}
