import { useState, useRef, useEffect, JSX } from 'react'
import {
  MessageSquare,
  Code2,
  FileText,
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
  ChevronDown
} from 'lucide-react'

interface Message {
  role: 'user' | 'assistant'
  content: string
}

export default function App(): JSX.Element {
  const [activeTab, setActiveTab] = useState<'chat' | 'code' | 'docs' | 'pentest'>('chat')
  const [prompt, setPrompt] = useState('')
  const [messages, setMessages] = useState<Message[]>([])
  const [loading, setLoading] = useState(false)
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null)
  const [gpuStats, setGpuStats] = useState({ used: 0, total: 6144, percent: 0 })
  const messagesEndRef = useRef<HTMLDivElement>(null)

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

  const copyToClipboard = (text: string, index: number): void => {
    void navigator.clipboard.writeText(text)
    setCopiedIndex(index)
    setTimeout(() => setCopiedIndex(null), 2000)
  }

  const handleSend = async (): Promise<void> => {
    if (!prompt.trim() || loading) return

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

      while (true) {
        const { value, done } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() || ''

        for (const line of lines) {
          const trimmed = line.trim()
          if (!trimmed.startsWith('data:')) continue

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
            // Update immutably tanpa memodifikasi object lama secara langsung
            setMessages(prev => [
              ...prev.slice(0, -1),
              { role: 'assistant', content: snapshot }
            ])
          }
        }
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
                    {msg.role === 'assistant'
                      ? msg.content
                        ? renderAssistantMessage(msg.content)
                        : loading && idx === messages.length - 1
                          ? 'Sedang berpikir...'
                          : ''
                      : msg.content}
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
            <input
              type="text"
              value={prompt}
              onChange={(e): void => setPrompt(e.target.value)}
              onKeyDown={(e): void => {
                if (e.key === 'Enter') void handleSend()
              }}
              placeholder={`Ketik instruksi untuk ${tabDetails[activeTab].title}...`}
              className="flex-1 bg-transparent px-4 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none"
            />
            <button
              onClick={(): void => {
                void handleSend()
              }}
              disabled={loading || !prompt.trim()}
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
