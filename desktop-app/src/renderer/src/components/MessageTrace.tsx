import { useEffect, useRef, useState, type JSX } from 'react'
import { Brain, Check, ChevronDown, Loader2, Workflow } from 'lucide-react'
import type { TraceStep } from '../lib/types'
import { formatSeconds } from '../lib/trace'

const duration = (step: TraceStep, now: number): number => (step.endedAt ?? now) - step.startedAt

export function MessageTrace({
  trace = [],
  thinking
}: {
  trace?: TraceStep[]
  thinking?: string
}): JSX.Element | null {
  const running = trace.some((s) => !s.endedAt)
  const [now, setNow] = useState(Date.now)
  // null follows the stream: open while the model is thinking, closed afterwards.
  const [thinkingOpen, setThinkingOpen] = useState<boolean | null>(null)
  const [stepsOpen, setStepsOpen] = useState(false)
  const thinkingBox = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!running) return
    const timer = setInterval(() => setNow(Date.now()), 250)
    return () => clearInterval(timer)
  }, [running])
  const thinkingSteps = trace.filter((s) => s.step === 'thinking')
  const thinkingNow = thinkingSteps.some((s) => !s.endedAt)
  const showThinking = thinkingOpen ?? thinkingNow
  useEffect(() => {
    if (thinkingNow && showThinking && thinkingBox.current)
      thinkingBox.current.scrollTop = thinkingBox.current.scrollHeight
  }, [thinking, thinkingNow, showThinking])
  if (!trace.length && !thinking) return null
  const current = [...trace].reverse().find((s) => !s.endedAt)
  const thinkingMs = thinkingSteps.reduce((sum, s) => sum + duration(s, now), 0)
  const totalMs = trace.length ? (trace[trace.length - 1].endedAt ?? now) - trace[0].startedAt : 0
  return (
    // Padding, not margin: main.css resets margins outside Tailwind's layers.
    <div className="flex flex-col gap-1.5 pr-10 pb-3 text-[13px]">
      {thinking && (
        <div className="rounded-lg border border-slate-700/60 bg-slate-900/40">
          <button
            type="button"
            aria-expanded={showThinking}
            onClick={() => setThinkingOpen(!showThinking)}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-slate-400 hover:text-slate-200"
          >
            {thinkingNow ? (
              <Loader2 size={14} className="shrink-0 animate-spin text-violet-300" />
            ) : (
              <Brain size={14} className="shrink-0 text-violet-300" />
            )}
            <span className="flex-1">
              {thinkingNow ? 'Berpikir…' : 'Berpikir selama ' + formatSeconds(thinkingMs)}
            </span>
            <ChevronDown
              size={14}
              className={`shrink-0 transition-transform ${showThinking ? 'rotate-180' : ''}`}
            />
          </button>
          {showThinking && (
            <div
              ref={thinkingBox}
              className="max-h-64 overflow-y-auto border-t border-slate-700/60 px-3 py-2 text-[12.5px] leading-relaxed whitespace-pre-wrap text-slate-400"
            >
              {thinking}
            </div>
          )}
        </div>
      )}
      {trace.length > 0 && (
        <div className="rounded-lg border border-slate-700/60 bg-slate-900/40">
          <button
            type="button"
            aria-expanded={stepsOpen}
            onClick={() => setStepsOpen(!stepsOpen)}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-slate-400 hover:text-slate-200"
          >
            {running ? (
              <Loader2 size={14} className="shrink-0 animate-spin text-emerald-300" />
            ) : (
              <Workflow size={14} className="shrink-0 text-emerald-300" />
            )}
            <span className="min-w-0 flex-1 truncate" role="status" aria-live="polite">
              {running && current
                ? current.label + (current.detail ? ' · ' + current.detail : '')
                : `Selesai dalam ${formatSeconds(totalMs)} · ${trace.length} langkah`}
            </span>
            <ChevronDown
              size={14}
              className={`shrink-0 transition-transform ${stepsOpen ? 'rotate-180' : ''}`}
            />
          </button>
          {stepsOpen && (
            <ol className="space-y-1.5 border-t border-slate-700/60 px-3 py-2">
              {trace.map((s, index) => (
                <li key={index} className="flex gap-2">
                  {s.endedAt ? (
                    <Check size={14} className="mt-0.5 shrink-0 text-emerald-400" />
                  ) : (
                    <Loader2 size={14} className="mt-0.5 shrink-0 animate-spin text-emerald-300" />
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="text-slate-300">{s.label}</div>
                    {s.detail && <div className="break-words text-slate-500">{s.detail}</div>}
                  </div>
                  <span className="shrink-0 tabular-nums text-slate-500">
                    {formatSeconds(duration(s, now))}
                  </span>
                </li>
              ))}
            </ol>
          )}
        </div>
      )}
    </div>
  )
}
