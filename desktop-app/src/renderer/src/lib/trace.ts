import type { Message, StreamEvent, TraceStep } from './types'

/** A status with the running step's id updates it; any other id closes it and starts a new step. */
export function traceStatus(
  trace: TraceStep[] = [],
  event: StreamEvent,
  now = Date.now()
): TraceStep[] {
  const step = event.step || 'running'
  const last = trace[trace.length - 1]
  if (last && !last.endedAt && last.step === step)
    return [
      ...trace.slice(0, -1),
      { ...last, label: event.label || last.label, detail: event.detail || last.detail }
    ]
  return [
    ...finishTrace(trace, now),
    { step, label: event.label || 'Memproses', detail: event.detail || undefined, startedAt: now }
  ]
}

export function finishTrace(trace: TraceStep[] = [], now = Date.now()): TraceStep[] {
  return trace.map((s) => (s.endedAt ? s : { ...s, endedAt: now }))
}

/** Fold one stream event into the pending assistant message: trace, reasoning and answer text. */
export function applyStreamEvent(message: Message, event: StreamEvent, now = Date.now()): Message {
  if (event.type === 'status') return { ...message, trace: traceStatus(message.trace, event, now) }
  if (event.type === 'thinking')
    return { ...message, thinking: (message.thinking || '') + (event.token || '') }
  if (event.type === 'token') return { ...message, content: message.content + (event.token || '') }
  return message
}

export function formatSeconds(ms: number): string {
  return (Math.max(ms, 0) / 1000).toLocaleString('id-ID', { maximumFractionDigits: 1 }) + ' dtk'
}
