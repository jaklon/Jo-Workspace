import type { StreamEvent } from './types'

export async function consumeStream(
  response: Response,
  onEvent: (event: StreamEvent) => void
): Promise<void> {
  if (!response.body || !response.headers.get('content-type')?.includes('text/event-stream')) {
    throw new Error('Backend tidak mengirim stream yang valid.')
  }
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let completed = false
  const process = (block: string): void => {
    const data = block
      .split(/\r?\n/)
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trimStart())
      .join('\n')
    if (!data) return
    const event = JSON.parse(data) as StreamEvent
    if (event.type === 'error') throw new Error(event.detail || 'Inferensi gagal.')
    if (event.type === 'done') completed = true
    onEvent(event)
  }
  try {
    while (true) {
      const { value, done } = await reader.read()
      buffer += done ? decoder.decode() : decoder.decode(value, { stream: true })
      let match: RegExpExecArray | null
      while ((match = /\r?\n\r?\n/.exec(buffer))) {
        process(buffer.slice(0, match.index))
        buffer = buffer.slice(match.index + match[0].length)
      }
      if (done) break
    }
    if (buffer.trim()) process(buffer)
    if (!completed) throw new Error('Koneksi terputus sebelum jawaban selesai. Coba lagi.')
  } finally {
    await reader.cancel().catch(() => undefined)
    reader.releaseLock()
  }
}
