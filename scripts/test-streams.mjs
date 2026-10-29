import assert from 'node:assert/strict'
import { build } from '../desktop-app/node_modules/esbuild/lib/main.js'
import { fileURLToPath } from 'node:url'

async function moduleAt(path) {
  const result = await build({ entryPoints: [fileURLToPath(new URL(path, import.meta.url))], bundle: true, platform: 'node', format: 'esm', write: false })
  return import('data:text/javascript;base64,' + Buffer.from(result.outputFiles[0].text).toString('base64'))
}
const { consumeStream } = await moduleAt('../desktop-app/src/renderer/src/lib/stream.ts')
const { readAnswer } = await moduleAt('../ai-agent-vscode/src/sse.ts')
const fixture = ': keepalive\r\n\r\ndata: {"type":"token","token":"café ✅"}\r\n\r\ndata: {"type":"result","result":"café ✅"}\r\n\r\ndata: {"type":"done"}\r\n\r\n'
function response(text) {
  const bytes = new TextEncoder().encode(text)
  return new Response(new ReadableStream({ start(controller) {
    // Split every byte, including UTF-8 code points and CRLF boundaries.
    for (const byte of bytes) controller.enqueue(new Uint8Array([byte]))
    controller.close()
  } }), { headers: { 'Content-Type': 'text/event-stream' } })
}
const received = []
await consumeStream(response(fixture), event => received.push(event))
assert.equal(received.find(e => e.type === 'result').result, 'café ✅')
assert.equal(await readAnswer(response(fixture)), 'café ✅')
for (const read of [r => consumeStream(r, () => {}), readAnswer]) {
  await assert.rejects(() => read(response('data: {"type":"token","token":"partial"}\n\n')), /terputus/)
  await assert.rejects(() => read(response('data: {"type":"error","detail":"model missing"}\n\n')), /model missing/)
  await assert.rejects(() => read(new Response('{}', { headers: { 'Content-Type': 'application/json' } })))
}
await assert.rejects(() => readAnswer(new Response('{"detail":"Unauthorized"}', { status: 401 })), /Unauthorized/)
console.log('9 SSE assertions passed (desktop + VS Code): UTF-8, CRLF, terminal event, errors, content type, HTTP failure.')

const { applyStreamEvent, finishTrace, traceStatus } = await moduleAt('../desktop-app/src/renderer/src/lib/trace.ts')
let message = { role: 'assistant', content: '', trace: traceStatus([], { type: 'status', step: 'queued', label: 'Antre' }, 0) }
for (const [event, at] of [
  [{ type: 'status', step: 'routing', label: 'Routing' }, 100],
  [{ type: 'status', step: 'routing', label: 'Routing', detail: 'Intent: percakapan' }, 900],
  [{ type: 'status', step: 'thinking', label: 'Berpikir' }, 1000],
  [{ type: 'thinking', token: 'pikir ' }, 1100],
  [{ type: 'thinking', token: 'dulu' }, 1200],
  [{ type: 'status', step: 'writing', label: 'Menulis' }, 3000],
  [{ type: 'token', token: 'Halo' }, 3100]
]) message = applyStreamEvent(message, event, at)
assert.deepEqual(message.trace.map((s) => [s.step, s.startedAt, s.endedAt]),
  [['queued', 0, 100], ['routing', 100, 1000], ['thinking', 1000, 3000], ['writing', 3000, undefined]])
assert.equal(message.trace[1].detail, 'Intent: percakapan')
assert.equal(message.thinking, 'pikir dulu')
assert.equal(message.content, 'Halo')
assert.equal(finishTrace(message.trace, 4000)[3].endedAt, 4000)
console.log('5 trace assertions passed: step merge, step timing, reasoning/answer separation, finish.')
