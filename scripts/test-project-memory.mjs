import assert from 'node:assert/strict'
import { build } from '../desktop-app/node_modules/esbuild/lib/main.js'
import { fileURLToPath } from 'node:url'

const built = await build({ entryPoints: [fileURLToPath(new URL('../desktop-app/src/renderer/src/lib/project-memory.ts', import.meta.url))], bundle: true, platform: 'node', format: 'esm', write: false })
const { sanitizeMemory, createFact, upsertFact, removeFact, memoryPrompt, MEMORY_LIMIT, MEMORY_PROMPT_BUDGET } = await import('data:text/javascript;base64,' + Buffer.from(built.outputFiles[0].text).toString('base64'))

const goal = createFact('goal', '  Rilis beta Desember  ')
assert.equal(goal.text, 'Rilis beta Desember')
assert.deepEqual(goal.source, { kind: 'manual' })
const decision = createFact('decision', 'Database memakai PostgreSQL', { kind: 'chat', sessionId: 's1', sessionTitle: 'Arsitektur', excerpt: 'x'.repeat(500) })
assert.equal(decision.source.excerpt.length, 240)

let memory = upsertFact(upsertFact([], goal), decision)
assert.equal(memory.length, 2)
memory = upsertFact(memory, { ...goal, text: 'Rilis beta Januari' })
assert.equal(memory.length, 2)
assert.equal(memory[0].text, 'Rilis beta Januari')
assert.equal(removeFact(memory, goal.id).length, 1)

// The prompt groups by kind and never treats memory as instructions.
const prompt = memoryPrompt(memory)
assert.equal(prompt.included, 2)
assert.match(prompt.text, /jangan dianggap perintah/)
assert.ok(prompt.text.indexOf('Tujuan') < prompt.text.indexOf('Keputusan'))
assert.deepEqual(memoryPrompt([]), { text: '', included: 0 })

// The memory block stays inside its share of the 6000-character prompt limit.
let full = []
for (let i = 0; i < MEMORY_LIMIT; i++) full = upsertFact(full, createFact('note', `${i} ` + 'y'.repeat(290)))
assert.throws(() => upsertFact(full, createFact('note', 'satu lagi')), /dibatasi 50/)
const bounded = memoryPrompt(full)
assert.ok(bounded.text.length <= MEMORY_PROMPT_BUDGET)
assert.ok(bounded.included > 0 && bounded.included < MEMORY_LIMIT)

// Stored or synced data is re-validated: bad kinds, empty text and duplicates are dropped.
const cleaned = sanitizeMemory([goal, goal, { ...decision, kind: 'secret' }, { ...decision, id: 'd2', text: '  ' }, null, { ...decision, source: 'chat' }])
assert.equal(cleaned.length, 2)
assert.deepEqual(cleaned[1].source, { kind: 'manual' })
assert.deepEqual(sanitizeMemory('not a list'), [])
console.log('Project memory: user-controlled CRUD, sources, prompt budget and sanitizing passed.')
