import assert from 'node:assert/strict'
import { build } from '../desktop-app/node_modules/esbuild/lib/main.js'
import { fileURLToPath } from 'node:url'

const built = await build({ entryPoints: [fileURLToPath(new URL('../desktop-app/src/renderer/src/lib/citations.ts', import.meta.url))], bundle: true, platform: 'node', format: 'esm', write: false })
const { coverageNotes, orderedSources } = await import('data:text/javascript;base64,' + Buffer.from(built.outputFiles[0].text).toString('base64'))

const full = coverageNotes({ selected: 3, total: 3, complete: true, matched: 2, cited: 1, unreadable_pages: [] }, true)
assert.deepEqual(full.map(([tone]) => tone), ['ok'])
const partial = coverageNotes({ selected: 5, total: 40, complete: false, matched: 0, cited: 0, unreadable_pages: [4, 7] }, true)
const text = partial.map(([, t]) => t).join(' | ')
assert.match(text, /5 dari 40 bagian/)
assert.match(text, /4, 7/)
assert.match(text, /tidak ditemukan/)
assert.match(text, /tidak merujuk/)
// Older messages without the new fields only show the coverage line.
assert.equal(coverageNotes({ selected: 1, total: 2, complete: false }, true).length, 1)
const ordered = orderedSources([{ label: 'a', text: '', section: 3 }, { label: 'b', text: '', section: 9, cited: true }, { label: 'c', text: '', section: 1 }])
assert.deepEqual(ordered.map((s) => s.label), ['b', 'c', 'a'])
console.log('Document citations: coverage, unreadable pages, not-found and uncited warnings passed.')
