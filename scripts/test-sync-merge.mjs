import assert from 'node:assert/strict'
import { build } from '../desktop-app/node_modules/esbuild/lib/main.js'
import { fileURLToPath } from 'node:url'

const built = await build({ entryPoints: [fileURLToPath(new URL('../desktop-app/src/renderer/src/lib/sync-merge.ts', import.meta.url))], bundle: true, platform: 'node', format: 'esm', write: false })
const { fingerprint, reconcileRemote } = await import('data:text/javascript;base64,' + Buffer.from(built.outputFiles[0].text).toString('base64'))
const key = 'session:s1'
const original = { id: 's1', title: 'first' }
const localEdit = { id: 's1', title: 'local edit' }
const remoteEdit = { id: 's1', title: 'remote edit' }
const base = { [key]: { version: 1, fingerprint: fingerprint(original) } }
const remote = { kind: 'session', id: 's1', version: 2, deleted: false, data: remoteEdit }
assert.equal(fingerprint({ b: 2, a: 1 }), fingerprint({ a: 1, b: 2 }))
assert.equal(reconcileRemote({ [key]: original }, base, [remote]).updates.length, 1)
assert.equal(reconcileRemote({ [key]: localEdit }, base, [remote]).conflicts.length, 1)
const unchangedRemote = { ...remote, data: original }
assert.equal(reconcileRemote({ [key]: localEdit }, base, [unchangedRemote]).updates.length, 0)
assert.equal(reconcileRemote({ [key]: localEdit }, base, [unchangedRemote]).accepted[key].version, 2)
assert.equal(reconcileRemote({ [key]: remoteEdit }, base, [remote]).accepted[key].version, 2)
const deletion = { ...remote, version: 3, deleted: true, data: null }
assert.equal(reconcileRemote({ [key]: localEdit }, base, [deletion]).conflicts.length, 1)
assert.equal(reconcileRemote({ [key]: original }, base, [deletion]).updates[0].deleted, true)
assert.equal(reconcileRemote({ [key]: localEdit }, {}, [remote]).conflicts.length, 1)
console.log('Reconciliation decisions: unchanged, concurrent edits, migration and deletion passed.')
