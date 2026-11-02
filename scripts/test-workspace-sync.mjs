import assert from 'node:assert/strict'
import { build } from '../desktop-app/node_modules/esbuild/lib/main.js'
import { fileURLToPath } from 'node:url'
const built = await build({ entryPoints: [fileURLToPath(new URL('../desktop-app/src/renderer/src/lib/workspace-sync.ts', import.meta.url))], bundle: true, platform: 'node', format: 'esm', write: false })
const { emptySync, localRecords, pendingChanges, receiveRemote, acknowledge, resolveConflict, conflictList, mergeRecovery } = await import('data:text/javascript;base64,' + Buffer.from(built.outputFiles[0].text).toString('base64'))
const tabs = ['chat', 'code', 'vision', 'docs', 'pentest']
const sessions = Object.fromEntries(tabs.map(t => [t, [{ id: `empty-${t}`, title: 'Percakapan baru', createdAt: 1, updatedAt: 1, messages: [], attachments: [] }]]))
let state = { sessions, activeSessions: Object.fromEntries(tabs.map(t => [t, `empty-${t}`])), projects: [{ id: 'p', name: 'Local', instructions: '', createdAt: 1 }], sync: emptySync() }
assert.deepEqual(Object.keys(localRecords(state)), ['project:p'])
let change = pendingChanges(state)[0]
state = acknowledge(state, [change], [{ kind: 'project', id: 'p', version: 1 }])
state = { ...state, projects: [{ ...state.projects[0], name: 'Offline' }] }
const remote = { kind: 'project', id: 'p', version: 2, deleted: false, data: { id: 'p', name: 'Other', instructions: '', createdAt: 1 } }
state = receiveRemote(state, [remote], 2, 'backend-one')
assert.equal(conflictList(state).length, 1)
assert.equal(state.projects[0].name, 'Offline')
assert.equal(pendingChanges(state).length, 0)
state = resolveConflict(state, 'project:p', 'local')
change = pendingChanges(state)[0]
assert.equal(change.expected, 2)
assert.equal(change.data.name, 'Offline')
state = acknowledge(state, [change], [{ kind: 'project', id: 'p', version: 3 }])
assert.equal(pendingChanges(state).length, 0)
const deletion = { ...remote, version: 4, deleted: true, data: null }
state = receiveRemote(state, [deletion], 4, 'backend-one')
assert.equal(state.projects.length, 0)
state = { ...state, projects: [{ id: 'p', name: 'Imported old', instructions: '', createdAt: 1 }] }
assert.equal(pendingChanges(state).length, 0)
assert.equal(conflictList(state).length, 1)
state = resolveConflict(state, 'project:p', 'local')
assert.equal(pendingChanges(state)[0].restore, true)
assert.throws(() => receiveRemote(state, [], 0, 'another-backend'))
const clean = receiveRemote({ ...state, projects: [], sync: emptySync() }, [remote], 2, 'backend-one')
const recovery = { sessions, activeSessions: clean.activeSessions, projects: [{ ...remote.data, name: 'From recovery' }] }
const merged = mergeRecovery(clean, recovery)
assert.equal(merged.projects[0].name, 'From recovery')
assert.equal(conflictList(merged)[0].remote.data.name, 'Other')
assert.equal(pendingChanges(merged).length, 0)
assert.equal(resolveConflict(merged, 'project:p', 'remote').projects[0].name, 'Other')
assert.throws(() => mergeRecovery({ ...clean, projects: [{ ...remote.data, name: 'Unsynced' }] }, recovery))
console.log('Workspace sync: offline changes, conflict choices, explicit restore and backend identity passed.')
