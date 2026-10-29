import assert from 'node:assert/strict'
import { build } from '../desktop-app/node_modules/esbuild/lib/main.js'
import { fileURLToPath } from 'node:url'

async function moduleAt(path) {
  const result = await build({ entryPoints: [fileURLToPath(new URL(path, import.meta.url))], bundle: true, platform: 'node', format: 'esm', write: false })
  return import('data:text/javascript;base64,' + Buffer.from(result.outputFiles[0].text).toString('base64'))
}
const { exportBackup, importBackup } = await moduleAt('../desktop-app/src/renderer/src/lib/backup.ts')
const { defaultPreferences, normalizePreferences, personalizedPrompt } = await moduleAt('../desktop-app/src/renderer/src/lib/preferences.ts')
const { createSession, validate, TAB_TYPES } = await moduleAt('../desktop-app/src/renderer/src/lib/sessions.ts')
const projects = [{ id: 'project-original', name: 'Client work', instructions: 'Use TypeScript', createdAt: 1 }]
const sessions = Object.fromEntries(TAB_TYPES.map(tab => [tab, [createSession()]]))
Object.assign(sessions.chat[0], { projectId: projects[0].id, pinned: true, archived: true, attachments: [{ id: 'private-attachment', filename: 'private.pdf', kind: 'document' }], messages: [{ role: 'assistant', content: 'Saved answer', image: 'blob:private', proposals: [{ id: 'private-proposal', path: 'x', diff: 'x' }] }] })
const backup = exportBackup(sessions, projects, defaultPreferences)
assert(!backup.includes('private-attachment'))
assert(!backup.includes('private-proposal'))
assert(!backup.includes('blob:private'))
const restored = importBackup(backup)
assert.notEqual(restored.sessions.chat[0].id, sessions.chat[0].id)
assert.notEqual(restored.projects[0].id, projects[0].id)
assert.equal(restored.sessions.chat[0].projectId, restored.projects[0].id)
assert.equal(restored.sessions.chat[0].pinned, true)
assert.equal(restored.sessions.chat[0].archived, true)
assert.equal(restored.sessions.chat[0].messages[0].content, 'Saved answer')
assert.deepEqual(restored.sessions.chat[0].attachments, [])
assert.throws(() => importBackup('{"format":"other"}'))
const malformed = JSON.parse(backup)
malformed.sessions.chat[0].messages = [{ role: 'system', content: 'Unsafe imported role' }]
assert.throws(() => importBackup(JSON.stringify(malformed)))
const saved = validate({ sessions, projects, activeSessions: { chat: sessions.chat[0].id } })
assert.equal(saved.sessions.chat[0].projectId, projects[0].id)
assert.equal(saved.activeSessions.chat, sessions.chat[0].id)
assert.equal(validate({ sessions }).sessions.chat[0].projectId, undefined)
assert.equal(validate({ chat: [{ role: 'user', content: 'Legacy chat' }] }).sessions.chat[0].messages[0].content, 'Legacy chat')
assert.equal(validate({ sessions: { chat: {} } }).sessions.chat.length, 1)
assert.equal(normalizePreferences({ theme: 'invalid', sendWithEnter: 'false' }).theme, 'dark')
assert.equal(normalizePreferences({ sendWithEnter: false }).sendWithEnter, false)
assert.match(personalizedPrompt('Hello', { ...defaultPreferences, responseLanguage: 'en', customInstructions: 'Use examples' }, 'Project context'), /Answer in English[\s\S]*Use examples[\s\S]*Project context[\s\S]*Hello/)
console.log('20 workspace assertions passed: backup safety, project remapping, migration, validation, and personalized prompts.')
