import assert from 'node:assert/strict'
import { build } from '../desktop-app/node_modules/esbuild/lib/main.js'
import { fileURLToPath } from 'node:url'
async function moduleAt(path) {
  const result = await build({ entryPoints: [fileURLToPath(new URL(path, import.meta.url))], bundle: true, platform: 'node', format: 'esm', write: false })
  return import('data:text/javascript;base64,' + Buffer.from(result.outputFiles[0].text).toString('base64'))
}
const { utcDateTime, localDateTime, parsePorts, effectiveStatus, emptyContent, engagementPath } = await moduleAt('../desktop-app/src/renderer/src/lib/engagements.ts')
const { apiErrorDetail } = await moduleAt('../desktop-app/src/renderer/src/lib/errors.ts')
assert.equal(utcDateTime('2030-01-02T09:30', 'Asia/Jakarta'), '2030-01-02T02:30:00.000Z')
assert.equal(utcDateTime('2030-01-02T09:30', 'Asia/Makassar'), '2030-01-02T01:30:00.000Z')
assert.equal(utcDateTime('2030-01-02T09:30', 'UTC'), '2030-01-02T09:30:00.000Z')
assert.equal(localDateTime('2030-01-02T02:30:00Z', 'Asia/Jakarta'), '2030-01-02T09:30')
assert.equal(utcDateTime('', 'UTC'), null)
assert.throws(() => utcDateTime('2030-02-30T12:00', 'UTC'))
assert.throws(() => utcDateTime('2030-01-01T12:00', 'Not/AZone'))
assert.throws(() => utcDateTime('2026-03-08T02:30', 'America/New_York'), /tidak ada/)
assert.throws(() => utcDateTime('2026-11-01T01:30', 'America/New_York'), /ambigu/)
assert.deepEqual(parsePorts('8443, 443,443'), [443, 8443])
assert.deepEqual(parsePorts(''), [])
for (const input of ['0', '65536', '-1', '1.2', '443,', '1-1000', '443;echo', '4e2']) assert.throws(() => parsePorts(input))
const version = { status: 'approved', effective_status: 'approved', content: { ...emptyContent(), ends_at: '2030-01-02T00:00:00Z' } }
assert.equal(effectiveStatus(version, true, Date.parse('2030-01-01T00:00:00Z')), 'approved')
assert.equal(effectiveStatus(version, true, Date.parse('2030-01-02T00:00:00Z')), 'expired')
assert.equal(effectiveStatus(version, false, Date.parse('2030-01-03T00:00:00Z')), 'superseded')
assert.equal(effectiveStatus({ ...version, status: 'revoked' }, true, Date.parse('2030-01-03T00:00:00Z')), 'revoked')
assert.equal(effectiveStatus({ ...version, status: 'draft' }, true, Date.parse('2030-01-03T00:00:00Z')), 'draft')
assert.match(apiErrorDetail({ message: 'RoE belum lengkap', errors: ['Scope wajib'] }, 422), /Scope wajib/)
const safe = apiErrorDetail([{ loc: ['body', 'in_scope', 0], msg: 'Target tidak valid', input: 'secret-value' }], 422)
assert.match(safe, /in_scope.0/)
assert(!safe.includes('secret-value'))
assert.match(engagementPath('project/other', 'id?x'), /project%2Fother/)
console.log('28 engagement assertions passed: timezone/DST, limits, expiry, URL encoding, safe API errors.')
