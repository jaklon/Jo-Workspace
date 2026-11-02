import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { build } from '../desktop-app/node_modules/esbuild/lib/main.js'
import { fileURLToPath } from 'node:url'

const result = await build({ entryPoints: [fileURLToPath(new URL('../desktop-app/src/main/recovery-profile.ts', import.meta.url))], bundle: true, platform: 'node', format: 'esm', write: false })
const { recoveryProfile } = await import('data:text/javascript;base64,' + Buffer.from(result.outputFiles[0].text).toString('base64'))
const root = await mkdtemp(join(tmpdir(), 'jo-profile-test-'))
try {
  assert.equal(recoveryProfile(undefined), undefined)
  assert.throws(() => recoveryProfile('relative/path'))
  assert.throws(() => recoveryProfile(root))
  for (const name of ['runtime', 'workspace', 'browser']) await mkdir(join(root, name))
  assert.throws(() => recoveryProfile(root))
  await writeFile(join(root, 'browser', 'state.json'), '{}')
  assert.equal(recoveryProfile(root), root)
  console.log('Recovery profile path tests passed.')
} finally {
  await rm(root, { recursive: true, force: true })
}
