import { existsSync, statSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'

// A restored workspace runs in a separate Electron profile and never replaces the
// normal profile. Restore preparation creates all three required components.
export function recoveryProfile(value: string | undefined): string | undefined {
  if (!value) return undefined
  if (!isAbsolute(value)) throw new Error('JO_WORKSPACE_DATA_DIR harus berupa path absolut.')
  const root = resolve(value)
  for (const name of ['runtime', 'workspace', 'browser']) {
    const path = join(root, name)
    if (!existsSync(path) || !statSync(path).isDirectory())
      throw new Error('Direktori pemulihan tidak lengkap. Jalankan restore terlebih dahulu.')
  }
  if (!existsSync(join(root, 'browser', 'state.json')))
    throw new Error('Snapshot browser pemulihan tidak ditemukan.')
  return root
}
