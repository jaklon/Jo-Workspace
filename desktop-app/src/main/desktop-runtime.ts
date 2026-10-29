import { spawn, type ChildProcess } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  writeFileSync
} from 'node:fs'
import { join } from 'node:path'
import { createServer } from 'node:net'

export interface DesktopRuntime {
  origin: string
  authenticate: () => Promise<void>
  stop: () => void
}

async function ensurePortAvailable(port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const probe = createServer()
    probe.once('error', () =>
      reject(
        new Error(
          `Port desktop ${port} sedang digunakan aplikasi lain. Tutup aplikasi tersebut lalu buka Jo Workspace kembali.`
        )
      )
    )
    probe.listen(port, '127.0.0.1', () => probe.close(() => resolve()))
  })
}

async function startOllama(): Promise<void> {
  const url = process.env.OLLAMA_URL || 'http://127.0.0.1:11434'
  try {
    if ((await fetch(`${url}/api/tags`, { signal: AbortSignal.timeout(1500) })).ok) return
  } catch {
    /* Try the installed local Ollama service below. */
  }
  if (!['http://127.0.0.1:11434', 'http://localhost:11434'].includes(url)) return
  const executable = [
    join(process.env.LOCALAPPDATA || '', 'Programs', 'Ollama', 'ollama.exe'),
    join(process.env.ProgramFiles || 'C:\\Program Files', 'Ollama', 'ollama.exe')
  ].find(existsSync)
  if (!executable) return // The connection panel explains how to install Ollama.
  const service = spawn(executable, ['serve'], {
    windowsHide: true,
    detached: true,
    stdio: 'ignore'
  })
  service.on('error', () => {
    /* A missing runtime is reported by the health endpoint. */
  })
  service.unref() // Shared Ollama service remains available to other clients.
}

export async function startDesktopRuntime(
  resources: string,
  dataDir: string,
  sessionFetch: typeof fetch
): Promise<DesktopRuntime> {
  const port = 18010
  const origin = `http://127.0.0.1:${port}`
  const executable = join(resources, 'backend', 'agent-backend.exe')
  if (!existsSync(executable) || !existsSync(join(resources, 'web', 'index.html')))
    throw new Error(
      'Komponen backend/web tidak lengkap. Pasang ulang Jo Workspace menggunakan installer.'
    )
  const runtimeDir = join(dataDir, 'runtime')
  const workspace = join(dataDir, 'workspace')
  const logs = join(dataDir, 'logs')
  for (const path of [runtimeDir, workspace, logs]) mkdirSync(path, { recursive: true })
  const tokenPath = join(runtimeDir, 'api-token')
  if (!existsSync(tokenPath))
    writeFileSync(tokenPath, randomBytes(32).toString('base64url'), { flag: 'wx', mode: 0o600 })
  const token = readFileSync(tokenPath, 'utf8').trim()
  if (token.length < 24) throw new Error(`Token desktop tidak valid. Periksa ${tokenPath}.`)
  await ensurePortAvailable(port)
  const logPath = join(logs, 'backend.log')
  const descriptor = openSync(
    logPath,
    existsSync(logPath) && statSync(logPath).size < 2_000_000 ? 'a' : 'w'
  )
  let child: ChildProcess
  try {
    child = spawn(executable, ['--port', String(port), '--parent-pid', String(process.pid)], {
      windowsHide: true,
      cwd: dataDir,
      stdio: ['ignore', descriptor, descriptor],
      env: {
        ...process.env,
        AGENT_DATA_DIR: runtimeDir,
        AGENT_WORKSPACE: workspace,
        AGENT_WEB_DIR: join(resources, 'web'),
        AGENT_API_TOKEN: token,
        AGENT_ALLOWED_ORIGINS: origin
      }
    })
  } finally {
    closeSync(descriptor)
  }
  let failed = ''
  child.once('error', (error) => {
    failed = error.message
  })
  child.once('exit', (code) => {
    failed = `Backend berhenti (kode ${code ?? 'unknown'}).`
  })
  const stop = (): void => {
    if (child.exitCode === null && !child.killed) child.kill()
  }
  const authenticate = async (): Promise<void> => {
    const response = await sessionFetch(`${origin}/api/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ token }),
      signal: AbortSignal.timeout(5000)
    })
    if (!response.ok) throw new Error('Sesi desktop gagal dihubungkan. Buka ulang aplikasi.')
  }
  try {
    const deadline = Date.now() + 60_000
    let ready = false
    while (Date.now() < deadline) {
      if (failed) throw new Error(`${failed} Log: ${logPath}`)
      try {
        ready = (
          await fetch(`${origin}/api/metrics`, {
            headers: { Authorization: `Bearer ${token}` },
            signal: AbortSignal.timeout(1000)
          })
        ).ok
      } catch {
        /* Backend may still be importing libraries on first launch. */
      }
      if (ready) break
      await new Promise((resolve) => setTimeout(resolve, 300))
    }
    if (!ready) throw new Error(`Backend belum siap setelah 60 detik. Log: ${logPath}`)
    await authenticate()
    void startOllama()
    return { origin, authenticate, stop }
  } catch (error) {
    stop()
    throw error
  }
}
