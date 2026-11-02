import { app, shell, BrowserWindow, dialog, ipcMain, session } from 'electron'
import { join } from 'node:path'
import { electronApp, optimizer, is } from '@electron-toolkit/utils'
import { startDesktopRuntime, type DesktopRuntime } from './desktop-runtime'
import { recoveryProfile } from './recovery-profile'
import icon from '../../resources/agent-os.png?asset'

app.setName('Jo Workspace')
let mainWindow: BrowserWindow | null = null
let desktopRuntime: DesktopRuntime | null = null
const bundledBackend = app.isPackaged && process.platform === 'win32'
// Preserve existing Electron storage across the branding change.
app.setPath(
  'userData',
  recoveryProfile(process.env.JO_WORKSPACE_DATA_DIR) ||
    join(app.getPath('appData'), bundledBackend ? 'Agent OS' : 'agent-os')
)

async function createWindow(): Promise<void> {
  mainWindow = new BrowserWindow({
    title: 'Jo Workspace',
    width: 1280,
    height: 840,
    minWidth: 420,
    minHeight: 560,
    backgroundColor: '#212121',
    show: false,
    autoHideMenuBar: true,
    icon,
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: true,
      additionalArguments: bundledBackend ? ['--agent-bundled-backend'] : [],
      contextIsolation: true,
      nodeIntegration: false
    }
  })
  mainWindow.on('ready-to-show', () => {
    if (process.env.JO_TEST_HIDDEN !== '1') mainWindow?.show()
  })
  mainWindow.on('closed', () => {
    mainWindow = null
  })
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    try {
      const target = new URL(url)
      if (['https:', 'http:'].includes(target.protocol)) void shell.openExternal(target.href)
    } catch {
      /* Invalid URLs stay inside the application boundary. */
    }
    return { action: 'deny' }
  })
  mainWindow.webContents.on('will-navigate', (event) => event.preventDefault())
  if (is.dev && process.env.ELECTRON_RENDERER_URL) {
    await mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL)
  } else if (bundledBackend) {
    await mainWindow.loadURL(
      'data:text/html;charset=utf-8,' +
        encodeURIComponent(
          '<html><body style="margin:0;background:#212121;color:#ececec;font:16px Segoe UI;display:grid;place-items:center;height:100vh"><div style="text-align:center"><h1>Jo Workspace</h1><p>Menyiapkan ruang kerja lokal Anda…</p><small>Backend akan berjalan otomatis.</small></div></body></html>'
        )
    )
    if (!desktopRuntime)
      desktopRuntime = await startDesktopRuntime(
        process.resourcesPath,
        app.getPath('userData'),
        (url, options) => session.defaultSession.fetch(url, options)
      )
    await mainWindow.loadURL(desktopRuntime.origin)
  } else {
    await mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

if (!app.requestSingleInstanceLock()) {
  app.quit()
} else {
  app.on('second-instance', () => {
    if (mainWindow?.isMinimized()) mainWindow.restore()
    mainWindow?.show()
    mainWindow?.focus()
  })
  app
    .whenReady()
    .then(async () => {
      electronApp.setAppUserModelId('id.agentos.desktop')
      app.on('browser-window-created', (_, window) => optimizer.watchWindowShortcuts(window))
      ipcMain.handle('agent:reconnect', async (event) => {
        if (
          !desktopRuntime ||
          event.sender !== mainWindow?.webContents ||
          event.senderFrame?.url !== desktopRuntime.origin + '/'
        )
          return false
        await desktopRuntime.authenticate()
        return true
      })
      try {
        await createWindow()
      } catch (error) {
        desktopRuntime?.stop()
        dialog.showErrorBox(
          'Jo Workspace tidak dapat dimulai',
          error instanceof Error ? error.message : String(error)
        )
        app.quit()
      }
      app.on('activate', () => {
        if (!BrowserWindow.getAllWindows().length)
          void createWindow().catch((error) => dialog.showErrorBox('Jo Workspace', String(error)))
      })
    })
    .catch((error) => {
      dialog.showErrorBox('Jo Workspace', String(error))
      app.quit()
    })
}
app.on('before-quit', () => desktopRuntime?.stop())
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
