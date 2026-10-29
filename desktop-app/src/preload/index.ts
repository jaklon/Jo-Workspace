import { contextBridge, ipcRenderer } from 'electron'
if (process.argv.includes('--agent-bundled-backend')) {
  contextBridge.exposeInMainWorld('agentDesktop', {
    reconnect: (): Promise<boolean> => ipcRenderer.invoke('agent:reconnect')
  })
}
