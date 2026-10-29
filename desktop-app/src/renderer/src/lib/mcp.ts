export interface MCPConfig {
  name: string
  adapter: string
  allowed_tools: string[]
  max_wall_seconds: number
  max_output_kb: number
}
export interface MCPServer {
  id: string
  revision: number
  state: 'draft' | 'approved' | 'disabled'
  config: MCPConfig
  config_hash: string
  descriptor_hash: string
  descriptor: Record<string, unknown>
  review: { actor_label: string; note: string; at: string } | null
  events?: {
    id: number
    revision: number
    at: string
    action: string
    actor: string
    note: string
  }[]
  checks?: { id: string; at: string; server_revision: number; result: Record<string, unknown> }[]
}
export interface MCPCatalog {
  servers: MCPServer[]
  catalog: Record<string, unknown>
  descriptor_hash: string
  runner_supported: boolean
  limits: { concurrency: number; max_wall_seconds: number; max_output_kb: number }
  external_servers_enabled: false
  pentest_execution_enabled: false
}
export interface MCPBinding {
  server_id: string
  server_revision: number
  descriptor_hash: string
  tool: string
  arguments: Record<string, string>
}
export const fixtureNames = [
  'headers_missing',
  'headers_present',
  'config_insecure',
  'config_hardened'
]
export const mcpTools = ['fixture.inspect', 'fixture.compare']
