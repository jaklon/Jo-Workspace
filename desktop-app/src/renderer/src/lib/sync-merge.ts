/** Pure reconciliation decisions. Applying them and persisting metadata are separate. */
export type SyncKind = 'project' | 'session'
export interface SyncRecord {
  kind: SyncKind
  id: string
  version: number
  deleted: boolean
  data: Record<string, unknown> | null
}
export interface SyncBase {
  version: number
  fingerprint: string | null
}
export interface SyncConflict {
  key: string
  local: Record<string, unknown> | null
  remote: SyncRecord
}

export function syncKey(kind: SyncKind, id: string): string {
  return `${kind}:${id}`
}

/** Canonical comparison ignores object key order but retains array order and values. */
export function fingerprint(value: unknown): string {
  const canonical = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(canonical)
    if (item && typeof item === 'object') {
      return Object.fromEntries(
        Object.entries(item as Record<string, unknown>)
          .filter(([, v]) => v !== undefined)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([key, v]) => [key, canonical(v)])
      )
    }
    return item
  }
  return JSON.stringify(canonical(value))
}

export function reconcileRemote(
  local: Record<string, Record<string, unknown>>,
  base: Record<string, SyncBase>,
  records: SyncRecord[]
): { updates: SyncRecord[]; conflicts: SyncConflict[]; accepted: Record<string, SyncBase> } {
  const updates: SyncRecord[] = []
  const conflicts: SyncConflict[] = []
  const accepted: Record<string, SyncBase> = {}
  for (const remote of records) {
    const key = syncKey(remote.kind, remote.id)
    const value = local[key] ?? null
    const localHash = value === null ? null : fingerprint(value)
    const remoteHash = remote.deleted ? null : fingerprint(remote.data)
    const previous = base[key]
    // A migrated local item with the same ID must not silently replace remote data.
    const localChanged = previous ? localHash !== previous.fingerprint : localHash !== null
    const remoteChanged = previous ? remoteHash !== previous.fingerprint : true
    if (localChanged && remoteChanged && localHash !== remoteHash) {
      conflicts.push({ key, local: value, remote })
      continue
    }
    if (!localChanged && localHash !== remoteHash) updates.push(remote)
    accepted[key] = { version: remote.version, fingerprint: remoteHash }
  }
  return { updates, conflicts, accepted }
}
