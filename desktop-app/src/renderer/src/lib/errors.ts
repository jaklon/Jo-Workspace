export function apiErrorDetail(detail: unknown, status: number): string {
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail))
    return (
      detail
        .map((item) =>
          typeof item?.msg === 'string'
            ? `${Array.isArray(item.loc) ? item.loc.filter((p: unknown) => p !== 'body').join('.') + ': ' : ''}${item.msg}`
            : ''
        )
        .filter(Boolean)
        .join('\n') || `Permintaan ditolak (HTTP ${status}).`
    )
  if (
    detail &&
    typeof detail === 'object' &&
    'message' in detail &&
    typeof detail.message === 'string'
  ) {
    const errors =
      'errors' in detail && Array.isArray(detail.errors)
        ? detail.errors.filter((e: unknown) => typeof e === 'string')
        : []
    return [detail.message, ...errors].join('\n')
  }
  return `Permintaan ditolak (HTTP ${status}). Periksa input.`
}
