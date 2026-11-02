import type { Coverage, Source } from './types'

export type NoteTone = 'ok' | 'warn'

/** Plain-language checks that tell the reader how far a document answer can be trusted. */
export function coverageNotes(coverage: Coverage, answered: boolean): Array<[NoteTone, string]> {
  const notes: Array<[NoteTone, string]> = []
  notes.push(
    coverage.complete
      ? ['ok', 'Seluruh bagian dokumen tersedia untuk jawaban ini.']
      : [
          'warn',
          `Dokumen terlalu besar untuk dibaca sekaligus: ${coverage.selected} dari ${coverage.total} bagian dipilih berdasarkan pertanyaan. Jawaban ini bukan pemeriksaan seluruh dokumen.`
        ]
  )
  if (coverage.unreadable_pages?.length)
    notes.push([
      'warn',
      `Halaman tidak terbaca (tanpa lapisan teks, perlu OCR): ${coverage.unreadable_pages.join(', ')}.`
    ])
  if (coverage.matched === 0)
    notes.push([
      'warn',
      'Kata kunci pertanyaan tidak ditemukan di dokumen. Jawaban mungkin tidak didukung sumber.'
    ])
  if (answered && coverage.cited === 0)
    notes.push([
      'warn',
      'Jawaban tidak merujuk bagian sumber mana pun. Periksa isi sumber sebelum memakai jawaban ini.'
    ])
  return notes
}

/** Cited sources first, then the rest in document order. */
export function orderedSources(sources: Source[]): Source[] {
  return sources
    .map((source, index) => ({ source, index }))
    .sort(
      (a, b) =>
        Number(!!b.source.cited) - Number(!!a.source.cited) ||
        (a.source.section ?? a.index) - (b.source.section ?? b.index)
    )
    .map(({ source }) => source)
}
