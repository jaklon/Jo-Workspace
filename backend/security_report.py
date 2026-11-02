"""Readable security report built only from a stored, integrity-checked report snapshot.

Every sentence here is derived from snapshot fields (finding status, severity, review,
evidence provenance); nothing is model-generated. The technical markdown with the full
snapshot stays available as an appendix, so this view never replaces the record."""
import re

SEVERITY = {'critical': 'Kritis', 'high': 'Tinggi', 'medium': 'Sedang', 'low': 'Rendah',
            'informational': 'Informasional', 'unrated': 'Belum dinilai'}
SEVERITY_ORDER = list(SEVERITY)
STATUS = {'candidate': 'Kandidat (belum direview)', 'inconclusive': 'Belum dapat disimpulkan',
          'validated': 'Tervalidasi, belum diperbaiki', 'retest_passed': 'Diperbaiki, lolos retest',
          'false_positive': 'Bukan masalah (false positive)'}
REVIEWED = ('validated', 'retest_passed', 'false_positive', 'inconclusive')


def _one_line(text, limit=400):
    text = re.sub(r'\s+', ' ', str(text or '')).strip()
    return text if len(text) <= limit else text[:limit - 1] + '…'


def confidence(finding, evidence):
    """How much the recorded evidence supports this finding, with the reason in words."""
    linked = [evidence[i] for i in finding['content'].get('evidence_ids', []) if i in evidence]
    observed = [e for e in linked if e.get('source') != 'offline_policy']
    status = finding['status']
    if status == 'retest_passed':
        return 'Tinggi', 'Divalidasi analis dan diperiksa ulang dengan bukti retest baru dari job berbeda.'
    if status == 'validated':
        if observed:
            return 'Tinggi', f'Divalidasi analis dengan {len(observed)} bukti observasi tercatat.'
        return 'Sedang', 'Divalidasi analis, tetapi hanya didukung bukti policy offline.'
    if status == 'false_positive':
        return 'Tidak berlaku', 'Analis menyatakan bukan masalah.'
    if status == 'inconclusive':
        return 'Rendah', 'Analis belum dapat menyimpulkan dari bukti yang ada.'
    return 'Rendah', 'Belum direview analis; bisa berupa temuan semu.'


def _finding_view(finding, evidence):
    c = finding['content']
    level, reason = confidence(finding, evidence)
    return {'id': finding['id'], 'title': c['title'], 'status': finding['status'], 'status_label': STATUS[finding['status']],
            'severity': c['severity'], 'severity_label': SEVERITY[c['severity']], 'severity_reason': _one_line(c.get('severity_reason')),
            'target': c['target'].get('value') if isinstance(c.get('target'), dict) else str(c.get('target')),
            'category': c.get('category', ''), 'description': _one_line(c.get('description'), 600),
            'remediation': _one_line(c.get('remediation'), 600), 'confidence': level, 'confidence_reason': reason,
            'evidence_ids': list(c.get('evidence_ids', [])), 'retest_evidence_ids': list(finding.get('retest_evidence_ids', [])),
            'review': {'actor': (finding.get('review') or {}).get('actor_label', ''),
                       'assessment': _one_line((finding.get('review') or {}).get('analyst_assessment')),
                       'at': (finding.get('review') or {}).get('at', '')} if finding.get('review') else None}


def _rank(view):
    return (SEVERITY_ORDER.index(view['severity']), view['title'])


def follow_up(view):
    if view['status'] == 'validated':
        fix = view['remediation'] or 'Tentukan perbaikan bersama pemilik sistem.'
        return f"{fix} Setelah diperbaiki, jalankan retest dan catat bukti baru."
    if view['status'] in ('candidate', 'inconclusive'):
        return 'Review oleh analis: validasi dengan bukti tambahan atau tandai false positive.'
    if view['status'] == 'retest_passed':
        return 'Pantau agar konfigurasi tidak kembali; sertakan dalam pemeriksaan berkala.'
    return None


def compare(current, previous):
    """Finding-level changes since the previous report snapshot of the same engagement."""
    before = {f['id']: f for f in previous['findings']}
    after = {f['id']: f for f in current['findings']}
    changed = [{'title': after[i]['content']['title'], 'from': STATUS[before[i]['status']], 'to': STATUS[after[i]['status']],
                'resolved': after[i]['status'] == 'retest_passed' and before[i]['status'] != 'retest_passed'}
               for i in after if i in before and before[i]['status'] != after[i]['status']]
    return {'previous_id': previous['id'], 'previous_title': previous['title'], 'previous_created_at': previous['created_at'],
            'new': [after[i]['content']['title'] for i in after if i not in before],
            'removed': [before[i]['content']['title'] for i in before if i not in after],
            'changed': changed,
            'still_open': [after[i]['content']['title'] for i in after if i in before
                           and before[i]['status'] == after[i]['status'] == 'validated'],
            'evidence_added': len({e['id'] for e in current['evidence']} - {e['id'] for e in previous['evidence']})}


def report_view(snapshot, previous=None):
    evidence = {e['id']: e for e in snapshot['evidence']}
    findings = sorted((_finding_view(f, evidence) for f in snapshot['findings']), key=_rank)
    open_items = [f for f in findings if f['status'] == 'validated']
    counts = {status: sum(1 for f in findings if f['status'] == status) for status in STATUS}
    by_severity = {SEVERITY[s]: sum(1 for f in open_items if f['severity'] == s) for s in SEVERITY_ORDER}
    worst = open_items[0]['severity_label'] if open_items else None
    headline = (f"{len(open_items)} masalah tervalidasi masih terbuka; tingkat tertinggi {worst}." if open_items
                else 'Tidak ada masalah tervalidasi yang masih terbuka.')
    owner = {'headline': headline, 'open_by_severity': {k: v for k, v in by_severity.items() if v},
             'fixed': counts['retest_passed'], 'unreviewed': counts['candidate'] + counts['inconclusive'],
             'dismissed': counts['false_positive'], 'analyst_summary': snapshot['summary']}
    return {'owner_summary': owner,
            'reviewed': [f for f in findings if f['status'] in REVIEWED],
            'unreviewed': [f for f in findings if f['status'] not in REVIEWED],
            'evidence': [{'id': e['id'], 'title': e['title'], 'source': e['source'], 'tool': e.get('tool_name', ''),
                          'captured_at': e.get('captured_at', ''), 'target': (e.get('target') or {}).get('value', '')}
                         for e in snapshot['evidence']],
            # Fixes first, then items awaiting review, then monitoring of resolved ones.
            'follow_ups': [{'title': f['title'], 'action': a}
                           for status in ('validated', 'candidate', 'inconclusive', 'retest_passed')
                           for f in findings if f['status'] == status and (a := follow_up(f))],
            'limitations': snapshot['limitations'],
            'comparison': compare(snapshot, previous) if previous else None}


def readable_markdown(snapshot, report_hash, previous=None):
    view = report_view(snapshot, previous)
    owner = view['owner_summary']
    out = [f"# {_one_line(snapshot['title'])}",
           f"\nDibuat {snapshot['created_at']} oleh {_one_line(snapshot['author_declaration'])} (deklarasi lokal) · "
           f"RoE v{snapshot['roe_version']} · SHA-256 snapshot `{report_hash}`",
           '\n## Ringkasan untuk pemilik sistem', f"\n**{owner['headline']}**\n"]
    if owner['open_by_severity']:
        out.append('Masalah terbuka per tingkat: ' + ', '.join(f"{k} {v}" for k, v in owner['open_by_severity'].items()) + '.')
    out.append(f"Sudah diperbaiki dan lolos retest: {owner['fixed']}. Belum direview: {owner['unreviewed']}. "
               f"Dinyatakan bukan masalah: {owner['dismissed']}.")
    out += ['\nRingkasan analis:', '\n> ' + _one_line(owner['analyst_summary'], 2000)]
    comparison = view['comparison']
    if comparison:
        out.append(f"\n## Perbandingan dengan laporan sebelumnya ({_one_line(comparison['previous_title'])}, {comparison['previous_created_at']})\n")
        for label, items in (('Temuan baru', comparison['new']), ('Masih terbuka', comparison['still_open']),
                             ('Tidak lagi tercatat', comparison['removed'])):
            if items:
                out.append(f"- {label}: " + '; '.join(_one_line(t, 160) for t in items))
        for item in comparison['changed']:
            out.append(f"- {'Diperbaiki' if item['resolved'] else 'Status berubah'}: {_one_line(item['title'], 160)} "
                       f"({item['from']} → {item['to']})")
        out.append(f"- Evidence baru sejak laporan sebelumnya: {comparison['evidence_added']}")
        if not (comparison['new'] or comparison['changed'] or comparison['removed']):
            out.append('- Tidak ada perubahan status temuan.')
    out.append('\n## Temuan yang telah direview')
    if not view['reviewed']:
        out.append('\nBelum ada temuan yang direview analis.')
    for n, f in enumerate(view['reviewed'], 1):
        out += [f"\n### {n}. {_one_line(f['title'], 160)}",
                f"- Status: {f['status_label']}", f"- Tingkat: {f['severity_label']}"
                + (f" — {f['severity_reason']}" if f['severity_reason'] else ''),
                f"- Target: `{f['target']}` · Kategori: {_one_line(f['category'], 120)}",
                f"- Keyakinan: {f['confidence']} — {f['confidence_reason']}",
                f"- Deskripsi: {f['description']}",
                f"- Evidence: {', '.join(f['evidence_ids']) or '-'}"
                + (f" · retest: {', '.join(f['retest_evidence_ids'])}" if f['retest_evidence_ids'] else '')]
        if f['review']:
            out.append(f"- Review analis ({_one_line(f['review']['actor'], 120)}, {f['review']['at']}): {f['review']['assessment']}")
    if view['unreviewed']:
        out.append('\n## Kandidat belum direview\n\nBagian ini belum menjadi kesimpulan; jangan dijadikan dasar keputusan.\n')
        out += [f"- {_one_line(f['title'], 160)} ({f['severity_label']}, target `{f['target']}`)" for f in view['unreviewed']]
    out.append('\n## Evidence\n\n| ID | Judul | Sumber | Tool | Waktu | Target |\n|---|---|---|---|---|---|')
    out += [f"| {e['id']} | {_one_line(e['title'], 80).replace('|', '/')} | {e['source']} | {_one_line(e['tool'], 40).replace('|', '/')} "
            f"| {e['captured_at']} | {_one_line(e['target'], 80).replace('|', '/')} |" for e in view['evidence']]
    out.append('\n## Keterbatasan pemeriksaan\n')
    out += [f"- {_one_line(item)}" for item in view['limitations']]
    out.append('\n## Tindak lanjut\n')
    out += [f"- **{_one_line(item['title'], 160)}**: {item['action']}" for item in view['follow_ups']] or ['- Tidak ada tindak lanjut.']
    return '\n'.join(out) + '\n'
