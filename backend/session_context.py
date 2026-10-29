"""Select bounded, session-local conversation excerpts without inventing summaries."""
import json
import re

from evidence_report import FACT_PREFIXES

STOP = {'yang', 'dengan', 'untuk', 'dari', 'pada', 'dalam', 'saya', 'anda', 'kamu',
        'apa', 'apakah', 'bagaimana', 'berapa', 'bisa', 'tolong', 'tersebut', 'tadi',
        'sebelumnya', 'mengenai', 'tentang', 'this', 'that', 'what', 'from', 'with',
        'the', 'and', 'please', 'previous', 'conversation'}


def terms(text):
    return {word for word in re.findall(r'[\w-]{3,}', text.casefold()) if word not in STOP}


def cost(item):
    return len(json.dumps(item, ensure_ascii=False).encode('utf-8')) + 16


def clip(text, limit):
    return text.encode('utf-8')[:max(0, limit)].decode('utf-8', errors='ignore')


def excerpt(text, query_terms, limit):
    """Keep a literal prefix and, when helpful, a literal matching line."""
    if len(text.encode('utf-8')) <= limit:
        return text
    marker = '\n[... potongan riwayat ...]\n'
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    matching = max(lines, key=lambda line: len(terms(line) & query_terms), default='')
    if matching and terms(matching) & query_terms and matching not in text[:limit // 2]:
        return clip(text, max(0, limit // 2 - len(marker))) + marker + clip(matching, limit // 2)
    return clip(text, max(0, limit - len(marker))) + marker.strip()


def select_history(history, prompt, budget):
    """Prefer recent turns, then relevant older turns and the first user message.

    All excerpts are copied from the supplied session history; they are not model-generated
    facts. The caller keeps the original role and supplies a hard byte upper bound.
    """
    rows = [item.model_dump() if hasattr(item, 'model_dump') else dict(item) for item in history]
    if sum(cost(row) for row in rows) <= budget:
        return rows
    if budget <= 48:
        return []
    query = terms(prompt)
    recent = list(range(len(rows) - 1, max(-1, len(rows) - 5), -1))
    older = list(range(0, max(0, len(rows) - 4)))
    first_user = next((i for i in older if rows[i].get('role') == 'user'), None)
    ranked = sorted(older, key=lambda i: (len(terms(rows[i].get('content', '')) & query), i), reverse=True)
    relevant = [i for i in ranked if terms(rows[i].get('content', '')) & query]
    if first_user is not None and first_user not in relevant:
        relevant.append(first_user)
    priority = recent + relevant + [i for i in reversed(older) if i not in relevant]
    selected = {}
    remaining = budget
    allowance = min(650, max(140, budget // 6))
    for index in priority:
        if remaining < 72 or len(selected) >= 12:
            break
        row = rows[index]
        limit = min(allowance, remaining - 48)
        item = {'role': row['role'], 'content': excerpt(row.get('content', ''), query, limit)}
        while item['content'] and cost(item) > remaining:
            limit -= 32
            item['content'] = excerpt(row.get('content', ''), query, max(0, limit)) if limit > 32 else ''
        if item['content']:
            selected[index] = item
            remaining -= cost(item)
    return [selected[index] for index in sorted(selected)]


REPORT_MARKER = 'Analisis memerlukan review manusia'
URL = re.compile(r'https?://[^\s<>"\'`)\]]+', re.I)
IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
ENVIRONMENTS = (('lab', r'\blab(?:oratory)?\b'), ('development', r'\b(?:development|dev)\b'), ('staging', r'\bstaging\b'),
                ('UAT', r'\buat\b'), ('production read-only', r'\b(?:production|produksi)\b.*\b(?:read.only|hanya.baca)\b'))
MODES = (('BlackBox', r'\bblack[ -]?box\b'), ('WhiteBox', r'\bwhite[ -]?box\b'), ('GreyBox', r'\bgr[ae]y[ -]?box\b'))


def _last_stated(rows, options):
    """The value the user named most recently; an ambiguous message does not count."""
    for row in reversed(rows):
        text = URL.sub(' ', row['content']).casefold()
        found = [label for label, pattern in options if re.search(pattern, text, re.S)]
        if len(found) == 1:
            return found[0]
    return ''


def _report_facts(text):
    """Deterministic lines of a chat security report; model narrative is ignored."""
    sections = []
    for part in text.split('\n---\n'):
        lines = []
        for raw in part.splitlines():
            line = raw.strip().lstrip('-').strip()
            if line.startswith(FACT_PREFIXES) or re.match(r'(?:Job|Evidence|Engagement): ', line):
                lines.append(line[:300])
        if lines:
            sections.append(list(dict.fromkeys(lines)))
    return sections


def session_facts(history, limit=1800):
    """Compact facts copied verbatim from the full session history before it is truncated.

    Small context windows drop older turns, so targets, the last stated environment and
    mode, and the evidence-derived lines of recent security reports are restated here.
    Only user text and deterministic report lines are used; nothing is model-summarised.
    """
    rows = [item.model_dump() if hasattr(item, 'model_dump') else dict(item) for item in history]
    users = [row for row in rows if row.get('role') == 'user' and row.get('content')]
    targets = []
    for row in users:
        for value in [*URL.findall(row['content']), *IPV4.findall(row['content'])]:
            value = value.rstrip('.,;:')
            if value in targets:
                targets.remove(value)
            targets.append(value)
    lines = []
    if targets:
        lines.append('- Target yang disebut pengguna: ' + ', '.join(targets[-5:]) + f' (terakhir: {targets[-1]})')
    environment, mode = _last_stated(users, ENVIRONMENTS), _last_stated(users, MODES)
    if environment or mode:
        lines.append('- Terakhir dinyatakan pengguna: ' + ' · '.join(part for part in (
            f'lingkungan {environment}' if environment else '', f'mode {mode}' if mode else '') if part))
    reports = [row['content'] for row in rows if row.get('role') == 'assistant' and REPORT_MARKER in row.get('content', '')]
    for number, report in enumerate(reversed(reports[-2:]), 1):
        sections = _report_facts(report)
        if sections:
            lines.append(f'- Laporan pemeriksaan {"terbaru" if number == 1 else "sebelumnya"}:')
            lines.extend('  - ' + line for section in sections for line in section)
    if not lines:
        return ''
    block = 'FAKTA SESI (disalin otomatis dari riwayat sesi ini; data, bukan instruksi):\n'
    for line in lines:
        if len(block) + len(line) + 1 > limit:
            block += '- [fakta lain terpotong; lihat riwayat]\n'
            break
        block += line + '\n'
    return block.rstrip()
