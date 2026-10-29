"""Evidence grounding for local-model security analysis.

The model may summarise and recommend, but every sentence it returns is checked
against the recorded evidence before it is stored or shown in chat:

* Literal anchors (URLs, hosts, IP addresses, ports, CVE IDs, file names and
  ``x-*`` header names) must appear verbatim in the evidence or target.
* Security concepts (cookie, CSP, HSTS, CORS, TLS, JWT, ...) must be backed by
  at least one evidence term, unless the sentence only states that the thing
  was *not* observed.
* Structured observations must carry an ``evidence_quote`` that is found in the
  evidence (case- and whitespace-insensitive).
* Claims about a structured fact (header present/missing, HTTPS, cache-control,
  CORS, cookie flags) must agree with the recorded value. A quote such as
  "content-security-policy" proves the header was *checked*, not that it was
  present, so "CSP tersedia" is rejected when the check says ``missing``.
  Quality claims ("aman", "kuat", "secure") about headers are rejected because
  evidence stores presence only, never header values.

Sentences that fail are removed and counted, so the report says how many model
claims were dropped instead of silently presenting them as facts.
"""
import json
import re

# Bump when the checks change; stored reports from older versions are re-checked when read.
GROUNDING_VERSION = 2

# concept -> (pattern that detects the concept in model text, evidence terms that support it)
CONCEPTS = {
    'cookie': (r'\bcookies?\b|set-cookie|httponly|samesite', ('cookie',)),
    'CSP': (r'\bcsp\b|content[- ]security[- ]policy', ('content-security-policy', 'csp')),
    'HSTS': (r'\bhsts\b|strict[- ]transport[- ]security', ('strict-transport-security', 'hsts')),
    'CORS': (r'\bcors\b|access-control-allow|\bpreflight\b', ('access-control', 'cors')),
    'X-Frame-Options': (r'x-frame-options|clickjacking|frame-ancestors', ('x-frame-options', 'frame-ancestors')),
    'TLS': (r'\btls\b|\bssl\b|sertifikat|certificate|cipher', ('tls', 'ssl', 'certificate', 'cert', 'cipher')),
    'JWT': (r'\bjwt\b|\bbearer\b', ('jwt', 'bearer', 'authorization')),
    'SQL injection': (r'sql[- ]?injection|\bsqli\b|injeksi sql', ('sql',)),
    'XSS': (r'\bxss\b|cross[- ]site[- ]scripting', ('xss', 'reflect', '<script')),
    'CSRF': (r'\bcsrf\b|\bxsrf\b', ('csrf', 'xsrf')),
    'kredensial': (r'\bpassword\b|kata sandi|kredensial|credential|hard-?coded secret',
                   ('password', 'passwd', 'credential', 'secret', 'api_key', 'apikey')),
    'cache': (r'cache-control|\bcaching\b|\bcache\b', ('cache',)),
    'redirect': (r'\bredirect|\bpengalihan\b', ('redirect', 'location')),
    'admin': (r'\badmin(?:istrator)?\b', ('admin',)),
    'directory listing': (r'directory listing|index of /', ('index of', 'directory')),
    'server version': (r'\bversi server\b|server version|banner', ('server', 'version', 'banner')),
}

NEGATION = re.compile(
    r'\b(?:tidak (?:ada|ditemukan|teramati|terlihat|tersedia|terdeteksi|tercakup|diuji)|belum (?:diuji|teramati|diperiksa)'
    r'|di luar cakupan|not (?:observed|present|found|detected|tested|covered)|no evidence|absent|out of scope)\b', re.I)

LITERAL_PATTERNS = (
    re.compile(r'\bCVE-\d{4}-\d{3,7}\b', re.I),
    re.compile(r'https?://[^\s"\'<>)\]]+', re.I),
    re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    re.compile(r'\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|id|dev|app|test|example|local|internal|co|ai|cloud)\b', re.I),
    re.compile(r'\b[\w./-]+\.(?:py|js|ts|tsx|jsx|php|java|go|rb|json|ya?ml|conf|cfg|ini|env|xml|sql|sh|ps1)\b', re.I),
    re.compile(r'\bx-[a-z][a-z0-9-]{2,}\b', re.I),
)
PORT = re.compile(r'\bport\s*:?\s*(\d{1,5})\b', re.I)
SENTENCE = re.compile(r'(?<=[.!?])\s+(?=[A-Z0-9"“(\[])')


def normalize(text):
    return re.sub(r'\s+', ' ', str(text)).strip().strip('"\'“”‘’`').lower()


def evidence_text(source):
    """Flatten evidence to searchable text: all values, and keys only when their value is non-empty."""
    parts = []

    def walk(value, key=None):
        if isinstance(value, dict):
            if key and value:
                parts.append(str(key))
            for k, v in value.items():
                walk(v, k)
        elif isinstance(value, (list, tuple)):
            if key and value:
                parts.append(str(key))
            for item in value:
                walk(item)
        elif value is None or value is False or value == '' or value == 0:
            return
        else:
            if key:
                parts.append(str(key))
            parts.append(str(value))

    result = source.get('result') or {}
    if result.get('kind') == 'operator_import':
        parts.append(str(result.get('content', '')))
        for name in ('tool_name', 'title', 'parameters'):
            if result.get(name):
                parts.append(str(result[name]))
    else:
        walk(result)
    target = (source.get('target') or {}).get('value')
    if target:
        parts.append(str(target))
    return normalize(' \n '.join(parts).replace('_', '-')) + ' ' + normalize(' \n '.join(parts))


def pair_key(key):
    return str(key).lower().replace('_', '-').rsplit('.', 1)[-1].strip(' "\'')


def pair_value(value):
    return (str(value).lower() if isinstance(value, bool) else str(value)).strip().strip('"\'').lower()


def evidence_pairs(source):
    """All (key, value) pairs of the structured result, including false/zero values; check rows map check -> status."""
    pairs = set()

    def walk(value, key=None):
        if isinstance(value, dict):
            if 'check' in value and 'status' in value:
                pairs.add((pair_key(value['check']), pair_value(value['status'])))
            for k, v in value.items():
                walk(v, k)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item, key)
        elif key is not None and value is not None:
            pairs.add((pair_key(key), pair_value(value)))

    result = source.get('result') or {}
    if result.get('kind') != 'operator_import':
        walk(result)
    return pairs


QUOTE_PAIR = re.compile(r'([A-Za-z][\w.-]*)\s*[:=]\s*([^,{}\[\]]+?)\s*(?=[,}\]]|$)')


def quoted_pairs_supported(quote, pairs):
    """Models quote the structured context as "key: value" (or nested braces); every pair must exist."""
    found = [(pair_key(key), pair_value(value)) for key, value in QUOTE_PAIR.findall(quote)
             if pair_value(value) not in ('', '{', '[')]
    return bool(found) and all(pair in pairs for pair in found)


def unsupported_terms(sentence, evidence):
    """Return the anchors in a sentence that the evidence does not support."""
    missing = []
    lowered = sentence.lower()
    for pattern in LITERAL_PATTERNS:
        for match in pattern.findall(sentence):
            token = normalize(match).rstrip('.,;:')
            if token and token not in evidence:
                missing.append(match.rstrip('.,;:'))
    for port in PORT.findall(sentence):
        if not re.search(r'(?<!\d)' + port + r'(?!\d)', evidence):
            missing.append('port ' + port)
    negated = bool(NEGATION.search(lowered))
    for label, (pattern, terms) in CONCEPTS.items():
        if re.search(pattern, lowered) and not any(term in evidence for term in terms) and not negated:
            missing.append(label)
    return list(dict.fromkeys(missing))


def split_sentences(text):
    return [part.strip() for part in SENTENCE.split(str(text).strip()) if part.strip()]


# Structured facts: label -> pattern that names it in model text.
FACT_PATTERNS = {
    'CSP': CONCEPTS['CSP'][0],
    'HSTS': CONCEPTS['HSTS'][0],
    'X-Frame-Options': r'x-frame-options',
    'X-Content-Type-Options': r'x-content-type-options|\bnosniff\b',
    'Referrer-Policy': r'referrer[- ]policy',
    'Permissions-Policy': r'permissions[- ]policy',
    'HTTPS': r'\bhttps\b(?!://)|\btls\b|\bterenkripsi\b|\bencrypted\b',
    'Cache-Control': r'cache-control',
    'CORS': r'access-control-allow-origin|\bcors\b',
    'HttpOnly': r'\bhttponly\b',
    'SameSite': r'\bsamesite\b',
    'Secure flag': r'\b(?:flag|atribut|attribute)\s+secure\b|\bsecure\s+(?:flag|attribute)\b',
}
# Headers whose value is never stored, so quality claims about them cannot be verified.
VALUE_LESS = {'CSP', 'HSTS', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy',
              'Cache-Control', 'CORS'}
CHECK_NAMES = {
    'content-security-policy': 'CSP', 'csp': 'CSP', 'strict-transport-security': 'HSTS', 'hsts': 'HSTS',
    'x-frame-options': 'X-Frame-Options', 'x-content-type-options': 'X-Content-Type-Options',
    'referrer-policy': 'Referrer-Policy', 'permissions-policy': 'Permissions-Policy', 'https_transport': 'HTTPS',
}
STATUS_VALUES = {'present': True, 'verified': True, 'missing': False, 'absent': False, 'unencrypted': False}
ABSENT = re.compile(
    r'\b(?:tidak|tak|belum|tanpa|bukan|hilang|absen|kosong|missing|absent|lacks?|lacking|without|no|not|none)\b', re.I)
QUALITY = re.compile(
    r'\b(?:aman|kuat|ketat|lemah|longgar|optimal|memadai|secure|safe|strong|strict|weak|permissive|insecure|robust'
    r'|properly|correctly|adequate|misconfigured|well[- ]configured|salah konfigurasi)\b', re.I)
PRESENT = re.compile(
    r'\b(?:ada|tersedia|ditemukan|teramati|terlihat|terpasang|dipasang|diterapkan|dikonfigurasi|dikirim|aktif|sudah'
    r'|memakai|menggunakan|mengirim|memiliki|menyertakan|menerapkan|mengaktifkan|dilindungi'
    r'|present|enabled|configured|implemented|observed|exists?|set|uses?|sends?|includes?|has|have)\b', re.I)
# Coordinated clauses share a subject ("CSP tersedia dan aman"); causal ones do not.
COORDINATION = re.compile(r'\s*(?:,|;|\bdan\b|\band\b|\bserta\b)\s*', re.I)
BREAK = re.compile(r'\s*(?:\btetapi\b|\bnamun\b|\bsedangkan\b|\bsehingga\b|\bkarena\b|\bmeskipun\b|\bbut\b|\bwhile\b'
                   r'|\bwhereas\b|\bso\b|\bbecause\b|\balthough\b)\s*', re.I)
# Scope statements ("CSP tidak diuji") say nothing about presence.
NOT_TESTED = re.compile(
    r'\b(?:(?:tidak|belum) (?:diuji|diperiksa|dievaluasi|dicakup|tercakup|dinilai|divalidasi)|di luar cakupan'
    r'|not (?:tested|checked|evaluated|covered|assessed|validated)|out of scope|untested)\b', re.I)


def structured_facts(source):
    """Collect unambiguous structured facts from the evidence; conflicting values are dropped."""
    facts = {}

    def put(label, value):
        facts.setdefault(label, set()).add(value)

    def cookies(rows):
        flags = [row for row in rows if isinstance(row, dict)]
        put('cookie', bool(flags))
        for key, label in (('httponly', 'HttpOnly'), ('samesite', 'SameSite'), ('secure', 'Secure flag')):
            count = sum(bool(row.get(key)) for row in flags)
            if flags and count in (0, len(flags)):
                put(label, count == len(flags))

    def walk(value):
        if isinstance(value, dict):
            name, status = str(value.get('check', '')).lower(), str(value.get('status', '')).lower()
            if name in CHECK_NAMES and status in STATUS_VALUES:
                put(CHECK_NAMES[name], STATUS_VALUES[status])
            for key, item in value.items():
                key = str(key).lower()
                if key == 'headers' and isinstance(item, dict):
                    for header, state in item.items():
                        if str(header).lower() in CHECK_NAMES and str(state).lower() in STATUS_VALUES:
                            put(CHECK_NAMES[str(header).lower()], STATUS_VALUES[str(state).lower()])
                elif key == 'csp_observation' and item == 'missing_header_candidate':
                    put('CSP', False)
                elif key == 'cache' and isinstance(item, dict) and isinstance(item.get('header_present'), bool):
                    put('Cache-Control', item['header_present'])
                elif key == 'cors' and isinstance(item, dict) and isinstance(item.get('allow_origin_present'), bool):
                    put('CORS', item['allow_origin_present'])
                elif key == 'tls' and isinstance(item, dict) and isinstance(item.get('verified'), bool):
                    put('HTTPS', item['verified'])
                elif key == 'cookie_flags' and isinstance(item, list):
                    cookies(item)
                walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item)

    result = source.get('result') or {}
    if result.get('kind') != 'operator_import':
        walk(result)
    return {label: values.pop() for label, values in facts.items() if len(values) == 1}


def fact_conflicts(sentence, facts):
    """Return reasons a sentence contradicts structured facts or makes an unverifiable quality claim."""
    conflicts = []
    for segment in BREAK.split(sentence):
        subjects = []
        for clause in COORDINATION.split(segment):
            named = [label for label, pattern in FACT_PATTERNS.items() if re.search(pattern, clause, re.I)]
            subjects = named or subjects
            if not subjects or NOT_TESTED.search(clause):
                continue
            if ABSENT.search(clause):
                claim = False
            elif QUALITY.search(clause):
                claim = 'quality'
            elif PRESENT.search(clause):
                claim = True
            else:
                continue
            for label in subjects:
                known = facts.get(label)
                if claim == 'quality':
                    if known is False:
                        conflicts.append(f'{label} bertentangan dengan evidence (tidak ada)')
                    elif label in VALUE_LESS:
                        conflicts.append(f'kualitas {label} tidak dapat diverifikasi (nilai header tidak disimpan)')
                elif known is not None and known != claim:
                    conflicts.append(f"{label} bertentangan dengan evidence ({'ada' if known else 'tidak ada'})")
    return list(dict.fromkeys(conflicts))


class Grounder:
    def __init__(self, source):
        self.source = source
        self.evidence = evidence_text(source)
        self.facts = structured_facts(source)
        self.pairs = evidence_pairs(source)
        self.removed = 0
        self.kept = 0
        self.terms = []

    def check(self, sentence, facts=True):
        missing = unsupported_terms(sentence, self.evidence) + (fact_conflicts(sentence, self.facts) if facts else [])
        if missing:
            self.removed += 1
            self.terms.extend(missing)
            return False
        self.kept += 1
        return True

    def text(self, value, facts=True):
        return ' '.join(sentence for sentence in split_sentences(value) if self.check(sentence, facts))

    def items(self, values, limit=8, facts=True):
        kept = []
        for value in values or []:
            text = self.text(value, facts)
            if text and text not in kept:
                kept.append(text[:500])
        return kept[:limit]

    def observation(self, item):
        if isinstance(item, dict):
            statement = str(item.get('statement', '')).strip()
            quote = str(item.get('evidence_quote', '')).strip()
            needle = normalize(quote)
            if len(needle) < 3 or (needle not in self.evidence and not quoted_pairs_supported(quote, self.pairs)):
                self.removed += 1
                self.terms.append('kutipan yang tidak cocok')
                return None
            checked = self.text(statement) if statement else ''
            if statement and not checked:
                # A quote proves only that the field was recorded; it cannot rescue a rejected interpretation.
                return None
            quote = quote.strip('"\'“”')
            return (f'{checked} (bukti: “{quote[:200]}”)' if checked else f'Kutipan evidence: “{quote[:200]}”')[:500]
        text = self.text(item)
        return text[:500] or None


def reviewed_report(payload):
    """Return a stored analysis for display, re-checking reports made before the current grounding version.

    The stored payload is hash-protected and never rewritten; contradicted sentences are hidden in the
    returned view and the report is marked so it is not mistaken for one that passed the current checks."""
    if payload.get('grounding_version') == GROUNDING_VERSION:
        return {**payload, 'grounding_status': 'current'}
    facts = structured_facts(payload.get('source') or {})
    output = payload.get('output') or {}
    removed = 0

    def keep(line):
        nonlocal removed
        statement = re.sub(r'\s*\(bukti: “.*?”\)\s*$', '', str(line))
        if any(fact_conflicts(sentence, facts) for sentence in split_sentences(statement)):
            removed += 1
            return False
        return True

    summary = ' '.join(s for s in split_sentences(output.get('summary', '')) if keep(s))
    observations = [line for line in output.get('observations') or [] if keep(line)]
    note = (f'Laporan lama: dibuat sebelum validasi fakta terstruktur (grounding v{GROUNDING_VERSION}). '
            + (f'{removed} pernyataan yang bertentangan dengan evidence disembunyikan saat ditampilkan. ' if removed else '')
            + 'Jalankan ulang Deep Analysis untuk laporan yang lolos pemeriksaan terbaru.')
    return {**payload, 'grounding_status': 'legacy_rechecked', 'legacy_statements_hidden': removed, 'output': {
        **output,
        'summary': summary or 'Ringkasan laporan lama bertentangan dengan evidence dan disembunyikan; tinjau evidence asli.',
        'observations': observations or ['Observasi laporan lama disembunyikan karena bertentangan dengan evidence.'],
        'limitations': [note, *(output.get('limitations') or [])],
    }}


def grounded_output(candidate, source):
    """Keep only model statements that are consistent with the recorded evidence."""
    grounder = Grounder(source)
    observations = []
    for item in candidate.get('observations', []) or []:
        line = grounder.observation(item)
        if line and line not in observations:
            observations.append(line)
    summary = grounder.text(candidate.get('summary', ''))
    limitations = grounder.items(candidate.get('limitations'), limit=6)
    # Recommendations are prescriptive ("Terapkan CSP yang ketat"), so only anchors are checked.
    recommendations = grounder.items(candidate.get('recommendations'), facts=False)
    if not summary:
        summary = (f"Ringkasan model untuk evidence {source['evidence_id']} tidak dapat diverifikasi terhadap evidence; "
                   'gunakan observasi dan evidence asli sebagai acuan.')
    if not observations:
        observations = ['Tidak ada observasi model yang dapat dicocokkan dengan evidence; tinjau evidence secara manual.']
    limitations.append('Pernyataan model telah dicocokkan dengan evidence tersensor, tetapi bukan bukti kerentanan; '
                       'penilaian risiko memerlukan review manusia.')
    if grounder.removed:
        terms = ', '.join(dict.fromkeys(grounder.terms)) or 'kutipan yang tidak cocok'
        limitations.append(f'{grounder.removed} pernyataan model dihapus karena merujuk hal yang tidak ada di evidence ({terms[:300]}).')
    return {
        'summary': summary[:1400],
        'observations': observations[:8],
        'limitations': limitations[:8],
        'recommendations': recommendations[:8],
    }
