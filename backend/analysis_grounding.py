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

Sentences that fail are removed and counted, so the report says how many model
claims were dropped instead of silently presenting them as facts.
"""
import json
import re

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


class Grounder:
    def __init__(self, source):
        self.source = source
        self.evidence = evidence_text(source)
        self.removed = 0
        self.kept = 0
        self.terms = []

    def check(self, sentence):
        missing = unsupported_terms(sentence, self.evidence)
        if missing:
            self.removed += 1
            self.terms.extend(missing)
            return False
        self.kept += 1
        return True

    def text(self, value):
        return ' '.join(sentence for sentence in split_sentences(value) if self.check(sentence))

    def items(self, values, limit=8):
        kept = []
        for value in values or []:
            text = self.text(value)
            if text and text not in kept:
                kept.append(text[:500])
        return kept[:limit]

    def observation(self, item):
        if isinstance(item, dict):
            statement = str(item.get('statement', '')).strip()
            quote = str(item.get('evidence_quote', '')).strip()
            needle = normalize(quote)
            if len(needle) < 3 or needle not in self.evidence:
                self.removed += 1
                return None
            statement = self.text(statement) if statement else ''
            quote = quote.strip('"\'“”')
            return (f'{statement} (bukti: “{quote[:200]}”)' if statement else f'Kutipan evidence: “{quote[:200]}”')[:500]
        text = self.text(item)
        return text[:500] or None


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
    recommendations = grounder.items(candidate.get('recommendations'))
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
