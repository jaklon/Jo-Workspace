"""Correlate runtime (DAST) findings with vulnerable source lines (SAST) and
vulnerable dependencies (SCA), producing editor diagnostics. Pure and deterministic:
operates on already-parsed scan-result payloads, never touches the network or disk,
and never invents a source location — an uncorrelated runtime finding yields
`source: null` rather than a guess."""
from urllib.parse import urlsplit

DAST_TOOLS = {'nuclei-head', 'zap-head', 'auth-unauthenticated-get', 'auth-two-session',
              'inventory-html', 'js-bundle-inventory', 'scoped-spider', 'active-reflection',
              'browser-automate', 'public-head-1.0'}
SAST_TOOLS = {'semgrep-sast', 'bandit-sast'}
SCA_TOOLS = {'trivy-sca'}
# Tokens that tie a missing/weak HTTP security header to the code that should set it.
HEADER_TOKENS = {
    'content-security-policy': ('content-security-policy', 'csp'),
    'strict-transport-security': ('strict-transport-security', 'hsts'),
    'x-frame-options': ('x-frame-options', 'frame-options', 'clickjack'),
    'x-content-type-options': ('x-content-type-options', 'nosniff', 'content-type-options'),
    'referrer-policy': ('referrer-policy',),
    'permissions-policy': ('permissions-policy', 'feature-policy'),
}


def _tool(result):
    return result.get('tool') or result.get('adapter') or ''


def normalize_dast(result):
    """Pull runtime security findings out of a DAST result payload."""
    tool = _tool(result)
    url = result.get('target') or result.get('url') or ''
    findings = []
    # Nuclei CSP observation.
    if result.get('csp_observation') == 'missing_header_candidate':
        findings.append({'category': 'missing_header', 'header': 'content-security-policy',
                         'name': 'CSP header candidate missing', 'severity': 'medium', 'url': url, 'tool': tool})
    # HEAD/ZAP header checks (web_checks.probe / zap-head 'head').
    head = result.get('head') or result
    for check in (head.get('checks') or []):
        if isinstance(check, dict) and check.get('status') == 'missing' and check.get('check') in HEADER_TOKENS:
            findings.append({'category': 'missing_header', 'header': check['check'],
                             'name': 'Header tidak ada: ' + check['check'], 'severity': 'medium', 'url': url, 'tool': tool})
        if isinstance(check, dict) and check.get('check') == 'https_transport' and check.get('status') == 'unencrypted':
            findings.append({'category': 'transport', 'header': 'strict-transport-security',
                             'name': 'Transport tidak terenkripsi', 'severity': 'high', 'url': url, 'tool': tool})
    return findings


def extract_sast(result):
    return [f for f in (result.get('findings') or []) if _tool(result) in SAST_TOOLS]


def extract_sca(result):
    return [f for f in (result.get('findings') or []) if _tool(result) in SCA_TOOLS]


def _path_segments(url):
    try:
        path = urlsplit(url).path
    except ValueError:
        return []
    return [seg.lower() for seg in path.split('/') if len(seg) > 2]


def correlate(dast, sast, sca):
    """Return editor diagnostics plus the runtime→source correlations behind them."""
    diagnostics, correlations = [], []
    # SAST findings are already located in code.
    for f in sast:
        diagnostics.append({'file': f['file'], 'line_start': f.get('line_start', 0),
                            'line_end': f.get('line_end', f.get('line_start', 0)),
                            'severity': f.get('severity', 'info'), 'code': f.get('rule_id', ''),
                            'message': f.get('message', ''), 'source_tool': f.get('tool', 'sast'), 'confidence': 'direct'})
    # SCA findings point at the dependency manifest.
    for f in sca:
        diagnostics.append({'file': f.get('file', 'dependencies'), 'line_start': 0, 'line_end': 0,
                            'severity': f.get('severity', 'info'), 'code': f.get('vuln_id', ''),
                            'message': f"{f.get('pkg','')} {f.get('installed_version','')}: {f.get('vuln_id','')}"
                                       + (f" (fixed in {f['fixed_version']})" if f.get('fixed_version') else ''),
                            'source_tool': f.get('tool', 'sca'), 'confidence': 'direct'})
    # Correlate each runtime finding to candidate source lines; never fabricate one.
    for r in dast:
        source = None
        confidence = None
        rationale = ''
        if r.get('category') in ('missing_header', 'transport') and r.get('header') in HEADER_TOKENS:
            tokens = HEADER_TOKENS[r['header']]
            for f in sast:
                blob = (str(f.get('rule_id', '')) + ' ' + str(f.get('message', ''))).lower()
                if any(tok in blob for tok in tokens):
                    source = {'file': f['file'], 'line_start': f.get('line_start', 0), 'line_end': f.get('line_end', 0)}
                    confidence = 'medium'
                    rationale = f"Runtime '{r['name']}' cocok dengan aturan SAST {f.get('rule_id','')} yang menyebut {r['header']}."
                    break
        if source is None and r.get('url'):
            segments = _path_segments(r['url'])
            for f in sast:
                lowered = str(f.get('file', '')).lower()
                hit = next((seg for seg in segments if seg in lowered), None)
                if hit:
                    source = {'file': f['file'], 'line_start': f.get('line_start', 0), 'line_end': f.get('line_end', 0)}
                    confidence = 'low'
                    rationale = f"Segmen rute '{hit}' pada {r['url']} cocok dengan berkas {f['file']}."
                    break
        correlations.append({'runtime': r, 'source': source, 'confidence': confidence, 'rationale': rationale})
        if source is not None:
            diagnostics.append({'file': source['file'], 'line_start': source['line_start'],
                                'line_end': source['line_end'], 'severity': r.get('severity', 'medium'),
                                'code': 'DAST-CORRELATED', 'message': r['name'] + ' — ' + rationale,
                                'source_tool': r.get('tool', 'dast'), 'confidence': confidence})
    return {'diagnostics': diagnostics, 'correlations': correlations}


def diagnostics(results):
    """Build correlated diagnostics from a list of parsed scan-result payloads."""
    dast, sast, sca = [], [], []
    for result in results:
        if not isinstance(result, dict):
            continue
        tool = _tool(result)
        if tool in SAST_TOOLS:
            sast.extend(extract_sast(result))
        elif tool in SCA_TOOLS:
            sca.extend(extract_sca(result))
        else:
            dast.extend(normalize_dast(result))
    merged = correlate(dast, sast, sca)
    return {**merged, 'counts': {'dast': len(dast), 'sast': len(sast), 'sca': len(sca),
                                 'diagnostics': len(merged['diagnostics'])}, 'execution_enabled': False}
