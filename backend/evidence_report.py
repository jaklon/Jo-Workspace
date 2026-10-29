"""Deterministic baseline report sections rendered directly from recorded evidence.

Small local models often drop or misplace facts, so the facts a report must always
contain (header presence, TLS, cookie flags, redirects, TCP ports) are rendered here
from the structured result. The model may add narrative, which is still grounded
separately; it can never remove or change these lines. Recommendations come from a
fixed knowledge base keyed by the recorded status, not from the model.

Lines start with stable prefixes (``FACT_PREFIXES``) so session memory can recognise
them in chat history without trusting model prose.
"""

# check name -> (label, recommendation when missing)
HEADERS = (
    ('strict-transport-security', 'HSTS',
     'Pertimbangkan Strict-Transport-Security dengan max-age yang memadai setelah memastikan seluruh '
     'subdomain siap HTTPS (rujukan: OWASP Secure Headers Project).'),
    ('content-security-policy', 'CSP',
     'Susun Content-Security-Policy secara bertahap, misalnya mulai dengan mode Report-Only, untuk membatasi '
     'sumber skrip (rujukan: OWASP Content Security Policy Cheat Sheet).'),
    ('x-content-type-options', 'X-Content-Type-Options', 'Tambahkan X-Content-Type-Options: nosniff.'),
    ('x-frame-options', 'X-Frame-Options',
     'Tambahkan X-Frame-Options (DENY/SAMEORIGIN) atau direktif CSP frame-ancestors untuk mitigasi clickjacking.'),
    ('referrer-policy', 'Referrer-Policy', 'Tetapkan Referrer-Policy, misalnya strict-origin-when-cross-origin.'),
    ('permissions-policy', 'Permissions-Policy', 'Tetapkan Permissions-Policy untuk menonaktifkan fitur browser yang tidak dipakai.'),
)
FACT_PREFIXES = ('Status HTTP:', 'Header ada:', 'Header tidak ada:', 'HTTPS:', 'Cookie tercatat:', 'Cache-Control:', 'CORS:',
                 'Redirect:', 'Port terbuka:', 'Port lain:', 'Evidence inventaris mencatat', 'Evidence bundle JS mencatat')
SEVERITY_NOTE = ('Prioritas temuan header bersifat informasional: header yang absen bukan bukti eksploit '
                 'dan nilai header tidak disimpan sehingga kualitas konfigurasinya belum dinilai.')


def head_result(result):
    """Return the HEAD probe record for http-head and zap-head evidence, else None."""
    if result.get('tool') == 'zap-head':
        result = result.get('head') or {}
    if result.get('tool') or not isinstance(result.get('checks'), list):
        return None
    return result


def head_baseline(head):
    statuses = {str(item.get('check', '')).lower(): item.get('status') for item in head['checks'] if isinstance(item, dict)}
    status = head.get('http_status')
    observations, recommendations, limitations = [], [], []
    summary = []
    if isinstance(status, int):
        observations.append(f'Status HTTP: {status}.')
        summary.append(f'Respons HEAD menghasilkan HTTP {status}.')
    present = [label for check, label, _ in HEADERS if statuses.get(check) == 'present']
    missing = [(label, advice) for check, label, advice in HEADERS if statuses.get(check) == 'missing']
    if present:
        observations.append('Header ada: ' + ', '.join(present) + '.')
    if missing:
        observations.append('Header tidak ada: ' + ', '.join(label for label, _ in missing) + '.')
        recommendations.extend(advice for _, advice in missing)
    if present or missing:
        summary.append(f'{len(present)} dari {len(present) + len(missing)} header keamanan yang diperiksa tercatat ada'
                       + (f'; tidak ada: {", ".join(label for label, _ in missing)}.' if missing else '.'))
    tls = head.get('tls') if isinstance(head.get('tls'), dict) else {}
    transport = statuses.get('https_transport')
    if transport == 'verified' or tls.get('verified') is True:
        detail = ', '.join(part for part in (tls.get('version'), 'sertifikat berlaku hingga ' + ' '.join(tls['certificate_expires'].split())
                                              if isinstance(tls.get('certificate_expires'), str) else None) if part)
        observations.append('HTTPS: terverifikasi' + (f' ({detail}).' if detail else '.'))
    elif transport == 'unencrypted' or tls.get('verified') is False:
        observations.append('HTTPS: tidak digunakan; respons diterima tanpa enkripsi.')
        summary.append('Respons diterima tanpa HTTPS.')
        recommendations.insert(0, 'Layani situs melalui HTTPS dan alihkan seluruh permintaan HTTP ke HTTPS.')
    cookies = head.get('cookie_flags')
    if isinstance(cookies, list) and cookies:
        lacking = {flag: sum(1 for c in cookies if isinstance(c, dict) and c.get(key) is False)
                   for flag, key in (('Secure', 'secure'), ('HttpOnly', 'httponly'), ('SameSite', 'samesite'))}
        gaps = [f'{count} tanpa {flag}' for flag, count in lacking.items() if count]
        observations.append(f'Cookie tercatat: {len(cookies)} Set-Cookie' + (f' ({", ".join(gaps)}).' if gaps else '; semua memiliki Secure, HttpOnly, dan SameSite.'))
        if gaps:
            recommendations.append('Tinjau atribut Secure, HttpOnly, dan SameSite pada cookie yang belum memilikinya, '
                                   'sesuai fungsi masing-masing cookie.')
    elif isinstance(cookies, list):
        observations.append('Cookie tercatat: tidak ada Set-Cookie pada respons ini.')
    config = head.get('http_configuration') if isinstance(head.get('http_configuration'), dict) else {}
    cache, cors = config.get('cache') or {}, config.get('cors') or {}
    if isinstance(cache.get('header_present'), bool):
        observations.append('Cache-Control: ' + ('ada' + (' (no-store)' if cache.get('no_store') else '') + '.' if cache['header_present'] else 'tidak ada.'))
    if isinstance(cors.get('allow_origin_present'), bool):
        if cors['allow_origin_present']:
            observations.append('CORS: Access-Control-Allow-Origin ada' + (', bernilai *' if cors.get('wildcard_origin_observed') else '')
                                + (', Allow-Credentials true.' if cors.get('allow_credentials_true') else '.'))
            if cors.get('wildcard_origin_observed'):
                recommendations.append('Tinjau apakah Access-Control-Allow-Origin: * memang diperlukan untuk respons ini.')
        else:
            observations.append('CORS: Access-Control-Allow-Origin tidak ada pada respons tanpa header Origin.')
        limitations.append('CORS belum diuji dengan header Origin atau preflight.')
    if head.get('redirect_observed') or (isinstance(status, int) and 300 <= status < 400):
        observations.append('Redirect: respons adalah pengalihan dan tidak diikuti.')
        limitations.insert(0, 'Header di atas milik respons pengalihan; header halaman tujuan belum diperiksa.')
    if head.get('head_supported') is False:
        limitations.insert(0, 'Server tidak mendukung HEAD; header mungkin tidak mewakili respons GET.')
    if missing or present:
        limitations.append(SEVERITY_NOTE)
    if isinstance(head.get('limitations'), str):
        limitations.insert(0, head['limitations'])
    return {'summary': ' '.join(summary), 'observations': observations,
            'recommendations': recommendations, 'limitations': limitations}


def tcp_baseline(result):
    ports = [item for item in result.get('ports') or [] if isinstance(item, dict) and isinstance(item.get('port'), int)]
    if not ports:
        return None
    opened = sorted(item['port'] for item in ports if item.get('status') == 'open')
    others = sorted((item['port'], str(item.get('status') or 'unknown')) for item in ports if item.get('status') != 'open')
    target = result.get('target')
    observations = ['Port terbuka: ' + (', '.join(map(str, opened)) if opened else 'tidak ada') + '.']
    if others:
        observations.append('Port lain: ' + ', '.join(f'{port} ({status})' for port, status in others) + '.')
    summary = (f"Scan {result.get('tool')} terhadap {target}: {len(opened)} dari {len(ports)} port terbuka"
               + (f" ({', '.join(map(str, opened))})." if opened else '.'))
    recommendations = (['Pastikan setiap port terbuka memang diperlukan dan aksesnya dibatasi sesuai kebutuhan.'] if opened else [])
    limitations = [result['limitation']] if isinstance(result.get('limitation'), str) else []
    return {'summary': summary, 'observations': observations, 'recommendations': recommendations, 'limitations': limitations}


def baseline(source):
    """Deterministic sections for supported evidence, or None (operator imports are never interpreted)."""
    result = source.get('result') or {}
    if result.get('kind') == 'operator_import':
        return None
    head = head_result(result)
    if head is not None:
        return head_baseline(head)
    if result.get('tool') in ('tcp-connect', 'nmap'):
        return tcp_baseline(result)
    return None
