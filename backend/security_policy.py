"""Offline policy evaluation only. No DNS, sockets, subprocesses, or execution tokens."""
import hashlib
import ipaddress
import json
import re
from datetime import timedelta
from urllib.parse import urlsplit, urlunsplit

POLICY_VERSION = "scope-policy-2.0"
NETWORK_ACTIONS = {"tcp_discovery", "http_headers", "unauthenticated_access_check", "service_inventory", "scoped_spider", "active_reflection", "authenticated_api_review", "monitoring_read", "passive_recon"}
ALL_ACTIONS = NETWORK_ACTIONS | {"configuration_review", "document_review"}
BLOCKED = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48",
    "100::/64", "2001::/32", "2002::/16", "fe80::/10", "ff00::/8",
))
LOOPBACK = ipaddress.ip_network("127.0.0.0/8")


def network(asset):
    if asset.kind in ("ip", "cidr"):
        return ipaddress.ip_network(asset.value, strict=True)
    if asset.kind == "url":
        try:
            return ipaddress.ip_network(urlsplit(asset.value).hostname, strict=True)
        except ValueError:
            pass
    return None


def host(asset):
    if asset.kind in ("domain", "ip"):
        return asset.value
    if asset.kind == "url":
        return urlsplit(asset.value).hostname
    return None


def path_contains(parent, child):
    # A scope /api includes /api and /api/..., never /apix. Case remains significant.
    return parent == "/" or child == parent or child.startswith(parent.rstrip("/") + "/")


def contains(parent, child):
    if parent.kind == "url":
        if child.kind != "url":
            return False
        p, c = urlsplit(parent.value), urlsplit(child.value)
        return (p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)) == (c.scheme, c.hostname, c.port or (443 if c.scheme == "https" else 80)) and path_contains(p.path, c.path)
    pn, cn = network(parent), network(child)
    if pn is not None and cn is not None:
        return pn.version == cn.version and cn.subnet_of(pn)
    if parent.kind == "domain":
        return child.kind in ("domain", "url") and host(parent) == host(child)
    return False


def overlaps(left, right):
    if left.kind == right.kind == "url":
        return contains(left, right) or contains(right, left)
    ln, rn = network(left), network(right)
    if ln is not None and rn is not None:
        return ln.version == rn.version and ln.overlaps(rn)
    return host(left) is not None and host(left) == host(right)


def fully_excluded(asset, exclusions):
    if any(contains(excluded, asset) for excluded in exclusions):
        return True
    remaining = [network(asset)] if asset.kind in ("ip", "cidr") else []
    for excluded in exclusions:
        en = network(excluded) if excluded.kind in ("ip", "cidr") else None
        if en is None:
            continue
        next_remaining = []
        for part in remaining:
            if part.version != en.version or not part.overlaps(en):
                next_remaining.append(part)
            elif not part.subnet_of(en):
                next_remaining.extend(part.address_exclude(en))
        remaining = next_remaining
    return asset.kind in ("ip", "cidr") and not remaining


def asset_problem(asset, environment, check_addresses=True):
    """Conservative URL/host grammar; old stored snapshots remain readable."""
    hostname = host(asset)
    if hostname and network(asset) is None:
        # Refuse alternate numeric IP spellings interpreted differently by network libraries.
        if all(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", label, re.I) for label in hostname.split(".")):
            return "Host numerik ambigu; gunakan alamat IP eksplisit."
    if asset.kind == "url":
        path = urlsplit(asset.value).path
        if "%" in path or ";" in path or "//" in path or any(segment in (".", "..") for segment in path.split("/")) or any(ord(c) > 126 for c in path):
            return "Path URL harus ASCII tanpa percent-encoding, titik koma, double slash, atau segmen titik."
    if not check_addresses:
        return None
    net = network(asset)
    if net is not None:
        if any(net.version == item.version and net.overlaps(item) for item in BLOCKED):
            return "Alamat metadata/link-local, multicast, unspecified, atau transisi IPv6 diblokir policy."
        if environment != "lab" and net.version == 4 and net.overlaps(LOOPBACK):
            return "Loopback IPv4 hanya boleh dicatat sebagai scope izin pada lingkungan lab."
    return None


def scope_report(content):
    findings = []
    def finding(code, severity, message, location):
        findings.append({"code": code, "severity": severity, "message": message, "location": location})
    for index, asset in enumerate(content.in_scope):
        location = f"in_scope[{index}]"
        problem = asset_problem(asset, content.environment)
        if problem:
            finding("UNSAFE_SCOPE", "error", problem, location)
        if fully_excluded(asset, content.out_of_scope):
            finding("FULLY_EXCLUDED", "error", f"{asset.value} sepenuhnya ditutup pengecualian.", location)
        elif any(overlaps(asset, excluded) for excluded in content.out_of_scope):
            finding("EXCLUSION_OVERRIDES", "warning", f"{asset.value} beririsan dengan pengecualian; bagian yang beririsan selalu ditolak.", location)
        if any(overlaps(asset, other) for other in content.in_scope[:index]):
            finding("OVERLAPPING_INCLUDE", "warning", "Scope izin saling beririsan; izin tidak memperluas batas tindakan atau port.", location)
    for index, asset in enumerate(content.out_of_scope):
        # Special-address exclusions are valid, but alias/transition representations
        # cannot stand in for explicit canonical IPv4 exclusions.
        problem = asset_problem(asset, "lab", check_addresses=False)
        net = network(asset)
        aliases = [ipaddress.ip_network(n) for n in ("::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2002::/16")]
        if net is not None and net.version == 6 and any(net.overlaps(n) for n in aliases):
            problem = "Pengecualian mencakup representasi alias/transisi IPv6; gunakan rentang alamat langsung yang tidak ambigu."
        if problem:
            finding("AMBIGUOUS_EXCLUSION", "error", problem, f"out_of_scope[{index}]")
    if {"http_headers", "unauthenticated_access_check", "service_inventory", "scoped_spider", "active_reflection", "authenticated_api_review"} & set(content.allowed_actions) and not content.ports:
        finding("HTTP_PORTS_REQUIRED", "error", "Daftar port eksplisit wajib untuk tindakan HTTP/API.", "ports")
    named = any(network(a) is None for a in content.in_scope + content.out_of_scope)
    if named:
        finding("DNS_NOT_VERIFIED", "warning", "Domain bersifat exact-host; subdomain tidak otomatis termasuk. DNS belum diverifikasi, sehingga rencana jaringan berbasis nama akan ditolak guard.", "scope")
    errors = [f["message"] for f in findings if f["severity"] == "error"]
    return {"policy_version": POLICY_VERSION, "valid": not errors, "findings": findings, "execution_enabled": False}


def evaluate(content, head, engagement, proposal, now, dns_pinning=False):
    """Always re-read current DB state before calling. Results grant no capability."""
    checks = []
    def check(code, passed, message):
        checks.append({"code": code, "passed": bool(passed), "message": message})
    check("CURRENT_REVISION", proposal.expected_revision == engagement["revision"] and proposal.roe_version == head["version"] and proposal.content_hash == head["content_hash"], "Revisi, versi RoE, dan hash harus cocok dengan snapshot terkini.")
    actual_hash = hashlib.sha256(json.dumps(content.model_dump(mode="json"), sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    check("SNAPSHOT_INTEGRITY", actual_hash == head["content_hash"], "Hash snapshot harus sesuai dengan isi RoE yang tersimpan.")
    check("APPROVED_ROE", head["status"] == "approved", "RoE terkini harus disetujui secara lokal dan belum dicabut.")
    report = scope_report(content)
    check("VALID_ROE", not content.submission_errors() and report["valid"], "RoE harus lengkap dan lolos validasi scope policy terbaru.")
    check("ACTIVE_WINDOW", content.starts_at is not None and content.ends_at is not None and content.starts_at <= now < content.ends_at, "Waktu server harus berada dalam jadwal RoE: awal inklusif, akhir eksklusif.")
    check("ACTION_ALLOWED", proposal.action in ALL_ACTIONS and proposal.action in content.allowed_actions, "Tindakan harus terdaftar secara eksplisit dalam RoE.")
    check("TARGET_SAFE", asset_problem(proposal.target, content.environment) is None, asset_problem(proposal.target, content.environment) or "Bentuk target dan kelas alamat memenuhi policy statis.")
    check("IN_SCOPE", any(contains(asset, proposal.target) for asset in content.in_scope), "Seluruh target harus tercakup satu entri scope; domain exact-host, URL mengikuti scheme/port dan batas segmen path.")
    check("NOT_EXCLUDED", not any(overlaps(asset, proposal.target) for asset in content.out_of_scope), "Pengecualian selalu mengalahkan izin; CIDR atau target luas yang menyentuh pengecualian ditolak seluruhnya.")
    network_action = proposal.action in NETWORK_ACTIONS
    shape_ok = (proposal.action == "tcp_discovery" and proposal.target.kind in ("ip", "cidr", "domain")) or (proposal.action == 'monitoring_read' and proposal.target.kind == 'ip') or (proposal.action in ("http_headers", "unauthenticated_access_check", "service_inventory", "scoped_spider", "active_reflection", "authenticated_api_review") and proposal.target.kind == "url") or proposal.action in ("configuration_review", "document_review")
    shape_ok = shape_ok or (proposal.action=='passive_recon' and proposal.target.kind=='domain')
    check("ACTION_TARGET_TYPE", shape_ok, "TCP memakai IP/CIDR/domain; HTTP/API memakai URL eksplisit; recon pasif memakai domain.")
    ports = list(proposal.ports)
    if proposal.action in ("http_headers", "unauthenticated_access_check", "service_inventory", "scoped_spider", "active_reflection", "authenticated_api_review") and proposal.target.kind == "url":
        parsed = urlsplit(proposal.target.value)
        url_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        port_shape = not ports or set(ports) == {url_port}
        ports = [url_port]
    else:
        port_shape = True
    check("PORTS_ALLOWED", port_shape and (bool(ports) if network_action else True) and set(ports).issubset(content.ports), "Port harus subset port RoE; port HTTP diturunkan dari URL dan tidak boleh ditimpa.")
    check("BUDGET_ALLOWED", proposal.max_http_rps <= content.max_http_rps and proposal.max_concurrency <= content.max_concurrency and proposal.max_duration_minutes <= content.max_duration_minutes, "RPS, concurrency, dan durasi tidak boleh melampaui RoE.")
    check("WINDOW_FITS", content.ends_at is not None and now + timedelta(minutes=proposal.max_duration_minutes) <= content.ends_at, "Durasi rencana harus selesai sebelum atau tepat saat jadwal berakhir.")
    check("TEST_ACCOUNT", proposal.action != "authenticated_api_review" or bool(proposal.test_account_ref and proposal.test_account_ref in content.test_account_refs), "Review API memerlukan alias akun uji yang tercatat pada RoE.")
    target_net = network(proposal.target)
    uncertain_exclusions = any(network(a) is None for a in content.out_of_scope)
    check("DNS_REQUIREMENTS", not network_action or proposal.action=='passive_recon' or (target_net is not None and not uncertain_exclusions) or (dns_pinning and proposal.action in ('http_headers','unauthenticated_access_check','service_inventory','scoped_spider','active_reflection','authenticated_api_review') and proposal.target.kind == 'url'), "Target nama memerlukan pinning; recon pasif tidak menghubungi atau meresolusi target.")
    check("TARGET_SIZE", not network_action or target_net is None or target_net.num_addresses <= 256, "Rencana jaringan dibatasi maksimal 256 alamat per evaluasi; IPv6 /128 didukung.")
    normalized = proposal.model_dump(mode="json")
    digest = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"policy_version": POLICY_VERSION, "decision": "pass" if all(c["passed"] for c in checks) else "deny", "checks": checks,
            "evaluated_at": now.isoformat(), "project_id": engagement["project_id"], "engagement_id": engagement["id"],
            "revision": engagement["revision"], "roe_version": head["version"], "content_hash": head["content_hash"],
            "proposal": normalized, "proposal_hash": digest, "scope_report": report, "execution_enabled": False,
            "execution_blockers": ["STAGE_2_PLANNING_ONLY"], "grants_execution": False}


# --- Real-time scope-drift interceptor -------------------------------------
# A hard-blocking guard that runs immediately before a tool is executed. It
# extracts every target from a tool's argument payload, then reuses the pure
# scope relations above to verify each one against the active in-scope list and
# exclusions. DNS resolution is I/O, so it stays out of this module: callers
# resolve names themselves (a fast getaddrinfo in the adapter layer) and pass
# the results in via `resolved`, keeping this module free of sockets so its
# offline determinism and test guarantees hold.
DRIFT_POLICY_VERSION = "scope-drift-1.0"
_IPV4 = r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
_URL_RE = re.compile(r"https?://[^\s\"'<>\\)}]+", re.I)
_CIDR_RE = re.compile(r"(?<![\w.])" + _IPV4 + r"/(?:3[0-2]|[12]?\d)(?![\w.])")
# Permissive: match any hex/colon run (incl. "::" compression and IPv4-mapped
# tails); classify_target validates each candidate with ipaddress and drops the
# non-addresses, so over-matching here is harmless.
_IPV6_CIDR_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f.]{0,4}(?:/\d{1,3})?(?![\w:.])")
_IPV4_RE = re.compile(r"(?<![\w.])" + _IPV4 + r"(?![\w.])")
_DOMAIN_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w.-])", re.I)


class ScopeDriftError(Exception):
    """Raised to hard-block a tool call whose targets leave the approved scope."""
    def __init__(self, report):
        self.report = report
        super().__init__(report.get("reason") or "SCOPE_DRIFT")


class _Target:
    __slots__ = ("kind", "value")

    def __init__(self, kind, value):
        self.kind, self.value = kind, value


def classify_target(value):
    """Return a normalized _Target for one candidate string, or None if it is
    not a URL/IP/CIDR/domain the scope relations can reason about."""
    value = value.strip().rstrip(".")
    if not value:
        return None
    if _URL_RE.fullmatch(value) or value.lower().startswith(("http://", "https://")):
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                return None
            hostname = parsed.hostname
            try:
                ip = ipaddress.ip_address(hostname)
                host_part = ("[" + str(ip) + "]") if ip.version == 6 else str(ip)
            except ValueError:
                host_part = _normalize_domain(hostname)
                if host_part is None:
                    return None
            port = parsed.port
            default = (parsed.scheme, port) in (("http", 80), ("https", 443))
            netloc = host_part if port is None or default else f"{host_part}:{port}"
            return _Target("url", urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", "")))
        except ValueError:
            return None
    if "/" in value:
        try:
            return _Target("cidr", str(ipaddress.ip_network(value, strict=False)))
        except ValueError:
            return None
    try:
        return _Target("ip", str(ipaddress.ip_address(value)))
    except ValueError:
        pass
    normalized = _normalize_domain(value)
    return _Target("domain", normalized) if normalized else None


def _normalize_domain(value):
    value = value.strip().rstrip(".")
    if "_" in value or " " in value or "." not in value:
        return None
    try:
        value = value.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        value = value.lower()
    if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
        return None
    return value


def _collect_strings(payload, into, depth=0):
    if depth > 12 or len(into) > 2000:
        return
    if isinstance(payload, str):
        into.append(payload)
    elif isinstance(payload, dict):
        for key, item in payload.items():
            if isinstance(key, str):
                into.append(key)
            _collect_strings(item, into, depth + 1)
    elif isinstance(payload, (list, tuple, set)):
        for item in payload:
            _collect_strings(item, into, depth + 1)


def _targets_in_text(text):
    found = []
    masked = text
    for match in _URL_RE.finditer(text):
        target = classify_target(match.group().rstrip(".,;:!?"))
        if target:
            found.append(target)
        masked = masked[:match.start()] + " " * (match.end() - match.start()) + masked[match.end():]
    for pattern, _kind in ((_CIDR_RE, "cidr"), (_IPV6_CIDR_RE, "ip"), (_IPV4_RE, "ip"), (_DOMAIN_RE, "domain")):
        for match in pattern.finditer(masked):
            target = classify_target(match.group())
            if target:
                found.append(target)
            masked = masked[:match.start()] + " " * (match.end() - match.start()) + masked[match.end():]
    return found


def extract_targets(payload):
    """Pull every distinct URL/IP/CIDR/domain out of an arbitrary tool-argument
    payload (strings, dicts, lists), deduplicated and normalized."""
    strings = []
    _collect_strings(payload, strings)
    seen, targets = set(), []
    for text in strings:
        for target in _targets_in_text(text):
            key = (target.kind, target.value)
            if key not in seen:
                seen.add(key)
                targets.append(target)
    return targets


def _violation(target, code, detail, resolved_ip=None):
    entry = {"kind": target.kind, "value": target.value, "code": code, "detail": detail}
    if resolved_ip is not None:
        entry["resolved_ip"] = resolved_ip
    return entry


def scope_drift(targets, in_scope, out_of_scope, environment, resolved=None):
    """Pure scope-drift evaluation. `resolved` maps a target hostname to the list
    of IP strings it resolved to, so a name that is approved but points at a
    forbidden or excluded network (DNS rebinding) is caught as well."""
    resolved = resolved or {}
    violations, checked = [], []
    for target in targets:
        entry = {"kind": target.kind, "value": target.value}
        checked.append(entry)
        problem = asset_problem(target, environment)
        if problem:
            violations.append(_violation(target, "BLOCKED_ADDRESS", problem))
        if not any(contains(asset, target) for asset in in_scope):
            violations.append(_violation(target, "OUT_OF_SCOPE", "Target tidak tercakup entri in-scope manapun."))
        if any(overlaps(asset, target) for asset in out_of_scope):
            violations.append(_violation(target, "EXCLUDED", "Target menyentuh daftar pengecualian."))
        hostname = host(target)
        for address in resolved.get(hostname, []) if hostname else []:
            try:
                ip = _Target("ip", str(ipaddress.ip_address(address)))
            except ValueError:
                violations.append(_violation(target, "DNS_INVALID", f"Resolusi mengembalikan alamat tidak valid: {address}", resolved_ip=address))
                continue
            problem = asset_problem(ip, environment)
            if problem:
                violations.append(_violation(target, "DNS_REBIND_BLOCKED", f"Nama ter-resolusi ke jaringan terlarang: {problem}", resolved_ip=ip.value))
            if any(overlaps(asset, ip) for asset in out_of_scope):
                violations.append(_violation(target, "DNS_REBIND_EXCLUDED", "Nama ter-resolusi ke alamat pada daftar pengecualian.", resolved_ip=ip.value))
    return {"policy_version": DRIFT_POLICY_VERSION, "decision": "block" if violations else "allow",
            "violations": violations, "checked": checked, "execution_enabled": False}


def enforce_scope_drift(payload, in_scope, out_of_scope, environment, resolved=None):
    """Extract targets from `payload` and raise ScopeDriftError if any drifts.
    Returns the allow report (with the targets it cleared) when nothing drifts."""
    report = scope_drift(extract_targets(payload), in_scope, out_of_scope, environment, resolved)
    if report["decision"] == "block":
        report["reason"] = report["violations"][0]["code"]
        raise ScopeDriftError(report)
    return report
