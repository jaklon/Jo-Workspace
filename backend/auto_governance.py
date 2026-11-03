"""Create an auditable, bounded job from an explicitly confirmed chat plan."""
from datetime import timedelta
from urllib.parse import urlsplit
from uuid import UUID
import ipaddress

from engagements import Decision, EngagementContent, ScopeAsset, utc_now
from security_jobs import Approval, CreateJob

TOOLS = {
    "http-head": ("url", "http_headers", 1, 20),
    "tcp-connect": ("ip", "tcp_discovery", 1, 60),
    "nmap": ("ip", "tcp_discovery", 1, 60),
    "nuclei-head": ("url", "http_headers", 1, 60),
    "zap-head": ("url", "http_headers", 3, 180),
    "subfinder-passive": ("domain", "passive_recon", 2, 120),
    "amass-passive": ("domain", "passive_recon", 4, 240),
    "inventory-html": ("url", "service_inventory", 1, 60),
    "js-bundle-inventory": ("url", "service_inventory", 1, 60),
    "auth-unauthenticated-get": ("url", "unauthenticated_access_check", 1, 60),
    "auth-two-session": ("url", "authenticated_api_review", 1, 60),
    "scoped-spider": ("url", "scoped_spider", 1, 60),
    "active-reflection": ("url", "active_reflection", 1, 60),
    "monitoring-local": ("ip", "monitoring_read", 1, 60),
    "document-review": ("document", "document_review", 1, 60),
}


def prepare_plan(slots):
    if slots.selections:
        if slots._url_va_profile and not slots.selections[0].target:
            # Ask for every missing slot at once; the URL is never guessed from a hostname or wording.
            missing = ["URL HTTP(S) lengkap dari website yang akan diperiksa"]
            if not slots.environment:
                missing.append("lingkungan (lab, development, staging, UAT, atau production read-only)")
            if not slots.assessment_mode:
                missing.append("mode analisis (BlackBox, WhiteBox, atau GreyBox)")
            return None, "Untuk menyiapkan pemeriksaan, mohon sebutkan " + ", ".join(missing[:-1]) + (" dan " if len(missing) > 1 else "") + missing[-1] + "."
        if not slots.environment or not slots.assessment_mode:
            missing = []
            if not slots.environment:
                missing.append("lingkungan (lab, development, staging, UAT, atau production read-only)")
            if not slots.assessment_mode:
                missing.append("mode analisis (BlackBox, WhiteBox, atau GreyBox)")
            return None, "Untuk menyiapkan pemeriksaan, mohon sebutkan " + " dan ".join(missing) + "."
        if slots.assessment_mode in ("whitebox", "greybox") and not any(item.tool == "document-review" or (slots.assessment_mode == "whitebox" and item.tool == "monitoring-local") or (slots.assessment_mode == "greybox" and item.tool == "auth-two-session") for item in slots.selections):
            return None, ("Untuk WhiteBox, lampirkan dokumen atau kode dan minta document-review. "
                          "Untuk GreyBox, pilih document-review dengan evidence yang relevan atau auth-two-session dengan dua alias akun uji.")
        if slots._url_va_profile and slots.selections[0].target:
            try:
                parsed = urlsplit(slots.selections[0].target)
                if parsed.scheme.lower() not in ('http', 'https') or (parsed.port or (443 if parsed.scheme.lower() == 'https' else 80)) not in (80, 443):
                    return None, "Paket VA URL dasar hanya mendukung URL publik pada port 80 atau 443."
            except ValueError:
                return None, "URL atau port pada target tidak valid."
        plans = []
        for selected in slots.selections:
            single = slots.model_copy(update={"selections": [], "tool": selected.tool,
                                               "target": selected.target, "ports": selected.ports,
                                               "assessment_mode": slots.assessment_mode if selected.tool in ("document-review", "monitoring-local", "auth-two-session") else "blackbox",
                                               "evidence_kind": slots.evidence_kind if selected.tool == "document-review" else "",
                                               "test_account_ref": slots.test_account_ref if selected.tool == "document-review" else ""})
            plan, question = prepare_plan(single)
            if question:
                return None, f"Untuk {selected.tool}: {question}"
            if any(item["tool"] == plan["tool"] and item["target"] == plan["target"] for item in plans):
                raise ValueError("Tool dan target yang sama tidak boleh diulang dalam satu rencana.")
            plans.append(plan)
        return {**plans[0], "jobs": plans, "assessment_mode": slots.assessment_mode,
                "url_va_profile": slots._url_va_profile,
                "specialists": list(dict.fromkeys(slots.specialists))}, None
    if slots.tool == "unsupported":
        if slots._va_constrained:
            return None, "Permintaan memuat pengecualian. Ulangi permintaan dengan tool yang ingin dijalankan, URL, lingkungan, dan mode agar rencana sesuai batas yang Anda inginkan."
        return None, (
            "Alur chat menyiapkan satu pemeriksaan terbatas; RoE dan job dibuat otomatis "
            "setelah Anda menyetujui kartu konfirmasi, jadi ia tidak membuat RoE kosong untuk "
            "diedit manual (gunakan Security Workspace → Engagement untuk itu). Sebutkan "
            "pemeriksaan yang didukung beserta URL atau target, lingkungan (lab, development, "
            "staging, UAT, atau production read-only), dan mode (BlackBox, WhiteBox, atau GreyBox). "
            "Pemeriksaan yang tersedia: " + ", ".join(TOOLS) + ". "
            "Contoh: “VA https://staging.example staging blackbox” atau "
            "“http-head https://staging.example staging blackbox”.")
    kind, action, duration, timeout = TOOLS[slots.tool]
    missing = []
    if not slots.target:
        missing.append({"url": "URL HTTP(S) lengkap", "ip": "satu alamat IP", "domain": "domain eksplisit", "document": "target IP, domain, atau URL yang dicakup review"}[kind])
    if slots.tool in ("tcp-connect", "nmap") and not slots.ports:
        missing.append("daftar port TCP (maksimal 16)")
    if not slots.environment:
        missing.append("lingkungan (lab, development, staging, UAT, atau production read-only)")
    if not slots.assessment_mode:
        missing.append("mode analisis (BlackBox, WhiteBox, atau GreyBox)")
    if missing:
        return None, "Untuk menyiapkan pemeriksaan, mohon berikan " + ", ".join(missing) + "."
    if slots.tool == "document-review":
        if slots.assessment_mode == "blackbox":
            return None, "Review dokumen memerlukan mode WhiteBox atau GreyBox."
        if not slots.evidence_kind:
            return None, "Jenis bukti apa yang dilampirkan: source_code, configuration, api_documentation, authenticated_observation, atau monitoring?"
        from deep_analysis import MODES
        if slots.evidence_kind not in MODES[slots.assessment_mode]['kinds']:
            return None, "Jenis bukti tidak sesuai mode yang dipilih. Sebutkan jenis bukti yang relevan."
        if slots.assessment_mode == "greybox" and not slots.test_account_ref:
            return None, "Sebutkan alias akun uji yang disetujui untuk GreyBox, tanpa kata sandi atau token."
    elif slots.tool == "monitoring-local":
        if slots.assessment_mode != "whitebox" or slots.environment != "lab" or slots.target != "127.0.0.1":
            return None, "Monitoring lokal dibatasi 127.0.0.1, lingkungan lab, dan mode WhiteBox."
    elif slots.tool == "auth-two-session":
        if slots.assessment_mode != "greybox":
            return None, "Perbandingan dua sesi memerlukan mode GreyBox."
        if len(slots.account_refs) != 2 or len(set(slots.account_refs)) != 2:
            return None, "Sebutkan dua alias akun uji berbeda. Token sesi dimasukkan hanya pada kartu konfirmasi, bukan di chat."
    elif slots.assessment_mode != "blackbox":
        return None, "Untuk WhiteBox/GreyBox, pilih review dokumen dan lampirkan bukti yang relevan."
    if kind == "document":
        if slots.target.lower().startswith(("http://", "https://")):
            kind = "url"
        else:
            try:
                ipaddress.ip_address(slots.target)
                kind = "ip"
            except ValueError:
                kind = "domain"
    target = ScopeAsset(kind=kind, value=slots.target)
    ports = sorted(set(slots.ports))
    if kind == "url":
        parsed = urlsplit(target.value)
        ports = [parsed.port or (443 if parsed.scheme == "https" else 80)]
    elif kind == "domain":
        ports = [443]
    elif slots.tool == "monitoring-local":
        ports = [3000, 9090]
    if any(not 1 <= port <= 65535 for port in ports) or len(ports) > 16:
        raise ValueError("Port harus berupa 1–16 angka unik antara 1 dan 65535.")
    if slots.environment == "production_readonly" and slots.tool not in ("http-head", "nuclei-head", "zap-head"):
        raise ValueError("Production read-only hanya mengizinkan pemeriksaan header HTTP.")
    return {"tool": slots.tool, "target": target.model_dump(), "ports": ports,
            "environment": slots.environment, "assessment_mode": slots.assessment_mode,
            "action": action, "duration": duration, "timeout": timeout,
            "evidence_kind": "monitoring" if slots.tool == "monitoring-local" else "authenticated_observation" if slots.tool == "auth-two-session" else slots.evidence_kind if slots.tool == "document-review" else "",
            "test_account_ref": slots.account_refs[0] if slots.tool == "auth-two-session" else slots.test_account_ref if slots.tool == "document-review" else "",
            "account_refs": slots.account_refs if slots.tool == "auth-two-session" else [],
            "owner_json_pointer": slots.owner_json_pointer if slots.tool == "auth-two-session" else "",
            "specialists": list(dict.fromkeys(slots.specialists))}, None


def adapter_plan(plan):
    tool = plan["tool"]
    fingerprint = ""
    if tool == "nmap":
        from bounded_scan import binary_hash
        fingerprint = binary_hash()
    elif tool == "nuclei-head":
        from nuclei_adapter import binary_hash
        fingerprint = binary_hash()
    elif tool in ("zap-head", "subfinder-passive", "amass-passive"):
        from zap_adapter import image_hash
        from subfinder_adapter import fingerprint as subfinder_hash, amass_fingerprint
        fingerprint = image_hash() if tool == "zap-head" else subfinder_hash() if tool == "subfinder-passive" else amass_fingerprint()
    if fingerprint is None:
        raise ValueError("Tool atau image yang diminta tidak tersedia; tidak ada job yang dijalankan.")
    step = {"target": plan["target"], "action": plan["action"], "ports": [] if tool == "http-head" else plan["ports"],
            "max_http_rps": 1, "max_concurrency": 1, "max_duration_minutes": plan["duration"],
            "test_account_ref": plan.get("test_account_ref", "")}
    web = {"adapter": "public-head-1.0"} if tool == "http-head" else None
    scan = {"tool": tool, "binary_sha256": fingerprint,
            "provider_disclosure": tool in ("subfinder-passive", "amass-passive"),
            "account_refs": plan.get("account_refs", []), "owner_json_pointer": plan.get("owner_json_pointer", "")} if tool not in ("http-head", "document-review") else None
    from web_checks import validate_plan
    from bounded_scan import validate_scan
    adapter = {"steps": [step], "wall_timeout_seconds": plan["timeout"], "web": web, "scan": scan, "mcp": None}
    validate_plan(adapter)
    validate_scan(adapter)
    return step, web, scan


# --- Dynamic approval threshold -------------------------------------------
# Passive/offline work runs without interruption; bounded network checks need
# one explicit approval; active scanners (Nuclei/ZAP), spidering, reflection,
# authenticated review and fuzzing need an explicit confirmation backed by the
# local session PIN. Unknown actions fail safe to the strictest tier.
PASSIVE_ACTIONS = {"passive_recon", "configuration_review", "document_review", "monitoring_read"}
MEDIUM_ACTIONS = {"tcp_discovery", "http_headers", "unauthenticated_access_check", "service_inventory"}
HIGH_ACTIONS = {"scoped_spider", "active_reflection", "authenticated_api_review"}
INTRUSIVE_TOOLS = {"nuclei-head", "zap-head", "scoped-spider", "active-reflection", "auth-two-session"}
TIER_LABELS = {"low": "Low / pasif", "medium": "Medium", "high": "High / intrusif"}
TIER_ORDER = {"low": 0, "medium": 1, "high": 2}


def classify_risk(action, tool=""):
    """Map one action/tool to an approval tier and the confirmation it needs."""
    if tool in INTRUSIVE_TOOLS or action in HIGH_ACTIONS:
        tier, requires = "high", "session_pin"
    elif action in MEDIUM_ACTIONS:
        tier, requires = "medium", "one_click"
    elif action in PASSIVE_ACTIONS:
        tier, requires = "low", "auto"
    else:
        tier, requires = "high", "session_pin"
    return {"tier": tier, "requires": requires, "action": action, "tool": tool,
            "label": TIER_LABELS[tier], "auto_execute": tier == "low"}


def plan_risk(plan):
    """Highest tier across every job in a (possibly multi-tool) plan."""
    jobs = plan.get("jobs") or [plan]
    classes = [classify_risk(job.get("action", ""), job.get("tool", "")) for job in jobs]
    top = max(classes, key=lambda item: TIER_ORDER[item["tier"]])
    return {**top, "per_job": classes, "requires_pin": top["tier"] == "high"}


def require_pin(plan):
    return plan_risk(plan)["requires_pin"]


# --- Dry-run blast-radius simulator ---------------------------------------
# Deterministic projection of the load a plan would place on a target before it
# runs: estimated HTTP requests, concurrency, wall-clock duration and a 0–100
# blast-radius score. No network, no DNS — the adapters pace one request per
# second, so request count is the primary driver of time and exposure.
TOOL_REQUESTS = {
    "http-head": 1, "nuclei-head": 1, "zap-head": 1, "auth-unauthenticated-get": 1,
    "inventory-html": 1, "js-bundle-inventory": 1, "auth-two-session": 3,
    "scoped-spider": 20, "active-reflection": 6, "monitoring-local": 2,
    "subfinder-passive": 0, "amass-passive": 0, "document-review": 0,
}
TOOL_BASE_SCORE = {
    "document-review": 2, "monitoring-local": 5, "subfinder-passive": 8, "amass-passive": 12,
    "http-head": 18, "inventory-html": 20, "js-bundle-inventory": 22, "auth-unauthenticated-get": 24,
    "tcp-connect": 30, "nmap": 34, "auth-two-session": 48, "scoped-spider": 62,
    "active-reflection": 66, "nuclei-head": 72, "zap-head": 80,
}
ENVIRONMENT_WEIGHT = {"lab": 0.5, "development": 0.75, "staging": 1.0, "uat": 1.0, "production_readonly": 1.4}


def _address_count(target):
    value = (target or {}).get("value", "")
    kind = (target or {}).get("kind", "")
    if kind == "cidr":
        try:
            return ipaddress.ip_network(value, strict=False).num_addresses
        except ValueError:
            return 1
    return 1


def _estimated_requests(tool, ports, action):
    if tool in ("tcp-connect", "nmap"):
        return max(1, len(ports or []))
    if tool in TOOL_REQUESTS:
        return TOOL_REQUESTS[tool]
    # Fall back on the action when no concrete tool is named (policy preview).
    return {"tcp_discovery": max(1, len(ports or [])), "passive_recon": 0,
            "configuration_review": 0, "document_review": 0, "monitoring_read": 2}.get(action, 1)


def blast_radius(*, base, requests, addresses, concurrency, environment):
    """Bounded 0–100 score combining tool intrusiveness, request volume,
    target breadth, concurrency and the environment's sensitivity."""
    import math
    volume = min(30, requests * 1.5)
    breadth = min(25, math.log2(max(1, addresses)) * 3)
    parallel = min(10, (max(1, concurrency) - 1) * 5)
    raw = (base + volume + breadth + parallel) * ENVIRONMENT_WEIGHT.get(environment, 1.0)
    return max(0, min(100, round(raw)))


def _job_simulation(job, environment):
    tool = job.get("tool", "")
    action = job.get("action", "")
    ports = job.get("ports") or []
    requests = _estimated_requests(tool, ports, action)
    addresses = _address_count(job.get("target"))
    concurrency = job.get("max_concurrency", 1)
    # Adapters pace ~1 request/second; add a fixed handshake/overhead allowance.
    paced = requests * max(1, concurrency ** 0)  # requests are serialized at 1 rps
    estimated_seconds = min(job.get("timeout", 60), 4 + paced)
    score = blast_radius(base=TOOL_BASE_SCORE.get(tool, 40), requests=requests,
                         addresses=addresses, concurrency=concurrency, environment=environment)
    risk = classify_risk(action, tool)
    return {"tool": tool or action or "unknown", "action": action, "target": (job.get("target") or {}).get("value", ""),
            "estimated_requests": requests, "target_addresses": addresses, "concurrency": concurrency,
            "estimated_seconds": estimated_seconds, "blast_radius": score, "risk_tier": risk["tier"],
            "passive": requests == 0}


def simulate_plan(plan):
    """Projected load for a prepared plan or a single job, for a dry-run panel."""
    environment = plan.get("environment", "lab")
    jobs = plan.get("jobs") or [plan]
    sims = [_job_simulation(job, environment) for job in jobs]
    risk = plan_risk(plan)
    return {"environment": environment, "jobs": sims, "job_count": len(sims),
            "total_requests": sum(item["estimated_requests"] for item in sims),
            "max_concurrency": max((item["concurrency"] for item in sims), default=1),
            "estimated_seconds": sum(item["estimated_seconds"] for item in sims),
            "blast_radius": max((item["blast_radius"] for item in sims), default=0),
            "risk_tier": risk["tier"], "risk_label": risk["label"], "requires": risk["requires"],
            "requires_pin": risk["requires_pin"], "execution_enabled": False}


def create_approved_jobs(state, project_id, session_id, plan, session_tokens=None):
    project = str(UUID(project_id))
    now = utc_now()
    plans = plan.get("jobs") or [plan]
    if not 1 <= len(plans) <= 6:
        raise ValueError("Rencana harus memiliki 1–6 job.")
    authenticated = [item for item in plans if item["tool"] == "auth-two-session"]
    if len(authenticated) > 1 or bool(authenticated) != bool(session_tokens):
        raise ValueError("Satu job dua sesi memerlukan tepat dua token sesi sementara.")
    adapters = [adapter_plan(item) for item in plans]
    targets = list({(item["target"]["kind"], item["target"]["value"]) for item in plans})
    content = EngagementContent(
        name="Pemeriksaan dari chat", objective="Pemeriksaan terbatas sesuai rencana yang disetujui dalam chat.",
        owner="operator sesi lokal", contact="tidak diberikan", environment=plan["environment"],
        authorization_ref=f"CHAT-APPROVED-{session_id}", in_scope=[ScopeAsset(kind=k, value=v) for k, v in targets],
        ports=sorted({p for item in plans for p in item["ports"]}),
        allowed_actions=list(dict.fromkeys(item["action"] for item in plans)),
        starts_at=now-timedelta(minutes=1), ends_at=now+timedelta(hours=24),
        max_http_rps=1, max_concurrency=1, max_duration_minutes=max(item["duration"] for item in plans),
        emergency_contact="tidak diberikan", stop_conditions="Hentikan ketika operator meminta atau policy menolak.",
        test_account_refs=list(dict.fromkeys(ref for item in plans for ref in (item.get("account_refs") or ([item["test_account_ref"]] if item.get("test_account_ref") else [])))))
    if content.submission_errors():
        raise ValueError("RoE tidak lolos validasi: " + "; ".join(content.submission_errors()))
    issued = []
    try:
      with state.engagements.transaction() as db:
        eid = state.engagements.create_in(db, project, content)
        for decision in ("submit", "approve"):
            engagement, _ = state.engagements.head(db, project, eid)
            state.engagements.decide_in(db, project, eid, Decision(
                expected_revision=engagement["revision"], action=decision, actor_label="operator sesi lokal",
                note="Persetujuan lokal atas rencana yang ditampilkan di chat; bukan verifikasi izin pihak ketiga.", acknowledge=True))
        engagement, head = state.engagements.head(db, project, eid)
        risk = plan_risk(plan)
        gate_note = f"Gate dibuka berdasarkan konfirmasi chat. Tingkat risiko rencana: {risk['label']} (perlu {risk['requires']})."
        db.execute("INSERT INTO security_engagement_gates VALUES (?,0,1,?,?,?)",
                   (eid, now.isoformat(), "operator sesi lokal", gate_note))
        state.engagements.event(db, eid, head["version"], "gate_opened", "operator sesi lokal",
                                gate_note, head["content_hash"])
        ids = []
        for item, (step, web, scan) in zip(plans, adapters):
            payload = CreateJob(expected_roe_revision=engagement["revision"], roe_version=head["version"],
                                content_hash=head["content_hash"], name="Chat · " + item["tool"], steps=[step],
                                wall_timeout_seconds=item["timeout"], web=web, scan=scan)
            jid = state.jobs.create_in(db, project, eid, payload)
            issued.append(jid)
            state.jobs.approve_in(db, project, eid, jid, Approval(
                expected_revision=1, actor_label="operator sesi lokal", acknowledge=True,
                note="Rencana dan batas pemeriksaan disetujui dalam chat.",
                session_tokens=session_tokens if item["tool"] == "auth-two-session" else None))
            ids.append(jid)
    except Exception:
        for jid in issued:
            state.jobs.sessions.discard(jid)
        raise
    return project, eid, ids


def create_approved_job(state, project_id, session_id, plan):
    if len(plan.get("jobs") or [plan]) != 1:
        raise ValueError("Gunakan create_approved_jobs untuk rencana multi-tool.")
    project, eid, ids = create_approved_jobs(state, project_id, session_id, plan)
    return project, eid, ids[0]
