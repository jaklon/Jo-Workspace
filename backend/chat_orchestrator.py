"""Classify chat intent without invoking workspace or network tools."""
from typing import Literal
import re
import ipaddress
from pydantic import BaseModel, ConfigDict, Field
from model_runtime import bounded_messages, runtime


class Intent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intent: Literal["chat", "coding", "security", "web"]


ToolName = Literal["http-head", "tcp-connect", "nmap", "nuclei-head", "zap-head", "subfinder-passive", "amass-passive", "inventory-html", "js-bundle-inventory", "auth-unauthenticated-get", "auth-two-session", "scoped-spider", "active-reflection", "monitoring-local", "document-review", "unsupported"]


class ToolSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: ToolName
    target: str = Field(default="", max_length=1000)
    ports: list[int] = Field(default_factory=list, max_length=16)


class SecuritySlots(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: ToolName = "unsupported"
    target: str = Field(default="", max_length=1000)
    ports: list[int] = Field(default_factory=list, max_length=16)
    environment: Literal["lab", "development", "staging", "uat", "production_readonly", ""] = ""
    assessment_mode: Literal["blackbox", "whitebox", "greybox", ""] = ""
    selections: list[ToolSelection] = Field(default_factory=list, max_length=6)
    evidence_kind: Literal["source_code", "configuration", "api_documentation", "authenticated_observation", "monitoring", ""] = ""
    test_account_ref: str = Field(default="", max_length=120)
    account_refs: list[str] = Field(default_factory=list, max_length=2)
    owner_json_pointer: str = Field(default="", max_length=256)
    specialists: list[Literal["recon", "web_api", "auth_bola", "llm_security", "reporting"]] = Field(default_factory=list, max_length=5)


def complete_explicit_slots(slots, user_text):
    """Fill unambiguous literal values only; never expand a URL into another scope."""
    lower = user_text.casefold()
    environments = {"lab": r"\blab(?:oratory)?\b", "development": r"\b(development|dev)\b",
                    "staging": r"\bstaging\b", "uat": r"\buat\b",
                    "production_readonly": r"\b(production|produksi)\b.*\b(read.only|hanya.baca)\b"}
    modes = {"blackbox": r"\bblack[ -]?box\b", "whitebox": r"\bwhite[ -]?box\b", "greybox": r"\bgr[ae]y[ -]?box\b"}
    for field, patterns in (("environment", environments), ("assessment_mode", modes)):
        matches = [key for key, pattern in patterns.items() if re.search(pattern, lower, re.S)]
        if len(matches) == 1:
            setattr(slots, field, matches[0])
    evidence_patterns = {"source_code": r"\b(source_code|kode sumber|source code)\b",
                         "configuration": r"\b(configuration|konfigurasi)\b",
                         "api_documentation": r"\b(api_documentation|dokumentasi api|api documentation)\b",
                         "authenticated_observation": r"\b(authenticated_observation|observasi terautentikasi)\b",
                         "monitoring": r"\bmonitoring\b"}
    kinds_found = [name for name, pattern in evidence_patterns.items() if re.search(pattern, lower)]
    if len(kinds_found) == 1:
        slots.evidence_kind = kinds_found[0]
    aliases = re.findall(r"\balias(?:\s+akun(?:\s+uji)?)?\s*(?:[:=]\s*)?([a-z0-9][a-z0-9_.-]{0,119})\b", user_text, re.I)
    aliases = [alias for alias in aliases if alias.casefold() not in {"akun", "uji", "yang", "untuk", "test"}]
    if not slots.test_account_ref and len(set(aliases)) == 1:
        slots.test_account_ref = aliases[0]
    pair = re.search(r"\balias(?:\s+akun(?:\s+uji)?)?\s*[:=]\s*([a-z0-9][a-z0-9_.-]{0,119})\s*(?:,|dan|&)\s*([a-z0-9][a-z0-9_.-]{0,119})\b", user_text, re.I)
    if pair and not slots.account_refs:
        slots.account_refs = [pair.group(1), pair.group(2)]
    urls = list(dict.fromkeys(re.findall(r"https?://[^\s<>\"']+", user_text, re.I)))
    remaining = user_text
    for url in urls:
        remaining = remaining.replace(url, " ")
    ips = []
    for value in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", remaining):
        try:
            ipaddress.ip_address(value)
            if value not in ips: ips.append(value)
        except ValueError:
            pass
    domains = list(dict.fromkeys(value for value in re.findall(r"(?<![\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?![\w.-])", remaining, re.I)))
    port_values = []
    for group in re.findall(r"\bports?\s*(?:tcp\s*)?(\d{1,5}(?:\s*[,/]\s*\d{1,5})*)", lower):
        port_values.extend(int(value) for value in re.findall(r"\d+", group))
    ports = sorted(set(port_values)) if port_values and all(1 <= value <= 65535 for value in port_values) else []
    kinds = {"http-head": "url", "nuclei-head": "url", "zap-head": "url", "inventory-html": "url",
             "js-bundle-inventory": "url", "auth-unauthenticated-get": "url", "auth-two-session": "url", "scoped-spider": "url",
             "active-reflection": "url", "tcp-connect": "ip", "nmap": "ip", "monitoring-local": "ip",
             "subfinder-passive": "domain", "amass-passive": "domain"}
    found = [(match.start(), name) for name in kinds
             if (match := re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", lower))]
    explicit = [name for _, name in sorted(found)]
    if len(explicit) > 1 and not re.search(r"\b(jangan|tanpa|kecuali|hindari|bukan|not|without)\b", lower):
        existing = {item.tool: item for item in slots.selections}
        slots.selections = [existing.get(name, ToolSelection(tool=name)) for name in explicit]
    def fill(selection):
        kind = kinds.get(selection.tool)
        candidates = {"url": urls, "ip": ips, "domain": domains}.get(kind, [])
        if selection.tool == 'document-review': candidates = urls + ips + domains
        if not selection.target and len(candidates) == 1: selection.target = candidates[0]
        if not selection.ports and selection.tool in ('tcp-connect', 'nmap'): selection.ports = ports
    if slots.selections:
        for selection in slots.selections: fill(selection)
    else:
        selection = ToolSelection(tool=slots.tool, target=slots.target, ports=slots.ports)
        fill(selection)
        slots.target, slots.ports = selection.target, selection.ports
    if not re.search(r"\b(spesialis|specialist|agen|agent|tim keamanan)\b", lower):
        slots.specialists = []
    elif not re.search(r"\b(jangan|tanpa|kecuali|hindari|bukan|not|without)\b", lower):
        roles = [name for name in ("recon", "web_api", "auth_bola", "llm_security", "reporting")
                 if re.search(rf"(?<![\w]){name}(?![\w])", lower)]
        if roles:
            slots.specialists = roles
    return slots


async def security_slots(prompt, history, model):
    messages = bounded_messages(
        "Ekstrak hanya fakta yang dinyatakan pengguna dari percakapan. tool http-head untuk "
        "pemeriksaan header HTTP, tcp-connect untuk scan port TCP, atau pilih adapter bernama "
        "nmap, nuclei-head, zap-head, subfinder-passive, amass-passive, inventory-html, "
        "js-bundle-inventory, auth-unauthenticated-get, auth-two-session, scoped-spider, active-reflection, monitoring-local jika pengguna memintanya. Gunakan auth-two-session untuk membandingkan dua akun uji. Gunakan document-review untuk review "
        "WhiteBox atau GreyBox dari dokumen yang dilampirkan. Untuk beberapa tool, isi selections "
        "dengan setiap tool dan target yang disebut, jangan mengubah URL menjadi domain atau sebaliknya. "
        "Pilih unsupported untuk tool yang tidak tercakup. "
        "Jangan mengarang target, port, lingkungan, atau mode analisis. Jika belum disebut, "
        "pakai string kosong atau daftar kosong. Untuk auth-two-session catat dua alias akun uji dalam account_refs, bukan kredensial; owner_json_pointer hanya bila diminta eksplisit. "
        "Jenis bukti adalah source_code, configuration, api_documentation, authenticated_observation atau monitoring. "
        "Isi specialists dengan peran relevan yang diminta: recon, web_api, auth_bola, llm_security, reporting. "
        "URL harus tetap persis seperti yang diberikan. "
        "Kembalikan JSON sesuai skema.", prompt, history)
    result = await runtime.chat(model, messages, format_schema=SecuritySlots.model_json_schema(), output_tokens=256)
    if result.get("tool_calls"):
        raise ValueError("Router tidak boleh memanggil tool.")
    try:
        slots = SecuritySlots.model_validate_json(result["content"])
        user_text = "\n".join([*(item.content for item in history if item.role == "user"), prompt])
        if slots.target and slots.target.casefold() not in user_text.casefold():
            slots.target = ""
        if slots.ports and any(not re.search(rf"(?<!\d){port}(?!\d)", user_text) for port in slots.ports):
            slots.ports = []
        if slots.test_account_ref and slots.test_account_ref.casefold() not in user_text.casefold():
            slots.test_account_ref = ""
        slots.account_refs = [ref for ref in slots.account_refs if ref and ref.casefold() in user_text.casefold()]
        if slots.owner_json_pointer and slots.owner_json_pointer not in user_text:
            slots.owner_json_pointer = ""
        for selection in slots.selections:
            if selection.target and selection.target.casefold() not in user_text.casefold():
                selection.target = ""
            if selection.ports and any(not re.search(rf"(?<!\d){port}(?!\d)", user_text) for port in selection.ports):
                selection.ports = []
        lower = user_text.casefold()
        env_patterns = {"lab": r"\blab(?:oratory)?\b", "development": r"\b(development|dev)\b",
                        "staging": r"\bstaging\b", "uat": r"\buat\b",
                        "production_readonly": r"\b(production|produksi)\b.*\b(read.only|hanya.baca)\b"}
        if slots.environment and not re.search(env_patterns[slots.environment], lower, re.S):
            slots.environment = ""
        mode_patterns = {"blackbox": r"\bblack[ -]?box\b", "whitebox": r"\bwhite[ -]?box\b",
                         "greybox": r"\bgr[ae]y[ -]?box\b"}
        if slots.assessment_mode and not re.search(mode_patterns[slots.assessment_mode], lower):
            slots.assessment_mode = ""
        return complete_explicit_slots(slots, user_text)
    except ValueError as exc:
        raise ValueError("Parameter pemeriksaan tidak dapat dibaca. Jelaskan target dan jenis pemeriksaan.") from exc


async def classify(prompt, history, model):
    messages = bounded_messages(
        "Klasifikasikan pesan terbaru. Pilih coding hanya jika pengguna meminta agen "
        "memeriksa atau mengubah file workspace; security hanya jika meminta menjalankan "
        "pemeriksaan keamanan pada target; web jika meminta pencarian online. "
        "Pertanyaan umum, penjelasan kode, dan diskusi keamanan adalah chat. Jika pesan terbaru "
        "menjawab pertanyaan lanjutan tentang parameter pemeriksaan keamanan yang belum selesai, pilih security. "
        "Jangan menjalankan tool. Kembalikan JSON sesuai skema.", prompt, history)
    result = await runtime.chat(model, messages, format_schema=Intent.model_json_schema(), output_tokens=128)
    if result.get("tool_calls"):
        raise ValueError("Router tidak boleh memanggil tool.")
    try:
        return Intent.model_validate_json(result["content"]).intent
    except ValueError as exc:
        raise ValueError("Router tidak dapat menentukan jenis permintaan. Coba jelaskan tugas lebih spesifik.") from exc
