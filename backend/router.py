"""Explicit modality routing and retrieval over the entire attachment."""
import re
from pathlib import Path
from config import DOCUMENT_EXTENSIONS, IMAGE_EXTENSIONS, CONTEXT_TOKENS, OUTPUT_TOKENS
import config
from model_runtime import clean_answer, token_upper_bound

clean_reasoning_output = clean_answer

# Location markers written by doc_engine; a PDF page marker applies to the lines below it.
PAGE = re.compile(r"^\[Halaman (\d+)\]$")
UNREADABLE = re.compile(r"^\[Halaman (\d+) tidak terbaca\b")
LINE_MARK = re.compile(r"^\[((?:Paragraf|Header|Footer) \d+|Tabel \d+, baris \d+|Sheet [^\]]+?, baris \d+)\]")
STOPWORDS = {"yang", "dan", "apa", "pada", "ini", "itu", "dari", "di", "dokumen", "file", "saya", "tolong", "berikan", "saja"}


def detect_pipeline_route(filename, prompt):
    if filename:
        ext = Path(filename).suffix.lower()
        if ext in IMAGE_EXTENSIONS:
            return "VISION_PIPELINE"
        if ext in DOCUMENT_EXTENSIONS:
            return "DOCUMENT_PIPELINE"
        raise ValueError("Format lampiran tidak didukung.")
    if re.search(r"\b(nmap|sqlmap|cve|pentest|vulnerability|audit|exploit|payload)\b", prompt, re.I):
        return "CYBERSECURITY_PIPELINE"
    if re.search(r"\b(function|class|debug|error|traceback|code|kode|refactor)\b", prompt, re.I):
        return "CODING_PIPELINE"
    return "GENERAL_REASONING"


def line_locations(lines):
    """Human-readable location of every line: page, paragraph, table row, sheet row or line."""
    page, result = None, []
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if match := PAGE.match(stripped) or UNREADABLE.match(stripped):
            page = match.group(1)
        mark = LINE_MARK.match(stripped)
        result.append(f"hal. {page}" if page else mark.group(1) if mark else f"baris {number}")
    return result


def span(locations):
    unique = list(dict.fromkeys(locations))
    return unique[0] if len(unique) == 1 else f"{unique[0]} – {unique[-1]}"


def chunks_for(attachment):
    chunks = []
    lines = attachment["content"].splitlines()
    locations = line_locations(lines)
    for number, line in enumerate(lines, 1):
        remaining = line.strip()
        while remaining:
            end = min(len(remaining), 500)
            while len(remaining[:end].encode("utf-8")) > 700:
                end = max(1, end // 2)
            piece, remaining = remaining[:end], remaining[end:]
            if chunks and chunks[-1]["line_end"] >= number - 1 and len((chunks[-1]["text"]+piece).encode("utf-8")) < 700:
                chunks[-1]["text"] += "\n" + piece
                chunks[-1]["line_end"] = number
            else:
                chunks.append({"attachment_id": attachment["id"], "filename": attachment["name"],
                               "line_start": number, "line_end": number, "text": piece})
    for i, chunk in enumerate(chunks, 1):
        chunk["section"] = i
        chunk["location"] = span(locations[chunk["line_start"] - 1:chunk["line_end"]])
    return chunks


def unreadable_pages(attachments):
    return sorted({int(m.group(1)) for a in attachments for line in a["content"].splitlines()
                   if (m := UNREADABLE.match(line.strip()))})


def retrieve(attachments, prompt, system):
    candidates = [c for a in attachments for c in chunks_for(a)]
    terms = set(re.findall(r"\w+", prompt.lower())) - STOPWORDS
    def score(chunk):
        return len(terms & set(re.findall(r"\w+", chunk["text"].lower())))
    ranked = sorted(enumerate(candidates), key=lambda item: (-score(item[1]), item[0]))
    available = config.CONTEXT_TOKENS - config.OUTPUT_TOKENS - config.THINKING_TOKENS - token_upper_bound(system + prompt) - 450
    selected = []
    for _, chunk in ranked:
        label = f"[{chunk['filename']} · {chunk['location']} · bagian {chunk['section']}]"
        cost = token_upper_bound(label + "\n" + chunk["text"]) + 20
        if cost <= available:
            selected.append({**chunk, "label": label, "matched": score(chunk) > 0})
            available -= cost
    if candidates and not selected:
        raise ValueError("Tidak cukup ruang konteks untuk sumber. Persingkat pertanyaan.")
    unreadable = unreadable_pages(attachments)
    coverage = {"selected": len(selected), "total": len(candidates), "complete": len(selected) == len(candidates),
                "matched": sum(1 for c in candidates if score(c) > 0), "unreadable_pages": unreadable[:50]}
    notes = ["Seluruh bagian tersedia." if coverage["complete"] else
             f"Cakupan terbatas: {len(selected)} dari {len(candidates)} bagian dipilih berdasarkan pertanyaan. Ini bukan pemeriksaan seluruh dokumen."]
    if terms and not coverage["matched"]:
        notes.append("Tidak ada bagian yang memuat kata kunci pertanyaan; nyatakan bila jawabannya tidak ditemukan.")
    if unreadable:
        notes.append("Halaman tanpa teks (tidak terbaca): " + ", ".join(map(str, unreadable[:20])) + ".")
    context = " ".join(notes) + "\n\n" + "\n\n".join(c["label"]+"\n"+c["text"] for c in selected)
    return context, selected, coverage


CITATION = re.compile(r"bagian\s+(\d+)", re.I)


def mark_citations(answer, sources, coverage):
    """Flag which supplied sources the answer cites by their `bagian N` label."""
    cited = {int(n) for n in CITATION.findall(answer or "")}
    marked = [{**s, "cited": s.get("section") in cited} for s in sources]
    if coverage is not None:
        coverage = {**coverage, "cited": sum(1 for s in marked if s["cited"])}
    return marked, coverage
