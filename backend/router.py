"""Explicit modality routing and retrieval over the entire attachment."""
import re
from pathlib import Path
from config import DOCUMENT_EXTENSIONS, IMAGE_EXTENSIONS, CONTEXT_TOKENS, OUTPUT_TOKENS
import config
from model_runtime import clean_answer, token_upper_bound

clean_reasoning_output = clean_answer


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


def chunks_for(attachment):
    chunks = []
    for number, line in enumerate(attachment["content"].splitlines(), 1):
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
    return chunks


def retrieve(attachments, prompt, system):
    candidates = [c for a in attachments for c in chunks_for(a)]
    terms = set(re.findall(r"\w+", prompt.lower())) - {"yang", "dan", "apa", "pada", "ini", "itu", "dari", "di", "dokumen", "file", "saya", "tolong", "berikan", "saja"}
    def score(chunk):
        return len(terms & set(re.findall(r"\w+", chunk["text"].lower())))
    ranked = sorted(enumerate(candidates), key=lambda item: (-score(item[1]), item[0]))
    available = config.CONTEXT_TOKENS - config.OUTPUT_TOKENS - config.THINKING_TOKENS - token_upper_bound(system + prompt) - 450
    selected = []
    for _, chunk in ranked:
        label = f"[{chunk['filename']} bagian {chunk['section']}, baris {chunk['line_start']}-{chunk['line_end']}]"
        cost = token_upper_bound(label + "\n" + chunk["text"]) + 20
        if cost <= available:
            selected.append({**chunk, "label": label})
            available -= cost
    if candidates and not selected:
        raise ValueError("Tidak cukup ruang konteks untuk sumber. Persingkat pertanyaan.")
    coverage = {"selected": len(selected), "total": len(candidates), "complete": len(selected) == len(candidates)}
    notice = ("Seluruh bagian tersedia." if coverage["complete"] else
              f"Cakupan terbatas: {len(selected)} dari {len(candidates)} bagian dipilih berdasarkan pertanyaan. Ini bukan pemeriksaan seluruh dokumen.")
    context = notice + "\n\n" + "\n\n".join(c["label"]+"\n"+c["text"] for c in selected)
    return context, selected, coverage
