import os
import re
from ollama import Client

REASONING_MODEL = "qwen-9b-reasoning"

ollama_client = Client(host="http://127.0.0.1:11434")

def detect_pipeline_route(filename: str | None, prompt: str) -> str:
    """Mendeteksi alur pipeline berdasarkan ekstensi file dan intent prompt."""
    if filename:
        ext = os.path.splitext(filename)[1].lower()
        if ext in [".png", ".jpg", ".jpeg", ".webp"]:
            return "VISION_PIPELINE"
        if ext in [".pdf", ".docx", ".xlsx", ".txt", ".csv"]:
            return "DOCUMENT_PIPELINE"

    lower_prompt = prompt.lower()
    if any(
        k in lower_prompt
        for k in [
            "nmap", "sqlmap", "cve", "pentest", "vulnerability", "audit",
            "exploit", "payload",
        ]
    ):
        return "CYBERSECURITY_PIPELINE"
    if any(k in lower_prompt for k in ["function", "class", "debug", "error", "traceback", "code"]):
        return "CODING_PIPELINE"

    return "GENERAL_REASONING"


def clean_reasoning_output(raw_content: str) -> str:
    """Menghapus reasoning internal dari jawaban yang ditampilkan ke pengguna."""
    cleaned = re.sub(r"<think>.*?</think>", "", raw_content, flags=re.DOTALL)
    # Beberapa template model menyembunyikan tag pembuka, tetapi tetap mengirim
    # penutupnya. Dalam kasus itu, teks sebelum penutup adalah reasoning internal.
    if "</think>" in cleaned:
        cleaned = cleaned.split("</think>", maxsplit=1)[-1]
    return cleaned.strip()


def analyze_document_with_r1(document_text: str, user_prompt: str) -> str:
    """Menganalisis dokumen atau pertanyaan umum dengan Qwen 9B."""
    # Potong jika teks terlalu panjang melebihi context window
    truncated_text = document_text[:12000]

    system_instruction = (
        "Kamu adalah AI Lead Architect & Technical/Document Auditor. "
        "Analisis pertanyaan atau dokumen berikut secara mendalam, objektif, "
        "dan berikan jawaban yang terstruktur rapi dalam bahasa Indonesia."
    )

    if truncated_text.strip():
        combined_input = (
            f"KONTEN DOKUMEN:\n\"\"\"\n{truncated_text}\n\"\"\"\n\n"
            f"PERMINTAAN USER: {user_prompt}"
        )
    else:
        combined_input = user_prompt

    response = ollama_client.chat(
        model=REASONING_MODEL,
        messages=[
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": combined_input}
        ],
        # Progres tingkat tinggi sudah dikirim oleh endpoint SSE. Menonaktifkan
        # thinking internal mencegah model menghabiskan waktu lama pada reasoning
        # tersembunyi yang pada akhirnya dibuang oleh clean_reasoning_output().
        think=False,
        options={
            "temperature": 0.3,
            "num_ctx": 4096,
            "num_predict": 1200,
        },
    )

    raw_content = response["message"]["content"]
    return clean_reasoning_output(raw_content)
