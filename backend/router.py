import os
import re
import ollama

REASONING_MODEL = "deepseek-r1:7b"
VISION_MODEL = "minicpm-v:latest"

ollama_client = ollama.Client(host="http://127.0.0.1:11434")

def detect_pipeline_route(filename: str | None, prompt: str) -> str:
    """Mendeteksi alur pipeline berdasarkan ekstensi file dan intent prompt."""
    if filename:
        ext = os.path.splitext(filename)[1].lower()
        if ext in [".png", ".jpg", ".jpeg", ".webp"]:
            return "VISION_PIPELINE"
        if ext in [".pdf", ".docx", ".xlsx", ".txt", ".csv"]:
            return "DOCUMENT_PIPELINE"

    lower_prompt = prompt.lower()
    if any(k in lower_prompt for k in ["nmap", "sqlmap", "cve", "pentest", "vulnerability", "audit"]):
        return "CYBERSECURITY_PIPELINE"
    if any(k in lower_prompt for k in ["function", "class", "debug", "error", "traceback", "code"]):
        return "CODING_PIPELINE"

    return "GENERAL_REASONING"


def analyze_document_with_r1(document_text: str, user_prompt: str) -> str:
    """DeepSeek-R1 menganalisis teks dokumen yang telah diparsing."""
    # Potong jika teks terlalu panjang melebihi context window
    truncated_text = document_text[:12000]

    system_instruction = (
        "Kamu adalah AI Document Analyst & Legal/Technical Auditor. "
        "Analisis dokumen berikut secara mendalam, ekstrak poin-poin utama, pasal penting, "
        "atau kejanggalan sesuai instruksi pengguna. Jawab dengan bahasa Indonesia yang rapi."
    )

    combined_input = (
        f"KONTEN DOKUMEN:\n\"\"\"\n{truncated_text}\n\"\"\"\n\n"
        f"PERMINTAAN USER: {user_prompt}"
    )

    response = ollama_client.chat(
        model=REASONING_MODEL,
        messages=[
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": combined_input}
        ]
    )

    raw_content = response["message"]["content"]
    # Bersihkan tag <think> jika tidak ingin ditampilkan mentah ke UI
    return re.sub(r"<think>.*?</think>", "", raw_content, flags=re.DOTALL).strip()