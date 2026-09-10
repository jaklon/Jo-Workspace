import re
import json
from ollama import Client
from tools import TOOL_DEFINITIONS, TOOL_RUNNERS

ollama_client = Client(host="http://127.0.0.1:11434")

# Model yang sama menangani perencanaan reasoning dan eksekusi coding/tool-calling.
AGENT_MODEL = "qwen-9b-reasoning"


def clean_output(text: str) -> str:
    """Membersihkan tag <think>...</think> dari jawaban model."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def run_reasoning_step(user_prompt: str, history: list) -> str:
    """Stage 1: Qwen 9B merumuskan rencana eksekusi."""
    system_prompt = (
        "Kamu adalah AI Lead Architect. Analisis kebutuhan user dan buat rencana langkah kerja "
        "yang ringkas untuk dieksekusi. Jawab dalam bahasa Indonesia."
    )
    messages = [
        {"role": "system", "content": system_prompt},
        *history,
        {"role": "user", "content": user_prompt},
    ]

    response = ollama_client.chat(
        model=AGENT_MODEL,
        messages=messages,
        options={"temperature": 0.2, "num_ctx": 4096},
    )
    return clean_output(response["message"]["content"])


def run_coder_step(plan: str, history: list):
    """Stage 2: Qwen 9B memilih tools berdasarkan plan arsitek."""
    messages = [
        {
            "role": "system",
            "content": (
                "Kamu adalah AI Execution Engineer. Jalankan rencana berikut menggunakan tools yang tersedia. "
                "Panggil tool yang sesuai atau berikan konfirmasi jika tugas selesai."
            ),
        },
        *history,
        {
            "role": "user",
            "content": f"Rencana Kerja:\n{plan}\n\nLakukan aksi sekarang.",
        },
    ]

    response = ollama_client.chat(
        model=AGENT_MODEL,
        messages=messages,
        tools=TOOL_DEFINITIONS,
        options={"temperature": 0.1, "num_ctx": 4096},
    )
    return response["message"]

def execute_agent_pipeline(user_prompt: str, max_iterations: int = 5):
    history = []

    # Tahap 1: Analisis awal dan perumusan plan
    plan = run_reasoning_step(user_prompt, history)
    print(f"[STAGE 1 - PLAN]:\n{plan}\n")

    # Tahap 2: Eksekusi tools berbasis loop
    for i in range(max_iterations):
        print(f"--- Iterasi Eksekusi {i + 1} ---")
        coder_message = run_coder_step(plan, history)
        tool_calls = coder_message.get("tool_calls")

        # Jika model selesai dan tidak memanggil tool lagi
        if not tool_calls:
            print("[SELESAI]:", coder_message.get("content"))
            return coder_message.get("content")

        # Catat pesan assistant ke riwayat
        history.append(coder_message)

        # Jalankan setiap tool yang dipanggil Qwen2.5
        for call in tool_calls:
            func_name = call["function"]["name"]
            func_args = call["function"]["arguments"]
            
            # Safety check jika arguments masih bertipe string JSON
            if isinstance(func_args, str):
                try:
                    func_args = json.loads(func_args)
                except Exception:
                    func_args = {}

            print(f"[TOOL CALL] {func_name}({func_args})")
            if func_name in TOOL_RUNNERS:
                try:
                    tool_result = TOOL_RUNNERS[func_name](**func_args)
                except Exception as e:
                    tool_result = f"Error saat menjalankan {func_name}: {str(e)}"
            else:
                tool_result = f"Error: Tool {func_name} tidak terdaftar."

            # Tambahkan respons tool ke history
            history.append(
                {
                    "role": "tool",
                    "content": str(tool_result),
                    "name": func_name,
                }
            )

    return "Batas iterasi eksekusi tercapai."
