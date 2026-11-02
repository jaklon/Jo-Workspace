"""Review aids for code proposals: hunks that can be accepted one by one, and a risk summary.

Hunks are derived from the original file and the proposed content with the same
SequenceMatcher on both sides (proposal time and apply time), so the indices the user
selects always mean the same edits. Applying a subset never touches unselected lines."""
import difflib
import re
from pathlib import PurePosixPath

CONTEXT = 3
RISK_RULES = (
    (re.compile(r"(^|/)(package(-lock)?\.json|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|yarn\.lock|pnpm-lock\.yaml|go\.(mod|sum)|Cargo\.(toml|lock))$", re.I),
     "Dependensi berubah; pasang ulang paket dan tinjau sumbernya."),
    (re.compile(r"(^|/)(\.github/|\.gitlab-ci|Dockerfile|docker-compose|Makefile$|.*\.(sh|ps1|bat|cmd)$)", re.I),
     "Skrip build/CI atau shell; perubahan dapat menjalankan perintah di mesin lain."),
    (re.compile(r"(auth|login|password|token|secret|crypt|session|permission|security)", re.I),
     "Area keamanan (autentikasi, kredensial, izin); tinjau baris demi baris."),
    (re.compile(r"\.(ya?ml|toml|ini|cfg|conf|json|env\.example)$", re.I),
     "File konfigurasi; perubahan berlaku tanpa kompilasi."),
)


def _lines(text):
    return text.splitlines(True)


def hunks(old_text, new_text):
    """Grouped edit opcodes; each group is one reviewable hunk with its own diff text."""
    old, new = _lines(old_text), _lines(new_text)
    result = []
    for index, group in enumerate(difflib.SequenceMatcher(None, old, new, autojunk=False).get_grouped_opcodes(CONTEXT)):
        i1, i2, j1, j2 = group[0][1], group[-1][2], group[0][3], group[-1][4]
        body, added, removed = [], 0, 0
        for tag, a1, a2, b1, b2 in group:
            if tag == "equal":
                body += [" " + line for line in old[a1:a2]]
                continue
            body += ["-" + line for line in old[a1:a2]]
            body += ["+" + line for line in new[b1:b2]]
            removed += a2 - a1
            added += b2 - b1
        header = f"@@ -{i1 + 1},{i2 - i1} +{j1 + 1},{j2 - j1} @@\n"
        result.append({"index": index, "header": header.strip(), "added": added, "removed": removed,
                       "diff": header + "".join(line if line.endswith("\n") else line + "\n" for line in body)})
    return result


def apply_hunks(old_text, new_text, selected):
    """Old text with only the selected hunks' edits applied."""
    old, new = _lines(old_text), _lines(new_text)
    groups = list(difflib.SequenceMatcher(None, old, new, autojunk=False).get_grouped_opcodes(CONTEXT))
    chosen = set(selected)
    if not chosen or not chosen <= set(range(len(groups))):
        raise ValueError("Pilih minimal satu bagian perubahan yang valid.")
    edits = [op for index, group in enumerate(groups) if index in chosen for op in group if op[0] != "equal"]
    output, cursor = [], 0
    for _, a1, a2, b1, b2 in sorted(edits, key=lambda op: op[1]):
        output += old[cursor:a1] + new[b1:b2]
        cursor = a2
    return "".join(output + old[cursor:])


def summary(path, old_text, new_text, existed):
    parts = hunks(old_text, new_text)
    added, removed = sum(h["added"] for h in parts), sum(h["removed"] for h in parts)
    risks = [note for pattern, note in RISK_RULES if pattern.search(PurePosixPath(path).as_posix())]
    old_count = len(_lines(old_text))
    if existed and old_count >= 20 and removed >= old_count * 0.5:
        risks.append(f"Menghapus {removed} dari {old_count} baris; pastikan tidak ada bagian yang hilang tanpa sengaja.")
    if not existed:
        risks.append("File baru akan dibuat.")
    return {"new_file": not existed, "added": added, "removed": removed, "hunk_count": len(parts), "risks": risks}
