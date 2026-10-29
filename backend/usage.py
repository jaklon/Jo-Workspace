"""Daily inference totals in UTC; no conversation contents or identifiers."""
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path


class UsageLedger:
    def __init__(self, path: Path):
        self.path = path
        self.rows = []
        self.persistence_error = False
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, list):
                self.rows = value
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            self.persistence_error = True

    def record(self, model, status, seconds, chunk=None):
        chunk = chunk or {}
        today = datetime.now(timezone.utc).date().isoformat()
        cutoff = (datetime.now(timezone.utc).date() - timedelta(days=89)).isoformat()
        self.rows = [r for r in self.rows if r.get("date", "") >= cutoff]
        row = next((r for r in self.rows if r["date"] == today and r["model"] == model), None)
        if row is None:
            row = {"date": today, "model": model, "completed": 0, "failed": 0,
                   "cancelled": 0, "input_tokens": 0, "output_tokens": 0,
                   "measured": 0, "seconds": 0}
            self.rows.append(row)
        row[status] += 1
        row["seconds"] = round(row["seconds"] + seconds, 3)
        if isinstance(chunk.get("prompt_eval_count"), int) and isinstance(chunk.get("eval_count"), int):
            row["input_tokens"] += max(0, chunk["prompt_eval_count"])
            row["output_tokens"] += max(0, chunk["eval_count"])
            row["measured"] += 1
        self.persist()

    def persist(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps(self.rows), encoding="utf-8")
            temporary.replace(self.path)
            self.persistence_error = False
        except OSError:
            self.persistence_error = True
            logging.getLogger("agent.usage").warning("Usage hanya tersimpan dalam memori.")

    def clear(self):
        previous = self.rows
        self.rows = []
        self.persist()
        if self.persistence_error:
            self.rows = previous
            raise OSError("Usage gagal dihapus dari disk.")
