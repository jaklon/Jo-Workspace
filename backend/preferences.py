"""Validated, persistent model settings. Never stores credentials or prompts."""
import json
import logging
from pydantic import BaseModel, ConfigDict, Field, model_validator
import config


class InferenceSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context_tokens: int = Field(default=config.CONTEXT_TOKENS, ge=2048, le=32768)
    output_tokens: int = Field(default=config.OUTPUT_TOKENS, ge=128, le=8192)
    temperature: float = Field(default=0.2, ge=0, le=2)
    model_timeout: int = Field(default=int(config.MODEL_TIMEOUT), ge=30, le=600)
    queue_timeout: int = Field(default=int(config.QUEUE_TIMEOUT), ge=5, le=120)

    @model_validator(mode="after")
    def output_budget(self):
        if self.output_tokens > self.context_tokens // 3:
            raise ValueError("Token jawaban maksimal sepertiga context window.")
        return self


class ModelSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reasoning: str = Field(default=config.MODELS["reasoning"], min_length=1, max_length=120, pattern=r"^[\w.\-/:]+$")
    coding: str = Field(default=config.MODELS["coding"], min_length=1, max_length=120, pattern=r"^[\w.\-/:]+$")
    vision: str = Field(default=config.MODELS["vision"], min_length=1, max_length=120, pattern=r"^[\w.\-/:]+$")
    security: str = Field(default=config.MODELS["security"], min_length=1, max_length=120, pattern=r"^[\w.\-/:]+$")


class ServerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    models: ModelSettings = Field(default_factory=ModelSettings)
    inference: InferenceSettings = Field(default_factory=InferenceSettings)


current = ServerSettings()
defaults = current.model_dump()


def apply_settings(value):
    global current
    current = value
    config.MODELS.update(value.models.model_dump())
    config.CONTEXT_TOKENS = value.inference.context_tokens
    config.OUTPUT_TOKENS = value.inference.output_tokens
    config.MODEL_TIMEOUT = value.inference.model_timeout
    config.QUEUE_TIMEOUT = value.inference.queue_timeout


def save_settings(value):
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = config.DATA_DIR / "settings.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(value.model_dump_json(indent=2), encoding="utf-8")
    temporary.replace(path)
    apply_settings(value)


def load_settings():
    path = config.DATA_DIR / "settings.json"
    if path.exists():
        try:
            value = ServerSettings.model_validate_json(path.read_text(encoding="utf-8"))
            apply_settings(value)
        except (ValueError, OSError):
            logging.getLogger("agent.settings").warning("Pengaturan tersimpan tidak valid; memakai konfigurasi awal.")
