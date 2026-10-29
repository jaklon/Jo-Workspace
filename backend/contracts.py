from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

Target = Literal["reasoning", "coding", "security", "vision"]


class HistoryMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(max_length=16_000)


class ChatPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=6000)
    target: Target = "reasoning"
    history: list[HistoryMessage] = Field(default_factory=list, max_length=12)
    attachment_ids: list[str] = Field(default_factory=list, max_length=4)
    session_id: str = Field(default="default", min_length=1, max_length=100)
    web_mode: Literal["auto", "on", "off"] = "off"
    project_id: UUID | None = None


class AgentPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=6000)
    max_iterations: int = Field(default=5, ge=1, le=8)
    session_id: str = Field(default="default", min_length=1, max_length=100)


def event(kind: str, **values):
    return {"type": kind, **values}
