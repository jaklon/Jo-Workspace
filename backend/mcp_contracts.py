"""Only reviewed fixture tools are callable while pentest execution is locked."""
from typing import Literal
from uuid import UUID
from pydantic import Field, model_validator
from engagements import StrictModel
from mcp_fixture_server import inspect_arguments


class MCPBinding(StrictModel):
    server_id: UUID
    server_revision: int = Field(ge=1,strict=True)
    descriptor_hash: str = Field(pattern=r'^[a-f0-9]{64}$')
    tool: Literal['fixture.inspect','fixture.compare']
    arguments: dict

    @model_validator(mode='after')
    def strict_arguments(self):
        inspect_arguments(self.tool,self.arguments)
        return self
