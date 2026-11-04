"""Only reviewed fixture tools are callable while pentest execution is locked.

External MCP transport configs are validated here too, but are only *accepted* by the
gateway when the operator has opted in (config.EXTERNAL_MCP_ENABLED). Secret values are
never stored: for stdio we keep only the names of ENV vars to forward at runtime."""
import re
from typing import Literal
from urllib.parse import urlsplit
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


_SHELL_META = set('&|;<>$`\n\r\0"\'')


class ExternalMCPConfig(StrictModel):
    """Transport for an external MCP server. stdio: a command + args + the names (not
    values) of ENV vars to forward. http: a loopback or HTTPS URL, no credentials."""
    transport: Literal['stdio', 'http']
    command: str = Field(default='', max_length=500)
    args: list[str] = Field(default_factory=list, max_length=20)
    env_keys: list[str] = Field(default_factory=list, max_length=20)
    url: str = Field(default='', max_length=500)

    @model_validator(mode='after')
    def consistent(self):
        if self.transport == 'stdio':
            if not self.command or self.url:
                raise ValueError('Transport stdio memerlukan command dan tidak memakai url.')
            for value in [self.command, *self.args]:
                if not value or any(c in _SHELL_META or ord(c) < 32 for c in value):
                    raise ValueError('Command/args tidak boleh memuat metakarakter shell atau karakter kontrol.')
            if any(not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', key) for key in self.env_keys) or len(set(self.env_keys)) != len(self.env_keys):
                raise ValueError('env_keys harus nama variabel unik (HURUF_BESAR), bukan nilai rahasia.')
        else:
            if not self.url or self.command or self.args or self.env_keys:
                raise ValueError('Transport http hanya memakai url.')
            parsed = urlsplit(self.url)
            loopback = parsed.hostname in ('127.0.0.1', 'localhost', '::1')
            if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError('URL MCP http harus tanpa kredensial/query/fragment.')
            if parsed.scheme == 'http' and not loopback:
                raise ValueError('http hanya diizinkan untuk loopback; selain itu gunakan https.')
        return self
