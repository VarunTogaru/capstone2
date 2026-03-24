import re

from pydantic import BaseModel, Field, field_validator
from typing import Optional

_TARGET_RE = re.compile(r'^[a-zA-Z0-9.\:\/\-\[\]_%,\*\?]+$')
_MAX_TARGET_LEN = 253


class Request(BaseModel):
    target: str = Field(..., examples=["scanme.nmap.org", "192.168.1.10"])

    @field_validator('target')
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError('target must not be empty')
        if len(v) > _MAX_TARGET_LEN:
            raise ValueError(f'target exceeds maximum length of {_MAX_TARGET_LEN}')
        if v.startswith('-'):
            raise ValueError('target must not start with a hyphen')
        if not _TARGET_RE.match(v):
            raise ValueError('target contains invalid characters')
        return v
    scan_type: str = Field("tcp", examples=["tcp", "syn", "version", "custom"])
    ports: Optional[str] = Field(None, examples=["22,80,443", "1-1024"])
    use_privileged: bool = Field(False, examples=[False, True])
    timeout_seconds: int = Field(180, ge=10, le=3600, examples=[120, 300])
    request_id: Optional[str] = Field(None, examples=["req_abc123"])
    extra_args: list[str] = Field(
        default_factory=list,
        examples=[["-Pn", "-T4", "--open"], ["--script", "vuln"]],
    )
