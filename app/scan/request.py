from pydantic import BaseModel, Field
from typing import Optional

class Request(BaseModel):
    target: str = Field(..., examples=["scanme.nmap.org", "192.168.1.10"])
    scan_type: str = Field("tcp", examples=["tcp", "syn", "version", "custom"])
    ports: Optional[str] = Field(None, examples=["22,80,443", "1-1024"])
    use_privileged: bool = Field(False, examples=[False, True])
    timeout_seconds: int = Field(180, ge=10, le=3600, examples=[120, 300])
    request_id: Optional[str] = Field(None, examples=["req_abc123"])
    extra_args: list[str] = Field(
        default_factory=list,
        examples=[["-Pn", "-T4", "--open"], ["--script", "vuln"]],
    )
