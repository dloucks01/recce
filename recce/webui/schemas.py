"""Type schemas for webui API (validation + serialization)."""
from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


class CommandFlag(BaseModel):
    name: str
    flag: str
    label: str
    active: bool = False


class CommandDef(BaseModel):
    label: str
    group: str
    targets: str = "optional"
    profile: bool = False
    creds: bool = False
    lhost: bool = False
    flags: list[CommandFlag] = Field(default_factory=list)


class ScanJob(BaseModel):
    id: str
    cmd: str
    status: str  # "running" | "done" | "failed"
    started: float
    ended: Optional[float] = None
    log: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    ip: str
    port: int
    title: str
    severity: str
    output: str
    confidence: str
    cwes: list[str] = Field(default_factory=list)
    reviewed: bool = False
    notes: str = ""


class Host(BaseModel):
    ip: str
    hostname: Optional[str] = None
    ports: int = 0
    os: Optional[str] = None
    reviewed: bool = False
    notes: str = ""


class Credential(BaseModel):
    username: str
    password: Optional[str] = None
    hash: Optional[str] = None
    domain: Optional[str] = None
    source: Optional[str] = None


class ChatMessage(BaseModel):
    author: str
    text: str
    timestamp: float
    media: Optional[str] = None


class ImportPreview(BaseModel):
    kind: str
    count: int
    summary: str
    items: list[dict[str, Any]] = Field(default_factory=list)


class NotePayload(BaseModel):
    finding_id: str
    text: str


class TickPayload(BaseModel):
    finding_id: str


class AssignPayload(BaseModel):
    ip: str
    tester: Optional[str] = None


class LabelPayload(BaseModel):
    ip: str
    label: str


class PresencePayload(BaseModel):
    tester: str


class ChatPayload(BaseModel):
    tester: str
    text: str


class ScanPayload(BaseModel):
    cmd: str
    targets: Optional[str] = None
    flags: list[str] = Field(default_factory=list)
    creds: Optional[dict[str, str]] = None
    lhost: Optional[str] = None
