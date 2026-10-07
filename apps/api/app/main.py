from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator

app = FastAPI(title="Guardify API", version="1.0.0")
origins = [item.strip() for item in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",") if item.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["*"])

class UrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Only credential-free http(s) URLs are supported")
        try:
            addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(parsed.hostname, None)}
        except socket.gaierror as exc:
            raise ValueError("Hostname cannot be resolved") from exc
        if any(address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_unspecified for address in addresses):
            raise ValueError("Private, local, and metadata addresses are not allowed")
        if parsed.hostname.lower() in {"metadata.google.internal", "metadata.amazonaws.com"}:
            raise ValueError("Cloud metadata endpoints are not allowed")
        return value.strip()

class EmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sender: str = Field(min_length=1, max_length=320)
    recipient: str = Field(min_length=1, max_length=320)
    subject: str = Field(default="", max_length=998)
    body_text: str = Field(default="", max_length=1_000_000)
    body_html: str = Field(default="", max_length=2_000_000)
    headers: dict[str, str] = Field(default_factory=dict)
    attachments: list[dict] = Field(default_factory=list, max_length=20)

class Citizen(BaseModel):
    verdict: str
    summary: str
    impact: list[str] = Field(default_factory=list)
    next_step: str

def result(scan_type: str, digest: str, request_id: str) -> dict:
    return {"success": True, "data": {"scan_id": str(uuid.uuid4()), "type": scan_type, "verdict": "UNKNOWN", "citizen": {"verdict": "UNKNOWN", "summary": "We could not obtain enough trustworthy evidence to determine whether this item is safe.", "impact": [], "next_step": "Treat it cautiously until additional information is available."}, "analyst": {"sha256": digest, "evidence": "No external threat-intelligence result was available."}, "cached": False, "created_at": datetime.now(timezone.utc).isoformat()}, "error": None, "request_id": request_id}

@app.middleware("http")
async def request_context(request: Request, call_next):
    request.state.request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["x-request-id"] = request.state.request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

@app.get("/api/v1/health")
async def health(request: Request):
    return {"status": "healthy", "services": {"database": "unconfigured", "cache": "unconfigured", "virustotal": "unconfigured", "gemini": "unconfigured"}, "request_id": request.state.request_id}

@app.post("/api/v1/analyze/url")
async def analyze_url(payload: UrlRequest, request: Request):
    digest = hashlib.sha256(payload.url.encode()).hexdigest()
    return result("url", digest, request.state.request_id)

@app.post("/api/v1/analyze/file")
async def analyze_file(file: UploadFile = File(...), request: Request = None):
    maximum = int(os.getenv("MAX_FILE_SIZE_MB", "10")) * 1024 * 1024
    content = await file.read(maximum + 1)
    if len(content) > maximum:
        raise HTTPException(status_code=413, detail="File exceeds configured size limit")
    digest = hashlib.sha256(content).hexdigest()
    return result("file", digest, request.state.request_id)

@app.post("/api/v1/analyze/email")
async def analyze_email(payload: EmailRequest, request: Request):
    canonical = payload.model_dump_json(exclude_none=True, by_alias=True).encode()
    return result("email", hashlib.sha256(canonical).hexdigest(), request.state.request_id)

@app.post("/api/v1/webhooks/email")
async def email_webhook(payload: EmailRequest, request: Request, x_webhook_secret: str | None = Header(default=None)):
    expected = os.getenv("EMAIL_WEBHOOK_SECRET")
    if expected and x_webhook_secret != expected:
        raise HTTPException(status_code=401, detail="Invalid webhook credentials")
    return await analyze_email(payload, request)
