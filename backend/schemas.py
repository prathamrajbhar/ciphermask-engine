"""
CipherMask – Pydantic Schemas
Request/response validation models for the API layer.
"""
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, List
from datetime import datetime


# ── Auth ──────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    role: str
    name: str


class UserOut(BaseModel):
    id: int
    name: str
    email: str
    role: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── Files ─────────────────────────────────────────────────────

class FileOut(BaseModel):
    id: int
    original_filename: str
    file_type: str
    status: str
    uploaded_by: int
    file_hash: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class FileListResponse(BaseModel):
    files: list[FileOut]
    total: int


# ── PII Detection ────────────────────────────────────────────

class PIIEntity(BaseModel):
    text: str
    pii_type: str
    start: int
    end: int
    confidence: float = 1.0


class MaskResult(BaseModel):
    file_id: int
    status: str
    total_pii_found: int
    pii_breakdown: Dict[str, int]
    risk_score: float
    compliance_status: str


# ── Token Vault ───────────────────────────────────────────────

class TokenMappingOut(BaseModel):
    id: int
    token: str
    pii_type: str
    file_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class ReverseTokenRequest(BaseModel):
    tokens: list[str] = []  # empty = reverse all


class ReverseTokenResponse(BaseModel):
    mappings: Dict[str, str]


# ── Compliance Report ────────────────────────────────────────

class ComplianceReportOut(BaseModel):
    id: int
    file_id: int
    total_pii_found: int
    pii_breakdown: Optional[Dict[str, int]] = None
    risk_score: float
    compliance_status: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── Dashboard ─────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_files: int
    files_processed: int
    total_pii_found: int
    avg_risk_score: float


# ── Audit Logs ────────────────────────────────────────────────

class AuditLogOut(BaseModel):
    id: int
    user_id: int
    user_email: str
    action: str
    resource_type: str
    resource_id: Optional[int] = None
    details: Optional[str] = None
    ip_address: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True
