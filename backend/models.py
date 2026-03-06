"""
CipherMask – Database Models
SQLAlchemy ORM models for the DPDPA PII Masking Engine.

Tables:
  - users: Admin and standard users with role-based access
  - files: Uploaded file records with processing status
  - token_mappings: Encrypted PII→token vault entries
  - compliance_reports: Per-file risk scoring and PII breakdown
  - audit_logs: Immutable security audit trail
"""
import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Float, Text,
    ForeignKey, Enum as SAEnum,
)
from sqlalchemy.orm import relationship
from database import Base
import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"


class FileStatus(str, enum.Enum):
    UPLOADED = "uploaded"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(SAEnum(UserRole), default=UserRole.USER, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    files = relationship("FileRecord", back_populates="uploader")


class FileRecord(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    file_type = Column(String(20), nullable=False)  # csv, json, sql, pdf, docx
    original_path = Column(Text, nullable=False)
    sanitized_path = Column(Text, nullable=True)
    file_hash = Column(String(64), nullable=True)  # SHA-256 integrity hash
    status = Column(SAEnum(FileStatus), default=FileStatus.UPLOADED)
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    uploader = relationship("User", back_populates="files")
    tokens = relationship("TokenMapping", back_populates="file", cascade="all, delete-orphan")
    report = relationship(
        "ComplianceReport", back_populates="file",
        uselist=False, cascade="all, delete-orphan",
    )


class TokenMapping(Base):
    """Secure token vault: maps generated tokens to AES-256 encrypted originals."""
    __tablename__ = "token_mappings"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(100), nullable=False, index=True)
    encrypted_original = Column(Text, nullable=False)  # AES-256-CBC encrypted
    pii_type = Column(String(50), nullable=False)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    file = relationship("FileRecord", back_populates="tokens")


class ComplianceReport(Base):
    """Per-file DPDPA compliance report with risk scoring."""
    __tablename__ = "compliance_reports"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"), unique=True, nullable=False)
    total_pii_found = Column(Integer, default=0)
    pii_breakdown = Column(Text, nullable=True)  # JSON: {"AADHAAR": 5, "PAN": 3, ...}
    risk_score = Column(Float, default=0.0)       # 0.0 – 10.0
    compliance_status = Column(String(50), default="pending")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    file = relationship("FileRecord", back_populates="report")


class AuditLog(Base):
    """Immutable audit trail for DPDPA compliance."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String(50), nullable=False)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(Integer, nullable=True)
    details = Column(Text, nullable=True)  # JSON context
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User")
