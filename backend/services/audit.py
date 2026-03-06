"""
Audit Logging Service
Logs all security-relevant actions for DPDPA compliance.
"""
import hashlib
import json
import logging
from typing import Optional
from sqlalchemy.orm import Session
import models

logger = logging.getLogger(__name__)


def compute_file_hash(filepath: str) -> str:
    """Compute SHA-256 hash of a file for integrity verification."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def log_action(
    db: Session,
    user_id: int,
    action: str,
    resource_type: str,
    resource_id: Optional[int] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
) -> models.AuditLog:
    """Record an audit log entry."""
    entry = models.AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=json.dumps(details) if details else None,
        ip_address=ip_address,
    )
    db.add(entry)
    db.flush()
    logger.info(
        "AUDIT | user=%s action=%s resource=%s:%s",
        user_id, action, resource_type, resource_id,
    )
    return entry
