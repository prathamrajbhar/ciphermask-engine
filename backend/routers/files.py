"""
Files Router
Handles file upload, masking pipeline, download, reports, token vault,
and dashboard/audit endpoints.

Follows the DPDPA pipeline:
  Upload → Detect → Score → Tokenize → Mask → Download
"""
import os
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from database import get_db
from config import settings
from utils.security import get_current_user, require_admin
from services.pipeline import run_masking_pipeline
from services.tokenizer import tokenizer
from services.audit import compute_file_hash, log_action
import models
import schemas

router = APIRouter(prefix="/api", tags=["Files"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ── Upload ────────────────────────────────────────────────────

@router.post("/upload", response_model=schemas.FileOut, status_code=status.HTTP_201_CREATED)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    """Upload a file for PII processing (admin only)."""
    _, ext = os.path.splitext(file.filename)
    ext = ext.lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {ext}. Allowed: {', '.join(sorted(settings.ALLOWED_EXTENSIONS))}",
        )

    unique_name = f"{uuid.uuid4().hex}{ext}"
    filepath = os.path.join(settings.UPLOAD_DIR, unique_name)
    content = await file.read()
    with open(filepath, "wb") as f:
        f.write(content)

    file_hash = compute_file_hash(filepath)

    file_record = models.FileRecord(
        original_filename=file.filename,
        stored_filename=unique_name,
        file_type=ext.lstrip("."),
        original_path=filepath,
        file_hash=file_hash,
        status=models.FileStatus.UPLOADED,
        uploaded_by=current_user.id,
    )
    db.add(file_record)
    db.flush()

    log_action(
        db, current_user.id, "upload", "file", file_record.id,
        details={"filename": file.filename, "type": ext, "hash": file_hash},
        ip_address=_client_ip(request),
    )
    db.commit()
    db.refresh(file_record)
    return file_record


# ── Masking Pipeline ──────────────────────────────────────────

@router.post("/mask/{file_id}", response_model=schemas.MaskResult)
def mask_pipeline(
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    """Run the full PII detection and masking pipeline on an uploaded file."""
    file_record = db.query(models.FileRecord).filter(models.FileRecord.id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    if file_record.status == models.FileStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="File already processed")

    file_record.status = models.FileStatus.PROCESSING
    db.commit()

    try:
        result = run_masking_pipeline(file_record, db)

        log_action(
            db, current_user.id, "mask", "file", file_id,
            details={
                "pii_found": result["total_pii_found"],
                "risk_score": result["risk_score"],
                "status": result["compliance_status"],
            },
            ip_address=_client_ip(request),
        )
        db.commit()

        return schemas.MaskResult(
            file_id=file_id,
            status="completed",
            total_pii_found=result["total_pii_found"],
            pii_breakdown=result["pii_breakdown"],
            risk_score=result["risk_score"],
            compliance_status=result["compliance_status"],
        )

    except Exception as e:
        file_record.status = models.FileStatus.FAILED
        db.commit()
        raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")


# ── File Listing ──────────────────────────────────────────────

@router.get("/files", response_model=schemas.FileListResponse)
def list_files(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """List all processed files."""
    files = db.query(models.FileRecord).order_by(models.FileRecord.created_at.desc()).all()
    return schemas.FileListResponse(files=files, total=len(files))


# ── Download Sanitized ────────────────────────────────────────

@router.get("/files/{file_id}/download")
def download_sanitized(
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Download the sanitized version of a file."""
    file_record = db.query(models.FileRecord).filter(models.FileRecord.id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    if not file_record.sanitized_path or not os.path.exists(file_record.sanitized_path):
        raise HTTPException(status_code=404, detail="Sanitized file not available")

    # Verify file integrity
    if file_record.file_hash:
        current_hash = compute_file_hash(file_record.original_path)
        if current_hash != file_record.file_hash:
            raise HTTPException(
                status_code=500,
                detail="File integrity check failed — file may have been tampered with",
            )

    log_action(db, current_user.id, "download", "file", file_id, ip_address=_client_ip(request))
    db.commit()

    return FileResponse(
        path=file_record.sanitized_path,
        filename=f"sanitized_{file_record.original_filename}",
        media_type="application/octet-stream",
    )


# ── Compliance Report ─────────────────────────────────────────

@router.get("/report/{file_id}", response_model=schemas.ComplianceReportOut)
def get_report(
    file_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Get compliance report for a file."""
    report = db.query(models.ComplianceReport).filter(
        models.ComplianceReport.file_id == file_id,
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return schemas.ComplianceReportOut(
        id=report.id,
        file_id=report.file_id,
        total_pii_found=report.total_pii_found,
        pii_breakdown=json.loads(report.pii_breakdown) if report.pii_breakdown else {},
        risk_score=report.risk_score,
        compliance_status=report.compliance_status,
        created_at=report.created_at,
    )


# ── Token Reversal (Admin) ───────────────────────────────────

@router.post("/reverse/{file_id}", response_model=schemas.ReverseTokenResponse)
def reverse_tokens(
    file_id: int,
    request: Request,
    req: schemas.ReverseTokenRequest = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    """Reverse token mappings to recover original data (admin only)."""
    file_record = db.query(models.FileRecord).filter(models.FileRecord.id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    token_filter = req.tokens if req and req.tokens else None
    mappings = tokenizer.reverse_tokens(file_id, db, token_filter)

    if not mappings:
        raise HTTPException(status_code=404, detail="No token mappings found")

    log_action(
        db, current_user.id, "reverse_tokens", "file", file_id,
        details={"tokens_reversed": len(mappings)},
        ip_address=_client_ip(request),
    )
    db.commit()

    return schemas.ReverseTokenResponse(mappings=mappings)


# ── Token Vault (Admin) ──────────────────────────────────────

@router.get("/vault/{file_id}", response_model=list[schemas.TokenMappingOut])
def get_vault(
    file_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    """View token vault entries for a file (admin only)."""
    tokens = db.query(models.TokenMapping).filter(
        models.TokenMapping.file_id == file_id,
    ).all()

    log_action(db, current_user.id, "vault_access", "file", file_id, ip_address=_client_ip(request))
    db.commit()

    return tokens


# ── Dashboard Stats ───────────────────────────────────────────

@router.get("/stats", response_model=schemas.DashboardStats)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Get dashboard statistics."""
    total_files = db.query(models.FileRecord).count()
    processed = db.query(models.FileRecord).filter(
        models.FileRecord.status == models.FileStatus.COMPLETED,
    ).count()

    reports = db.query(models.ComplianceReport).all()
    total_pii = sum(r.total_pii_found for r in reports)
    avg_risk = sum(r.risk_score for r in reports) / len(reports) if reports else 0.0

    return schemas.DashboardStats(
        total_files=total_files,
        files_processed=processed,
        total_pii_found=total_pii,
        avg_risk_score=round(avg_risk, 2),
    )


# ── Audit Logs (Admin) ───────────────────────────────────────

@router.get("/audit-logs", response_model=list[schemas.AuditLogOut])
def get_audit_logs(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    """Get all audit log entries (admin only)."""
    logs = (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.created_at.desc())
        .limit(500)
        .all()
    )
    results = []
    for log_entry in logs:
        user = db.query(models.User).filter(models.User.id == log_entry.user_id).first()
        results.append(schemas.AuditLogOut(
            id=log_entry.id,
            user_id=log_entry.user_id,
            user_email=user.email if user else "unknown",
            action=log_entry.action,
            resource_type=log_entry.resource_type,
            resource_id=log_entry.resource_id,
            details=log_entry.details,
            ip_address=log_entry.ip_address,
            created_at=log_entry.created_at,
        ))
    return results
