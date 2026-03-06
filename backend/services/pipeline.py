"""
Processing Pipeline Orchestrator
Coordinates the full PII masking pipeline as specified in the DPDPA design:

  File Upload
  → File Type Detection
  → File Parsing Layer
  → Text/Data Extraction
  → Contextual PII Detection Engine
  → Risk Scoring
  → Tokenization Engine
  → Secure Token Vault Storage
  → Sanitized File Generation
  → Download API
"""
import json
import math
import os
import shutil
import logging
from collections import Counter
from sqlalchemy.orm import Session

from config import settings
from services.file_processor import extract_text_from_file
from services.pii_detector import pii_detector
from services.tokenizer import tokenizer
from services.masker import mask_file
import models

logger = logging.getLogger(__name__)

# PII risk classification for DPDPA compliance scoring
HIGH_RISK_TYPES = {"AADHAAR", "PAN", "PASSPORT", "BANK_ACCOUNT", "VOTER_ID", "IFSC"}
MEDIUM_RISK_TYPES = {"PHONE_NUMBER", "EMAIL_ADDRESS", "UPI_ID"}
LOW_RISK_TYPES = {"PERSON_NAME", "ADDRESS"}


def compute_risk_score(detections: list) -> float:
    """
    Compute a risk score (0.0 – 10.0) using a presence-based model.

    Three components:
      1. Severity ceiling (0-8): based on the HIGHEST risk class present
         - High-risk PII (Aadhaar, PAN, Passport, Bank, Voter ID, IFSC) → 8.0
         - Medium-risk PII (Phone, Email, UPI) → 5.0
         - Low-risk PII (Name, Address) → 2.0

      2. Diversity bonus (0-1.0): fraction of distinct PII types found
         More different PII types = broader exposure = higher risk

      3. Volume bonus (0-1.0): log-scaled count of total PII items
         More PII items (more individuals) = larger breach impact

    Final = severity + diversity_bonus + volume_bonus  (capped at 10.0)
    """
    if not detections:
        return 0.0

    total = len(detections)
    type_counts = Counter(d.pii_type for d in detections)
    unique_types = len(type_counts)

    high_count = sum(c for t, c in type_counts.items() if t in HIGH_RISK_TYPES)
    medium_count = sum(c for t, c in type_counts.items() if t in MEDIUM_RISK_TYPES)

    # 1. Severity ceiling from worst PII class present
    if high_count > 0:
        base = 8.0
    elif medium_count > 0:
        base = 5.0
    else:
        base = 2.0

    # 2. Diversity bonus: more PII types → broader exposure
    diversity = min(unique_types / 8.0, 1.0)

    # 3. Volume bonus: log-scaled total detections (saturates around 1000)
    volume = min(math.log10(total + 1) / 3.0, 1.0)

    score = base + diversity + volume
    return min(round(score, 1), 10.0)


def determine_compliance_status(risk_score: float, total_pii: int) -> str:
    """
    Map risk score to DPDPA compliance status.

    - compliant:   No PII found → file is safe as-is
    - low_risk:    Only names/addresses (score ≤ 4)
    - medium_risk: Contact info present (score ≤ 7)
    - high_risk:   Sensitive IDs like Aadhaar/PAN/Bank (score ≤ 9)
    - critical:    High-risk PII at scale (score > 9)
    """
    if total_pii == 0:
        return "compliant"
    if risk_score > 9:
        return "critical"
    if risk_score > 7:
        return "high_risk"
    if risk_score > 4:
        return "medium_risk"
    return "low_risk"


def run_masking_pipeline(file_record: models.FileRecord, db: Session) -> dict:
    """
    Execute the full PII detection → tokenization → masking pipeline.

    Steps:
    1. Extract text from file (format-aware)
    2. Run contextual PII detection
    3. Score risk level
    4. Tokenize detected PII and store in encrypted vault
    5. Generate sanitized file in original format
    6. Create compliance report

    Returns: dict with pipeline results (total_pii, breakdown, risk_score, status)
    """
    # Step 1: Text extraction
    text = extract_text_from_file(file_record.original_path, file_record.file_type)

    # Step 2: PII detection
    detections = pii_detector.detect(text)

    # Step 3: Risk scoring
    risk_score = compute_risk_score(detections)
    pii_types = [d.pii_type for d in detections]
    breakdown = dict(Counter(pii_types))
    total = len(detections)

    # Step 4: Tokenization + vault storage
    sanitized_name = f"sanitized_{file_record.stored_filename}"
    sanitized_path = os.path.join(settings.SANITIZED_DIR, sanitized_name)

    if detections:
        mapping = tokenizer.tokenize_and_store(detections, file_record.id, db)

        # Step 5: Generate sanitized file
        mask_file(
            file_record.original_path, file_record.file_type,
            mapping, sanitized_path,
        )
    else:
        # No PII found – copy original as sanitized
        shutil.copy2(file_record.original_path, sanitized_path)

    file_record.sanitized_path = sanitized_path

    # Step 6: Compliance report
    compliance_status = determine_compliance_status(risk_score, total)

    report = models.ComplianceReport(
        file_id=file_record.id,
        total_pii_found=total,
        pii_breakdown=json.dumps(breakdown),
        risk_score=risk_score,
        compliance_status=compliance_status,
    )
    db.add(report)

    file_record.status = models.FileStatus.COMPLETED
    db.flush()

    return {
        "total_pii_found": total,
        "pii_breakdown": breakdown,
        "risk_score": risk_score,
        "compliance_status": compliance_status,
    }
