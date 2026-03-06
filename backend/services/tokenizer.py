"""
Tokenization Engine
Generates replacement tokens (e.g. PERSON_A12F9, PHONE_92KD1) and stores
AES-256 encrypted originals in the secure token vault.

Pipeline step: PII Detections → Token Generation → Vault Storage
"""
import secrets
from typing import Dict, List
from sqlalchemy.orm import Session
from utils.encryption import encrypt_value, decrypt_value
import models

# Map PII types to shorter token prefixes
_PREFIX_MAP = {
    "PERSON_NAME": "PERSON",
    "PHONE_NUMBER": "PHONE",
    "EMAIL_ADDRESS": "EMAIL",
    "AADHAAR": "AADHAAR",
    "PAN": "PAN",
    "BANK_ACCOUNT": "BANK",
    "ADDRESS": "ADDR",
    "PASSPORT": "PASSPORT",
    "IFSC": "IFSC",
    "UPI_ID": "UPI",
    "VOTER_ID": "VOTER",
}


class Tokenizer:
    """Generates tokens in PREFIX_XXXXX format with unique alphanumeric IDs."""

    def __init__(self):
        self._used_ids: set = set()

    def reset(self):
        self._used_ids.clear()

    def generate_token(self, pii_type: str) -> str:
        """Generate a token like PERSON_A12F9, PHONE_92KD1."""
        prefix = _PREFIX_MAP.get(pii_type, pii_type)
        while True:
            suffix = secrets.token_hex(3)[:5].upper()
            token = f"{prefix}_{suffix}"
            if token not in self._used_ids:
                self._used_ids.add(token)
                return token

    def tokenize_and_store(
        self,
        detections: list,
        file_id: int,
        db: Session,
    ) -> Dict[str, str]:
        """
        For each PII detection, generate a token, encrypt the original,
        and store the mapping in the database vault.

        Returns: dict mapping original_text → token
        """
        self.reset()
        mapping: Dict[str, str] = {}
        seen_texts: Dict[str, str] = {}

        for det in detections:
            original_text = det.text

            # Re-use token for duplicate values
            if original_text in seen_texts:
                mapping[original_text] = seen_texts[original_text]
                continue

            token = self.generate_token(det.pii_type)
            encrypted = encrypt_value(original_text)

            token_record = models.TokenMapping(
                token=token,
                encrypted_original=encrypted,
                pii_type=det.pii_type,
                file_id=file_id,
            )
            db.add(token_record)

            mapping[original_text] = token
            seen_texts[original_text] = token

        db.flush()
        return mapping

    @staticmethod
    def reverse_tokens(
        file_id: int, db: Session, token_filter: list = None,
    ) -> Dict[str, str]:
        """
        Reverse token mappings for a file.
        Returns: dict mapping token → original_value (decrypted)
        """
        query = db.query(models.TokenMapping).filter(
            models.TokenMapping.file_id == file_id,
        )
        if token_filter:
            query = query.filter(models.TokenMapping.token.in_(token_filter))

        result = {}
        for record in query.all():
            try:
                original = decrypt_value(record.encrypted_original)
                result[record.token] = original
            except Exception:
                result[record.token] = "[DECRYPTION_ERROR]"

        return result


tokenizer = Tokenizer()
