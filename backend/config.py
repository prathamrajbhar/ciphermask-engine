"""
CipherMask – Configuration
Central settings for the DPDPA PII Masking Engine.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    PROJECT_NAME: str = "CipherMask"
    VERSION: str = "2.0.0"
    DESCRIPTION: str = "Context-Aware PII Masking Engine – DPDPA Compliant"

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./ciphermask.db")

    # JWT
    JWT_SECRET: str = os.getenv("JWT_SECRET", "ciphermask-super-secret-key-change-in-production")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 60 * 24  # 24 hours

    # AES-256 Encryption key (must be 32 hex chars = 16 bytes, or 64 hex chars = 32 bytes)
    AES_KEY: str = os.getenv("AES_KEY", "0123456789abcdef0123456789abcdef")

    # File paths
    UPLOAD_DIR: str = os.path.join(os.path.dirname(__file__), "uploads")
    SANITIZED_DIR: str = os.path.join(os.path.dirname(__file__), "sanitized")

    # Supported file formats per DPDPA requirements
    ALLOWED_EXTENSIONS: set = {".csv", ".json", ".sql", ".pdf", ".docx", ".doc"}

    # PII Detection confidence threshold
    PII_CONFIDENCE_THRESHOLD: float = float(os.getenv("PII_CONFIDENCE_THRESHOLD", "0.6"))

    # Hugging Face Token (for NER models)
    HF_TOKEN: str = os.getenv("HF_TOKEN", "")


settings = Settings()

# Ensure directories exist
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.SANITIZED_DIR, exist_ok=True)
