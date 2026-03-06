# CipherMask – Backend Architecture & Flow Documentation

## 1. System Overview
The CipherMask backend is a robust FastAPI application serving as a DPDPA-compliant PII Masking Engine. It acts as the core processor for orchestrating the extraction, contextual detection, risk scoring, encryption/tokenization, and masking of Personally Identifiable Information (PII) across multiple file formats. The application relies on an SQLite database (capable of transitioning to any SQLAlchemy-supported DB) to store user roles, file processing states, compliance reports, secure token vaults, and immutable audit logs. It runs completely offline on CPU seamlessly complying with security standards.

## 2. Directory & Module Structure
- `main.py`: The FastAPI entry point. Bootstraps the application, handles database initialization via lifespan events, configures CORS for the Next.js frontend, serves static files (`/uploads` and `/sanitized`), and registers `auth` and `files` routers.
- `config.py`: Centralized configuration management using `python-dotenv`. Manages environment limits, AES keys, JWT secrets, and defines the constants such as supported file types (`.csv`, `.json`, `.sql`, `.pdf`, `.docx`, `.doc`).
- `database.py`: Establishes the SQLAlchemy engine and provides the `get_db` dependency for database sessions.
- `models.py`: Contains the SQLAlchemy ORM models outlining the database schema.
- `schemas.py`: Contains Pydantic models for request/response validation.
- `routers/`:
  - `auth.py`: Authentication endpoints (Register, Login, Me).
  - `files.py`: All file processing endpoints, vault access, reverse token, dashboard statistics, and audit logs.
- `services/`:
  - `pipeline.py`: Orchestrates the masking flow end-to-end. Includes the `compute_risk_score` function to rate files for DPDPA compliance.
  - `pii_detector.py`: A highly specialized 3-layer contextual PII detection engine processing Indian PII formats.
  - `tokenizer.py`: Replaces detected PII values with prefix-based alphanumeric tokens and vault storage.
  - `masker.py`: Restructures and safely writes the tokenized data out to original file formats without corrupting layouts.
  - `file_processor.py`: Responsible for deeply parsing heterogeneous file types for NLP analysis.
  - `audit.py`: Logs comprehensive and immutable user activity tracking along with file integrity checks.
- `utils/`:
  - `encryption.py`: AES-256-CBC engine ensuring original values are encrypted before resting in the DB vault.
  - `security.py`: JWT utilities and password hashing.

## 3. Core Database Models (`models.py`)
1. **User (`users`)**: Fields include `id`, `email`, `name`, `password_hash`, `role` (`admin`/`user`), `created_at`.
2. **FileRecord (`files`)**: Tracks each uploaded file. Fields: `original_filename`, `stored_filename`, `file_type`, `original_path`, `sanitized_path`, `file_hash` (SHA-256 for integrity validation), `status` (UPLOADED, PROCESSING, COMPLETED, FAILED), `uploaded_by`.
3. **TokenMapping (`token_mappings`)**: Represents the Secure Token Vault. Fields: `token` (e.g., `PERSON_A12F9`), `encrypted_original` (AES-256 encrypted original PII), `pii_type`, `file_id`.
4. **ComplianceReport (`compliance_reports`)**: Details DPDPA compliance metrics. Fields: `total_pii_found`, `pii_breakdown` (JSON of PII counts per type), `risk_score` (Float 0.0 - 10.0), `compliance_status`.
5. **AuditLog (`audit_logs`)**: Immutable logging structure. Fields: `user_id`, `action`, `resource_type`, `resource_id`, `details` (JSON context), `ip_address`.

## 4. In-Depth Feature Architecture & Flows

### A. Authentication & Authorization
- **Implementation:** Custom bearer token strategy leveraging JSON Web Tokens (JWT).
- **Registration Flow:** Users can register via `POST /api/auth/register`. The system always creates them as standard `USER`s by default to prevent privilege escalation. Passwords are comprehensively hashed before storage.
- **Login Flow:** Users login via `POST /api/auth/login`. On yielding a correct signature, a JWT is provisioned packing the User's ID and Role.
- **Admin Setup:** Admin roles are only provisioned via command-line execution (`create_admin.py`) assuring absolute internal security segregation.
- **Security Check:** API endpoints enforce limits. Many routers such as vault access, uploads, masking initiation, and total audit log viewing utilize the `require_admin` dependency restricting access strictly to Admin accounts. Standard users can only download logic output and view their compliance dashboard.

### B. Uploads & File Management
- **Flow:** Admin submits a file -> `POST /api/upload`.
- **Steps:**
  1. The API checks if the file matches the subset in `settings.ALLOWED_EXTENSIONS`.
  2. The file is temporarily allocated a UUID hex name to deter enumeration capabilities.
  3. The file is written chunk-by-chunk to the local `uploads` directory.
  4. An SHA-256 file signature (`file_hash`) is generated to monitor tamper resistance.
  5. The model `FileRecord` instantiates with a status of `UPLOADED`.
  6. The `upload` action is deeply documented inside `AuditLog` alongside the file hash and executor IP address.
- **Verification/Listing:** Users can pull all file context histories over `GET /api/files`.

### C. Processing & Masking Pipeline (The Core Engine)
- **Flow:** Admin hits `POST /api/mask/{file_id}` -> Transfers to `pipeline.py:run_masking_pipeline`.
- **Steps:**
  1. **Text Extraction (`file_processor.py`)**: Based on file typology format readers extract out the NLP-ready pure text strings.
  2. **Detection Layer (`pii_detector.py`)**: 
     - *Layer 1:* Regex expressions identify tightly coupled formats (Indian Phone Numbers, AADHAAR, PAN, Voter ID, Bank Accts, IFSC, UPI IDs).
     - *Layer 2:* `spaCy` NER classifies loosely formatted variants like generic `PERSON_NAME` and `ADDRESS`, intentionally avoiding geographic exclusions (e.g., ignoring country labels).
     - *Structured Filtering:* Automatically snipes headers explicitly tagged as PII fields (e.g., matching a CSV header named `address`).
     - *Layer 3:* Contextual matching logic prevents false positives by scanning surrounding windows (120 chars) forcing unstructured ambiguous data (like 9 random digits) to be prefixed or postfixed with a descriptive noun (e.g. `phone`, `account`).
     - *Deduplication:* Overlapping spans are resolved favoring highest span bandwidth.
  3. **Risk Scoring (`pipeline.py:compute_risk_score`)**:
     - Calculates a severity ceiling based on high/medium/low risk presences. High risks (Aadhaar, PAN) score 8.0 natively, while low risks score 2.0.
     - Adds a "Diversity Bonus" depending on cross-variety coverage of collected PII types.
     - Adds a "Volume Bonus", a log-scale calculation proportional to absolute hit detection totals.
     - Evaluates a status bound ranging from `compliant` up to `critical`.
  4. **Tokenization Vault Engine (`tokenizer.py`)**:
     - Binds each PII entity to a mapped UUID representation suffixing the type (`PHONE_AB34C`, `AADHAAR_91ACD`).
     - Encrypts via `AES-256-CBC` the actual PII text and preserves securely onto `token_mappings`.
  5. **Sanitization Generation (`masker.py`)**:
     - Routes parsed mapped replacements against CSV formats using mapping logic, deep JSON recursive substitutions, layout-preserving DOCX text runs rewrites, Regex substitutions inside raw SQL strings, and complex PDF localized rewrites wrapping `PyMuPDF (fitz)`.
     - Output is directed toward the `sanitized_dir/sanitized_{uuid}.{ext}`.
  6. **Reporting (`pipeline.py`)**:
     - Status updates are committed seamlessly shifting logic gates from `PROCESSING` -> `COMPLETED`.
     - Compliance calculations form a unified entry inside the `ComplianceReport` dataset linked inherently to the target file.
     - Exhaustive `mask` `AuditLog` generated denoting exactly what amount and what severity level entities were processed.

### D. Reporting & Token Reversal Engine
- **Report Generation (`GET /api/report/{file_id}`)**: Delivers the PII breakdown metadata for dashboard rendering to the clientside.
- **Vault Retrieval (`GET /api/vault/{file_id}`)**: (Admin-only) Queries all tokens directly correlating with an asset, bypassing general viewing restrictions.
- **Reversal Flow (`POST /api/reverse/{file_id}`)**: (Admin-only) Utilizing the exact token ID sequences and utilizing the unified `.env` key space, standardizes the `utils.encryption.decrypt_value()` against requested assets enabling total dynamic reversion. Perfect for legal or administrative investigations needing unredacted access.

### E. File Deliverables & Auditing
- **Downloads (`GET /api/files/{id}/download`)**: Standard retrieval endpoint. Critically, checks real-time filesystem SHA256 hashes against original uploads to determine tampering validity. Will refuse download rendering on compromise.
- **Dashboard Metrics (`GET /api/stats`)**: Yields platform-wide analytics for rendering in Next.js (Total files, averages risk score, aggregate PII found).
- **Audit Logging (`GET /api/audit-logs`)**: Streams out massive payloads containing exact timeline sequences on `register`, `login`, `upload`, `mask`, `vault_access`, and `download` tracing exact user associations and granular metadata schemas protecting accountability.

## 5. Security Summary
- Complete Air-Gapped / Offline execution capability.
- Segregated Database privileges. Default routes guarantee unauthenticated actors receive absolutely zero context.
- AES-256-CBC cryptographic securing ensuring no database dump presents plaintext unredacted Indian PII assets. File system integrity actively checked before output deliveries preventing backdoors. All queries actively trace specific client bounds protecting IP spoofings natively inside `routers`.
