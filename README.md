# CipherMask 🛡️

**A robust, DPDPA-compliant PII (Personally Identifiable Information) Masking Engine designed for secure, offline, and contextual data sanitization.**

CipherMask provides an end-to-end pipeline to extract, contextually detect, assess risk, tokenize, and mask sensitive information across multiple file formats (CSV, JSON, SQL, PDF, DOCX). Built with a focus on the Indian Digital Personal Data Protection Act (DPDPA), it handles Indian PII formats with high precision using a multi-layered NLP and regex detection engine, backed by AES-256-CBC encryption for secure token vaults.

---

## 🌟 Key Features

### Core Masking Engine
- **Multi-layered PII Detection**:
  - **Layer 1**: Regex targeting tight formats (Indian Phone Numbers, AADHAAR, PAN, Voter ID, Bank Accounts, IFSC, UPI IDs).
  - **Layer 2**: spaCy NER for classifying generic formats (PERSON_NAME, ADDRESS).
  - **Layer 3**: Semantic contextual matching (120-char window) to prevent false positives for ambiguous numeric payloads.
- **Heterogeneous File Support**: Process `.csv`, `.json`, `.sql`, `.pdf`, and `.docx` recursively without corrupting native document layouts.
- **Risk Scoring Algorithm**: Generates automated compliance metrics mapping severity based on volume, variety, and presence of critical assets (e.g., AADHAAR scores 8.0 out of the gate).

### Security & Compliance
- **Secure Token Vault**: Detected PII isn't just masked; it's symmetrically encrypted (AES-256-CBC) and securely mapped to alphanumeric tokens (e.g., `AADHAAR_91ACD`) for authorized reversibility.
- **Air-Gapped & Offline Execution**: The entire system, including ML models, runs completely offline on the CPU, guaranteeing zero data leakage to third-party endpoints.
- **Immutable Audit Logging**: Every system action—registration, logins, file uploads, mask executions, vault accesses, and dataset downloads—is cryptographically hashed via SHA-256 and stored strictly to enforce absolute non-repudiation.

### Platform Usability
- **Role-Based Access Control (RBAC)**: Segregated privileges. Standard users can monitor dashboards and download outputs. Admins control file ingestion, pipeline trigger logic, and token decryption operations.
- **Highly Reactive Dashboard**: Deep Next.js UI leveraging Tailwind CSS v4 and glassmorphism logic for real-time statistical insight.
- **Tamper-Evident Downloads**: Real-time filesystem hash verification prevents the distribution of compromised deliverables.

---

## 🏗️ Architecture & Tech Stack

CipherMask operates on a decoupled client-server model:

### Backend (Python/FastAPI)
- **Framework**: FastAPI
- **Database**: SQLite (SQLAlchemy ORM ready for PostgreSQL/MySQL drop-ins)
- **Core ML/NLP**: spaCy, regex, PyMuPDF (fitz) for PDF localized sanitization.
- **Security**: JWT Authentication, AES-256-CBC Encryption, bcrypt password hashing.

### Frontend (Next.js/React)
- **Framework**: Next.js 16 (App Router), React 19
- **Styling**: Tailwind CSS v4
- **State/Auth**: Standard React Context (`AuthProvider`) wrapping local storage JWT strategies.

---

## 📁 Project Structure

```text
Nirma_Hackathon/
├── backend/                  # FastAPI Application Core
│   ├── main.py               # Entry point, CORS, routers initialization
│   ├── config.py             # Environment variables & constants
│   ├── database.py           # SQLAlchemy configuration
│   ├── models.py             # SQLite ORM models (User, FileRecord, TokenMapping, AuditLog)
│   ├── schemas.py            # Pydantic validation schemas
│   ├── routers/              # Auth & File logic endpoints
│   ├── services/             # Core Engine (PiiDetector, Masker, Tokenizer, RiskScoring)
│   └── utils/                # Crypto & JWT toolsets
├── frontend/                 # Next.js Application
│   ├── package.json          # Dependencies & Scripts
│   ├── src/
│   │   ├── app/              # App Router Pages (Dashboard, Upload, Vault, Audit)
│   │   ├── components/       # Reusable UI (Navbar, ProtectedRoute, RiskBadge)
│   │   └── lib/              # API Client (fetch wrappers) & Auth Context
├── backend.md                # Detailed Backend Architecture Documentation
└── frontend.md               # Detailed Frontend Architecture Documentation
```

---

## 🚀 Getting Started

### Prerequisites
- Node.js (v18+)
- Python (3.11+)

### 1. Setting Up the Backend
```bash
cd backend

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure Environment Variables
# Create a .env file referring to the project configuration (AES keys, JWT secrets)

# Run the FastAPI server
uvicorn main:app --reload --port 8000
```

### 2. Setting Up the Frontend
```bash
cd frontend

# Install dependencies
npm install

# Run the Next.js development server
npm run dev
```

The frontend will be accessible at `http://localhost:3000` and the backend API at `http://localhost:8000`.

---

## 📖 Usage Flow

1. **Authentication:** Register an account. The first admin account usually needs to be provisioned via backend command-line scripts (`create_admin.py`).
2. **Uploading Data:** (Admin) Navigate to `/upload` to drop in sensitive documents.
3. **Trigger Pipeline:** Enter the file view and run the masking engine. The system extracts text, intercepts PII, calculates risk, and writes the sanitized output.
4. **Compliance Checking:** Review the generated dynamic report detailing exactly what formats were found and their severity metrics.
5. **Secure Reversal:** (Admin) Within the Vault route, authenticate to decrypt the vault mappings and recover exact text values from their token representations.
6. **Audit Monitoring:** (Admin) Utilize the Audit Logs screen to view every transactional footprint natively across the system.

---

## 📝 Compliance
Developed explicitly for Indian Data Localization and the Digital Personal Data Protection Act (DPDPA), ensuring zero third-party data transit and strict handling of generalized financial and telecommunications assets.
