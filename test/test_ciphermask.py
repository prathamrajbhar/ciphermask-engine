"""
CipherMask – Comprehensive Test Suite
Tests PII detection, API endpoints, encryption, masking, and full pipeline.

Run from repo root:
    python test/test_ciphermask.py

Or start the backend first for end-to-end API tests:
    cd backend && uvicorn main:app --host 0.0.0.0 --port 8000 &
    python test/test_ciphermask.py --api
"""
import sys
import os
import json
import csv
import tempfile
import time
import argparse
import textwrap

# ── Add backend to path ───────────────────────────────────────────────────────
BACKEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
sys.path.insert(0, BACKEND_DIR)

PASS = "\033[92m✓ PASS\033[0m"
FAIL = "\033[91m✗ FAIL\033[0m"
WARN = "\033[93m⚠ WARN\033[0m"
HEAD = "\033[94m"
ENDC = "\033[0m"

RESULTS = {"passed": 0, "failed": 0, "warnings": 0}


def report(name: str, ok: bool, detail: str = ""):
    status = PASS if ok else FAIL
    suffix = f"  ({detail})" if detail else ""
    print(f"  {status}  {name}{suffix}")
    if ok:
        RESULTS["passed"] += 1
    else:
        RESULTS["failed"] += 1


def section(title: str):
    print(f"\n{HEAD}{'─' * 60}{ENDC}")
    print(f"{HEAD}  {title}{ENDC}")
    print(f"{HEAD}{'─' * 60}{ENDC}")


# ─────────────────────────────────────────────────────────────────────────────
# 1. UNIT TESTS: Encryption / Decryption
# ─────────────────────────────────────────────────────────────────────────────
def test_encryption():
    section("Encryption / Decryption")
    from utils.encryption import encrypt_value, decrypt_value

    # Basic round-trip
    for val in ["test@example.com", "9876543210", "ABCDE1234F", "1234 5678 9012"]:
        enc = encrypt_value(val)
        dec = decrypt_value(enc)
        report(f"Round-trip: {val!r}", dec == val, f"got {dec!r}" if dec != val else "")

    # Different plaintext → different ciphertext (due to random IV)
    e1 = encrypt_value("same")
    e2 = encrypt_value("same")
    report("Random IV (different ciphertexts per call)", e1 != e2)

    # Decryption of tampered ciphertext raises exception
    import base64
    try:
        bad_data = base64.b64encode(b"\x00" * 48).decode()
        decrypt_value(bad_data)
        report("Tampered ciphertext raises error", False, "expected exception")
    except Exception:
        report("Tampered ciphertext raises error", True)


# ─────────────────────────────────────────────────────────────────────────────
# 2. UNIT TESTS: JWT / Auth utilities
# ─────────────────────────────────────────────────────────────────────────────
def test_auth_utils():
    section("Auth Utilities (JWT + bcrypt)")
    from utils.security import hash_password, verify_password, create_access_token, decode_token

    # Password hashing
    pw = "SecurePass123!"
    hashed = hash_password(pw)
    report("Password hash is different from plaintext", hashed != pw)
    report("Verify correct password", verify_password(pw, hashed))
    report("Reject wrong password", not verify_password("wrong", hashed))

    # JWT
    payload = {"sub": "42", "role": "admin"}
    token = create_access_token(payload)
    decoded = decode_token(token)
    report("JWT sub matches", decoded["sub"] == "42")
    report("JWT role matches", decoded["role"] == "admin")

    # Expired token
    from datetime import timedelta
    from utils.security import create_access_token as cat
    from fastapi import HTTPException
    short_token = cat(payload, expires_delta=timedelta(seconds=-1))
    try:
        decode_token(short_token)
        report("Expired token rejected", False, "expected HTTPException")
    except HTTPException:
        report("Expired token rejected", True)


# ─────────────────────────────────────────────────────────────────────────────
# 3. UNIT TESTS: PII Detector (fast, model-cached)
# ─────────────────────────────────────────────────────────────────────────────
def test_pii_detector():
    section("PII Detector – Core Detection")
    from services.pii_detector import pii_detector

    def detect(text):
        return pii_detector.detect(text)

    def types(matches):
        return [m.pii_type for m in matches]

    def has_type(matches, t):
        return t in types(matches)

    def no_duplicates(matches):
        seen = set()
        for m in matches:
            key = (m.start, m.end, m.pii_type)
            if key in seen:
                return False
            seen.add(key)
        return True

    # ── Regex detections ─────────────────────────────────────────────────────
    m = detect("Aadhaar: 1234 5678 9012")
    report("Aadhaar detected", has_type(m, "AADHAAR"))
    report("No duplicate Aadhaar", no_duplicates(m))

    m = detect("PAN card: ABCDE1234F")
    report("PAN detected", has_type(m, "PAN"))

    m = detect("Mobile: 9876543210")
    report("Phone detected (with keyword)", has_type(m, "PHONE_NUMBER"))

    m = detect("Contact ph: +919876543210")
    report("Phone detected (+91 prefix)", has_type(m, "PHONE_NUMBER"))

    m = detect("Bank account: 1234567890123456")
    report("Bank account detected", has_type(m, "BANK_ACCOUNT"))

    m = detect("Passport: Z1234567")
    report("Passport detected", has_type(m, "PASSPORT"))

    # ── Email detection ───────────────────────────────────────────────────────
    m = detect("Email: john.doe@company.com")
    report("Email detected", has_type(m, "EMAIL_ADDRESS"), str(types(m)))

    m = detect("Reach me at rahul.sharma@gmail.com")
    report("Email in sentence detected", has_type(m, "EMAIL_ADDRESS"), str(types(m)))

    # ── spaCy NER ─────────────────────────────────────────────────────────────
    m = detect("John Doe visited Mumbai")
    report("Person name detected (NER)", has_type(m, "PERSON_NAME"), str(types(m)))

    # ── False-positive tests ──────────────────────────────────────────────────
    m = detect("Random 9876543210")
    report("Random number without context not flagged", len(m) == 0,
           f"detected: {[(x.text, x.pii_type) for x in m]}")

    # ── No duplicate entries in results ──────────────────────────────────────
    m = detect("Contact: John Doe, phone: 9876543210, email: test@email.com")
    report("No duplicate detections in multi-PII text", no_duplicates(m))

    # ── Empty / whitespace input ──────────────────────────────────────────────
    report("Empty string returns empty list", detect("") == [])
    report("Whitespace-only returns empty list", detect("   \n\t  ") == [])


# ─────────────────────────────────────────────────────────────────────────────
# 4. UNIT TESTS: File Processor
# ─────────────────────────────────────────────────────────────────────────────
def test_file_processor():
    section("File Processor – Text Extraction")
    from services.file_processor import extract_text_from_file

    with tempfile.TemporaryDirectory() as tmpdir:
        # CSV
        csv_path = os.path.join(tmpdir, "test.csv")
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["name", "email", "phone"])
            writer.writeheader()
            writer.writerow({"name": "John Doe", "email": "john@test.com", "phone": "9876543210"})
        text = extract_text_from_file(csv_path, "csv")
        report("CSV extracted to text", "john@test.com" in text)
        report("CSV preserves column context", "email:" in text.lower() or "email" in text.lower())

        # JSON
        json_path = os.path.join(tmpdir, "test.json")
        data = {"name": "Rahul", "aadhaar": "1234 5678 9012", "phone": "9876543210"}
        with open(json_path, "w") as f:
            json.dump(data, f)
        text = extract_text_from_file(json_path, "json")
        report("JSON extracted to text", "1234 5678 9012" in text)

        # SQL
        sql_path = os.path.join(tmpdir, "test.sql")
        with open(sql_path, "w") as f:
            f.write("INSERT INTO users VALUES ('John Doe', 'john@test.com', '9876543210');")
        text = extract_text_from_file(sql_path, "sql")
        report("SQL extracted", "john@test.com" in text)


# ─────────────────────────────────────────────────────────────────────────────
# 5. UNIT TESTS: Masker
# ─────────────────────────────────────────────────────────────────────────────
def test_masker():
    section("Masker – PII Replacement")
    from services.masker import mask_text, mask_csv, mask_json

    mapping = {
        "john@test.com": "EMAIL_ADDRESS_001",
        "9876543210": "PHONE_NUMBER_001",
        "John Doe": "PERSON_NAME_001",
    }

    # Text masking
    original = "Name: John Doe, Email: john@test.com, Phone: 9876543210"
    masked = mask_text(original, mapping)
    report("Longest first (name replaced)", "PERSON_NAME_001" in masked)
    report("Email replaced", "EMAIL_ADDRESS_001" in masked)
    report("Phone replaced", "PHONE_NUMBER_001" in masked)
    report("No original PII in masked text", "john@test.com" not in masked and "John Doe" not in masked)

    with tempfile.TemporaryDirectory() as tmpdir:
        # CSV masking
        csv_in = os.path.join(tmpdir, "in.csv")
        csv_out = os.path.join(tmpdir, "out.csv")
        with open(csv_in, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["name", "email"])
            writer.writeheader()
            writer.writerow({"name": "John Doe", "email": "john@test.com"})
        mask_csv(csv_in, mapping, csv_out)
        with open(csv_out) as f:
            content = f.read()
        report("CSV masked correctly", "john@test.com" not in content and "EMAIL_ADDRESS_001" in content)

        # JSON masking
        json_in = os.path.join(tmpdir, "in.json")
        json_out = os.path.join(tmpdir, "out.json")
        with open(json_in, "w") as f:
            json.dump({"name": "John Doe", "email": "john@test.com"}, f)
        mask_json(json_in, mapping, json_out)
        with open(json_out) as f:
            out = json.load(f)
        report("JSON masked correctly", out["email"] == "EMAIL_ADDRESS_001")
        report("JSON name masked", out["name"] == "PERSON_NAME_001")


# ─────────────────────────────────────────────────────────────────────────────
# 6. INTEGRATION TEST: Full Pipeline (no HTTP, uses DB session directly)
# ─────────────────────────────────────────────────────────────────────────────
def test_full_pipeline():
    section("Full Pipeline – CSV with Indian PII data")
    import json as json_mod
    import shutil
    from database import SessionLocal, init_db, Base, engine
    from utils.security import hash_password
    from services.file_processor import extract_text_from_file
    from services.pii_detector import pii_detector
    from services.tokenizer import tokenizer
    from services.masker import mask_file
    import models

    # Fresh in-memory test DB
    from sqlalchemy import create_engine as ce
    from sqlalchemy.orm import sessionmaker
    test_engine = ce("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    TestSession = sessionmaker(bind=test_engine)
    db = TestSession()

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test CSV with Indian PII
        csv_path = os.path.join(tmpdir, "pii_test.csv")
        csv_data = [
            {"name": "Rahul Sharma", "aadhaar": "1234 5678 9012", "pan": "ABCDE1234F",
             "email": "rahul.sharma@example.com", "phone": "9876543210"},
            {"name": "Priya Singh", "aadhaar": "9876 5432 1098", "pan": "XYZAB5678G",
             "email": "priya.singh@test.org", "phone": "8765432109"},
        ]
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(csv_data[0].keys()))
            writer.writeheader()
            writer.writerows(csv_data)

        # Create a test user
        user = models.User(
            name="Test Admin",
            email="test_admin@ciphermask.test",
            password_hash=hash_password("testpass123"),
            role=models.UserRole.ADMIN,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Create file record
        file_record = models.FileRecord(
            original_filename="pii_test.csv",
            stored_filename="pii_test.csv",
            file_type="csv",
            original_path=csv_path,
            status=models.FileStatus.UPLOADED,
            uploaded_by=user.id,
        )
        db.add(file_record)
        db.commit()
        db.refresh(file_record)

        # Run pipeline
        text = extract_text_from_file(csv_path, "csv")
        report("Text extracted from CSV", len(text) > 0)

        detections = pii_detector.detect(text)
        det_types = [d.pii_type for d in detections]
        report("Aadhaar detected in CSV", "AADHAAR" in det_types, str(det_types))
        report("PAN detected in CSV", "PAN" in det_types, str(det_types))
        report("Email detected in CSV", "EMAIL_ADDRESS" in det_types, str(det_types))
        report("Phone detected in CSV", "PHONE_NUMBER" in det_types, str(det_types))
        report("At least 4 PII types detected", len(set(det_types)) >= 4, str(set(det_types)))

        # No duplicate matches
        seen = set()
        dups = []
        for d in detections:
            key = (d.start, d.end)
            if key in seen:
                dups.append(d.text)
            seen.add(key)
        report("No duplicate PII detections", len(dups) == 0, f"dupes: {dups}")

        if detections:
            mapping = tokenizer.tokenize_and_store(detections, file_record.id, db)
            report("Tokenizer generates mappings", len(mapping) > 0)

            # Each unique PII text maps to a token
            for orig, tok in mapping.items():
                report(f"Token format valid ({tok})", "_" in tok and tok.split("_")[-1].isdigit())
                break  # Just check one

            # Mask the file
            sanitized_path = os.path.join(tmpdir, "sanitized_pii_test.csv")
            mask_file(csv_path, "csv", mapping, sanitized_path)
            report("Sanitized file created", os.path.exists(sanitized_path))

            # Verify original PII is gone from sanitized file
            with open(sanitized_path) as f:
                content = f.read()
            report("Aadhaar not in sanitized CSV", "1234 5678 9012" not in content)
            report("PAN not in sanitized CSV", "ABCDE1234F" not in content)
            report("Email not in sanitized CSV", "rahul.sharma@example.com" not in content)
            report("Phone not in sanitized CSV", "9876543210" not in content)
            report("Token present in sanitized CSV", any(t in content for t in mapping.values()))

            # Verify token→original reversal via encryption
            from utils.encryption import decrypt_value
            tokens = db.query(models.TokenMapping).filter(
                models.TokenMapping.file_id == file_record.id
            ).all()
            report("Token mappings stored in DB", len(tokens) > 0)

            all_correct = True
            for t in tokens:
                try:
                    dec = decrypt_value(t.encrypted_original)
                    if dec not in mapping:
                        all_correct = False
                except Exception as e:
                    all_correct = False

            report("All token originals decrypt correctly", all_correct)

    db.close()


# ─────────────────────────────────────────────────────────────────────────────
# 7. INTEGRATION TEST: JSON file pipeline
# ─────────────────────────────────────────────────────────────────────────────
def test_json_pipeline():
    section("Full Pipeline – JSON with nested PII")
    from services.file_processor import extract_text_from_file
    from services.pii_detector import pii_detector
    from services.masker import mask_json

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "test.json")
        data = {
            "employees": [
                {
                    "name": "Vikram Nair",
                    "contact": {
                        "mobile": "9123456789",
                        "email": "vikram.nair@corp.com"
                    },
                    "aadhaar": "2345 6789 0123"
                }
            ]
        }
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)

        text = extract_text_from_file(json_path, "json")
        detections = pii_detector.detect(text)
        det_types = [d.pii_type for d in detections]

        report("JSON phone detected", "PHONE_NUMBER" in det_types, str(det_types))
        report("JSON email detected", "EMAIL_ADDRESS" in det_types, str(det_types))
        report("JSON Aadhaar detected", "AADHAAR" in det_types, str(det_types))

        if detections:
            mapping = {d.text: f"{d.pii_type}_001" for d in detections}
            out_path = os.path.join(tmpdir, "sanitized.json")
            mask_json(json_path, mapping, out_path)

            with open(out_path) as f:
                out = json.load(f)
            raw = json.dumps(out)
            report("JSON nested email masked", "vikram.nair@corp.com" not in raw)
            report("JSON nested phone masked", "9123456789" not in raw)


# ─────────────────────────────────────────────────────────────────────────────
# 8. API TESTS (optional, requires backend running on :8000)
# ─────────────────────────────────────────────────────────────────────────────
def test_api(base_url: str = "http://localhost:8000"):
    section(f"API End-to-End Tests  [{base_url}]")
    try:
        import requests
    except ImportError:
        print(f"  {WARN}  'requests' not installed, skipping API tests")
        return

    unique = str(int(time.time()))

    # Health check
    try:
        r = requests.get(f"{base_url}/health", timeout=5)
        report("Health endpoint responds", r.status_code == 200)
    except Exception as e:
        report("Backend reachable", False, str(e))
        print("  Skipping remaining API tests (backend not reachable)")
        return

    # Register admin (role no longer accepted via API, admin created via CLI)
    admin_email = f"admin_{unique}@test.com"
    r = requests.post(f"{base_url}/auth/register", json={
        "name": "Test Admin",
        "email": admin_email,
        "password": "TestPass123!",
    })
    report("User registration (201)", r.status_code == 201, f"status={r.status_code}")
    admin_token = r.json().get("access_token", "") if r.status_code == 201 else ""

    # Register second user
    user_email = f"user_{unique}@test.com"
    r = requests.post(f"{base_url}/auth/register", json={
        "name": "Test User",
        "email": user_email,
        "password": "UserPass456!",
    })
    report("User registration (201)", r.status_code == 201)
    user_token = r.json().get("access_token", "") if r.status_code == 201 else ""

    # Duplicate email rejection
    r = requests.post(f"{base_url}/auth/register", json={
        "name": "Dup",
        "email": admin_email,
        "password": "pass",
    })
    report("Duplicate email rejected (400)", r.status_code == 400)

    # Login
    r = requests.post(f"{base_url}/auth/login", json={
        "email": admin_email,
        "password": "TestPass123!"
    })
    report("Admin login (200)", r.status_code == 200)
    if r.status_code == 200:
        admin_token = r.json().get("access_token", admin_token)

    # Wrong credentials
    r = requests.post(f"{base_url}/auth/login", json={
        "email": admin_email, "password": "wrong"
    })
    report("Wrong credentials rejected (401)", r.status_code == 401)

    # /auth/me
    r = requests.get(f"{base_url}/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    report("/auth/me returns user", r.status_code == 200 and r.json()["email"] == admin_email)

    # Upload file (admin required)
    csv_content = textwrap.dedent("""\
        name,phone,email,aadhaar
        Rahul Sharma,9876543210,rahul@test.com,1234 5678 9012
        Priya Singh,8765432109,priya@test.com,9876 5432 1098
    """)
    if not admin_token:
        print(f"  {WARN}  Skipping upload/mask tests (no admin token)")
        return

    r = requests.post(
        f"{base_url}/api/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("test.csv", csv_content.encode(), "text/csv")},
    )
    report("File upload (201)", r.status_code == 201, f"status={r.status_code}, detail={r.text[:100] if r.status_code != 201 else ''}")
    file_id = r.json().get("id") if r.status_code == 201 else None

    # Upload rejected for regular user
    r = requests.post(
        f"{base_url}/api/upload",
        headers={"Authorization": f"Bearer {user_token}"},
        files={"file": ("test.csv", csv_content.encode(), "text/csv")},
    )
    report("Non-admin upload rejected (403)", r.status_code == 403)

    # List files
    r = requests.get(f"{base_url}/api/files", headers={"Authorization": f"Bearer {user_token}"})
    report("List files accessible to user", r.status_code == 200)

    # Mask file
    if file_id:
        r = requests.post(
            f"{base_url}/api/mask/{file_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        report("Mask file (200)", r.status_code == 200, f"status={r.status_code} detail={r.text[:200] if r.status_code != 200 else ''}")

        if r.status_code == 200:
            result = r.json()
            report("Mask result has total_pii_found", "total_pii_found" in result)
            report("PII found > 0", result.get("total_pii_found", 0) > 0,
                   f"found={result.get('total_pii_found')}")
            report("Risk score present", "risk_score" in result)
            report("Compliance status present", "compliance_status" in result)

            # Already processed → error
            r2 = requests.post(
                f"{base_url}/api/mask/{file_id}",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            report("Re-masking already processed file returns 400", r2.status_code == 400)

            # Download sanitized
            r = requests.get(
                f"{base_url}/api/files/{file_id}/download",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            report("Sanitized file download (200)", r.status_code == 200)
            if r.status_code == 200:
                content = r.content.decode()
                report("Sanitized CSV does not contain raw phone", "9876543210" not in content)
                report("Sanitized CSV does not contain raw email", "rahul@test.com" not in content)

            # Report
            r = requests.get(
                f"{base_url}/api/report/{file_id}",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            report("Compliance report retrieved (200)", r.status_code == 200)

            # Vault
            r = requests.get(
                f"{base_url}/api/vault/{file_id}",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            report("Vault retrieved (200)", r.status_code == 200)
            if r.status_code == 200:
                vault = r.json()
                report("Vault contains tokens", len(vault) > 0)
                report("No plaintext in vault response", all(
                    "encrypted_original" not in str(t) or t.get("encrypted_original") is None
                    for t in vault
                ))

            # Vault blocked for non-admin
            r = requests.get(
                f"{base_url}/api/vault/{file_id}",
                headers={"Authorization": f"Bearer {user_token}"},
            )
            report("Vault blocked for non-admin (403)", r.status_code == 403)

            # Reverse tokens
            r = requests.post(
                f"{base_url}/api/reverse/{file_id}",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"tokens": []},
            )
            report("Token reversal (200)", r.status_code == 200)
            if r.status_code == 200:
                mappings = r.json().get("mappings", {})
                report("Reversal returns non-empty mappings", len(mappings) > 0)
                # Check reversal returns real values
                all_vals = list(mappings.values())
                report("Reversed values contain original PII",
                       any(v in ["9876543210", "rahul@test.com", "1234 5678 9012"] for v in all_vals),
                       str(all_vals[:3]))

    # Dashboard stats
    r = requests.get(f"{base_url}/api/stats", headers={"Authorization": f"Bearer {admin_token}"})
    report("Dashboard stats (200)", r.status_code == 200)

    # Unauthenticated access blocked
    r = requests.get(f"{base_url}/api/files")
    report("Unauthenticated request rejected (403)", r.status_code in (401, 403))


# ─────────────────────────────────────────────────────────────────────────────
# 9. REAL FILE TESTS: Actual files in test/ folder
# ─────────────────────────────────────────────────────────────────────────────
def test_real_files():
    section("Real File Tests – Actual Test Data Files")
    from services.file_processor import extract_text_from_file
    from services.pii_detector import pii_detector
    from services.masker import mask_file

    TEST_DIR = os.path.dirname(os.path.abspath(__file__))

    def _run_single(filename, file_type, expected_types=None, check_masked=None):
        """
        Extract → detect → mask one file.
        expected_types: list of PII type strings that MUST be found.
        check_masked: list of raw value substrings that must NOT appear in sanitized output.
        Returns (detections, type_set) or ([], set()) on failure.
        """
        label = filename
        filepath = os.path.join(TEST_DIR, filename)

        if not os.path.exists(filepath):
            report(f"[{label}] File exists", False, f"path not found: {filepath}")
            return [], set()
        report(f"[{label}] File exists", True)

        # ── Text extraction ───────────────────────────────────────────────────
        try:
            text = extract_text_from_file(filepath, file_type)
        except Exception as exc:
            report(f"[{label}] Text extraction", False, str(exc))
            return [], set()
        report(f"[{label}] Text extraction OK", len(text) > 0,
               f"got {len(text)} chars")

        # ── PII detection ─────────────────────────────────────────────────────
        try:
            detections = pii_detector.detect(text)
        except Exception as exc:
            report(f"[{label}] PII detection", False, str(exc))
            return [], set()

        det_types = {d.pii_type for d in detections}
        print(f"      Found {len(detections)} PII items → types: {sorted(det_types)}")
        report(f"[{label}] PII detected (≥ 1 item)", len(detections) > 0,
               "nothing detected" if not detections else "")

        # ── No duplicate spans ────────────────────────────────────────────────
        seen_spans: set = set()
        dups = []
        for d in detections:
            k = (d.start, d.end)
            if k in seen_spans:
                dups.append(d.text)
            seen_spans.add(k)
        report(f"[{label}] No duplicate PII spans", len(dups) == 0,
               f"dupes: {dups[:5]}" if dups else "")

        # ── Expected PII types present ────────────────────────────────────────
        if expected_types:
            for t in expected_types:
                found = t in det_types
                report(f"[{label}] {t} detected", found,
                       f"all types: {sorted(det_types)}" if not found else "")

        # ── Masking + sanitisation check ──────────────────────────────────────
        if detections and check_masked:
            # Build token mapping (unique by text, longest first)
            unique_vals = sorted({d.text for d in detections}, key=lambda x: -len(x))
            mapping = {v: f"{next(d.pii_type for d in detections if d.text == v)}_{i + 1:03d}"
                       for i, v in enumerate(unique_vals)}

            with tempfile.TemporaryDirectory() as tmpdir:
                safe_name = filename.replace(" ", "_")
                output_path = os.path.join(tmpdir, f"sanitized_{safe_name}")
                try:
                    mask_file(filepath, file_type, mapping, output_path)
                    with open(output_path, "r", errors="replace") as fh:
                        sanitized = fh.read()
                    for raw in check_masked:
                        report(f"[{label}] '{raw[:35]}' masked in output",
                               raw not in sanitized)
                except Exception as exc:
                    report(f"[{label}] Masking pipeline", False, str(exc))

        return detections, det_types

    # ── 1. test_data.csv (29 rows – core Indian PII types) ───────────────────
    print("\n  → test_data.csv (29 rows, comprehensive Indian PII)")
    _run_single(
        "test_data.csv", "csv",
        expected_types=["PHONE_NUMBER", "EMAIL_ADDRESS", "AADHAAR", "PAN"],
        check_masked=[
            "9876543210",            # Row 1 mobile
            "rahul.sharma@gmail.com",  # Row 1 email
            "2345 6789 0123",         # Row 1 aadhaar
            "ABCPS1234D",             # Row 1 PAN
        ],
    )

    # ── 2. test_data.json (same data in JSON format) ──────────────────────────
    print("\n  → test_data.json (same 29 records in JSON)")
    _run_single(
        "test_data.json", "json",
        expected_types=["PHONE_NUMBER", "EMAIL_ADDRESS", "AADHAAR", "PAN"],
        check_masked=[
            "9876543210",
            "rahul.sharma@gmail.com",
            "2345 6789 0123",
            "ABCPS1234D",
        ],
    )

    # ── 3. download.csv (30 rows – RandomUser Indian data) ───────────────────
    print("\n  → download.csv (30 rows, RandomUser Indian data)")
    _run_single(
        "download.csv", "csv",
        expected_types=["PHONE_NUMBER", "EMAIL_ADDRESS"],
        check_masked=[
            "sumana.gugale@example.com",  # Row 1 email
            "8228135159",                  # Row 1 phone
            "meghana.naik@example.com",   # Row 2 email
        ],
    )

    # ── 4. download (1).csv (30 rows – RandomUser Indian data) ───────────────
    print("\n  → download (1).csv (30 rows, RandomUser Indian data)")
    _run_single(
        "download (1).csv", "csv",
        expected_types=["PHONE_NUMBER", "EMAIL_ADDRESS"],
        check_masked=[
            "chandran.belligatti@example.com",  # Row 1 email
            "7368885170",                         # Row 1 phone
            "keya.mathew@example.com",            # Row 2 email
        ],
    )


# ─────────────────────────────────────────────────────────────────────────────
# 10. PERFORMANCE TEST: Large text detection stays within 30s
# ─────────────────────────────────────────────────────────────────────────────
def test_performance():
    section("Performance – Large File Detection")
    from services.pii_detector import pii_detector

    # Build ~100KB text with PII sprinkled in
    row = "Name: Rahul Sharma, Aadhaar: 1234 5678 9012, Phone: 9876543210, Email: rahul@test.com\n"
    large_text = row * 200   # ~200 rows

    start = time.time()
    detections = pii_detector.detect(large_text)
    elapsed = time.time() - start

    report(f"Large file detected in < 30s (took {elapsed:.1f}s)", elapsed < 30)
    report("Detections not empty", len(detections) > 0)
    report("No duplicates in large text", len(detections) == len(set((d.start, d.end) for d in detections)))


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CipherMask test suite")
    parser.add_argument("--api", action="store_true", help="Run API tests (requires running server)")
    parser.add_argument("--url", default="http://localhost:8000", help="Backend URL for API tests")
    parser.add_argument("--skip-perf", action="store_true", help="Skip performance test")
    args = parser.parse_args()

    print(f"\n{'=' * 62}")
    print(f"  CipherMask – Comprehensive Test Suite")
    print(f"  Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 62}")

    t0 = time.time()

    test_encryption()
    test_auth_utils()
    test_pii_detector()
    test_file_processor()
    test_masker()
    test_full_pipeline()
    test_json_pipeline()
    test_real_files()

    if not args.skip_perf:
        test_performance()

    if args.api:
        test_api(args.url)
    else:
        print(f"\n{WARN}  API tests skipped. Run with --api to test HTTP endpoints.")
        RESULTS["warnings"] += 1

    total = time.time() - t0
    p, f = RESULTS["passed"], RESULTS["failed"]
    total_tests = p + f
    print(f"\n{'=' * 62}")
    print(f"  Tests: {total_tests} total | \033[92m{p} passed\033[0m | \033[91m{f} failed\033[0m  "
          f"| {total:.1f}s")
    print(f"{'=' * 62}\n")

    sys.exit(0 if f == 0 else 1)


if __name__ == "__main__":
    main()
