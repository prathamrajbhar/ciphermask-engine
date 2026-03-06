"""
Context-Aware PII Detection Engine
3-layer detection combining Regex, NER, and Contextual Analysis
for Indian DPDPA compliance.

Pipeline:
  Layer 1 – Regex pattern matching for structured Indian PII
  Layer 2 – spaCy NER for person names and locations
  Layer 3 – Contextual relationship analysis (ensures patterns
            are only flagged when appearing near person-related context)

Detected PII types:
  PERSON_NAME, PHONE_NUMBER, EMAIL_ADDRESS, AADHAAR, PAN,
  BANK_ACCOUNT, ADDRESS, PASSPORT
"""
import re
import logging
from typing import List, Dict, Set
from dataclasses import dataclass, field

import spacy

logger = logging.getLogger(__name__)


@dataclass
class PIIMatch:
    text: str
    pii_type: str
    start: int
    end: int
    confidence: float = 1.0
    method: str = "regex"


# ── Regex patterns for Indian PII ─────────────────────────────

AADHAAR_RE = re.compile(r"\b(\d{4}[\s-]?\d{4}[\s-]?\d{4})\b")
PAN_RE = re.compile(r"\b([A-Z]{5}\d{4}[A-Z])\b")
PHONE_RE = re.compile(r"\b(?:\+91[\s-]?)?([6-9]\d{9})\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PASSPORT_RE = re.compile(r"\b([A-Z]\d{7})\b")
BANK_ACCOUNT_RE = re.compile(r"\b(\d{9,18})\b")
IFSC_RE = re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b")
UPI_RE = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z][A-Za-z0-9]*)\b")
VOTER_ID_RE = re.compile(r"\b([A-Z]{2}/\d{2}/\d{3}/\d{6})\b")

# Context keywords that signal PII presence nearby
CONTEXT_KEYWORDS: Dict[str, List[str]] = {
    "AADHAAR": ["aadhaar", "aadhar", "adhar", "uid", "uidai"],
    "PAN": ["pan", "permanent account", "pan_number", "pan_no", "pan card"],
    "PHONE_NUMBER": [
        "phone", "mobile", "cell", "contact", "ph", "mob",
        "telephone", "tel", "+91",
    ],
    "EMAIL_ADDRESS": ["email", "e-mail", "mail"],
    "PASSPORT": ["passport", "passport_number", "passport_no"],
    "BANK_ACCOUNT": [
        "account", "acct", "a/c", "bank", "bank_account",
        "account_number", "acc_no",
    ],
    "PERSON_NAME": [
        "name", "person", "customer", "employee", "patient",
        "student", "applicant", "first_name", "last_name",
        "full_name",
    ],
    "ADDRESS": [
        "address", "addr", "location", "city", "state",
        "street", "pincode", "zip", "residential",
    ],
    "IFSC": ["ifsc", "ifsc_code", "bank_code", "branch_code"],
    "UPI_ID": ["upi", "upi_id", "vpa", "virtual_payment"],
    "VOTER_ID": ["voter", "voter_id", "electoral", "election_id"],
}

# PII types that need a contextual keyword nearby to trigger
# (prevents random numbers, city names, and non-PII from being flagged)
CONTEXT_REQUIRED_TYPES: Set[str] = {
    "PHONE_NUMBER", "BANK_ACCOUNT", "PERSON_NAME", "ADDRESS",
    "IFSC", "UPI_ID",
}

# PII types that are self-evident from their pattern alone
SELF_EVIDENT_TYPES: Set[str] = {
    "AADHAAR", "PAN", "EMAIL_ADDRESS", "PASSPORT", "VOTER_ID",
}

# Common geographic / non-PII terms that spaCy detects as entities
# but should NOT be treated as PII
GEO_EXCLUSIONS: Set[str] = {
    # Countries
    "india", "in", "usa", "uk", "us", "china", "brazil",
    "south africa", "canada", "australia",
    # Common timezone/description fragments spaCy picks up
    "adelaide", "darwin", "bombay", "calcutta", "madras",
    "new delhi", "sri jayawardenepura", "colombo", "dhaka",
    "almaty", "kabul", "tehran", "abu dhabi", "muscat",
    "baku", "tbilisi", "guam", "samoa", "lima",
    "azores", "cape verde islands", "copenhagen",
    "hawaii", "alaska", "midway island",
}

# ── Structured field detection support ──────────────────────────
# Regex to extract label:value pairs from structured text
# (CSV extraction produces 'key: value | key: value' format)
_STRUCT_PAIR_RE = re.compile(r"([\w.]+)\s*:\s*(.+?)(?=\s+\||$)", re.MULTILINE)

# Label parts that indicate a PERSON_NAME value
_NAME_FIELD_PARTS = {
    "name", "person", "customer", "employee", "patient",
    "student", "applicant",
}

# Label parts that SUPPRESS a PERSON_NAME detection
# (geographic/non-personal contexts where "name" appears in the label)
_NAME_SUPPRESS_PARTS = {
    "location", "street", "city", "state", "country",
    "coordinates", "timezone", "postcode",
    "title", "id",
}

# Label parts that indicate an ADDRESS value
_ADDR_FIELD_PARTS = {"address", "addr", "street", "residential"}


class PIIDetector:
    """
    3-Layer Context-Aware PII detection engine.

    Layer 1: Regex patterns for structured Indian PII
    Layer 2: spaCy NER for person names & locations
    Layer 3: Contextual relationship analysis
    """

    def __init__(self):
        self._nlp = None

    def _load_nlp(self):
        if self._nlp is None:
            try:
                self._nlp = spacy.load("en_core_web_sm")
            except OSError:
                from spacy.cli import download
                download("en_core_web_sm")
                self._nlp = spacy.load("en_core_web_sm")
            logger.info("spaCy model loaded")

    # ── Layer 1: Regex Detection ────────────────────────────────

    def _layer1_regex(self, text: str) -> List[PIIMatch]:
        """Detect structured PII patterns using regex."""
        matches: List[PIIMatch] = []

        # Aadhaar (12 digits, optionally spaced/hyphenated in 4-4-4)
        for m in AADHAAR_RE.finditer(text):
            clean = m.group().replace(" ", "").replace("-", "")
            if len(clean) == 12 and clean.isdigit():
                matches.append(PIIMatch(
                    text=m.group(), pii_type="AADHAAR",
                    start=m.start(), end=m.end(),
                    confidence=0.95, method="regex",
                ))

        # PAN (ABCDE1234F format)
        for m in PAN_RE.finditer(text):
            val = m.group()
            alpha_count = sum(1 for c in val if c.isalpha())
            if alpha_count == 6:
                matches.append(PIIMatch(
                    text=val, pii_type="PAN",
                    start=m.start(), end=m.end(),
                    confidence=0.95, method="regex",
                ))

        # Phone numbers (Indian 10-digit starting with 6-9)
        for m in PHONE_RE.finditer(text):
            full_match = m.group()
            matches.append(PIIMatch(
                text=full_match, pii_type="PHONE_NUMBER",
                start=m.start(), end=m.end(),
                confidence=0.85, method="regex",
            ))

        # Email
        for m in EMAIL_RE.finditer(text):
            matches.append(PIIMatch(
                text=m.group(), pii_type="EMAIL_ADDRESS",
                start=m.start(), end=m.end(),
                confidence=0.95, method="regex",
            ))

        # Passport (letter + 7 digits)
        for m in PASSPORT_RE.finditer(text):
            matches.append(PIIMatch(
                text=m.group(), pii_type="PASSPORT",
                start=m.start(), end=m.end(),
                confidence=0.80, method="regex",
            ))

        # Bank account (9-18 digits)
        for m in BANK_ACCOUNT_RE.finditer(text):
            clean = m.group()
            # Must not overlap with aadhaar or phone already found
            if not any(
                max(m.start(), ex.start) < min(m.end(), ex.end)
                for ex in matches
            ):
                if len(clean) >= 9 and clean.isdigit():
                    matches.append(PIIMatch(
                        text=clean, pii_type="BANK_ACCOUNT",
                        start=m.start(), end=m.end(),
                        confidence=0.70, method="regex",
                    ))

        # IFSC code (4 alpha + 0 + 6 alphanumeric)
        for m in IFSC_RE.finditer(text):
            if not any(
                max(m.start(), ex.start) < min(m.end(), ex.end)
                for ex in matches
            ):
                matches.append(PIIMatch(
                    text=m.group(), pii_type="IFSC",
                    start=m.start(), end=m.end(),
                    confidence=0.85, method="regex",
                ))

        # UPI ID (identifier@handle without TLD)
        for m in UPI_RE.finditer(text):
            # Skip if followed by a dot (would be an email, not UPI)
            if m.end() < len(text) and text[m.end()] == ".":
                continue
            if not any(
                max(m.start(), ex.start) < min(m.end(), ex.end)
                for ex in matches
            ):
                matches.append(PIIMatch(
                    text=m.group(), pii_type="UPI_ID",
                    start=m.start(), end=m.end(),
                    confidence=0.85, method="regex",
                ))

        # Voter ID (XX/DD/DDD/DDDDDD)
        for m in VOTER_ID_RE.finditer(text):
            matches.append(PIIMatch(
                text=m.group(), pii_type="VOTER_ID",
                start=m.start(), end=m.end(),
                confidence=0.90, method="regex",
            ))

        return matches

    # ── Layer 2: NER Detection ──────────────────────────────────

    def _layer2_ner(self, text: str) -> List[PIIMatch]:
        """Use spaCy NER to detect person names and addresses."""
        self._load_nlp()
        matches: List[PIIMatch] = []

        # Process text in chunks for long documents
        max_len = 100_000
        for offset in range(0, len(text), max_len):
            chunk = text[offset:offset + max_len]
            doc = self._nlp(chunk)

            for ent in doc.ents:
                ent_text = ent.text.strip()
                ent_lower = ent_text.lower()

                # Skip anything in the geographic exclusion list
                if ent_lower in GEO_EXCLUSIONS:
                    continue

                # Skip dotted-path labels (e.g., 'location.street.number')
                # These are CSV column headers leaking into NER
                if "." in ent_text and all(
                    part.isalnum() for part in ent_text.split(".")
                ):
                    continue

                if ent.label_ == "PERSON" and len(ent_text) >= 2:
                    # Filter out names that are purely numeric
                    clean = ent_text.replace(" ", "").replace(".", "").replace("-", "")
                    if not clean.isalpha():
                        continue
                    # Skip very short single-word "names" (< 4 chars)
                    # to avoid spaCy tagging random short words as PERSON
                    if " " not in ent_text and len(ent_text) < 4:
                        continue

                    matches.append(PIIMatch(
                        text=ent_text, pii_type="PERSON_NAME",
                        start=offset + ent.start_char,
                        end=offset + ent.end_char,
                        confidence=0.85, method="ner",
                    ))
                elif ent.label_ in ("GPE", "LOC", "FAC") and len(ent_text) >= 5:
                    matches.append(PIIMatch(
                        text=ent_text, pii_type="ADDRESS",
                        start=offset + ent.start_char,
                        end=offset + ent.end_char,
                        confidence=0.70, method="ner",
                    ))

        return matches

    # ── Layer 2b: Structured Field Detection ────────────────────

    def _layer2_structured(self, text: str) -> List[PIIMatch]:
        """
        Detect PII from structured labels (CSV headers / JSON keys).

        When a label like 'full_name' or 'address' is found in the
        extracted text, the corresponding value is flagged as PII
        regardless of NER detection. This catches names and addresses
        that spaCy NER misses (common with Indian names).
        """
        matches: List[PIIMatch] = []

        for m in _STRUCT_PAIR_RE.finditer(text):
            label = m.group(1).strip().lower()
            value = m.group(2).strip()

            # Skip empty or very short values
            if len(value) < 2:
                continue

            label_parts = set(
                label.replace(".", " ").replace("_", " ").split()
            )

            # Check if this is a name field
            if label_parts & _NAME_FIELD_PARTS:
                # Suppress if label also has location/title/id context
                # (e.g., 'location.street.name', 'name.title', 'id.name')
                if label_parts & _NAME_SUPPRESS_PARTS:
                    continue
                # Must contain at least one alpha word
                if any(w.isalpha() for w in value.split()):
                    val_start = m.start(2)
                    matches.append(PIIMatch(
                        text=value, pii_type="PERSON_NAME",
                        start=val_start,
                        end=val_start + len(value),
                        confidence=0.95, method="structured",
                    ))

            # Check if this is an address field
            elif label_parts & _ADDR_FIELD_PARTS:
                if len(value) >= 5:
                    val_start = m.start(2)
                    matches.append(PIIMatch(
                        text=value, pii_type="ADDRESS",
                        start=val_start,
                        end=val_start + len(value),
                        confidence=0.95, method="structured",
                    ))

        return matches

    # ── Layer 3: Contextual Analysis ────────────────────────────

    def _has_context(self, text: str, start: int, end: int, pii_type: str) -> bool:
        """
        Check if the surrounding text contains contextual keywords
        that indicate the match is genuinely PII.

        A 10-digit number on its own is NOT flagged as a phone number.
        It's only flagged if near contextual keywords like 'phone', 'mobile',
        'contact', or near a detected person name.
        """
        # Self-evident types don't need extra context
        if pii_type in SELF_EVIDENT_TYPES:
            return True

        window = 120  # characters to look around
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        context = text[ctx_start:ctx_end].lower()

        # Check for direct keyword match for this PII type
        keywords = CONTEXT_KEYWORDS.get(pii_type, [])
        for kw in keywords:
            if kw in context:
                return True

        # Check if any PII-related keyword exists nearby (generic context)
        all_person_keywords = CONTEXT_KEYWORDS.get("PERSON_NAME", [])
        for kw in all_person_keywords:
            if kw in context:
                return True

        return False

    def _extract_structured_context(self, text: str, start: int) -> str:
        """
        Look backwards from a candidate position to find structured labels
        like 'name.first:' or 'location.city:' in CSV/JSON formatted text.
        Returns the full label (e.g. 'name.first', 'location.street.name').
        """
        prefix_start = max(0, start - 120)
        prefix = text[prefix_start:start]

        # Find the nearest colon before the match
        colon_pos = prefix.rfind(":")
        if colon_pos != -1:
            # Find the label before the colon
            label_start = max(
                prefix.rfind("|", 0, colon_pos) + 1,
                prefix.rfind("\n", 0, colon_pos) + 1,
                prefix.rfind(",", 0, colon_pos) + 1,
            )
            label = prefix[label_start:colon_pos].strip().lower().replace(" ", "_")
            return label
        return ""

    def _label_matches_type(self, label: str, pii_type: str) -> bool:
        """
        Check if a structured label (CSV column header) matches a PII type.
        Uses both exact keyword match and dotted path components.
        Also applies negative rules to prevent false positives.

        E.g., 'name.first' matches PERSON_NAME because 'name' is a keyword.
              'location.street.name' does NOT match PERSON_NAME because
              'location'/'street' suppress the PERSON_NAME interpretation.
              'login.password' does NOT match any PII type.
        """
        # Negative rules: labels that should NEVER produce PII
        # These are non-PII fields common in datasets
        NON_PII_PARTS = {
            "login", "password", "salt", "md5", "sha1", "sha256",
            "uuid", "username", "picture", "thumbnail", "large", "medium",
            "coordinates", "latitude", "longitude", "timezone", "offset",
            "description", "nat", "gender", "title", "age", "date",
            "registered", "dob", "postcode", "id",
        }

        # Labels that suppress PERSON_NAME (geographic/non-personal context)
        LOCATION_PARTS = _NAME_SUPPRESS_PARTS

        parts = set(label.replace(".", " ").replace("_", " ").split())

        # If ALL parts are known non-PII labels, reject entirely
        # (e.g., "id", "login.password", "registered.dob")
        # But "upi_id" passes because "upi" is not in NON_PII_PARTS
        if parts and parts.issubset(NON_PII_PARTS):
            return False

        # PERSON_NAME: reject if label has location-related parts
        if pii_type == "PERSON_NAME" and (parts & LOCATION_PARTS):
            return False

        # ADDRESS: only match for actual address/street fields,
        # NOT for city/state/country (which are general geography, not PII)
        if pii_type == "ADDRESS":
            addr_positive = {"address", "addr", "street", "residential"}
            if not (parts & addr_positive):
                return False

        # Check keyword match
        keywords = CONTEXT_KEYWORDS.get(pii_type, [])
        for kw in keywords:
            if kw in label or label in kw:
                return True

        # Check individual components
        for part in parts:
            for kw in keywords:
                if part == kw:
                    return True

        return False

    def _layer3_contextual_filter(
        self, text: str, matches: List[PIIMatch],
    ) -> List[PIIMatch]:
        """
        Filter regex/NER matches through contextual analysis.
        Ensures that PERSON_NAME, ADDRESS, PHONE_NUMBER, and BANK_ACCOUNT
        are only flagged when near person-related or location-related context.
        """
        filtered: List[PIIMatch] = []

        for m in matches:
            # Structured detections already validated by column header
            if m.method == "structured":
                filtered.append(m)
                continue

            if m.pii_type not in CONTEXT_REQUIRED_TYPES:
                # Self-evident types (Aadhaar, PAN, Email, Passport, Voter ID)
                filtered.append(m)
                continue

            # Check structured context (CSV headers, JSON keys)
            struct_label = self._extract_structured_context(text, m.start)
            if struct_label:
                # Does the label match this PII type?
                if self._label_matches_type(struct_label, m.pii_type):
                    m.confidence = min(1.0, m.confidence + 0.1)
                    filtered.append(m)
                    continue

                # For NER results, also check if the label matches a DIFFERENT
                # appropriate PII type (e.g., spaCy tags a city as PERSON
                # but it's under 'location.city' → should be ADDRESS not PERSON)
                if m.method == "ner":
                    # Check if label matches any PII type at all
                    reclassified = False
                    for other_type in CONTEXT_REQUIRED_TYPES:
                        if other_type == m.pii_type:
                            continue
                        if self._label_matches_type(struct_label, other_type):
                            m.pii_type = other_type
                            filtered.append(m)
                            reclassified = True
                            break
                    if reclassified:
                        continue

                # Label exists but doesn't match any PII type — skip
                # (e.g., 'login.password:', 'login.salt:', 'location.timezone.description:')
                continue

            # No structured label: check free-text context
            if self._has_context(text, m.start, m.end, m.pii_type):
                filtered.append(m)

        return filtered

    # ── Deduplication ───────────────────────────────────────────

    def _deduplicate(self, matches: List[PIIMatch]) -> List[PIIMatch]:
        """Remove overlapping detections, keeping widest span (then highest confidence)."""
        if not matches:
            return []

        # Sort by span width desc (prefer wider), then confidence desc
        matches.sort(key=lambda m: (-(m.end - m.start), -m.confidence))

        deduped: List[PIIMatch] = []
        for m in matches:
            overlaps = False
            for d in deduped:
                if max(m.start, d.start) < min(m.end, d.end):
                    overlaps = True
                    break
            if not overlaps:
                deduped.append(m)

        return deduped

    # ── Main Detection Entry Point ──────────────────────────────

    def detect(self, text: str) -> List[PIIMatch]:
        """
        Run the full 3-layer detection pipeline.

        Returns a deduplicated list of PII matches with types and positions.
        """
        if not text or not text.strip():
            return []

        # Layer 1: Regex patterns
        regex_matches = self._layer1_regex(text)

        # Layer 2a: NER (person names, addresses)
        ner_matches = self._layer2_ner(text)

        # Layer 2b: Structured field detection (CSV headers, JSON keys)
        struct_matches = self._layer2_structured(text)

        # Combine all candidates
        all_matches = regex_matches + ner_matches + struct_matches

        # Layer 3: Contextual filtering
        contextual_matches = self._layer3_contextual_filter(text, all_matches)

        # Deduplicate overlapping spans
        return self._deduplicate(contextual_matches)


# Singleton
pii_detector = PIIDetector()
