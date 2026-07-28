import hashlib

import httpx

from src.core.models import BreachRecord, Severity

# Data class severity weights
_DATA_CLASS_WEIGHTS = {
    "password": 10,
    "password_hash": 8,
    "passwords": 10,
    "hashed passwords": 8,
    "credit card": 10,
    "credit cards": 10,
    "bank account": 10,
    "social security": 10,
    "ssn": 10,
    "financial": 8,
    "email": 3,
    "emails": 3,
    "email addresses": 3,
    "username": 2,
    "usernames": 2,
    "ip": 2,
    "ip addresses": 2,
    "phone": 4,
    "phone numbers": 4,
    "physical address": 6,
    "address": 4,
    "date of birth": 5,
    "dob": 5,
    "name": 3,
    "names": 3,
    "gender": 1,
}


class BreachChecker:
    """Scores breach severity based on data classes and breach metadata."""

    def score_severity(self, record: BreachRecord) -> Severity:
        """Calculate severity for a breach record.

        Scoring factors:
        - Data class sensitivity (passwords, financial > email, username)
        - Number of exposed data classes
        - Whether breach is verified
        """
        score = 0

        # Score based on data classes
        for dc in record.data_classes:
            dc_lower = dc.lower().strip()
            for pattern, weight in _DATA_CLASS_WEIGHTS.items():
                if pattern in dc_lower:
                    score += weight
                    break

        # Bonus for multiple data classes (compound risk)
        if len(record.data_classes) >= 5:
            score += 5
        elif len(record.data_classes) >= 3:
            score += 2

        # Map score to severity
        if score >= 20:
            return Severity.CRITICAL
        elif score >= 12:
            return Severity.HIGH
        elif score >= 5:
            return Severity.MEDIUM
        elif score >= 1:
            return Severity.LOW
        else:
            return Severity.INFO

    def score_batch(self, records: list[BreachRecord]) -> list[BreachRecord]:
        """Score a batch of breach records."""
        for record in records:
            record.severity = self.score_severity(record)
        return records


class BlindQueryResolver:
    """Range-based privacy-preserving (k-anonymity) target check."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def hash_target(self, val: str, hash_type: str = "sha1") -> str:
        """Hash string into uppercase hex SHA-1 or SHA-256."""
        val_bytes = val.strip().encode("utf-8")
        if hash_type.lower() == "sha256":
            return hashlib.sha256(val_bytes).hexdigest().upper()
        return hashlib.sha1(val_bytes).hexdigest().upper()

    async def check_password_pwned(self, password: str) -> tuple[bool, int]:
        """Check if a password has been pwned using HaveIBeenPwned range API.

        Transmits ONLY the first 5 characters of the SHA-1 hash.
        """
        full_hash = self.hash_target(password, "sha1")
        prefix = full_hash[:5]
        suffix = full_hash[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    lines = resp.text.splitlines()
                    for line in lines:
                        if ":" in line:
                            h_suffix, count_str = line.split(":", 1)
                            if h_suffix.upper() == suffix:
                                return True, int(count_str)
        except Exception:
            # Under test or network issue
            pass

        return False, 0
