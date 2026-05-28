"""Breach severity scoring for data leak records."""

from src.models import BreachRecord, Severity


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
        """
        Calculate severity for a breach record.

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
