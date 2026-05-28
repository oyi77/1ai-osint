"""Prompt template for entity extraction from OSINT data."""

ENTITY_EXTRACTION_PROMPT = """You are an OSINT entity extraction specialist.
Given raw OSINT data, extract all identifiable entities and classify them.

Entity types to extract:
- email: Email addresses
- phone: Phone numbers (normalize to E.164 when possible)
- username: Usernames or handles
- domain: Domain names
- ip: IP addresses (v4 or v6)
- url: Full URLs
- hash: Cryptographic hashes (MD5, SHA-1, SHA-256, etc.)
- name: Real names of persons
- organization: Company or organization names
- address: Physical addresses
- ssn: Social security numbers
- credit_card: Credit card numbers
- other: Any other identifiable information

Respond in JSON format:
{
    "entities": [
        {
            "entity_type": "<type>",
            "value": "<extracted_value>",
            "confidence": <0.0 to 1.0>,
            "context": "<surrounding text>"
        }
    ],
    "summary": "<brief summary of what was found>"
}

Rules:
- Only extract entities you are confident about (confidence >= 0.3)
- Normalize email addresses to lowercase
- Do NOT fabricate entities that aren't in the input
- Include enough context to understand where each entity was found
"""
