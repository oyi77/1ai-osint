"""Phone number lookup module wrapping PhoneInfoga."""

import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

from src.models import Finding, ScanResult, Severity
from src.modules.base.base import BaseOSINTTool


# E.164 phone number pattern: +[country code][subscriber number]
_E164_PATTERN = re.compile(r"^\+[1-9]\d{1,14}$")


class PhoneInfo(BaseModel):
    """Structured phone number intelligence."""

    phone_number: str = Field(..., description="Original phone number")
    e164_format: Optional[str] = Field(
        default=None, description="E.164 formatted number"
    )
    is_valid_e164: bool = Field(
        default=False, description="Whether the number is valid E.164"
    )
    country_code: Optional[str] = Field(
        default=None, description="Country calling code"
    )
    country_name: Optional[str] = Field(
        default=None, description="Country name"
    )
    carrier: Optional[str] = Field(
        default=None, description="Telecommunications carrier"
    )
    line_type: Optional[str] = Field(
        default=None, description="Line type (mobile, landline, voip, etc.)"
    )
    location: Optional[str] = Field(
        default=None, description="Geographic location/region"
    )
    is_voip: Optional[bool] = Field(
        default=None, description="Whether the number is a VoIP number"
    )
    raw_data: dict[str, Any] = Field(default_factory=dict)


class PhoneFinderLookup(BaseOSINTTool):
    """
    Phone number OSINT lookup.

    Wraps chiasmodon's PhoneInfoga provider to perform carrier detection,
    location lookup, VoIP status check, and E.164 validation.
    """

    name = "phone_finder"
    description = "Phone number intelligence and carrier/VoIP detection"
    version = "0.1.0"

    def __init__(self, zkit_salt: Optional[str] = None):
        super().__init__(zkit_salt=zkit_salt)

    @staticmethod
    def validate_e164(phone: str) -> tuple[bool, Optional[str]]:
        """
        Validate and normalize a phone number to E.164 format.

        Args:
            phone: Raw phone number string

        Returns:
            Tuple of (is_valid, e164_formatted_or_none)
        """
        # Strip whitespace and common formatting characters
        cleaned = re.sub(r"[\s\-\(\)\.]", "", phone.strip())

        # If already E.164
        if _E164_PATTERN.match(cleaned):
            return True, cleaned

        # Try adding + prefix if it looks like an international number
        if cleaned.startswith("00"):
            candidate = "+" + cleaned[2:]
            if _E164_PATTERN.match(candidate):
                return True, candidate

        # Try with + prefix for digit-only strings starting with valid country code
        if cleaned.isdigit() and len(cleaned) >= 7:
            candidate = "+" + cleaned
            if _E164_PATTERN.match(candidate):
                return True, candidate

        return False, None

    def _get_provider(self) -> Any:
        """Get the PhoneInfoga provider."""
        try:
            from src.vendor.chiasmodon.providers.phoneinfoga import (
                PhoneInfogaProvider,
            )

            return PhoneInfogaProvider()
        except ImportError:
            return None

    async def search(self, query: str, **kwargs) -> ScanResult:
        """
        Look up a phone number for carrier, location, and VoIP info.

        Args:
            query: Phone number to look up (E.164 or raw format)
        """
        scan_id = self._make_scan_id()
        started_at = datetime.now(timezone.utc)
        errors: dict[str, str] = {}

        # Validate E.164
        is_valid, e164 = self.validate_e164(query)

        provider = self._get_provider()
        if provider is None:
            errors["phoneinfoga"] = "PhoneInfoga provider not available"
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=query,
                status="error",
                error="PhoneInfoga provider not available",
                metadata={"is_valid_e164": is_valid, "e164_format": e164},
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

        # Query provider (use E.164 format if valid, otherwise raw)
        lookup_number = e164 if e164 else query
        try:
            loop = asyncio.get_event_loop()
            raw_result = await loop.run_in_executor(
                None, provider.search, lookup_number
            )
        except Exception as exc:
            errors["phoneinfoga"] = str(exc)
            raw_result = {"error": str(exc)}

        # Handle provider errors
        if isinstance(raw_result, dict) and raw_result.get("error"):
            errors["phoneinfoga"] = raw_result["error"]

        # Parse into structured PhoneInfo
        phone_info = self._parse_result(query, e164, is_valid, raw_result)

        # Build findings
        findings = []
        if phone_info.carrier:
            findings.append(
                Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title=f"Carrier: {phone_info.carrier}",
                    description=f"Phone {query} is operated by {phone_info.carrier}",
                    severity=Severity.INFO,
                    raw_data={"carrier": phone_info.carrier, "phone": query},
                    confidence=0.8,
                    tags=["phone", "carrier"],
                )
            )

        if phone_info.is_voip is True:
            findings.append(
                Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title=f"VoIP Number Detected: {query}",
                    description=f"Phone {query} appears to be a VoIP number",
                    severity=Severity.LOW,
                    raw_data={"phone": query, "is_voip": True},
                    confidence=0.7,
                    tags=["phone", "voip"],
                )
            )

        if phone_info.location:
            findings.append(
                Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title=f"Location: {phone_info.location}",
                    description=f"Phone {query} is located in {phone_info.location}",
                    severity=Severity.INFO,
                    raw_data={"location": phone_info.location, "phone": query},
                    confidence=0.75,
                    tags=["phone", "location"],
                )
            )

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=query,
            status="ok" if not errors else "partial",
            findings=findings,
            metadata={
                "phone_info": phone_info.model_dump(exclude_none=True),
                "providers_queried": ["phoneinfoga"],
                "providers_errored": errors,
                "is_valid_e164": is_valid,
                "e164_format": e164,
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Alias for search."""
        return await self.search(target, **kwargs)

    async def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        """Analyze phone lookup results."""
        if isinstance(data, ScanResult):
            findings = data.findings
            phone_info_data = data.metadata.get("phone_info", {})
        else:
            return {"error": "Unsupported data type"}

        return {
            "total_findings": len(findings),
            "is_valid_e164": data.metadata.get("is_valid_e164", False),
            "e164_format": data.metadata.get("e164_format"),
            "carrier": phone_info_data.get("carrier"),
            "line_type": phone_info_data.get("line_type"),
            "is_voip": phone_info_data.get("is_voip"),
            "location": phone_info_data.get("location"),
            "country": phone_info_data.get("country_name"),
        }

    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        """Learn from feedback (future: improve carrier/VoIP heuristics)."""
        pass

    def _parse_result(
        self,
        original_number: str,
        e164: Optional[str],
        is_valid: bool,
        raw_result: Any,
    ) -> PhoneInfo:
        """Parse raw provider result into a structured PhoneInfo."""
        info = PhoneInfo(
            phone_number=original_number,
            e164_format=e164,
            is_valid_e164=is_valid,
        )

        if not isinstance(raw_result, dict) or raw_result.get("error"):
            return info

        # Extract carrier info from common PhoneInfoga result fields
        info.carrier = (
            raw_result.get("carrier")
            or raw_result.get("Carrier")
            or raw_result.get("carrier_name")
        )

        info.country_code = (
            raw_result.get("country_code")
            or raw_result.get("CountryCode")
            or raw_result.get("country", {}).get("code")
            if isinstance(raw_result.get("country"), dict)
            else raw_result.get("country_code")
        )

        info.country_name = (
            raw_result.get("country_name")
            or raw_result.get("CountryName")
            or raw_result.get("country", {}).get("name")
            if isinstance(raw_result.get("country"), dict)
            else raw_result.get("country_name")
        )

        info.line_type = (
            raw_result.get("line_type")
            or raw_result.get("LineType")
            or raw_result.get("number_type")
        )

        info.location = (
            raw_result.get("location")
            or raw_result.get("Location")
            or raw_result.get("geolocation")
        )

        # Determine VoIP status
        voip_indicators = ["voip", "virtual", "sip", "internet"]
        line = (info.line_type or "").lower()
        info.is_voip = any(ind in line for ind in voip_indicators)

        info.raw_data = raw_result
        return info
