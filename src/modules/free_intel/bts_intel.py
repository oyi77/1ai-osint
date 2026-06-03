"""BTS / Cell Tower Intelligence via OpenCelliD.

Free API with registration at opencellid.org.
Indonesia MCC = 510.
"""

import os
import logging
from typing import Optional
import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Indonesian mobile operator MNC codes
INDONESIA_OPERATORS = {
    "0811": ("Telkomsel", 10),
    "0812": ("Telkomsel", 10),
    "0813": ("Telkomsel", 10),
    "0821": ("Telkomsel", 10),
    "0822": ("Telkomsel", 10),
    "0823": ("Telkomsel", 10),
    "0851": ("Telkomsel", 10),
    "0852": ("Telkomsel", 10),
    "0853": ("Telkomsel", 10),
    "0814": ("Indosat", 1),
    "0815": ("Indosat", 1),
    "0816": ("Indosat", 1),
    "0855": ("Indosat", 1),
    "0856": ("Indosat", 1),
    "0857": ("Indosat", 1),
    "0858": ("Indosat", 1),
    "0817": ("XL Axiata", 11),
    "0818": ("XL Axiata", 11),
    "0819": ("XL Axiata", 11),
    "0859": ("XL Axiata", 11),
    "0877": ("XL Axiata", 11),
    "0878": ("XL Axiata", 11),
    "0831": ("Axis", 11),
    "0832": ("Axis", 11),
    "0833": ("Axis", 11),
    "0838": ("Axis", 11),
    "0895": ("Three", 89),
    "0896": ("Three", 89),
    "0897": ("Three", 89),
    "0898": ("Three", 89),
    "0899": ("Three", 89),
    "0881": ("Smartfren", 28),
    "0882": ("Smartfren", 28),
    "0883": ("Smartfren", 28),
    "0884": ("Smartfren", 28),
    "0885": ("Smartfren", 28),
    "0886": ("Smartfren", 28),
    "0887": ("Smartfren", 28),
    "0888": ("Smartfren", 28),
    "0889": ("Smartfren", 28),
}


class BTSTower(BaseModel):
    lat: float = 0.0
    lon: float = 0.0
    mcc: int = 0
    mnc: int = 0
    lac: int = 0
    cellid: int = 0
    range_m: int = 0
    samples: int = 0
    operator: str = ""


class PhoneIntel(BaseModel):
    phone_number: str = ""
    operator: str = ""
    mnc: int = 0
    country: str = "Indonesia"
    mcc: int = 510
    nearby_towers: list[BTSTower] = Field(default_factory=list)


class BTSIntel:
    """OpenCelliD-based cell tower intelligence."""

    API_URL = "https://opencellid.org/cell/getInArea"

    def __init__(self):
        self.token = os.environ.get("OPENCELLID_TOKEN", "")

    def identify_operator(self, phone: str) -> Optional[tuple[str, int]]:
        """Identify Indonesian mobile operator from phone number prefix."""
        # Normalize to 0xxx format
        p = (
            phone.replace("+62", "0")
            .replace("62", "0", 1)
            .replace("-", "")
            .replace(" ", "")
        )
        prefix = p[:4]
        return INDONESIA_OPERATORS.get(prefix)

    async def analyze_phone(self, phone: str) -> PhoneIntel:
        """Analyze an Indonesian phone number."""
        result = PhoneIntel(phone_number=phone)
        op = self.identify_operator(phone)
        if op:
            result.operator = op[0]
            result.mnc = op[1]
        return result

    async def get_towers_in_area(
        self, lat: float, lon: float, radius_km: int = 5
    ) -> list[BTSTower]:
        """Get cell towers in a geographic area."""
        if not self.token:
            logger.info("OPENCELLID_TOKEN not set — BTS lookup skipped")
            return []
        try:
            # Calculate bounding box
            delta = radius_km / 111.0  # ~111km per degree
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    self.API_URL,
                    params={
                        "token": self.token,
                        "BBOX": f"{lon - delta},{lat - delta},{lon + delta},{lat + delta}",
                        "format": "json",
                        "limit": 20,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    cells = data.get("cells", [])
                    return [
                        BTSTower(
                            lat=c.get("lat", 0),
                            lon=c.get("lon", 0),
                            mcc=c.get("mcc", 0),
                            mnc=c.get("mnc", 0),
                            lac=c.get("lac", 0),
                            cellid=c.get("cellid", 0),
                            range_m=c.get("range", 0),
                            samples=c.get("samples", 0),
                        )
                        for c in cells
                    ]
        except Exception as e:
            logger.warning("OpenCelliD lookup failed: %s", e)
        return []
