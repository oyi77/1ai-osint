import re
from typing import Dict, List

import httpx


class IdentityBridge:
    def __init__(self):
        self.client = httpx.AsyncClient(headers={"User-Agent": "Mozilla/5.0"})

    async def pivot_name_to_selectors(self, name: str) -> Dict[str, List[str]]:
        results: Dict[str, List[str]] = {"emails": [], "phones": []}

        email_query = f'"{name}" email'
        email_url = "https://lite.duckduckgo.com/lite/"

        try:
            resp_email = await self.client.post(email_url, data={"q": email_query})
            if resp_email.status_code == 200:
                text = resp_email.text
                emails = re.findall(
                    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text
                )
                results["emails"].extend(list(set(emails)))
        except Exception:
            pass

        phone_query = f'"{name}" phone number'
        try:
            resp_phone = await self.client.post(email_url, data={"q": phone_query})
            if resp_phone.status_code == 200:
                text = resp_phone.text
                phones = re.findall(r"\+?\d{10,14}", text)
                results["phones"].extend(list(set(phones)))
        except Exception:
            pass

        return results

    async def close(self):
        await self.client.aclose()
