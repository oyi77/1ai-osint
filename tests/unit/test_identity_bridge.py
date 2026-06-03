import asyncio
from unittest.mock import AsyncMock
from src.modules.deep_scan.identity_bridge import IdentityBridge


def test_pivot_name_to_selectors():
    async def run_test():
        bridge = IdentityBridge()

        mock_response_email = AsyncMock()
        mock_response_email.status_code = 200
        mock_response_email.text = "Contact me at john.doe@example.com for more info."

        mock_response_phone = AsyncMock()
        mock_response_phone.status_code = 200
        mock_response_phone.text = "Call me at +12345678901 for more info."

        async def mock_post(url, data, **kwargs):
            if "email" in data.get("q", ""):
                return mock_response_email
            return mock_response_phone

        bridge.client.post = AsyncMock(side_effect=mock_post)

        result = await bridge.pivot_name_to_selectors("John Doe")

        assert "john.doe@example.com" in result["emails"]
        assert "+12345678901" in result["phones"]

        await bridge.close()

    asyncio.run(run_test())
