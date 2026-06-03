from pydantic import BaseModel
class Finding(BaseModel):
    raw_data: dict

findings = [Finding(raw_data={"url": "http"}), Finding(raw_data={"url": "http2"})]
to_verify = [findings[0]]

async def verify(f):
    f.raw_data["verified"] = False

import asyncio
asyncio.run(verify(to_verify[0]))

verified_findings = []
for f in findings:
    if f in to_verify:
        if f.raw_data.get("verified", False):
            verified_findings.append(f)
    else:
        verified_findings.append(f)
print(verified_findings)
