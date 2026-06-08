import json
import subprocess


class PhoneInfogaProvider:
    def __init__(self, phoneinfoga_path="phoneinfoga"):
        self.phoneinfoga_path = phoneinfoga_path

    def search(self, phone):
        try:
            result = subprocess.run(
                [self.phoneinfoga_path, "scan", "-n", phone, "--output", "json"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return {"error": result.stderr.strip() or "PhoneInfoga failed"}
            return json.loads(result.stdout)
        except Exception as e:
            return {"error": str(e)}
