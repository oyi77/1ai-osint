import subprocess
import json


class AmassProvider:
    def __init__(self, amass_path="amass"):
        self.amass_path = amass_path

    def search(self, domain):
        try:
            result = subprocess.run(
                [self.amass_path, "enum", "-d", domain, "-json", "-"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return {"error": result.stderr.strip() or "Amass failed"}
            return [
                json.loads(line) for line in result.stdout.splitlines() if line.strip()
            ]
        except Exception as e:
            return {"error": str(e)}
