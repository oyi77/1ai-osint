import json
import subprocess


class MaigretProvider:
    def __init__(self, maigret_path="maigret"):
        self.maigret_path = maigret_path

    def search(self, username):
        try:
            result = subprocess.run(
                [self.maigret_path, username, "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return {"error": result.stderr.strip() or "Maigret failed"}
            return json.loads(result.stdout)
        except Exception as e:
            return {"error": str(e)}
