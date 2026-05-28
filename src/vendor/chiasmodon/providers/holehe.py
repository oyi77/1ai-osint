import subprocess
import json

class HoleheProvider:
    def __init__(self, holehe_path='holehe'):
        self.holehe_path = holehe_path
    def search(self, email):
        try:
            result = subprocess.run([self.holehe_path, email, '--json'], capture_output=True, text=True, check=False)
            if result.returncode != 0:
                return {"error": result.stderr.strip() or "Holehe failed"}
            return json.loads(result.stdout)
        except Exception as e:
            return {"error": str(e)}
