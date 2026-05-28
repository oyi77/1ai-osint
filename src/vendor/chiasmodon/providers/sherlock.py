import subprocess
import json

class SherlockProvider:
    def __init__(self, sherlock_path='sherlock'):
        self.sherlock_path = sherlock_path
    def search(self, username):
        try:
            result = subprocess.run([self.sherlock_path, username, '--json'], capture_output=True, text=True, check=False)
            if result.returncode != 0:
                return {"error": result.stderr.strip() or "Sherlock failed"}
            return json.loads(result.stdout)
        except Exception as e:
            return {"error": str(e)}
