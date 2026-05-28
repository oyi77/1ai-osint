import subprocess
import json

class WhatsMyNameProvider:
    def __init__(self, whatsmyname_path='whatsmyname'):
        self.whatsmyname_path = whatsmyname_path
    def search(self, username):
        try:
            result = subprocess.run([self.whatsmyname_path, '--username', username, '--output', 'json'], capture_output=True, text=True, check=False)
            if result.returncode != 0:
                return {"error": result.stderr.strip() or "WhatsMyName failed"}
            return json.loads(result.stdout)
        except Exception as e:
            return {"error": str(e)}
