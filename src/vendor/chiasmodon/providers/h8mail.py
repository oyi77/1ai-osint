import subprocess
import json

class H8mailProvider:
    def __init__(self, h8mail_path='h8mail'):
        self.h8mail_path = h8mail_path
    def search(self, email):
        try:
            result = subprocess.run([self.h8mail_path, '-t', email, '--json'], capture_output=True, text=True, check=False)
            if result.returncode != 0:
                return {"error": result.stderr.strip() or "h8mail failed"}
            return json.loads(result.stdout)
        except Exception as e:
            return {"error": str(e)}
