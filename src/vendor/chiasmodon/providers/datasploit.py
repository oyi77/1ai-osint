import json
import subprocess


class DatasploitProvider:
    def __init__(self, datasploit_path="datasploit"):
        self.datasploit_path = datasploit_path

    def search(self, query):
        try:
            result = subprocess.run(
                [self.datasploit_path, query, "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return {"error": result.stderr.strip() or "Datasploit failed"}
            return json.loads(result.stdout)
        except Exception as e:
            return {"error": str(e)}
