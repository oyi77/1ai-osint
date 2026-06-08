import json
import subprocess


class SpiderFootProvider:
    def __init__(self, spiderfoot_path="sf.py"):
        self.spiderfoot_path = spiderfoot_path

    def search(self, target):
        try:
            result = subprocess.run(
                ["python3", self.spiderfoot_path, "-q", target, "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return {"error": result.stderr.strip() or "SpiderFoot failed"}
            return json.loads(result.stdout)
        except Exception as e:
            return {"error": str(e)}
