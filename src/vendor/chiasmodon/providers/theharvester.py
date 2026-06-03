import subprocess


class TheHarvesterProvider:
    def __init__(self, theharvester_path="theHarvester"):
        self.theharvester_path = theharvester_path

    def search(self, query):
        try:
            result = subprocess.run(
                [self.theharvester_path, "-d", query, "-b", "all"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return {"error": result.stderr.strip() or "theHarvester failed"}
            return {"raw": result.stdout}
        except Exception as e:
            return {"error": str(e)}
