import subprocess
import json


class ExifToolProvider:
    def __init__(self, exiftool_path="exiftool"):
        self.exiftool_path = exiftool_path

    def search(self, image_path):
        try:
            result = subprocess.run(
                [self.exiftool_path, "-j", image_path],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return {"error": result.stderr.strip() or "ExifTool failed"}
            return json.loads(result.stdout)
        except Exception as e:
            return {"error": str(e)}
