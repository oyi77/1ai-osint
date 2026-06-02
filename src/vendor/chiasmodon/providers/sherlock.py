import json
import os
import subprocess
import tempfile


class SherlockProvider:
    def __init__(self, sherlock_path: str = "sherlock"):
        self.sherlock_path = sherlock_path

    def search(self, username: str) -> dict:
        """Run sherlock-project and return site → status JSON."""
        tmp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False,
            ) as tmp:
                tmp_path = tmp.name
            result = subprocess.run(
                [
                    self.sherlock_path,
                    username,
                    "--print-found",
                    "--json",
                    tmp_path,
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if result.returncode not in (0, 1) and not os.path.isfile(tmp_path):
                return {"error": result.stderr.strip() or "Sherlock failed"}
            with open(tmp_path, encoding="utf-8") as f:
                raw = f.read().strip()
            if not raw:
                return {}
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            return {"error": f"Sherlock JSON parse error: {exc}"}
        except Exception as exc:
            return {"error": str(exc)}
        finally:
            if tmp_path and os.path.isfile(tmp_path):
                os.unlink(tmp_path)
