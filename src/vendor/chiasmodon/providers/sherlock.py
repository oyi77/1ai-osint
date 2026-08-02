import csv
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any


class SherlockProvider:
    def __init__(self, sherlock_path: str = "sherlock"):
        self.sherlock_path = sherlock_path

    def search(self, username: str) -> dict:
        """Run sherlock-project and return site → status dict.

        sherlock >= 0.16.0 repurposed ``--json`` as an *input* flag (load a
        site-data file) — it is no longer an output format.  The structured
        output flag is ``--csv``, which writes ``<username>.csv`` into the
        process working directory.  We run sherlock inside a temp directory
        and parse that CSV into the historical ``{site: {...}}`` shape
        consumed by the people finder.
        """
        tmp_dir: str | None = None
        try:
            tmp_dir = tempfile.mkdtemp(prefix="sherlock_")
            result = subprocess.run(
                [
                    self.sherlock_path,
                    username,
                    "--csv",
                    "--no-txt",
                    "--no-color",
                    "--timeout",
                    "30",
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                cwd=tmp_dir,
            )
            safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", username)
            csv_path = os.path.join(tmp_dir, f"{safe_name}.csv")
            if not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0:
                err = result.stderr.strip() or result.stdout.strip() or "Sherlock failed"
                return {"error": err}
            return self._parse_csv(csv_path)
        except Exception as exc:
            return {"error": str(exc)}
        finally:
            if tmp_dir and os.path.isdir(tmp_dir):
                shutil.rmtree(tmp_dir, ignore_errors=True)

    @staticmethod
    def _parse_csv(csv_path: str) -> dict[str, dict[str, Any]]:
        """Parse sherlock's CSV into ``{site: {status, url, username}}``."""
        sites: dict[str, dict[str, Any]] = {}
        with open(csv_path, encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                name = (row.get("name") or "").strip()
                if not name:
                    continue
                sites[name] = {
                    "status": (row.get("exists") or "").strip().lower(),
                    "url": row.get("url_user") or row.get("url_main") or "",
                    "username": (row.get("username") or "").strip(),
                    "http_status": row.get("http_status") or "",
                    "response_time_s": row.get("response_time_s") or "",
                }
        return sites
