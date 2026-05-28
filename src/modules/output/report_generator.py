"""Main report orchestrator for 1ai-osint."""

from enum import Enum
from pathlib import Path
from typing import Optional

from src.models import ScanResult
from src.modules.output.json_formatter import JSONFormatter
from src.modules.output.sarif_formatter import SARIFFormatter
from src.modules.output.pdf_generator import PDFGenerator


class ReportFormat(str, Enum):
    """Supported report output formats."""
    JSON = "json"
    SARIF = "sarif"
    PDF = "pdf"


class ReportGenerator:
    """Orchestrates report generation across multiple output formats.

    Takes ScanResult objects from any module and produces formatted reports
    in JSON, SARIF, or PDF. All output uses ZKIT-compatible hashing so raw
    PII never appears in reports.
    """

    def __init__(self, salt: str = ""):
        """
        Args:
            salt: ZKIT salt for hashing identifiers in output.
        """
        self._salt = salt
        self._json = JSONFormatter(salt=salt)
        self._sarif = SARIFFormatter(salt=salt)
        self._pdf = PDFGenerator(salt=salt)

    def generate(
        self,
        results: list[ScanResult],
        fmt: ReportFormat = ReportFormat.JSON,
    ) -> bytes:
        """Generate a report from scan results.

        Args:
            results: ScanResult objects to include in the report.
            fmt: Output format (json, sarif, pdf).
        Returns:
            Report content as bytes.
        """
        if fmt == ReportFormat.JSON:
            return self._json.format(results).encode("utf-8")
        elif fmt == ReportFormat.SARIF:
            return self._sarif.format(results).encode("utf-8")
        elif fmt == ReportFormat.PDF:
            return self._pdf.generate(results)
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    def generate_all(self, results: list[ScanResult]) -> dict[ReportFormat, bytes]:
        """Generate reports in all supported formats.

        Args:
            results: ScanResult objects to include.
        Returns:
            Dict mapping format to report bytes.
        """
        return {fmt: self.generate(results, fmt) for fmt in ReportFormat}

    def save(
        self,
        results: list[ScanResult],
        output_dir: str | Path,
        fmt: ReportFormat = ReportFormat.JSON,
        filename: Optional[str] = None,
    ) -> Path:
        """Generate and save a report to disk.

        Args:
            results: ScanResult objects to include.
            output_dir: Directory to write the report file.
            fmt: Output format.
            filename: Optional filename. Defaults to 'report.<ext>'.
        Returns:
            Path to the written file.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        extensions = {
            ReportFormat.JSON: "json",
            ReportFormat.SARIF: "sarif",
            ReportFormat.PDF: "pdf",
        }
        ext = extensions[fmt]
        fname = filename or f"report.{ext}"
        file_path = output_path / fname

        content = self.generate(results, fmt)
        file_path.write_bytes(content)
        return file_path
