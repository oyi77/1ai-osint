"""Intel report exports — multi-format output for IntelReport objects.

Supports:
  - HTML (single-file, self-contained, with inline SVG)
  - JSON (schema-versioned)
  - STIX 2.1 (Intelligence Bundle with Identity, URL, Relationship SDOs)
  - PDF (via WeasyPrint, optional)
"""
from src.modules.deep_scan.models_report import IntelReport

from .json_export import export_json
from .html_export import export_html
from .stix_export import export_stix
from .pdf_briefing import export_pdf


def export_report(report: IntelReport, fmt: str = "html") -> str | bytes:
    """Export an IntelReport in the requested format.

    Args:
        report: IntelReport to export.
        fmt: One of 'html', 'json', 'stix', 'pdf'.

    Returns:
        Serialized string (or bytes for pdf) in the requested format.
    """
    if fmt == "pdf":
        return export_pdf(report)
    exporters = {
        "html": export_html,
        "json": export_json,
        "stix": export_stix,
    }
    exporter = exporters.get(fmt)
    if not exporter:
        raise ValueError(f"Unknown export format: {fmt}. Supported: {', '.join(exporters)}")
    return exporter(report)
