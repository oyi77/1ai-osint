"""1ai-osint — AI-Powered OSINT & ZKIT Research Platform."""

try:
    from importlib.metadata import version as _v

    __version__ = _v("1ai-osint")
except Exception:
    __version__ = "0.1.0"
