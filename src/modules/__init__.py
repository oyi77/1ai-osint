"""Module registry for 1ai-osint."""

import logging

from src.modules.base.base import BaseOSINTTool

logger = logging.getLogger(__name__)

# Module registry - maps module names to their classes
_MODULE_REGISTRY: dict[str, type] = {}


def register_module(name: str, cls: type) -> None:
    """Register a module class by name."""
    _MODULE_REGISTRY[name] = cls


def get_module(name: str) -> type:
    """Get a registered module class by name."""
    if name not in _MODULE_REGISTRY:
        raise KeyError(f"Module '{name}' not registered. Available: {list(_MODULE_REGISTRY.keys())}")
    return _MODULE_REGISTRY[name]


def list_modules() -> list[str]:
    """List all registered module names."""
    return list(_MODULE_REGISTRY.keys())


# Auto-register built-in modules
def _register_builtins():
    """Register built-in modules on import."""
    modules_to_register = [
        ("gitleaks", "src.modules.gitleaks.scanner", "GitleaksModule"),
        ("data_leaks", "src.modules.data_leaks.aggregator", "DataLeaksAggregator"),
        ("people_finder", "src.modules.people_finder", "PeopleFinderTool"),
        ("phone_finder", "src.modules.phone_finder", "PhoneFinderTool"),
        ("gc_lookup", "src.modules.phone_finder.gc_lookup", "GCLookupTool"),
        ("phone_intel", "src.modules.phone_intel", "PhoneIntelTool"),
        (
            "crypto_privatekey",
            "src.modules.crypto.privatekey.scanner",
            "PrivateKeyScanner",
        ),
        ("crypto_balance", "src.modules.crypto.balance", "CryptoBalanceTool"),
        ("crypto_tracer", "src.modules.crypto.tx_tracer", "BlockchainTxTracer"),
        ("domain_recon", "src.modules.domain_recon", "DomainReconTool"),
        ("email_osint", "src.modules.email_osint", "EmailOSINTTool"),
        ("social_osint", "src.modules.social_osint", "SocialOSINTTool"),
    ]

    for name, module_path, class_name in modules_to_register:
        try:
            import importlib

            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            register_module(name, cls)
        except (ImportError, AttributeError) as e:
            logger.debug("Module %s not available: %s", name, e)


_register_builtins()

__all__ = [
    "BaseOSINTTool",
    "register_module",
    "get_module",
    "list_modules",
]
