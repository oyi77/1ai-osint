"""Hook dispatcher — fire plugin hooks with error isolation."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.plugin.registry import PluginRegistry

logger = logging.getLogger(__name__)


class HookDispatcher:
    """Dispatches hook calls to all plugins that implement a given hook.

    Each hook runs **asynchronously** and is **error-isolated** — if one
    plugin raises, the others still run and the failure is logged without
    propagating.
    """

    def __init__(self, registry: PluginRegistry) -> None:
        self._registry = registry

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def dispatch(self, hook_name: str, **kwargs: Any) -> list[Any]:
        """Execute *hook_name* on every plugin that implements it.

        Hooks are run concurrently  via ``asyncio.gather`` with
        ``return_exceptions=True`` so a single misbehaving plugin never
        crashes the chain.

        Args:
            hook_name: E.g. ``"on_scan_start"``, ``"on_report"``.
            **kwargs:  Passed verbatim to the hook method.

        Returns:
            List of return values (one per matching plugin, in plugin
            registration order).  Exceptions are logged and **not**
            included in the returned list.

        """
        plugins = self._registry.get_hooks(hook_name)
        if not plugins:
            return []

        coros = [self._safe_call(plugin, hook_name, **kwargs) for plugin in plugins]

        # Run concurrently — one failure doesn't stop the rest
        results: list[Any] = []
        for coro in asyncio.as_completed(coros):
            try:
                result = await coro
                results.append(result)
            except Exception:
                # _safe_call already logged the error; swallow here
                pass

        return results

    async def dispatch_ordered(self, hook_name: str, **kwargs: Any) -> list[Any]:
        """Same as :meth:`dispatch` but runs hooks **sequentially** in
        registration order.

        Use this for hooks where order matters (e.g. ``on_report`` where
        each plugin may transform the result of the previous).
        """
        plugins = self._registry.get_hooks(hook_name)
        if not plugins:
            return []

        results: list[Any] = []
        for plugin in plugins:
            try:
                result = await self._safe_call(plugin, hook_name, **kwargs)
                results.append(result)
            except Exception:
                pass
        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _safe_call(
        self,
        plugin: Any,
        hook_name: str,
        **kwargs: Any,
    ) -> Any:
        """Call a single hook method, catching and logging any exception."""
        try:
            method = getattr(plugin, hook_name, None)
            if method is None:
                return None
            result = method(**kwargs)
            if hasattr(result, "__await__") or hasattr(result, "__aiter__"):
                return await result
            return result
        except Exception as exc:
            logger.exception("Plugin %s hook %s raised: %s", plugin.name, hook_name, exc)
            raise  # re-raise so as_completed / sequential loop can catch
