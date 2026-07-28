"""Neo4j integration for ZKIT identity graphs.

Provides:
- ``export_neo4j_json`` — convert an IdentityGraph to Neo4j-compatible JSON
- ``load_neo4j_json`` — restore an IdentityGraph from a JSON file
- ``Neo4jClient`` — real Neo4j Bolt driver with connect / query / bulk import

Supports both the old ``deep_scan.models_report.IdentityGraph`` (list-based)
and the new ``identity_tracking.identity_graph.IdentityGraph`` (method-based)
graph representations.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from src.modules.identity_tracking._neo4j_helpers import (
    NEO4J_PASSWORD,
    NEO4J_URI,
    NEO4J_USER,
    export_neo4j_json,
    load_neo4j_json,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attempt to import the neo4j driver — graceful fallback if unavailable
# ---------------------------------------------------------------------------

try:
    from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncSession
    from neo4j.exceptions import AuthError, ServiceUnavailable

    NEO4J_AVAILABLE = True
except ImportError:  # pragma: no cover
    NEO4J_AVAILABLE = False

    # Stub types so that annotations work even when neo4j is absent
    class AsyncDriver:  # type: ignore[no-redef]
        pass

    class AsyncSession:  # type: ignore[no-redef]
        async def __aenter__(self) -> Any:  # noqa: N805
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

        async def run(self, *args: Any, **kwargs: Any) -> Any: ...

        async def close(self) -> None:
            pass

    class ServiceUnavailable(Exception):  # type: ignore[no-redef]
        pass

    class AuthError(Exception):  # type: ignore[no-redef]
        pass


# ---------------------------------------------------------------------------
# Neo4j Bolt client
# ---------------------------------------------------------------------------


class Neo4jClient:
    """Real Neo4j Bolt driver with connection pooling and Cypher query support.

    Gracefully degrades when the ``neo4j`` package is not installed.

    Usage::

        async with Neo4jClient() as client:
            await client.connect(uri, user, password)
            await client.create_node("Person", {"name": "Alice"})
            await client.close()
    """

    def __init__(
        self,
        uri: str = "",
        user: str = "",
        password: str = "",
    ) -> None:
        """Args:
        uri: Bolt URI (defaults to ``NEO4J_URI`` env var).
        user: Neo4j username (defaults to ``NEO4J_USER`` env var).
        password: Neo4j password (defaults to ``NEO4J_PASSWORD`` env var).

        """
        self._uri = uri or NEO4J_URI
        self._user = user or NEO4J_USER
        self._password = password or NEO4J_PASSWORD
        self._driver: AsyncDriver | None = None
        self._connected = False

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect(
        self,
        uri: str = "",
        user: str = "",
        password: str = "",
    ) -> bool:
        """Establish a connection to the Neo4j database.

        Args:
            uri: Bolt URI. Falls back to the instance default then env var.
            user: Username. Falls back to instance default then env var.
            password: Password. Falls back to instance default then env var.

        Returns:
            True if connected successfully, False if the neo4j driver is
            not available (graceful fallback).

        Raises:
            neo4j.exceptions.ServiceUnavailable: If the server is unreachable.
            neo4j.exceptions.AuthError: If credentials are invalid.

        """
        uri = uri or self._uri
        user = user or self._user
        password = password or self._password

        if not NEO4J_AVAILABLE:
            logger.warning(
                "neo4j package not installed — Neo4jClient running in stub mode. "
                "Install with: pip install 'neo4j>=5.20.0'"
            )
            return False

        try:
            self._driver = AsyncGraphDatabase.driver(
                uri,
                auth=(user, password),
                max_connection_pool_size=10,
                connection_timeout=15,
            )
            # Verify connectivity
            await self._driver.verify_connectivity()
            self._connected = True
            logger.info("Connected to Neo4j at %s (user=%s)", uri, user)
            return True
        except ServiceUnavailable as e:
            logger.error("Neo4j server unreachable at %s: %s", uri, e)
            raise
        except AuthError as e:
            logger.error("Neo4j authentication failed for user %s: %s", user, e)
            raise

    async def close(self) -> None:
        """Close the driver and release all connections."""
        if self._driver is not None:
            await self._driver.close()
            self._driver = None
            self._connected = False
            logger.info("Neo4j connection closed")

    @property
    def is_connected(self) -> bool:
        """Check whether the driver has an active connection."""
        return self._connected and self._driver is not None

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

    def _session(self) -> AsyncSession:
        """Return a new session from the connection pool.

        Raises:
            RuntimeError: If not connected.

        """
        if not self._driver:
            raise RuntimeError("Neo4jClient not connected. Call connect() first.")
        return self._driver.session()

    # ------------------------------------------------------------------
    # CRUD operations
    # ------------------------------------------------------------------

    async def create_node(
        self,
        label: str,
        properties: dict[str, Any] | None = None,
    ) -> str | None:
        """Create a node with the given label and properties.

        Args:
            label: Node label (e.g. ``"EmailHash"``).
            properties: Optional dict of properties.

        Returns:
            The internal node id (string) on success, or ``None`` if the
            neo4j driver is unavailable (stub mode).

        """
        if not NEO4J_AVAILABLE or not self._driver:
            logger.debug("Neo4jClient stub: would create node %s(%s)", label, properties)
            return None

        props = properties or {}
        async with self._session() as session:
            result = await session.run(
                f"CREATE (n:{label} $props) RETURN elementId(n) AS id",
                props=props,
            )
            record = await result.single()
            return str(record["id"]) if record else None

    async def create_relationship(
        self,
        from_node_id: str,
        to_node_id: str,
        rel_type: str,
        properties: dict[str, Any] | None = None,
    ) -> str | None:
        """Create a relationship between two existing nodes.

        Args:
            from_node_id: Element ID (or property value) of the source node.
            to_node_id: Element ID (or property value) of the target node.
            rel_type: Relationship type (e.g. ``"CO_OCCURS_WITH"``).
            properties: Optional relationship properties.

        Returns:
            The relationship element ID, or ``None`` in stub mode.

        The method looks up nodes by ``elementId(n)`` for internal IDs
        or by ``n.id = $id`` for ZKIT hashed identifiers.

        """
        if not NEO4J_AVAILABLE or not self._driver:
            logger.debug(
                "Neo4jClient stub: would create rel %s ->[%s]-> %s",
                from_node_id,
                rel_type,
                to_node_id,
            )
            return None

        props = properties or {}
        async with self._session() as session:
            # Try matching by elementId first, then by property "id"
            result = await session.run(
                f"""
                MATCH (a), (b)
                WHERE elementId(a) = $from_id OR a.id = $from_id
                  AND elementId(b) = $to_id OR b.id = $to_id
                CREATE (a)-[r:{rel_type} $props]->(b)
                RETURN elementId(r) AS rid
                """,
                from_id=from_node_id,
                to_id=to_node_id,
                props=props,
            )
            record = await result.single()
            return str(record["rid"]) if record else None

    async def run_query(
        self,
        cypher: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute an arbitrary Cypher query.

        Args:
            cypher: The Cypher query string.
            parameters: Optional query parameters.

        Returns:
            A list of result records as dicts, or an empty list in stub mode.

        Raises:
            RuntimeError: If not connected.

        """
        if not NEO4J_AVAILABLE or not self._driver:
            logger.debug("Neo4jClient stub: would run query: %s", cypher[:120])
            return []

        async with self._session() as session:
            result = await session.run(cypher, parameters or {})
            records = await result.data()
            return records

    # ------------------------------------------------------------------
    # Bulk import from IdentityGraph
    # ------------------------------------------------------------------

    async def bulk_import(
        self,
        nodes: Sequence[dict[str, Any]] | None = None,
        relationships: Sequence[dict[str, Any]] | None = None,
        graph: Any | None = None,
    ) -> dict[str, int]:
        """Batch-import nodes and relationships into Neo4j.

        Accepts either raw ``nodes`` / ``relationships`` lists (as produced by
        :func:`export_neo4j_json`) or an ``IdentityGraph`` instance via the
        ``graph`` parameter.

        Args:
            nodes: List of node dicts with ``id``, ``labels``, ``properties``.
            relationships: List of relationship dicts with ``start``, ``end``,
                ``type``, ``properties``.
            graph: Alternative — an IdentityGraph instance (new or old style).

        Returns:
            A dict with ``nodes_created`` and ``rels_created`` counts.

        """
        # Resolve input
        if graph is not None:
            data = export_neo4j_json(graph)
            nodes = data.get("nodes", [])
            relationships = data.get("relationships", [])

        if not nodes:
            return {"nodes_created": 0, "rels_created": 0}

        if not NEO4J_AVAILABLE or not self._driver:
            logger.info(
                "Neo4jClient stub: would bulk-import %d nodes and %d relationships",
                len(nodes),
                len(relationships or []),
            )
            return {"nodes_created": 0, "rels_created": 0}

        created_nodes = 0
        created_rels = 0

        async with self._session() as session:
            # Create all nodes
            for n in nodes:
                node_id = n.get("id", "")
                labels = n.get("labels", ["ENTITY"])
                props = n.get("properties", {})
                props["id"] = node_id  # store the ZKIT hash as a property
                label_str = ":".join(labels)

                await session.run(
                    f"MERGE (n:{label_str} {{id: $node_id}}) SET n += $props",
                    node_id=node_id,
                    props=props,
                )
                created_nodes += 1

            # Create all relationships
            if relationships:
                for r in relationships:
                    rel_type = r.get("type", "RELATED_TO")
                    start_id = r.get("start", "")
                    end_id = r.get("end", "")
                    props = r.get("properties", {})

                    await session.run(
                        f"""
                        MATCH (a {{id: $start_id}})
                        MATCH (b {{id: $end_id}})
                        MERGE (a)-[r:{rel_type}]->(b)
                        SET r += $props
                        """,
                        start_id=start_id,
                        end_id=end_id,
                        props=props,
                    )
                    created_rels += 1

        logger.info(
            "Neo4j bulk import: %d nodes, %d relationships",
            created_nodes,
            created_rels,
        )
        return {"nodes_created": created_nodes, "rels_created": created_rels}

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> Neo4jClient:
        if not self._connected:
            await self.connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


__all__ = [
    "Neo4jClient",
    "export_neo4j_json",
    "load_neo4j_json",
    "NEO4J_AVAILABLE",
]
