"""Infrastructure Fingerprinting Engine — Phase 5 Pillar 5.

Builds complete infrastructure maps by correlating:
- TLS certificate SANs and issuer chains
- ASN/hosting provider identification
- Favicon hash clustering (mmh3 technique)
- Registrar and nameserver relationships
- Co-hosted infrastructure detection

All network calls use httpx with graceful fallback on timeout/error.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import ssl

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0
_IPINFO_URL = "https://ipinfo.io/{ip}/json"


class InfraFingerprint(BaseModel):
    """Infrastructure fingerprint for a single domain."""

    domain: str
    resolved_ips: list[str] = Field(default_factory=list)
    tls_cert_sha256: str | None = None
    tls_cert_sans: list[str] = Field(default_factory=list)
    tls_cert_issuer: str = ""
    tls_cert_subject: str = ""
    asn: str | None = None
    hosting_provider: str | None = None
    favicon_hash: int | None = None  # mmh3-style: Murmur3-like hash
    registrar: str = ""
    nameservers: list[str] = Field(default_factory=list)
    related_domains: list[str] = Field(default_factory=list)


class InfraCluster(BaseModel):
    """A cluster of domains sharing infrastructure characteristics."""

    cluster_id: str
    domains: list[str]
    shared_attribute: str  # "tls_cert" | "asn" | "favicon" | "nameserver"
    shared_value: str
    confidence: float = 0.7


class InfraFingerprintEngine:
    """Fingerprint and correlate domain infrastructure."""

    @staticmethod
    def _resolve_domain(domain: str) -> list[str]:
        """Resolve domain to IP addresses."""
        try:
            results = socket.getaddrinfo(domain, None)
            return list({str(r[4][0]) for r in results})
        except (socket.gaierror, OSError):
            return []

    @staticmethod
    def _get_tls_cert(domain: str, port: int = 443) -> dict | None:
        """Fetch TLS certificate details for a domain."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_sha256 = hashlib.sha256(cert_bin).hexdigest() if cert_bin else None
                    return {"cert": cert, "sha256": cert_sha256}
        except Exception:
            return None

    @staticmethod
    def _extract_cert_sans(cert: dict) -> list[str]:
        """Extract Subject Alternative Names from a cert dict."""
        sans = []
        for key, values in cert.get("subjectAltName", []):
            if key == "DNS":
                sans.append(values)
        return sans

    @staticmethod
    def _extract_cert_field(cert: dict, field: str) -> str:
        """Extract a field like CN from subject or issuer tuples."""
        for rdn in cert.get(field, []):
            for attr_type, attr_value in rdn:
                if attr_type == "commonName" or attr_type == "organizationName":
                    return attr_value
        return ""

    @staticmethod
    def _simple_hash(data: bytes) -> int:
        """Compute a simple integer hash for favicon content (mmh3-inspired).

        Uses first 4 bytes of MD5 as a deterministic integer.
        """
        digest = hashlib.md5(data).digest()
        return int.from_bytes(digest[:4], "big", signed=True)

    async def _fetch_favicon_hash(self, domain: str) -> int | None:
        """Fetch and hash the favicon.ico for a domain."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}/favicon.ico"
            try:
                async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200 and resp.content:
                        return self._simple_hash(resp.content)
            except Exception:
                continue
        return None

    async def _fetch_asn_info(self, ip: str) -> dict:
        """Fetch ASN and org info from ipinfo.io (no key required for basic data)."""
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(_IPINFO_URL.format(ip=ip))
                if resp.status_code == 200:
                    return resp.json()
        except Exception:
            pass
        return {}

    @staticmethod
    def _get_nameservers(domain: str) -> list[str]:
        """Get nameservers for domain via socket/DNS."""
        try:
            import subprocess

            result = subprocess.run(
                ["dig", "+short", "NS", domain],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            ns = [ns.rstrip(".") for ns in result.stdout.strip().splitlines() if ns.strip()]
            return ns[:4]
        except Exception:
            return []

    async def fingerprint_domain(self, domain: str) -> InfraFingerprint:
        """Build a full infrastructure fingerprint for a domain."""
        fp = InfraFingerprint(domain=domain)

        # DNS resolution
        fp.resolved_ips = self._resolve_domain(domain)

        # TLS certificate
        cert_data = self._get_tls_cert(domain)
        if cert_data:
            cert = cert_data.get("cert", {})
            fp.tls_cert_sha256 = cert_data.get("sha256")
            fp.tls_cert_sans = self._extract_cert_sans(cert)
            fp.tls_cert_issuer = self._extract_cert_field(cert, "issuer")
            fp.tls_cert_subject = self._extract_cert_field(cert, "subject")
            # Related domains from SANs (excluding wildcards)
            fp.related_domains = [s for s in fp.tls_cert_sans if not s.startswith("*") and s != domain][:20]

        # ASN/hosting info
        if fp.resolved_ips:
            asn_data = await self._fetch_asn_info(fp.resolved_ips[0])
            fp.asn = asn_data.get("org", "").split(" ")[0] if asn_data.get("org") else None
            fp.hosting_provider = asn_data.get("org", "")

        # Favicon hash
        fp.favicon_hash = await self._fetch_favicon_hash(domain)

        # Nameservers
        fp.nameservers = self._get_nameservers(domain)

        return fp

    async def correlate_infrastructure(
        self,
        fingerprints: list[InfraFingerprint],
    ) -> list[InfraCluster]:
        """Identify clusters of domains sharing infrastructure characteristics."""
        clusters: list[InfraCluster] = []
        cluster_idx = 0

        # Group by TLS cert hash
        cert_groups: dict[str, list[str]] = {}
        for fp in fingerprints:
            if fp.tls_cert_sha256:
                cert_groups.setdefault(fp.tls_cert_sha256, []).append(fp.domain)
        for cert_hash, domains in cert_groups.items():
            if len(domains) > 1:
                clusters.append(
                    InfraCluster(
                        cluster_id=f"tls_{cluster_idx}",
                        domains=domains,
                        shared_attribute="tls_cert",
                        shared_value=cert_hash[:16] + "...",
                        confidence=0.95,
                    )
                )
                cluster_idx += 1

        # Group by ASN
        asn_groups: dict[str, list[str]] = {}
        for fp in fingerprints:
            if fp.asn:
                asn_groups.setdefault(fp.asn, []).append(fp.domain)
        for asn, domains in asn_groups.items():
            if len(domains) > 1:
                clusters.append(
                    InfraCluster(
                        cluster_id=f"asn_{cluster_idx}",
                        domains=domains,
                        shared_attribute="asn",
                        shared_value=asn,
                        confidence=0.6,
                    )
                )
                cluster_idx += 1

        # Group by favicon hash
        favicon_groups: dict[int, list[str]] = {}
        for fp in fingerprints:
            if fp.favicon_hash is not None:
                favicon_groups.setdefault(fp.favicon_hash, []).append(fp.domain)
        for fav_hash, domains in favicon_groups.items():
            if len(domains) > 1:
                clusters.append(
                    InfraCluster(
                        cluster_id=f"favicon_{cluster_idx}",
                        domains=domains,
                        shared_attribute="favicon",
                        shared_value=str(fav_hash),
                        confidence=0.80,
                    )
                )
                cluster_idx += 1

        # Group by nameserver
        ns_groups: dict[str, list[str]] = {}
        for fp in fingerprints:
            for ns in fp.nameservers:
                ns_groups.setdefault(ns, []).append(fp.domain)
        for ns, domains in ns_groups.items():
            if len(domains) > 1:
                clusters.append(
                    InfraCluster(
                        cluster_id=f"ns_{cluster_idx}",
                        domains=domains,
                        shared_attribute="nameserver",
                        shared_value=ns,
                        confidence=0.5,
                    )
                )
                cluster_idx += 1

        return clusters
