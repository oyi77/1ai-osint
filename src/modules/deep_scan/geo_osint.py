"""Geospatial OSINT Engine — Phase 5 Pillar 4.

Fuses geospatial signals from multiple OSINT sources:
- EXIF metadata extraction from images (GPS coordinates, device info)
- IP geolocation clustering (probable home/work locations)
- Location timeline construction from evidence timestamps

All coordinates are rounded to ~1km precision (geohash-6) in reports
to avoid exact address disclosure.
"""

from __future__ import annotations

import logging
import math
import re
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Geohash alphabet
_BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz"


class LocationEvent(BaseModel):
    """A geolocation event extracted from evidence."""

    timestamp: Optional[datetime] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    geohash: str = ""
    source: str = ""
    label: str = ""
    confidence: float = 0.5
    raw_address: str = ""


class GeoCluster(BaseModel):
    """A cluster of location events around a probable physical location."""

    centroid_lat: float = 0.0
    centroid_lon: float = 0.0
    geohash: str = ""  # 6-char ~1.2km precision
    radius_km: float = 0.0
    evidence_count: int = 0
    label: str = "unknown"  # probable home | frequent location | one-time
    sources: list[str] = Field(default_factory=list)


class GeoOSINTEngine:
    """Fuse geospatial signals from OSINT evidence."""

    @staticmethod
    def encode_geohash(lat: float, lon: float, precision: int = 6) -> str:
        """Encode latitude/longitude as a geohash string.

        Precision 6 = ~1.2km x 0.6km cells.
        """
        lat_range = (-90.0, 90.0)
        lon_range = (-180.0, 180.0)
        bits = 0
        num_bits = 0
        result = []
        is_lon = True  # alternate between lon and lat

        for _ in range(precision * 5):
            if is_lon:
                mid = (lon_range[0] + lon_range[1]) / 2
                if lon >= mid:
                    bits = (bits << 1) | 1
                    lon_range = (mid, lon_range[1])
                else:
                    bits = bits << 1
                    lon_range = (lon_range[0], mid)
            else:
                mid = (lat_range[0] + lat_range[1]) / 2
                if lat >= mid:
                    bits = (bits << 1) | 1
                    lat_range = (mid, lat_range[1])
                else:
                    bits = bits << 1
                    lat_range = (lat_range[0], mid)
            is_lon = not is_lon
            num_bits += 1
            if num_bits == 5:
                result.append(_BASE32[bits])
                bits = 0
                num_bits = 0

        return "".join(result)

    @staticmethod
    def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Compute great-circle distance between two points in km."""
        R = 6371.0
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)
        a = (
            math.sin(dphi / 2) ** 2
            + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
        )
        return R * 2 * math.asin(math.sqrt(a))

    def extract_exif_coords(
        self, exif_data: dict[str, Any]
    ) -> Optional[tuple[float, float]]:
        """Extract GPS coordinates from EXIF metadata dict.

        Expects keys like: GPS_Latitude, GPS_Longitude, GPSLatitude, GPSLongitude
        or GPS.GPSLatitude / GPS.GPSLongitude in DMS or decimal format.
        """
        # Try decimal format first
        for lat_key in ("GPS_Latitude", "GPSLatitude", "Latitude", "lat"):
            for lon_key in ("GPS_Longitude", "GPSLongitude", "Longitude", "lon"):
                lat = exif_data.get(lat_key)
                lon = exif_data.get(lon_key)
                if lat is not None and lon is not None:
                    try:
                        lat_f = float(lat)
                        lon_f = float(lon)
                        if -90 <= lat_f <= 90 and -180 <= lon_f <= 180:
                            return (round(lat_f, 4), round(lon_f, 4))
                    except (ValueError, TypeError):
                        pass

        # Try DMS string format: "51 deg 30' 26.00" N"
        for lat_key in ("GPS_Latitude", "GPSLatitude"):
            lat_str = exif_data.get(lat_key, "")
            lon_str = exif_data.get(
                lat_key.replace("Lat", "Lon").replace("lat", "lon"), ""
            )
            lat_f = self._parse_dms(str(lat_str))
            lon_f = self._parse_dms(str(lon_str))
            if lat_f is not None and lon_f is not None:
                return (round(lat_f, 4), round(lon_f, 4))

        return None

    @staticmethod
    def _parse_dms(dms_str: str) -> Optional[float]:
        """Parse a DMS string like '51 deg 30\' 26.00" N' to decimal degrees."""
        pattern = re.compile(r"(\d+)\s*deg\s*(\d+)'\s*([\d.]+)\"?\s*([NSEW]?)")
        m = pattern.search(dms_str)
        if not m:
            return None
        d, mn, s, direction = (
            int(m.group(1)),
            int(m.group(2)),
            float(m.group(3)),
            m.group(4).upper(),
        )
        decimal = d + mn / 60 + s / 3600
        if direction in ("S", "W"):
            decimal = -decimal
        return decimal

    def cluster_ip_locations(self, ip_geos: list[dict[str, Any]]) -> list[GeoCluster]:
        """Cluster IP geolocation data into probable physical locations.

        Args:
            ip_geos: list of dicts with keys: ip, lat, lon, source (optional)
        """
        # Convert to LocationEvent list
        events = []
        for geo in ip_geos:
            lat = geo.get("lat")
            lon = geo.get("lon")
            if lat is None or lon is None:
                continue
            try:
                events.append(
                    LocationEvent(
                        lat=float(lat),
                        lon=float(lon),
                        source=geo.get("source", "ipinfo"),
                        label=geo.get("ip", ""),
                        confidence=0.6,
                    )
                )
            except (ValueError, TypeError):
                continue

        return self._cluster_events(events)

    def _cluster_events(self, events: list[LocationEvent]) -> list[GeoCluster]:
        """Simple greedy geographic clustering (50km radius)."""
        CLUSTER_RADIUS_KM = 50.0
        clusters: list[list[LocationEvent]] = []

        for event in events:
            if event.lat is None or event.lon is None:
                continue
            placed = False
            for cluster in clusters:
                centroid = cluster[0]
                if centroid.lat is None or centroid.lon is None:
                    continue
                dist = self.haversine_km(
                    event.lat, event.lon, centroid.lat, centroid.lon
                )
                if dist <= CLUSTER_RADIUS_KM:
                    cluster.append(event)
                    placed = True
                    break
            if not placed:
                clusters.append([event])

        result = []
        for cluster in clusters:
            lats = [e.lat for e in cluster if e.lat is not None]
            lons = [e.lon for e in cluster if e.lon is not None]
            if not lats:
                continue
            centroid_lat = sum(lats) / len(lats)
            centroid_lon = sum(lons) / len(lons)
            max_dist = max(
                self.haversine_km(centroid_lat, centroid_lon, e.lat, e.lon)
                for e in cluster
                if e.lat is not None
            )
            count = len(cluster)
            label = (
                "probable home/work"
                if count >= 3
                else "frequent location"
                if count == 2
                else "one-time"
            )
            result.append(
                GeoCluster(
                    centroid_lat=round(centroid_lat, 4),
                    centroid_lon=round(centroid_lon, 4),
                    geohash=self.encode_geohash(
                        centroid_lat, centroid_lon, precision=6
                    ),
                    radius_km=round(max_dist, 1),
                    evidence_count=count,
                    label=label,
                    sources=list({e.source for e in cluster}),
                )
            )

        return sorted(result, key=lambda c: c.evidence_count, reverse=True)

    def build_location_timeline(
        self,
        evidence: list[Any],  # EvidenceItem-like objects
    ) -> list[LocationEvent]:
        """Extract location events from an evidence list."""
        events = []
        for ev in evidence:
            raw = getattr(ev, "raw_data", {}) or {}
            source = getattr(ev, "source", "unknown")
            captured_at = getattr(ev, "captured_at", None)

            # Try GPS from raw_data
            coords = self.extract_exif_coords(raw)
            if coords:
                lat, lon = coords
                events.append(
                    LocationEvent(
                        timestamp=captured_at,
                        lat=lat,
                        lon=lon,
                        geohash=self.encode_geohash(lat, lon),
                        source=source,
                        label="exif",
                        confidence=0.85,
                    )
                )
                continue

            # Try address fields
            for key in ("city", "region", "country", "location"):
                val = raw.get(key)
                if val:
                    events.append(
                        LocationEvent(
                            timestamp=captured_at,
                            source=source,
                            label=key,
                            raw_address=str(val),
                            confidence=0.5,
                        )
                    )
                    break

        return sorted(
            [e for e in events if e.timestamp is not None],
            key=lambda e: e.timestamp or datetime.min,
        )
