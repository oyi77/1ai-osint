"""Tests for Phase 5 Pillar 4: Geospatial OSINT Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from src.modules.deep_scan.geo_osint import GeoOSINTEngine


@pytest.fixture
def engine():
    return GeoOSINTEngine()


def test_encode_geohash_london(engine):
    """London is approximately at 51.5, -0.1 — geohash starts with 'gcpu'."""
    gh = engine.encode_geohash(51.5, -0.1)
    assert len(gh) == 6
    assert gh.startswith("gcpu")  # well-known London geohash prefix


def test_encode_geohash_precision(engine):
    gh = engine.encode_geohash(40.7128, -74.0060, precision=4)
    assert len(gh) == 4


def test_haversine_km_same_point(engine):
    dist = engine.haversine_km(51.5, -0.1, 51.5, -0.1)
    assert dist == pytest.approx(0.0, abs=0.01)


def test_haversine_km_london_paris(engine):
    """London to Paris is about 340 km."""
    dist = engine.haversine_km(51.507, -0.127, 48.857, 2.352)
    assert 330 < dist < 350


def test_extract_exif_coords_decimal(engine):
    exif = {"GPSLatitude": "51.5074", "GPSLongitude": "-0.1278"}
    coords = engine.extract_exif_coords(exif)
    assert coords is not None
    lat, lon = coords
    assert abs(lat - 51.5074) < 0.001
    assert abs(lon - (-0.1278)) < 0.001


def test_extract_exif_coords_missing(engine):
    coords = engine.extract_exif_coords({})
    assert coords is None


def test_extract_exif_coords_invalid(engine):
    coords = engine.extract_exif_coords({"GPSLatitude": "not_a_number", "GPSLongitude": "also_not"})
    assert coords is None


def test_extract_exif_coords_out_of_range(engine):
    coords = engine.extract_exif_coords({"GPSLatitude": "999", "GPSLongitude": "999"})
    assert coords is None


def test_parse_dms_valid(engine):
    # 51 deg 30' 26.00" N
    result = engine._parse_dms("51 deg 30' 26.00\" N")
    assert result is not None
    assert abs(result - 51.507) < 0.01


def test_parse_dms_south(engine):
    result = engine._parse_dms("33 deg 52' 0.00\" S")
    assert result is not None
    assert result < 0


def test_parse_dms_invalid(engine):
    result = engine._parse_dms("not a coordinate")
    assert result is None


def test_cluster_ip_locations_groups_nearby(engine):
    ip_geos = [
        {"ip": "1.1.1.1", "lat": 51.5, "lon": -0.1},
        {"ip": "1.1.1.2", "lat": 51.51, "lon": -0.11},
        {"ip": "1.1.1.3", "lat": 51.49, "lon": -0.09},
        {"ip": "2.2.2.1", "lat": 40.71, "lon": -74.01},  # New York — different cluster
    ]
    clusters = engine.cluster_ip_locations(ip_geos)
    assert len(clusters) == 2
    assert clusters[0].evidence_count == 3  # London cluster has more


def test_cluster_ip_locations_labels(engine):
    ip_geos = [{"ip": f"1.1.1.{i}", "lat": 51.5 + i * 0.001, "lon": -0.1} for i in range(5)]
    clusters = engine.cluster_ip_locations(ip_geos)
    assert clusters[0].label == "probable home/work"


def test_cluster_ip_locations_empty(engine):
    clusters = engine.cluster_ip_locations([])
    assert clusters == []


def test_cluster_ip_locations_invalid_coords(engine):
    clusters = engine.cluster_ip_locations([{"ip": "1.2.3.4", "lat": None, "lon": None}])
    assert clusters == []


def test_build_location_timeline_from_evidence(engine):
    ev = MagicMock()
    ev.raw_data = {"GPSLatitude": "51.5", "GPSLongitude": "-0.1"}
    ev.source = "exiftool"
    ev.captured_at = datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc)

    events = engine.build_location_timeline([ev])
    assert len(events) == 1
    assert events[0].label == "exif"
    assert events[0].confidence == 0.85


def test_build_location_timeline_city_fallback(engine):
    ev = MagicMock()
    ev.raw_data = {"city": "Jakarta"}
    ev.source = "ipinfo"
    ev.captured_at = datetime(2024, 1, 15, tzinfo=timezone.utc)

    events = engine.build_location_timeline([ev])
    assert len(events) == 1
    assert events[0].raw_address == "Jakarta"
