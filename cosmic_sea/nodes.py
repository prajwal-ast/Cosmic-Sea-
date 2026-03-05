from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SatelliteNode:
    satellite_id: str
    role: str = "satellite"


@dataclass
class GroundStation:
    station_id: str = "GROUND-ALPHA"
    role: str = "ground_station"
