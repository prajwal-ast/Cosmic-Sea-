from __future__ import annotations

from dataclasses import dataclass
from math import cos, sin


@dataclass
class SatelliteNode:
    satellite_id: str
    role: str = "satellite"
    orbital_phase_deg: float = 0.0
    altitude_km: float = 550.0

    def position(self) -> tuple[float, float, float]:
        phase_rad = self.orbital_phase_deg * 3.141592653589793 / 180.0
        radius = 6371.0 + self.altitude_km
        x = radius * cos(phase_rad)
        y = radius * sin(phase_rad)
        z = self.altitude_km * sin(phase_rad / 2.0)
        return (round(x, 2), round(y, 2), round(z, 2))


@dataclass
class GroundStation:
    station_id: str = "GROUND-ALPHA"
    role: str = "ground_station"
