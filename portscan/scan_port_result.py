from dataclasses import dataclass


@dataclass
class ScanPortResult:
    port: int
    time: float | None = None
    protocol: str | None = None
