from dataclasses import dataclass


@dataclass
class PacketInfo:
    number: int
    timestamp: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str