from abc import ABC, abstractmethod
from typing import Any

from portscan.scan_port_result import ScanPortResult


class BaseScaner(ABC):
    def __init__(
        self,
        scan_manager: Any,
        target_ip: str,
        ports: list[int],
        client_ip: str,
        timeout: float = 2.0,
    ) -> None:
        self.scan_manager = scan_manager
        self.target_ip: str = target_ip
        self.ports: list[int] = ports
        self.timeout: float = timeout
        self.client_ip: str = client_ip

    @abstractmethod
    def start(self) -> None:
        ...

    @abstractmethod
    def handle(self, fd: int, event: int) -> None:
        ...

    @abstractmethod
    def is_finished(self) -> bool:
        ...

    @abstractmethod
    def get_results(self) -> list[ScanPortResult]:
        ...

    @abstractmethod
    def cleanup(self) -> None:
        ...

    @abstractmethod
    def is_sending(self) -> bool:
        ...
