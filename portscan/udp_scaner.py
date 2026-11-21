import select
import socket
import time
from collections import deque
from dataclasses import dataclass

from portscan.base_scaner import BaseScaner
from portscan.scan_port_result import ScanPortResult


@dataclass(frozen=True)
class UdpPingInfo:
    port: int
    sent_time: float


class UdpScaner(BaseScaner):
    SEND_BATCH_SIZE: int = 512

    def __init__(
        self,
        ports: list[int],
        scan_manager,
        target_ip: str,
        client_ip: str,
        timeout: float = 2.0,
    ) -> None:
        super().__init__(scan_manager, target_ip, ports, client_ip, timeout)
        self._udp_sock: socket.socket | None = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM
        )
        self._udp_sock.setblocking(False)
        self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 10 * 1024 * 1024)

        self.ports_to_info: dict[int, UdpPingInfo] = {}
        self._timeout_time: float | None = None
        self._results: dict[int, ScanPortResult] = {}
        self._unresolved_ports: set[int] = set()
        self._send_queue: deque[int] = deque()

    def start(self) -> None:
        if self._udp_sock is None:
            return

        for port in self.ports:
            self._send_queue.append(port)
            self._unresolved_ports.add(port)

        self.scan_manager.register(
            self._udp_sock.fileno(),
            self.handle,
            select.EPOLLIN | select.EPOLLOUT,
        )

    def _send_pending(self) -> None:
        if self._udp_sock is None:
            return

        sent = 0
        while self._send_queue and sent < self.SEND_BATCH_SIZE:
            port = self._send_queue[0]
            try:
                self._udp_sock.sendto(b"", (self.target_ip, port))
            except BlockingIOError:
                return
            except OSError:
                self._send_queue.popleft()
                self._unresolved_ports.discard(port)
                continue

            self._send_queue.popleft()
            self.ports_to_info[port] = UdpPingInfo(
                port=port, sent_time=time.monotonic()
            )
            sent += 1

        if not self._send_queue:
            self.scan_manager.modify(self._udp_sock.fileno(), select.EPOLLIN)
            self._timeout_time = time.monotonic() + self.timeout

    def _recv_pending(self) -> None:
        if self._udp_sock is None:
            return

        while True:
            try:
                _data, addr = self._udp_sock.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break

            received_from_ip, received_from_port = addr[0], addr[1]
            if received_from_ip != self.target_ip:
                continue

            if received_from_port in self.ports_to_info:
                info = self.ports_to_info[received_from_port]
                response_time = (time.monotonic() - info.sent_time) * 1000.0
                self._results[received_from_port] = ScanPortResult(
                    port=received_from_port,
                    time=response_time,
                )
                self._unresolved_ports.discard(received_from_port)

    def handle(self, fd: int, event: int) -> None:
        if self._udp_sock is None or fd != self._udp_sock.fileno():
            raise ValueError()

        if event & select.EPOLLOUT:
            self._send_pending()

        if event & select.EPOLLIN:
            self._recv_pending()

    def is_sending(self) -> bool:
        return self._udp_sock is not None and bool(self._send_queue)

    def is_finished(self) -> bool:
        if self._send_queue:
            return False
        if not self._unresolved_ports:
            return True
        return (
            self._timeout_time is not None
            and time.monotonic() >= self._timeout_time
        )

    def get_results(self) -> list[ScanPortResult]:
        return [self._results[port] for port in self.ports if port in self._results]

    def cleanup(self) -> None:
        self._send_queue.clear()
        if self._udp_sock is not None:
            self.scan_manager.unregister(self._udp_sock.fileno())
            try:
                self._udp_sock.close()
            except OSError:
                pass
            self._udp_sock = None