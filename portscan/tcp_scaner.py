import select
import socket
import time
from collections import deque
from dataclasses import dataclass

from portscan.base_scaner import BaseScaner
from portscan.scan_port_result import ScanPortResult
from portscan.tcp_network_filter import TcpNetworkFilter
from portscan.tcp_segment import TcpSegment
from portscan.utils import get_available_port


@dataclass(frozen=True)
class PingInfo:
    seq: int
    filter: TcpNetworkFilter
    sent_time: float


class TcpScaner(BaseScaner):
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
        self._sock: socket.socket | None = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
        )
        self._sock.setblocking(False)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 10 * 1024 * 1024)  # 10 MB
        self.ports_to_info: dict[int, PingInfo] = {}
        self._available_port: int = get_available_port()
        self._timeout_time: float | None = None
        self._results: dict[int, ScanPortResult] = {}
        self._unresolved_ports: set[int] = set()

        self._send_queue: deque[tuple[int, int, TcpSegment]] = deque() # (target_port, client_port, TcpSegment)

    def start(self) -> None:
        if self._sock is None:
            return

        for idx, port in enumerate(self.ports):
            client_port = ((self._available_port + idx - 1024) % 64511) + 1024
            segment = TcpSegment(port, client_port, self.target_ip, self.client_ip)
            self._send_queue.append((port, client_port, segment))
            self._unresolved_ports.add(port)

        self.scan_manager.register(
            self._sock.fileno(),
            self.handle,
            select.EPOLLIN | select.EPOLLOUT,
        )

    def _send_pending(self) -> None:
        sent = 0
        while self._send_queue and sent < self.SEND_BATCH_SIZE:
            port, client_port, segment = self._send_queue[0]
            try:
                self._sock.sendto(segment.tcp_syn_segment, (self.target_ip, port))
            except BlockingIOError:
                return
            except OSError:
                self._send_queue.popleft()
                self._unresolved_ports.discard(port)
                continue

            self._send_queue.popleft()
            net_filter = TcpNetworkFilter(
                self.client_ip, self.target_ip, client_port, port
            )
            self.ports_to_info[port] = PingInfo(
                seq=segment.seq_num, filter=net_filter, sent_time=time.monotonic()
            )
            sent += 1

        if not self._send_queue and self._sock is not None:
            self.scan_manager.modify(self._sock.fileno(), select.EPOLLIN)
            self._timeout_time = time.monotonic() + self.timeout

    def _recv_pending(self) -> None:
        while True:
            try:
                data, addr = self._sock.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break

            if addr[0] != self.target_ip:
                continue

            received_segment = TcpNetworkFilter.get_tcp_segment_from_ip_packet(data)
            if len(received_segment) < 20:
                continue

            source_resp_port, _ = TcpSegment.get_ports_from_raw_segment(received_segment)
            if source_resp_port not in self.ports_to_info:
                continue

            info = self.ports_to_info[source_resp_port]
            if info.filter.is_valid_tcp_response(
                received_segment, self.target_ip, info.seq
            ):
                response_time = (time.monotonic() - info.sent_time) * 1000.0
                if TcpNetworkFilter.is_ack_in_segment(
                    received_segment
                ) and not TcpNetworkFilter.is_rst_in_segment(received_segment):
                    self._results[source_resp_port] = ScanPortResult(
                        port=source_resp_port,
                        time=response_time,
                    )
                self._unresolved_ports.discard(source_resp_port)

    def handle(self, fd: int, event: int) -> None:
        if self._sock is None or fd != self._sock.fileno():
            raise ValueError()

        if event & select.EPOLLOUT:
            self._send_pending()

        if event & select.EPOLLIN:
            self._recv_pending()

    def is_finished(self) -> bool:
        if self._send_queue:
            return False
        if not self._unresolved_ports:
            return True
        return self._timeout_time is not None and time.monotonic() >= self._timeout_time

    def get_results(self) -> list[ScanPortResult]:
        return [self._results[port] for port in self.ports if port in self._results]

    def cleanup(self) -> None:
        if self._sock is not None:
            self.scan_manager.unregister(self._sock.fileno())
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def is_sending(self) -> bool:
        return self._sock is not None and bool(self._send_queue)