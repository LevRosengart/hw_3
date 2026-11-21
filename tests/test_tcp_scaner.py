import socket

from portscan.utils import get_available_port
from portscan.tcp_scaner import TcpScaner
from portscan.tcp_network_filter import TcpNetworkFilter
from portscan.scan_manager import ScanManager
from portscan.tcp_segment import TcpSegment


class TestTcpScaner:
    def test_start(self) -> None:
        target_ip = client_ip = "127.0.0.1"
        target_port = get_available_port()
        server_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
        )
        server_socket.bind((client_ip, target_port))
        tcp_scaner_port: int = 44444
        scan_manager = ScanManager()
        tcp_scaner: TcpScaner = TcpScaner(
            [target_port], scan_manager, target_ip, client_ip, 2.0
        )
        tcp_scaner._available_port = tcp_scaner_port
        scan_manager.run([tcp_scaner])
        while True:
            data = server_socket.recv(65535)
            segment: bytes = TcpNetworkFilter.get_tcp_segment_from_ip_packet(data)
            src_recv_port, dest_recv_port = TcpSegment.get_ports_from_raw_segment(
                segment
            )
            if src_recv_port != tcp_scaner_port or dest_recv_port != target_port:
                continue
            else:
                assert (
                    segment[13] & 0x02 # syn?
                    and int.from_bytes(segment[4:8], byteorder="big") # seq_num
                    == tcp_scaner.ports_to_info[target_port].seq
                )
                break
