import socket

import dns.message
import dns.query


class ProtocolGuesser:
    ECHO_REQUEST: bytes = b"PING_ECHO_12345"

    def __init__(self, target_ip: str, timeout: float = 1.0) -> None:
        self.target_ip: str = target_ip
        self.timeout: float = timeout

    def guess_tcp(self, port: int) -> str | None:
        if self._is_echo_tcp(port):
            return "ECHO"
        if self._is_http(port):
            return "HTTP"
        if self._is_dns_tcp(port):
            return "DNS"
        return None

    def guess_udp(self, port: int) -> str | None:
        if self._is_echo_udp(port):
            return "ECHO"
        if self._is_http_udp(port):
            return "HTTP"
        if self._is_dns_udp(port):
            return "DNS"
        return None

    def _is_http(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target_ip, port))
                request = (
                    f"GET / HTTP/1.0\r\nHost: {self.target_ip}\r\n"
                    f"User-Agent: portscan\r\n\r\n"
                ).encode("ascii")
                s.sendall(request)
                response = s.recv(1024)
                return response.startswith(b"HTTP/")
        except OSError:
            return False

    def _is_dns_tcp(self, port: int) -> bool:
        try:
            query = dns.message.make_query("example.com", dns.rdatatype.A)
            response = dns.query.tcp(query, self.target_ip, port=port, timeout=self.timeout)
            return response is not None and response.id == query.id
        except (OSError, dns.exception.DNSException):
            return False

    def _is_echo_tcp(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target_ip, port))
                s.sendall(self.ECHO_REQUEST)
                response = s.recv(1024)
                return self.ECHO_REQUEST in response
        except OSError:
            return False

    def _is_dns_udp(self, port: int) -> bool:
        try:
            query = dns.message.make_query("example.com", dns.rdatatype.A)
            response = dns.query.udp(query, self.target_ip, port=port, timeout=self.timeout)
            return response is not None and response.id == query.id
        except (OSError, dns.exception.DNSException):
            return False

    def _is_http_udp(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                request = (
                    f"GET / HTTP/1.0\r\nHost: {self.target_ip}\r\n"
                    f"User-Agent: portscan\r\n\r\n"
                ).encode("ascii")
                s.sendto(request, (self.target_ip, port))
                response, _ = s.recvfrom(1024)
                if response.startswith(b"HTTP/"):
                    return True
        except OSError:
            pass

        return False

    def _is_echo_udp(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(self.ECHO_REQUEST, (self.target_ip, port))
                response, _ = s.recvfrom(1024)
                return self.ECHO_REQUEST in response
        except OSError:
            return False
