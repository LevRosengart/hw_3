class TcpNetworkFilter:
    def __init__(
        self,
        client_source_ip: str,
        client_dest_ip: str,
        client_source_port: int,
        client_dest_port: int,
    ) -> None:
        self._resp_dest_ip: str = client_source_ip
        self._resp_dest_port: int = client_source_port
        self._resp_source_ip: str = client_dest_ip
        self._resp_source_port: int = client_dest_port

    def is_valid_tcp_response(self, segment: bytes, server_ip: str, sent_seq_num: int) -> bool:
        if not self._is_valid_tcp_response_dest(segment, server_ip):
            return False
        if self.is_ack_in_segment(segment):
            received_ack_num: int = int.from_bytes(segment[8:12], byteorder="big")
            return received_ack_num == (sent_seq_num + 1) & 0xFFFF_FFFF
        if self.is_rst_in_segment(segment):
            received_rst_seq_num: int = int.from_bytes(segment[4:8], byteorder="big")
            expected_seq_num: int = (sent_seq_num + 1) & 0xFFFF_FFFF
            return received_rst_seq_num in (expected_seq_num, 0)

        return False

    @staticmethod
    def get_tcp_segment_from_ip_packet(packet: bytes) -> bytes:
        if len(packet) < 20:
            return b""
        version: int = packet[0] >> 4
        if version != 4:
            return b""
        ip_header_length_in_words: int = packet[0] & 0x0F  # In 32-bit words
        ip_header_len_in_bytes: int = ip_header_length_in_words * 4

        return packet[ip_header_len_in_bytes:]

    def _is_valid_tcp_response_dest(self, segment: bytes, server_ip: str) -> bool:
        if len(segment) < 20:
            return False
        if server_ip != self._resp_source_ip:
            return False
        received_resp_source_port: int = int.from_bytes(segment[:2], byteorder="big")
        received_resp_dest_port: int = int.from_bytes(segment[2:4], byteorder="big")
        return (
            received_resp_dest_port == self._resp_dest_port
            and received_resp_source_port == self._resp_source_port
        )

    @classmethod
    def is_ack_in_segment(cls, segment: bytes) -> bool:
        if len(segment) < 20:
            return False
        flags_byte = segment[13]
        is_ack: bool = bool(flags_byte & 0x10)
        return is_ack

    @classmethod
    def is_rst_in_segment(cls, segment: bytes) -> bool:
        if len(segment) < 20:
            return False
        flags_byte = segment[13]
        is_rst: bool = bool(flags_byte & 0x04)
        return is_rst
