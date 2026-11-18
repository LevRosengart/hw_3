import random
from struct import Struct

import pytest

from ports_scanner.tcp_network_filter import TcpNetworkFilter


class TestTcpNetworkFilter:
    EXPECTED_RESP_SOURCE_IP: str = "8.8.8.8"
    EXPECTED_RESP_SOURCE_PORT: int = 443
    EXPECTED_RESP_DEST_IP: str = "192.168.0.1"
    EXPECTED_RESP_DEST_PORT: int = 54321
    SENT_SEQ = 100
    EXPECTED_ACK = SENT_SEQ + 1
    LENGTH_AND_FLAGS_SYN_ACK: int = 0b001010_000_00010010
    LENGTH_AND_FLAGS_RST_ACK: int = 0b001010_000_00010100
    LENGTH_AND_FLAGS_RST: int = 0b001010_000_00000100
    RESP_URG_POINTER: int = 0
    RESP_SEQ: int = random.randint(0, 2**32 - 1)
    RESP_CHECKSUM: int = random.randint(0, 2**16 - 1)  # Checksum should check OS
    RESP_WINDOW_SIZE: int = random.randint(0, 2**16 - 1)
    EXPECTED_PORTS: bytes = EXPECTED_RESP_SOURCE_PORT.to_bytes(
        2
    ) + EXPECTED_RESP_DEST_PORT.to_bytes(2)
    EXPECTED_SYN_ACK_SEGMENT: bytes = (
        EXPECTED_PORTS
        + RESP_SEQ.to_bytes(4)
        + EXPECTED_ACK.to_bytes(4)
        + LENGTH_AND_FLAGS_SYN_ACK.to_bytes(2)
        + RESP_WINDOW_SIZE.to_bytes(2)
        + RESP_CHECKSUM.to_bytes(2)
        + RESP_URG_POINTER.to_bytes(2)
    )
    RST_SEGMENT_TO_PACK: bytearray = bytearray(EXPECTED_SYN_ACK_SEGMENT)
    Struct("!H").pack_into(RST_SEGMENT_TO_PACK, 12, LENGTH_AND_FLAGS_RST)
    RST_SEGMENT: bytes = bytes(RST_SEGMENT_TO_PACK)
    SHORT_SEGMENTS_PARAMS: tuple[bytes, bytes] = (b"\x00" * 4, EXPECTED_PORTS)

    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self.filter = TcpNetworkFilter(
            self.EXPECTED_RESP_DEST_IP,
            self.EXPECTED_RESP_SOURCE_IP,
            self.EXPECTED_RESP_DEST_PORT,
            self.EXPECTED_RESP_SOURCE_PORT,
        )

    @pytest.fixture
    def create_segment(self, segment_data: bytes, fmt: str, offset: int, replacement: int) -> bytes:
        segment = bytearray(segment_data)
        Struct(fmt).pack_into(segment, offset, replacement)
        return bytes(segment)

    def test_is_valid_with_incorrect_resp_source_ip(self) -> None:
        incorrect_ip: str = "1.1.1.1"
        assert not self.filter.is_valid_tcp_response(
            self.EXPECTED_SYN_ACK_SEGMENT, incorrect_ip, self.SENT_SEQ
        )

    @pytest.mark.parametrize(
        ("segment_data", "fmt", "offset", "replacement", "expected_result"),
        [
            pytest.param(
                EXPECTED_SYN_ACK_SEGMENT,
                "!H",
                12,
                LENGTH_AND_FLAGS_SYN_ACK,
                True,
                id="valid-syn-ack",
            ),
            pytest.param(
                EXPECTED_SYN_ACK_SEGMENT,
                "!H",
                12,
                LENGTH_AND_FLAGS_RST_ACK,
                True,
                id="valid-rst-ack-true",
            ),
            pytest.param(RST_SEGMENT, "!I", 4, EXPECTED_ACK, True, id="valid-rst-incremented-seq"),
            pytest.param(RST_SEGMENT, "!I", 4, 0, True, id="valid-rst-zero-seq"),
            pytest.param(RST_SEGMENT, "!I", 4, SENT_SEQ - 1, False, id="invalid-rst-seq"),
            pytest.param(
                EXPECTED_SYN_ACK_SEGMENT,
                "!H",
                2,
                EXPECTED_RESP_DEST_PORT + 1,
                False,
                id="invalid-rst-resp-dest-port",
            ),
            pytest.param(
                EXPECTED_SYN_ACK_SEGMENT,
                "!H",
                0,
                EXPECTED_RESP_SOURCE_PORT + 1,
                False,
                id="invalid-rst-src-dest-port",
            ),
        ],
    )
    def test_is_valid_segment(self, create_segment: bytes, expected_result: bool) -> None:
        assert (
            self.filter.is_valid_tcp_response(
                create_segment, self.EXPECTED_RESP_SOURCE_IP, self.SENT_SEQ
            )
            == expected_result
        )

    @pytest.mark.parametrize(
        ("segment_data", "fmt", "offset", "replacement", "expected_is_rst", "expected_is_ack"),
        [
            pytest.param(
                EXPECTED_SYN_ACK_SEGMENT,
                "!H",
                12,
                LENGTH_AND_FLAGS_SYN_ACK,
                False,
                True,
                id="syn-ack",
            ),
            pytest.param(
                EXPECTED_SYN_ACK_SEGMENT,
                "!H",
                12,
                LENGTH_AND_FLAGS_RST_ACK,
                True,
                True,
                id="rst-ack",
            ),
            pytest.param(
                RST_SEGMENT,
                "!H",
                12,
                LENGTH_AND_FLAGS_RST,
                True,
                False,
                id="rst",
            ),
        ],
    )
    def test_is_rst_ack_in_segment(
        self, create_segment: bytes, expected_is_rst: bool, expected_is_ack: bool
    ) -> None:
        assert TcpNetworkFilter.is_rst_in_segment(create_segment) == expected_is_rst
        assert TcpNetworkFilter.is_ack_in_segment(create_segment) == expected_is_ack

    @pytest.mark.parametrize(
        "short_segment",
        SHORT_SEGMENTS_PARAMS,
    )
    def test_is_rst_ack_in_short_segment(self, short_segment: bytes) -> None:
        assert not TcpNetworkFilter.is_ack_in_segment(short_segment)
        assert not TcpNetworkFilter.is_rst_in_segment(short_segment)

    @pytest.mark.parametrize(
        "short_segment",
        SHORT_SEGMENTS_PARAMS,
    )
    def test_is_valid_short_segment(self, short_segment: bytes) -> None:
        assert not self.filter.is_valid_tcp_response(
            short_segment, self.EXPECTED_RESP_SOURCE_IP, self.SENT_SEQ
        )
