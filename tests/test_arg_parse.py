import pytest

from portscan.arg_parse import parse_args


def test_parse_args_from_desc_example():
    cmd = ["1.1.1.1", "tcp/80", "tcp/12000-12002", "udp/3000-3001,3200"]
    args = parse_args(cmd)

    assert args.ip_address == "1.1.1.1"
    assert args.tcp_ports == [80, 12000, 12001, 12002]
    assert args.udp_ports == [3000, 3001, 3200]
    assert args.timeout == 2.0
    assert args.verbose is False
    assert args.guess is False
    assert args.num_threads is None


def test_parse_args_all_options_and_whole_protocol():
    cmd = ["-v", "-g", "--timeout", "5.5", "-j", "4", "8.8.8.8", "tcp", "udp/40000"]
    args = parse_args(cmd)

    assert args.ip_address == "8.8.8.8"
    assert len(args.tcp_ports) == 65535
    assert args.tcp_ports[0] == 1
    assert args.tcp_ports[-1] == 65535
    assert args.udp_ports == [40000]
    assert args.timeout == 5.5
    assert args.num_threads == 4
    assert args.verbose is True
    assert args.guess is True


def test_parse_args_invalid_ip():
    with pytest.raises(ValueError, match="Invalid IP address"):
        parse_args(["999.999.999.999", "tcp/80"])


def test_parse_args_invalid_port_range():
    with pytest.raises(ValueError, match="out of valid range"):
        parse_args(["1.1.1.1", "tcp/70000"])

    with pytest.raises(ValueError, match="start port"):
        parse_args(["1.1.1.1", "udp/100-50"])
