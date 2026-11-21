import argparse
import ipaddress
from dataclasses import dataclass, field

ALL_PORTS: list[int] = list(range(1, 65536))


@dataclass
class ParsedArguments:
    ip_address: str
    tcp_ports: list[int] = field(default_factory=list)
    udp_ports: list[int] = field(default_factory=list)
    timeout: float = 2.0
    num_threads: int | None = None
    verbose: bool = False
    guess: bool = False


def _parse_port_range(port_spec: str) -> list[int]:
    ports: list[int] = []
    seen: set[int] = set()

    for item in port_spec.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start_str, end_str = item.split("-", 1)
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError as err:
                raise ValueError(f"Invalid port range '{item}': ports must be integers") from err

            if start > end:
                raise ValueError(f"Invalid port range '{item}': start port {start} > end port {end}")
            if start < 1 or end > 65535:
                raise ValueError(f"Port range '{item}' out of valid range (1-65535)")

            for p in range(start, end + 1):
                if p not in seen:
                    seen.add(p)
                    ports.append(p)
        else:
            try:
                p = int(item)
            except ValueError as err:
                raise ValueError(f"Invalid port '{item}': must be an integer") from err

            if p < 1 or p > 65535:
                raise ValueError(f"Port {p} out of valid range (1-65535)")
            if p not in seen:
                seen.add(p)
                ports.append(p)

    return ports


def parse_port_targets(target_specs: list[str]) -> tuple[list[int], list[int]]:
    tcp_ports: list[int] = []
    udp_ports: list[int] = []
    seen_tcp: set[int] = set()
    seen_udp: set[int] = set()

    for spec in target_specs:
        spec = spec.strip()
        if not spec:
            continue

        if "/" in spec:
            protocol, port_str = spec.split("/", 1)
            protocol = protocol.lower()
            if protocol not in ("tcp", "udp"):
                raise ValueError(f"Unknown protocol '{protocol}' in target '{spec}' (must be 'tcp' or 'udp')")

            ports = _parse_port_range(port_str)
        else:
            protocol = spec.lower()
            if protocol not in ("tcp", "udp"):
                raise ValueError(f"Unknown target specification '{spec}' (expected 'tcp', 'udp', or 'protocol/ports')")
            ports = list(ALL_PORTS)

        if protocol == "tcp":
            for p in ports:
                if p not in seen_tcp:
                    seen_tcp.add(p)
                    tcp_ports.append(p)
        else:
            for p in ports:
                if p not in seen_udp:
                    seen_udp.add(p)
                    udp_ports.append(p)

    return tcp_ports, udp_ports


def validate_ip_address(ip_str: str) -> str:
    try:
        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError as err:
        raise ValueError(f"Invalid IP address: '{ip_str}'") from err


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscan",
        description="TCP/UDP port scanner",
        usage="portscan [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout waiting for response in seconds (default: 2s)",
    )
    parser.add_argument(
        "-j",
        "--num-threads",
        type=int,
        default=None,
        dest="num_threads",
        help="Number of threads (for multithreaded implementation)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Verbose output (includes response time)",
    )
    parser.add_argument(
        "-g",
        "--guess",
        action="store_true",
        default=False,
        help="Guess application-layer protocol (HTTP, DNS, ECHO)",
    )
    parser.add_argument(
        "ip_address",
        help="Target IP address",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Protocols and ports to scan: {tcp|udp}[/[PORT|PORT-PORT],...]",
    )
    return parser


def parse_args(args: list[str] | None = None) -> ParsedArguments:
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    ip = validate_ip_address(parsed_args.ip_address)
    if parsed_args.timeout <= 0:
        raise ValueError(f"Timeout must be positive, got {parsed_args.timeout}")

    if parsed_args.num_threads is not None and parsed_args.num_threads <= 0:
        raise ValueError(f"num-threads must be positive, got {parsed_args.num_threads}")

    tcp_ports, udp_ports = parse_port_targets(parsed_args.targets)

    if not parsed_args.targets:
        tcp_ports = list(ALL_PORTS)
        udp_ports = list(ALL_PORTS)

    return ParsedArguments(
        ip_address=ip,
        tcp_ports=tcp_ports,
        udp_ports=udp_ports,
        timeout=parsed_args.timeout,
        num_threads=parsed_args.num_threads,
        verbose=parsed_args.verbose,
        guess=parsed_args.guess,
    )
