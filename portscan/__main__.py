import sys
from concurrent.futures import ThreadPoolExecutor

from portscan.arg_parse import ParsedArguments, parse_args
from portscan.base_scaner import BaseScaner
from portscan.formatter import print_results
from portscan.protocol_guesser import ProtocolGuesser
from portscan.scan_manager import ScanManager
from portscan.scan_port_result import ScanPortResult
from portscan.tcp_scaner import TcpScaner
from portscan.udp_scaner import UdpScaner
from portscan.utils import get_client_ip


def run_cli(parsed_args: ParsedArguments) -> int:
    target_ip = parsed_args.ip_address
    client_ip = get_client_ip(target_ip)

    scan_manager = ScanManager()
    scanners: list[tuple[str, BaseScaner]] = []

    if parsed_args.tcp_ports:
        tcp_scanner = TcpScaner(
            ports=parsed_args.tcp_ports,
            scan_manager=scan_manager,
            target_ip=target_ip,
            client_ip=client_ip,
            timeout=parsed_args.timeout,
        )
        scanners.append(("TCP", tcp_scanner))

    if parsed_args.udp_ports:
        udp_scanner = UdpScaner(
            ports=parsed_args.udp_ports,
            scan_manager=scan_manager,
            target_ip=target_ip,
            client_ip=client_ip,
            timeout=parsed_args.timeout,
        )
        scanners.append(("UDP", udp_scanner))

    try:
        scan_manager.run([s for _, s in scanners])
    finally:
        scan_manager.close()

    all_results: list[tuple[str, ScanPortResult]] = []
    for proto, scanner in scanners:
        for res in scanner.get_results():
            all_results.append((proto, res))

    if parsed_args.guess and all_results:
        guesser = ProtocolGuesser(target_ip=target_ip, timeout=parsed_args.timeout)

        def _guess_worker(item: tuple[str, ScanPortResult]) -> tuple[str, ScanPortResult]:
            proto, res = item
            if proto == "TCP":
                res.protocol = guesser.guess_tcp(res.port)
            else:
                res.protocol = guesser.guess_udp(res.port)
            return proto, res

        max_workers = parsed_args.num_threads or 10
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            all_results = list(executor.map(_guess_worker, all_results))

    print_results(all_results, verbose=parsed_args.verbose, guess=parsed_args.guess)
    return 0


def main(args: list[str] | None = None) -> int:
    try:
        parsed = parse_args(args)
    except (ValueError, SystemExit) as err:
        if isinstance(err, SystemExit):
            return err.code if isinstance(err.code, int) else 0
        print(f"Error parsing arguments: {err}", file=sys.stderr)
        return 1

    try:
        return run_cli(parsed)
    except KeyboardInterrupt:
        return 130
    except PermissionError:
        print(
            "Error: Raw sockets require root / administrator privileges (run with sudo).",
            file=sys.stderr,
        )
        return 1
    except OSError as err:
        print(f"Network / OS error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
