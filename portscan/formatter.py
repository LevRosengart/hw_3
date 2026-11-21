from portscan.scan_port_result import ScanPortResult


def format_scan_result(
    protocol: str,
    result: ScanPortResult,
    verbose: bool = False,
    guess: bool = False,
) -> str:

    parts = [protocol.upper(), str(result.port)]
    if verbose:
        if result.time is not None:
            parts.append(f"{result.time:.1f}ms")
        else:
            parts.append("-")

    if guess:
        parts.append(result.protocol if result.protocol else "-")

    return " ".join(parts)


def print_results(
    results: list[tuple[str, ScanPortResult]],
    verbose: bool = False,
    guess: bool = False,
) -> None:
    for proto, res in results:
        print(format_scan_result(proto, res, verbose=verbose, guess=guess))
