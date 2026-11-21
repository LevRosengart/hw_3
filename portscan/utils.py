import socket


def get_available_port() -> int:
    sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 0))
    available_port: int = sock.getsockname()[1]
    try:
        sock.close()
    except socket.error:
        pass

    return available_port

def get_client_ip(dest_ip: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.connect((dest_ip, 12345))
        return str(conn.getsockname()[0])