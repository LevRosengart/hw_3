import select
from collections.abc import Callable
from portscan.base_scaner import BaseScaner


Handler = Callable[[int, int], None]


class ScanManager:
    def __init__(self) -> None:
        self._epoll: select.epoll = select.epoll()
        self._handlers: dict[int, Handler] = {}

    @property
    def epoll(self) -> select.epoll:
        return self._epoll

    def register(self, fd: int, handler: Handler, events: int = select.EPOLLIN) -> None:
        self._handlers[fd] = handler
        self._epoll.register(fd, events)

    def modify(self, fd: int, events: int) -> None:
        self._epoll.modify(fd, events)

    def unregister(self, fd: int) -> None:
        if fd in self._handlers:
            del self._handlers[fd]
        try:
            self._epoll.unregister(fd)
        except OSError:
            pass

    def run(self, scanners: list[BaseScaner], poll_timeout: float = 0.05) -> None:
        for scanner in scanners:
            scanner.start()

        try:
            while scanners:
                active_scanners = []
                sending = False
                for scanner in scanners:
                    if scanner.is_finished():
                        scanner.cleanup()
                    else:
                        active_scanners.append(scanner)
                        if scanner.is_sending():
                            sending = True
                scanners = active_scanners

                if not scanners:
                    break

                timeout = 0.0 if sending else poll_timeout
                events = self._epoll.poll(timeout=timeout)
                for fd, event in events:
                    if fd in self._handlers:
                        self._handlers[fd](fd, event)
        finally:
            for scanner in scanners:
                scanner.cleanup()

    def close(self) -> None:
        try:
            self._epoll.close()
        except OSError:
            pass
