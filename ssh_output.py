"""Считать оба потока SSH, которые делят одно окно передачи."""

import socket
import time


def read_output(channel, timeout):
    out, err = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    while True:
        progress = False
        if channel.recv_ready():
            chunk = channel.recv(65536)
            out.extend(chunk)
            progress = bool(chunk)
        if channel.recv_stderr_ready():
            chunk = channel.recv_stderr(65536)
            err.extend(chunk)
            progress = progress or bool(chunk)
        if progress:
            deadline = time.monotonic() + timeout
            continue
        if (channel.eof_received or channel.closed) and channel.exit_status_ready():
            if channel.recv_ready() or channel.recv_stderr_ready():
                continue
            rc = channel.recv_exit_status()
            if rc == -1:
                raise EOFError("сервер не прислал код завершения")
            return rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout("сервер перестал передавать вывод или код завершения")
        time.sleep(min(0.01, left))
