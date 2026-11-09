#!/usr/bin/env python3
"""Helpers for scripts/e2-exit.sh (E2-17). Standard library only.

  proxy <listen-port> <upstream-port>   TCP proxy to 127.0.0.1; SIGUSR1 drops every open connection (new ones
                                        go through), SIGUSR2 holds the Core's bytes until the next SIGUSR2
  attach <out> <secs> <send-or-> -- <cmd...>
                                        runs `ainkradctl term attach` under a pty for <secs> (0: until it ends),
                                        types <send> after 1 s, records every byte to <out>; the exit status is
                                        the command's (or 0 when it was stopped at the deadline)
  soak-check <csv> <warmup-secs>        flatness of the RSS/FD samples (see below); exit 1 when not flat
"""
import csv
import fcntl
import struct
import termios
import os
import pty
import select
import signal
import socket
import statistics
import sys
import threading
import time


def proxy(listen, upstream):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen))
    srv.listen(64)
    open_socks, lock, hold = [], threading.Lock(), threading.Event()

    def pump(a, b, held):
        try:
            while data := a.recv(16384):
                while held and hold.is_set():
                    time.sleep(0.01)
                b.sendall(data)
        except OSError:
            pass
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def cut(*_):
        with lock:
            socks, open_socks[:] = list(open_socks), []
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def toggle(*_):
        hold.clear() if hold.is_set() else hold.set()

    signal.signal(signal.SIGUSR1, cut)
    signal.signal(signal.SIGUSR2, toggle)
    print("ready", flush=True)
    while True:
        try:
            down, _ = srv.accept()
        except InterruptedError:
            continue
        try:
            up = socket.create_connection(("127.0.0.1", upstream))
        except OSError:
            down.close()
            continue
        with lock:
            open_socks.extend([down, up])
        threading.Thread(target=pump, args=(down, up, False), daemon=True).start()
        threading.Thread(target=pump, args=(up, down, True), daemon=True).start()


def attach(out, secs, send, cmd):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    typed, start, status, stopped = send == "-", time.time(), None, False
    with open(out, "wb") as f:
        while True:
            if not typed and time.time() - start > 1:
                os.write(fd, send.encode().decode("unicode_escape").encode("latin-1"))
                typed = True
            if secs and not stopped and time.time() - start > secs:
                stopped, status = True, 0
                try:
                    os.write(fd, b"\x1c")  # Ctrl-\ : detach
                    time.sleep(0.3)
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    data = b""
                if not data:
                    break
                f.write(data)
                f.flush()
    _, st = os.waitpid(pid, 0)
    return status if status is not None else os.waitstatus_to_exitcode(st) % 256


def soak_check(path, warmup):
    """Flat means, per process, after the warm-up: RSS growth (median of the last quarter minus the
    median of the first quarter) within 5 % of the median plus 4 MiB, and FDs max - min <= 8."""
    rows = [r for r in csv.DictReader(open(path)) if int(r["t"]) >= warmup]
    ok = True
    for name in sorted({r["proc"] for r in rows}):
        mine = [r for r in rows if r["proc"] == name]
        if len(mine) < 8:
            print(f"{name}: only {len(mine)} samples after warm-up (too few to judge): FAIL")
            ok = False
            continue
        rss, fds = [int(r["rss_kb"]) for r in mine], [int(r["fds"]) for r in mine]
        q = max(1, len(rss) // 4)
        grow = statistics.median(rss[-q:]) - statistics.median(rss[:q])
        limit = 0.05 * statistics.median(rss) + 4096
        flat = grow <= limit and max(fds) - min(fds) <= 8
        ok &= flat
        print(f"{name}: rss {statistics.median(rss[:q]):.0f} -> {statistics.median(rss[-q:]):.0f} KB "
              f"(growth {grow:.0f}, limit {limit:.0f}); fds {min(fds)}..{max(fds)}: {'flat' if flat else 'NOT FLAT'}")
    return 0 if ok else 1


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["proxy"]:
        proxy(int(a[1]), int(a[2]))
    elif a[:1] == ["attach"]:
        sys.exit(attach(a[1], float(a[2]), a[3], a[a.index("--") + 1:]))
    elif a[:1] == ["soak-check"]:
        sys.exit(soak_check(a[1], int(a[2])))
    else:
        sys.exit(__doc__)
