#!/usr/bin/env bash
# Run on YOUR machine to claim the Core's bootstrap code (the first device). The admin socket admits only the
# service user's uid, so a plain `ssh -L` (which connects as your login user) is refused: this relays each
# connection to a local socket over SSH as `sudo -u ainkrad` on the host instead. Ctrl-C stops it.
#   scripts/install/admin-relay.sh <user>@<host> [<local socket>] [-- <ssh options, e.g. -i key>]
# then, while `bootstrap` waits on the host:
#   ainkradctl --socket <local socket> --host <dns name> pair <CODE> --core-fp <FP>
set -euo pipefail
dest=${1:?usage: admin-relay.sh <user>@<host> [<local socket>] [-- <ssh options>]}; shift
sock=${TMPDIR:-/tmp}/ainkrad-admin.sock
if [ $# -gt 0 ] && [ "$1" != -- ]; then sock=$1; shift; fi
[ "${1:-}" = -- ] && shift
remote=${AINKRAD_ADMIN_SOCKET:-/var/lib/ainkrad/core/admin.sock}
rm -f "$sock"
echo "relaying $sock -> $dest:$remote (as ainkrad); Ctrl-C to stop" >&2
exec python3 - "$sock" "$dest" "$remote" "$@" <<'PY'
import os, socket, subprocess, sys, threading
path, host, remote, opts = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
# On the host: stdio <-> the admin socket, as the service user (python3: AppArmor denies nc.openbsd the connect).
PUMP = """import os, socket, sys, threading
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
def up():
    while (d := os.read(0, 65536)):
        s.sendall(d)
    s.shutdown(socket.SHUT_WR)
threading.Thread(target=up, daemon=True).start()
while (d := s.recv(65536)):
    os.write(1, d)"""
old = os.umask(0o077)
srv = socket.socket(socket.AF_UNIX); srv.bind(path); os.umask(old); srv.listen(8)
def serve(c):
    p = subprocess.Popen(["ssh", *opts, host, f"sudo -u ainkrad python3 -c '{PUMP}' {remote}"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    def up():
        while (d := c.recv(65536)):
            p.stdin.write(d)
        p.stdin.close()
    threading.Thread(target=up, daemon=True).start()
    while (d := os.read(p.stdout.fileno(), 65536)):
        c.sendall(d)
    c.close(); p.kill()
try:
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()
except KeyboardInterrupt:
    pass
finally:
    os.unlink(path)
PY
