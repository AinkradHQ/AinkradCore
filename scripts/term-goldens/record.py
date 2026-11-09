#!/usr/bin/env python3
"""Record the real-app terminal streams in crates/term/tests/corpus (E2-04.4).

Usage: record.py <out-dir>   (Linux; needs vim, htop, tmux, less, ls on PATH)

Each session runs a real program in a pty at a FIXED size, with a fixed TERM/locale/LS_COLORS and a
scratch HOME and cwd, so nothing of the host (names, paths, users) reaches the bytes. Keystrokes are
sent one at a time, each after the output has gone quiet. Only the .vt streams are written; bless the
goldens with `BLESS=1 cargo test -p ainkrad-term --test corpus`. Re-recording is NOT byte-stable
(htop numbers, timing of partial redraws): the committed .vt files are the fixtures.
"""
import fcntl, os, pty, select, struct, subprocess, sys, tempfile, termios, time

ROWS, COLS = 24, 80
ENV = {
    "TERM": "xterm-256color", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "SHELL": "/bin/sh",
    "PATH": "/usr/local/bin:/usr/bin:/bin", "LESS": "-R", "COLUMNS": str(COLS), "LINES": str(ROWS),
    "LS_COLORS": "di=01;34:ln=01;36:ex=01;32:*.gz=01;31:*.txt=0:fi=0",
}

def run(argv, keys, cwd, home, quiet=0.4, boot=1.5):
    """Run argv in a pty; send each item of keys (bytes) after the output settles; return the bytes."""
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execvpe(argv[0], argv, dict(ENV, HOME=home))
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    out = bytearray()

    def drain(wait):
        end = time.time() + wait
        cap = time.time() + 3 * wait + 1  # a program that redraws forever (htop) must still settle
        while time.time() < min(end, cap):
            r, _, _ = select.select([fd], [], [], 0.05)
            if not r:
                continue
            try:
                data = os.read(fd, 65536)
            except OSError:
                return False
            if not data:
                return False
            out.extend(data)
            end = time.time() + wait
        return True

    alive = drain(boot)
    for k in keys:
        if not alive:
            break
        os.write(fd, k)
        alive = drain(quiet)
    drain(1.0)
    try:
        os.kill(pid, 9)
    except OSError:
        pass
    os.waitpid(pid, 0)
    return bytes(out)

def main():
    dest = sys.argv[1]
    os.makedirs(dest, exist_ok=True)
    work = tempfile.mkdtemp()
    home = os.path.join(work, "h")
    cwd = os.path.join(work, "w")
    os.makedirs(home); os.makedirs(cwd)
    # fixtures for the programs
    with open(os.path.join(cwd, "notes.txt"), "w") as f:
        f.write("".join(f"line {i:02d} of the notes file\n" for i in range(1, 60)))
    with open(os.path.join(cwd, "hello.c"), "w") as f:
        f.write('#include <stdio.h>\n\n/* greeting */\nint main(void) {\n    printf("hello\\n");\n    return 0;\n}\n')
    with open(os.path.join(cwd, "wide.txt"), "w") as f:
        f.write("ascii | plain\n"
                "cjk   | 你好世界 こんにちは 한글\n"
                "emoji | \U0001f600\U0001f680\U0001f468‍\U0001f469‍\U0001f467 ❤️ \U0001f1e9\U0001f1ea\n"
                "comb  | é ä ñ नमस्ते\n"
                "mixed | a你b\U0001f600c" + "x" * 70 + "你好 wraps\n")
    os.makedirs(os.path.join(cwd, "dir"))
    for name in ("run.sh", "data.tar.gz", "plain.txt"):
        open(os.path.join(cwd, name), "w").close()
    os.chmod(os.path.join(cwd, "run.sh"), 0o755)
    os.symlink("plain.txt", os.path.join(cwd, "link"))
    with open(os.path.join(home, "vimrc"), "w") as f:
        f.write("set nocompatible noswapfile nobackup viminfo= laststatus=2 ruler\nsyntax on\nset background=dark\n")
    with open(os.path.join(home, "tmux.conf"), "w") as f:
        f.write("set -g default-command 'env PS1=\"$ \" bash --norc --noprofile'\nset -g automatic-rename off\n"
                "set -g status-left '[s] '\nset -g status-right 'ainkrad'\nset -g status-interval 0\n")
    with open(os.path.join(home, "htoprc"), "w") as f:
        f.write("hide_userland_threads=1\ntree_view=0\nshow_cpu_frequency=0\nshow_cpu_temperature=0\n")
    os.makedirs(os.path.join(home, ".config/htop"))
    os.rename(os.path.join(home, "htoprc"), os.path.join(home, ".config/htop/htoprc"))

    esc = b"\x1b"
    sessions = {
        # insert text, undo, search, quit with a write: the classic edit loop, syntax colours on
        "real_vim_edit": (["vim", "-u", home + "/vimrc", "-i", "NONE", "hello.c"],
            [b"/printf\r", b"A", b"// ok", esc, b"u", b"o", b"/* more */", esc, b":wq\r"]),
        # two windows, scrolling inside one: DECSTBM scroll regions, status lines
        "real_vim_split_scroll": (["vim", "-u", home + "/vimrc", "-i", "NONE", "notes.txt"],
            [b":split\r", b"\x04", b"\x05", b"\x17j", b"\x06", b"G", b":q!\r", b":q!\r"]),
        # one refresh cycle of htop, then quit
        "real_htop": (["htop", "-d", "10"], [b"q"]),
        # two splits, typing in the panes, the status bar
        "real_tmux_splits": (["tmux", "-f", home + "/tmux.conf", "-L", "g", "new-session", "-s", "s", "-n", "main"],
            [b"echo one\r", b"\x02%", b"echo two\r", b"\x02\"", b"echo three\r", b"\x02o", b"ls --color=always\r",
             b"\x02d"]),
        "real_ls_color": (["ls", "--color=always", "-C", "-w", "80"], []),
        "real_wide_chars": (["cat", "wide.txt"], []),
        # alt-screen enter/leave around a pager, with shell output before and after
        "real_less_alt_screen": (["sh", "-c", "echo before; less notes.txt; echo after"],
            [b" ", b" ", b"b", b"/file 5", b"\r", b"q"]),
    }
    for name, (argv, keys) in sessions.items():
        data = run(argv, keys, cwd, home)
        with open(os.path.join(dest, name + ".vt"), "wb") as f:
            f.write(data)
        print(f"{name}: {len(data)} bytes")
    # a tmux server may linger
    subprocess.run(["tmux", "-L", "g", "kill-server"], stderr=subprocess.DEVNULL)

main()
