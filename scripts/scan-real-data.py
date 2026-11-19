#!/usr/bin/env python3
"""E12-6: look for real data in a repository before it goes public: scripts/scan-real-data.py [--history] [--report FILE] <repo>...

Looks in the working tree (tracked files) and, with --history, in every line ever added on any branch, for
  token   - GitHub, Anthropic, OpenAI, AWS and Slack token shapes and private-key headers
  email   - email addresses that are not documentation or no-reply ones
  host    - private network addresses, and the machines named in SCAN_HOSTS
  name    - the real names in SCAN_NAMES
It only reads. It never rewrites history and never prints a whole secret: each finding shows the rule, the place and a masked
excerpt (first 4 characters, then `...`). Exit 0 whatever it finds: it is a report, not a gate (`--strict` makes findings exit 1).
SCAN_HOSTS / SCAN_NAMES (comma separated) name the machines and people to look for. They are empty by default on purpose: a list of
real names inside a public repository would be the leak it looks for.
"""
import os, re, subprocess, sys

HOSTS = [h for h in os.environ.get("SCAN_HOSTS", "").split(",") if h]
NAMES = [n for n in os.environ.get("SCAN_NAMES", "").split(",") if n]
RULES = [
    ("token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|sk-ant-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")),
    ("host", re.compile(r"(?<![0-9.])(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?![0-9])" + "".join("|" + re.escape(h) for h in HOSTS))),
]
if NAMES:
    RULES.append(("name", re.compile("|".join(re.escape(n) for n in NAMES), re.I)))
# Email addresses that are fine in public.
OK_EMAIL = re.compile(r"@(example\.(com|org|net)|users\.noreply\.github\.com|noreply\.github\.com|ainkrad\.io|anthropic\.com|localhost|test\.|harbor-home\.example)|^(noreply|no-reply)@", re.I)
SKIP_PATH = re.compile(r"(^|/)(Cargo\.lock|package-lock\.json|Package\.resolved|\.build|node_modules|target|dist)/|\.(png|jpg|jpeg|webp|gif|pdf|woff2?|zip|dmg|icns|ico|xcassets)$|(^|/)Cargo\.lock$")

def mask(s):
    return s[:4] + "..." if len(s) > 4 else "..."

def scan_line(line):
    for rule, rx in RULES:
        for m in rx.finditer(line):
            v = m.group(0)
            if rule == "email" and OK_EMAIL.search(v):
                continue
            yield rule, mask(v)

def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, errors="replace", check=False).stdout

def scan_tree(repo):
    for path in git(repo, "ls-files").splitlines():
        if SKIP_PATH.search(path):
            continue
        try:
            with open(os.path.join(repo, path), errors="replace") as f:
                for n, line in enumerate(f, 1):
                    for rule, ex in scan_line(line[:2000]):
                        yield rule, f"tree:{path}:{n}", ex
        except OSError:
            continue

def scan_history(repo):
    p = subprocess.Popen(["git", "-C", repo, "log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=@@%h"],
                         stdout=subprocess.PIPE, text=True, errors="replace")
    commit = path = ""
    seen = set()
    for line in p.stdout:
        if line.startswith("@@") and not line.startswith("@@ "):
            commit = line[2:].strip()
        elif line.startswith("+++ b/"):
            path = line[6:].strip()
        elif line.startswith("+") and not line.startswith("+++") and path and not SKIP_PATH.search(path):
            for rule, ex in scan_line(line[1:2001]):
                key = (rule, path, ex)
                if key not in seen:   # the first commit that added it; later adds of the same thing are not repeated
                    seen.add(key)
                    yield rule, f"history:{commit}:{path}", ex
    p.wait()

def main(argv):
    hist = "--history" in argv
    strict = "--strict" in argv
    report = argv[argv.index("--report") + 1] if "--report" in argv else None
    repos = [a for a in argv if not a.startswith("--") and a != report]
    out, total = [], 0
    for repo in repos:
        rows = list(scan_tree(repo)) + (list(scan_history(repo)) if hist else [])
        total += len(rows)
        out.append(f"## {os.path.basename(os.path.abspath(repo))}: {len(rows)} findings")
        counts = {}
        for rule, where, ex in rows:
            counts[rule] = counts.get(rule, 0) + 1
            out.append(f"{rule}\t{where}\t{ex}")
        out.append("   by rule: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"))
    text = "\n".join(out) + "\n"
    (open(report, "w").write(text) if report else sys.stdout.write(text))
    return 1 if strict and total else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
