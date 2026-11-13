#!/usr/bin/env python3
"""E8.1 (phase-1) driver: the SAME reference task as scripts/e0-baseline.py, done with Code Mode.

The model sees `ainkrad_search` and `ainkrad_run` (their definitions are the real strings: the search tool and
its answer from the Core's catalogue/renderer, snapshotted in e0-baseline/codemode-defs.json; the run tool's
text and the session note read straight from crates/runner/src/v2/agent/{tools/mcp.rs,script/mod.rs}). A script
sent to `ainkrad_run` is REALLY executed: `ainkrad-runner __script <sock>` (built with `--features quickjs`) runs it
in QuickJS and its `ainkrad.<group>.<op>()` calls go over a unix socket to the fake Core below, which answers
from the E0 fixtures. Needs the runner binary: AINKRAD_RUNNER=<path> (default target/debug/ainkrad-runner).

  scripts/e8-codemode.py [--runs N]            JSON on stdout: baseline (E0 driver) vs two Code Mode variants

Variants (same cost model constants and 4 chars/token as E0, imported from e0-baseline.py):
  codemode_full      only the two tools; Jira and the propose step are assumed to be catalogue ops too
                     (E5/E6, NOT built yet: their definitions and answers are simulated).
  codemode_phase1    what Phase 1 can really do: Brain reads go through scripts; Jira (search, get) and
                     propose stay plain tools, so the list is the two Code Mode tools plus those three
                     (the other 28 plain tools are assumed hidden, which is E5.2, not built yet).
e0-baseline/codemode-defs.json is a snapshot of the Core's real `search_tool()` and of `ops_catalog::search(..)`
for SEARCH_QUERY in a Brain session (made by a throwaway gate test in modules/brain/module/tests/gate/ai.rs, not
committed); regenerate it when the catalogue, renderer or allow-list changes.
Modeled extras: each op call inside a script costs CALL_S, sequentially (scripts are synchronous); the
`ainkrad_run` call itself costs no extra hop. The session note Code Mode adds is counted in the context.
"""
import importlib.util
import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "e0-baseline")
ROOT = os.path.dirname(HERE)
_spec = importlib.util.spec_from_file_location("e0", os.path.join(HERE, "e0-baseline.py"))
e0 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e0)
tok, compact = e0.tok, e0.compact
RUNNER = os.environ.get("AINKRAD_RUNNER", os.path.join(ROOT, "target/debug/ainkrad-runner"))
SEARCH_QUERY = "brain rooms decisions record propose"


def rust_str(src, anchor):
    """The Rust string literal that follows `anchor` in `src`, unescaped (line-continuations included)."""
    i = src.index(anchor) + len(anchor)
    i = src.index('"', i) + 1
    out = []
    while src[i] != '"':
        if src[i] == "\\":
            i += 1
            c = src[i]
            if c == "\n":
                while src[i + 1] in " \t\n":
                    i += 1
            else:
                out.append({"n": "\n", '"': '"', "\\": "\\"}[c])
        else:
            out.append(src[i])
        i += 1
    return "".join(out)


def real_texts():
    rd = os.path.join(ROOT, "crates/runner/src/v2/agent")
    mcp = open(os.path.join(rd, "tools/mcp.rs")).read()
    note = rust_str(open(os.path.join(rd, "script/mod.rs")).read(), "pub const NOTE: &str =")
    run = {"name": "ainkrad_run", "description": rust_str(mcp, "name: RUN.to_owned(),\n                description:"),
           "inputSchema": {"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"],
                           "additionalProperties": False}}
    d = json.load(open(os.path.join(FIX, "codemode-defs.json")))
    st = d["search_tool"]
    search = {"name": "ainkrad_search", "description": st["description"], "inputSchema": st["input_schema"]}
    return note, run, search, d


# Hand-written stand-ins for connection ops, in the renderer's style (E5 does not exist yet).
JIRA_DEFS = [
    {"op": "searchIssues", "group": "jira", "risk": "read", "def": "/** Search Jira issues with JQL. [read] */\n"
     "ainkrad.jira.searchIssues(args: { jql: string; max_results?: number }): { issues: { key: string; fields: "
     "{ summary: string; status: object; priority: object } }[]; total: number }"},
    {"op": "getIssue", "group": "jira", "risk": "read", "def": "/** Read one Jira issue. [read] */\n"
     "ainkrad.jira.getIssue(args: { key: string }): { key: string; fields: object }"},
]


class Core:
    """The fake Core: MCP tools/list + tools/call for the Code Mode tools, and the op socket scripts call."""

    def __init__(self, data, tools, run_tool, search_tool, search_answer, plain):
        self.d, self.plain, self.tools = data, plain, [search_tool, run_tool] + tools
        self.answer = search_answer
        self.bytes_in = self.bytes_out = self.script_ops = 0
        self.proposed = []
        self.sock_path = os.path.join(tempfile.mkdtemp(), "t.sock")
        self.srv = socket.socket(socket.AF_UNIX)
        self.srv.bind(self.sock_path)
        self.srv.listen(4)
        threading.Thread(target=self._serve, daemon=True).start()

    # --- the op socket (what `ainkrad-runner __script` calls: tools/call ainkrad_call {op,args,run}) ---
    def _serve(self):
        while True:
            c, _ = self.srv.accept()
            threading.Thread(target=self._conn, args=(c,), daemon=True).start()

    def _conn(self, c):
        for line in c.makefile("r"):
            req = json.loads(line)
            a = req["params"]["arguments"]
            self.script_ops += 1
            try:
                body, err = self.op(a["op"], a["args"]), False
            except Exception as e:  # a refused op, as the script sees it
                body, err = {"code": "bad_args", "message": str(e)}, True
            c.sendall((json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": {
                "content": [{"type": "text", "text": json.dumps(body)}], "isError": err}}) + "\n").encode())

    def op(self, name, a):
        d = self.d
        # Brain shapes are the real ones from the rendered definitions (a session sees only its project's room).
        if name == "brainAiRooms":
            return [{"id": r["id"], "kind": "project", "name": r["name"], "open": True}
                    for r in d["rooms"] if r["project"] == d["project"]]
        if name == "brainAiDecisions":
            hits = [h for h in d["hits"] if h["kind"] == "decision"][: a.get("limit", 10)]
            return {"records": [self.rec(h["id"], h["title"] + ". " + h["snippet"], "decision", h["created"])
                                for h in hits], "rooms_closed": 0}
        if name == "brainAiRecord":
            r = d["records"][a["id"]]
            return self.rec(r["id"], r["title"] + ". " + r["body"], r["kind"], r["created"])
        if name == "searchIssues":
            rows = list(d["issues"].values())[: a.get("max_results", 50)]
            return {"issues": [{"key": r["key"], "fields": {k: r["fields"][k] for k in ("summary", "status", "priority")}}
                               for r in rows], "total": len(rows)}
        if name == "getIssue":
            return d["issues"][a["key"]]
        if name == "brainAiPropose":
            return self.propose(a["body"]["title"])
        raise KeyError(f"unknown op {name}")

    @staticmethod
    def rec(id, text, kind, created):
        return {"created_at": created, "id": id, "room": "room_core", "sources": [], "text": text,
                "truncated": False, "type": kind}

    def propose(self, title):
        self.proposed.append(title)
        return {"inbox_id": f"inb_{len(self.proposed)}", "state": "pending"}

    # --- the MCP face the harness sees ---
    def rpc(self, req):
        raw = compact(req)
        self.bytes_in += len(raw)
        out = compact({"jsonrpc": "2.0", "id": req["id"], "result": self._do(req)})
        self.bytes_out += len(out)
        return out

    def _do(self, req):
        if req["method"] == "tools/list":
            return {"tools": self.tools}
        p = req["params"]
        n, a = p["name"], p.get("arguments", {})
        if n == "ainkrad_search":
            return {"content": [{"type": "text", "text": compact(self.answer)}]}
        if n == "ainkrad_run":
            return {"content": [{"type": "text", "text": self.run(a["code"])}]}
        if n == "jira_search_issues":
            return {"content": [{"type": "text", "text": compact(self.op("searchIssues", a))}]}
        if n == "jira_get_issue":
            return {"content": [{"type": "text", "text": compact(self.op("getIssue", a))}]}
        if n == "brain_propose":
            return {"content": [{"type": "text", "text": compact(self.propose(a["title"]))}]}
        raise KeyError(n)

    def run(self, code):
        """The shim's job: run the script in the child, answer like `reply_text` (shim.rs)."""
        r = subprocess.run([RUNNER, "__script", self.sock_path], input=json.dumps({"code": code, "run": "r1"}),
                           capture_output=True, text=True, env={}, check=True)
        e = json.loads(r.stdout)
        console = f"\nconsole:\n{chr(10).join(e['logs'])}" if e["logs"] else ""
        footer = f"[{e['calls']} calls, {e['ms']} ms]"
        if e["ok"]:
            return f"{e.get('value') or 'null'}{console}\n{footer}"
        raise AssertionError(f"script failed: {e['error']}")


class Turns:
    """The accounting of E0: every turn re-reads the tool definitions and the whole conversation."""

    def __init__(self, core, defs_tok, ctx):
        self.core, self.defs_tok, self.ctx = core, defs_tok, ctx
        self.in_sum = self.out_sum = self.res_tok = self.calls = self.turns = 0
        self.wall, self.cid = 0.0, 0

    def turn(self, calls, ops=0):
        """One model turn issuing `calls` (parallel MCP calls); `ops` script ops add CALL_S each, in sequence."""
        self.turns += 1
        self.in_sum += self.defs_tok + self.ctx
        req = compact([{"name": n, "arguments": a} for n, a in calls])
        out = tok(req)
        self.out_sum += out
        self.ctx += out
        res = []
        for n, a in calls:
            self.cid += 1
            r = json.loads(self.core.rpc({"id": self.cid, "method": "tools/call", "params": {"name": n, "arguments": a}}))
            t = r["result"]["content"][0]["text"]
            res.append(t)
            self.calls += 1
            self.res_tok += tok(t)
            self.ctx += tok(t)
        self.wall += e0.TURN_BASE_S + out / e0.OUT_TPS + e0.CALL_S + ops * e0.CALL_S
        return res

    def answer(self, text):
        self.turns += 1
        self.in_sum += self.defs_tok + self.ctx
        out = tok(text)
        self.out_sum += out
        self.wall += e0.TURN_BASE_S + out / e0.OUT_TPS


def js(v):
    return json.dumps(v)


def brain_script(topic, project):
    return (f"const room = ainkrad.brain.brainAiRooms().find(r => r.open).id;\n"
            f"const decisions = ainkrad.brain.brainAiDecisions({{ room, limit: 10 }}).records.slice(0, 4).map(h => {{\n"
            f"  const r = ainkrad.brain.brainAiRecord({{ room, id: h.id }});\n"
            f"  return {{ id: h.id, title: r.text.split('. ')[0], gist: r.text.slice(0, 160) }};\n}});\n"
            f"{{JIRA}}return {{ room, decisions{{RET}} }};")


JIRA_JS = ("const found = ainkrad.jira.searchIssues({ jql: 'project = %s AND statusCategory != Done', max_results: 50 });\n"
           "const issues = found.issues.slice(0, 5).map(i => {\n"
           "  const x = ainkrad.jira.getIssue({ key: i.key });\n"
           "  return { key: i.key, summary: x.fields.summary, status: x.fields.status.name, priority: x.fields.priority.name };\n"
           "});\n")


def summary_of(topic, titles, keys):
    return ("Decisions on " + topic + ": " + "; ".join(titles) + ". Open issues: " + "; ".join(keys)
            + ". The open issues follow from the decisions above and none contradicts them; "
            "the highest priority ones should be taken first.")


def run_variant(variant):
    data = json.load(open(os.path.join(FIX, "data.json")))
    plain_all = {t["name"]: t for t in json.load(open(os.path.join(FIX, "tools.json")))}
    note, run_tool, search_tool, defs = real_texts()
    topic, project = data["topic"], data["project"]
    full = variant == "codemode_full"
    plain = [] if full else [plain_all[n] for n in ("jira_search_issues", "jira_get_issue", "brain_propose")]
    answer = defs["search_answer"]  # real: Core catalogue + renderer, Brain session
    if full:
        answer = {"defs": answer["defs"] + JIRA_DEFS}
    core = Core(data, plain, run_tool, search_tool, answer, plain)
    defs_listed = json.loads(core.rpc({"id": 0, "method": "tools/list"}))["result"]["tools"]
    t = Turns(core, tok(compact(defs_listed)),
              tok(e0.SYSTEM_PROMPT) + tok(note) + tok(e0.TASK.format(topic=topic, project=project)))
    q = ("ainkrad_search", {"query": SEARCH_QUERY + (" jira issues" if full else "")})
    if full:
        t.turn([q])
        code = brain_script(topic, project).replace("{JIRA}", JIRA_JS % project).replace(
            "{RET}", ", issues")
        got = json.loads(t.turn([("ainkrad_run", {"code": code})], ops=2 + 4 + 1 + 5)[0].rsplit("\n", 1)[0])
    else:
        code = brain_script(topic, project).replace("{JIRA}", "").replace("{RET}", "")
        jq = ("jira_search_issues", {"jql": f"project = {project} AND statusCategory != Done", "project": project,
                                     "fields": ["summary", "status", "priority"], "max_results": 50})
        r = t.turn([q, jq])
        keys = [i["key"] for i in json.loads(r[1])["issues"][:5]]
        r = t.turn([("ainkrad_run", {"code": code})] + [("jira_get_issue", {"key": k}) for k in keys], ops=2 + 4 + 1)
        got = json.loads(r[0].rsplit("\n", 1)[0])
        got["issues"] = [{"key": k} for k in keys]
    titles = [d["title"] for d in got["decisions"]]
    keys = [i["key"] for i in got["issues"]]
    s = summary_of(topic, titles, keys)
    body = {"kind": "note", "title": f"Open work on {topic}", "body": s, "sources": [d["id"] for d in got["decisions"]] + keys}
    if full:
        t.turn([("ainkrad_run", {"code": f"return ainkrad.brain.brainAiPropose({{ room: {js(got['room'])}, "
                                         f"body: {js(body)} }});"})], ops=1)
    else:
        t.turn([("brain_propose", {"room": got["room"], **body})])
    t.answer(s)
    assert core.proposed, "the task ends with one proposed record"
    return {"tool_definitions": len(defs_listed), "tool_definition_tokens": tok(compact(defs_listed)),
            "model_turns": t.turns, "mcp_calls": t.calls, "script_ops": core.script_ops, "result_tokens": t.res_tok,
            "output_tokens": t.out_sum, "input_tokens_total": t.in_sum, "tokens_total": t.in_sum + t.out_sum,
            "wall_modeled_s": round(t.wall, 2)}


def pct(new, old):
    return round(100 * (new - old) / old, 1)


def main(argv):
    n = int(argv[argv.index("--runs") + 1]) if "--runs" in argv else 2
    base = e0.run_once()
    out = {"runs": n, "baseline": base, "constants": {"token_chars": e0.TOKEN_CHARS, "turn_base_s": e0.TURN_BASE_S,
                                                       "out_tps": e0.OUT_TPS, "call_s": e0.CALL_S}}
    for v in ("codemode_full", "codemode_phase1"):
        runs = [run_variant(v) for _ in range(n)]
        for k in ("tokens_total", "wall_modeled_s"):  # repeatable within 5% (script ms in the footer varies)
            vals = [r[k] for r in runs]
            assert max(vals) - min(vals) <= 0.05 * max(vals), f"{v} {k} not repeatable: {vals}"
        r = runs[0]
        r["tokens_change_pct"] = pct(r["tokens_total"], base["tokens_total"])
        r["wall_change_pct"] = pct(r["wall_modeled_s"], base["wall_modeled_s"])
        r["gate_pass"] = r["tokens_change_pct"] <= -50 and r["wall_change_pct"] <= -50
        out[v] = r
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(sys.argv[1:])
