#!/usr/bin/env python3
"""E0.1 baseline driver: a scripted ("fake") model does the reference task through plain per-operation MCP
tools against a fake Core. Standard library only. Prints one JSON object. Touches no production crate.

Reference task: "find the decisions about <topic> in the Brain, read the open Jira issues of the project,
summarise, propose one record".

  scripts/e0-baseline.py [--runs N] [--regen]       (default: 2 runs, JSON on stdout)

Everything a number depends on is fixed: the tool list and data in scripts/e0-baseline/*.json (made by
gen.py), the plan below, and the cost model constants. Nothing calls a model or the network.

Cost model (constants, change them in one place, compare like with like):
  TOKEN_CHARS      4 characters per token (a coarse estimate; ratios between runs are what E8 compares)
  TURN_BASE_S      1.5 s per model turn before it starts writing
  OUT_TPS          60 output tokens per second
  CALL_S           0.15 s per MCP tool call (relay hop plus the Core's work); calls of one turn run in parallel
`wall_modeled_s` uses those; `wall_measured_s` is the real clock of this process (informational: the fake
Core answers in microseconds, so it is NOT what E8 compares).
"""
import json
import math
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "e0-baseline")
TOKEN_CHARS, TURN_BASE_S, OUT_TPS, CALL_S = 4, 1.5, 60, 0.15
SYSTEM_PROMPT = ("You are a coding session running on an Ainkrad runner. Use the tools you are given. "
                 "Answer briefly. " * 12)
TASK = ("Find the decisions about {topic} in the Brain, read the open Jira issues of project {project}, "
        "summarise them in one paragraph, and propose one Brain record that captures the outcome.")


def tok(s):
    return math.ceil(len(s) / TOKEN_CHARS)


def compact(o):
    return json.dumps(o, separators=(",", ":"), sort_keys=True)


class FakeCore:
    """An MCP server (JSON-RPC, the shape of `tools/mcp.rs`) over the fixtures. Counts bytes both ways."""

    def __init__(self, tools, data):
        self.tools, self.d = tools, data
        self.bytes_in = self.bytes_out = self.calls = 0
        self.proposed = []

    def rpc(self, req):
        raw = compact(req)
        self.bytes_in += len(raw)
        out = compact({"jsonrpc": "2.0", "id": req["id"], "result": self._do(req)})
        self.bytes_out += len(out)
        return out

    def _do(self, req):
        if req["method"] == "tools/list":
            return {"tools": self.tools}
        assert req["method"] == "tools/call", req
        self.calls += 1
        p = req["params"]
        r = getattr(self, p["name"])(**p.get("arguments", {}))
        return {"content": [{"type": "text", "text": r}]}

    @staticmethod
    def fence(src, o):  # the untrusted envelope (OpenBot E2): the model sees the wrapper
        return f'<untrusted source="{src}">{compact(o)}</untrusted>'

    def brain_list_rooms(self):
        return self.fence("brain.list_rooms", self.d["rooms"])

    def brain_search(self, room, query, kind=None, limit=10):
        hits = [h for h in self.d["hits"] if kind in (None, h["kind"])][:limit]
        return self.fence("brain.search", {"room": room, "query": query, "hits": hits})

    def brain_read_record(self, room, id):
        return self.fence("brain.read_record", self.d["records"][id])

    def brain_propose(self, room, kind, title, body, sources=()):
        self.proposed.append(title)
        return compact({"inbox_id": f"inb_{len(self.proposed)}", "state": "pending"})

    def jira_list_projects(self, **_):
        return compact({"values": [{"key": self.d["project"], "name": "Acme"}, {"key": "APP", "name": "App"}]})

    def jira_search_issues(self, jql="", project=None, max_results=50, **_):
        rows = list(self.d["issues"].values())[:max_results]
        slim = [{"key": r["key"], "fields": {k: r["fields"][k] for k in ("summary", "status", "priority")}}
                for r in rows]
        return compact({"issues": slim, "total": len(slim)})

    def jira_get_issue(self, key, fields=None):
        return compact(self.d["issues"][key])


def model_plan(topic, project):
    """The scripted model: a generator. It yields a list of (tool, args) per turn, is sent the list of result
    texts, and finally returns the answer text. The fixed plan of a competent session using plain tools."""
    r = yield [("brain_list_rooms", {}), ("jira_list_projects", {})]
    rooms = json.loads(r[0].split(">", 1)[1].rsplit("</", 1)[0])
    room = next(x["id"] for x in rooms if x["project"] == project)
    r = yield [("brain_search", {"room": room, "query": topic, "kind": "decision", "limit": 10}),
               ("jira_search_issues", {"jql": f"project = {project} AND statusCategory != Done", "project": project,
                                       "fields": ["summary", "status", "priority"], "max_results": 50})]
    hits = json.loads(r[0].split(">", 1)[1].rsplit("</", 1)[0])["hits"][:4]
    keys = [i["key"] for i in json.loads(r[1])["issues"][:5]]
    r = yield ([("brain_read_record", {"room": room, "id": h["id"]}) for h in hits]
               + [("jira_get_issue", {"key": k}) for k in keys])
    summary = ("Decisions on " + topic + ": " + "; ".join(h["title"] for h in hits) + ". Open issues: "
               + "; ".join(keys) + ". The open issues follow from the decisions above and none contradicts them; "
               "the highest priority ones should be taken first.")
    yield [("brain_propose", {"room": room, "kind": "note", "title": f"Open work on {topic}", "body": summary,
                              "sources": [h["id"] for h in hits] + keys})]
    return summary


def run_once():
    tools = json.load(open(os.path.join(FIX, "tools.json")))
    data = json.load(open(os.path.join(FIX, "data.json")))
    core = FakeCore(tools, data)
    t0 = time.perf_counter()
    defs = json.loads(core.rpc({"id": 0, "method": "tools/list"}))["result"]["tools"]
    defs_tok = tok(compact(defs))
    ctx = tok(SYSTEM_PROMPT) + tok(TASK.format(topic=data["topic"], project=data["project"]))
    in_sum = out_sum = res_tok = calls = turns = 0
    wall = 0.0
    plan = model_plan(data["topic"], data["project"])
    results, call_id = None, 0
    while True:
        try:
            batch = plan.send(results) if results is not None else next(plan)
        except StopIteration as done:
            out = tok(done.value)
            in_sum += defs_tok + ctx
            out_sum += out
            turns += 1
            wall += TURN_BASE_S + out / OUT_TPS
            break
        turns += 1
        in_sum += defs_tok + ctx  # every turn re-reads the tool definitions and the whole conversation
        req_text = compact([{"name": n, "arguments": a} for n, a in batch])
        out = tok(req_text)
        out_sum += out
        ctx += out
        wall += TURN_BASE_S + out / OUT_TPS + CALL_S
        results = []
        for n, a in batch:
            call_id += 1
            r = json.loads(core.rpc({"id": call_id, "method": "tools/call", "params": {"name": n, "arguments": a}}))
            text = r["result"]["content"][0]["text"]
            results.append(text)
            calls += 1
            res_tok += tok(text)
            ctx += tok(text)
    assert core.proposed, "the task ends with one proposed record"
    return {
        "tool_definitions": len(defs), "tool_definition_tokens": defs_tok, "model_turns": turns,
        "mcp_calls": calls, "result_tokens": res_tok, "output_tokens": out_sum,
        "input_tokens_total": in_sum, "tokens_total": in_sum + out_sum,
        "bytes_to_core": core.bytes_in, "bytes_from_core": core.bytes_out,
        "wall_modeled_s": round(wall, 2), "wall_measured_s": round(time.perf_counter() - t0, 4),
    }


def main(argv):
    if "--regen" in argv:
        subprocess.run([sys.executable, os.path.join(FIX, "gen.py")], check=True)
    n = int(argv[argv.index("--runs") + 1]) if "--runs" in argv else 2
    runs = [run_once() for _ in range(n)]
    for k in ("tokens_total", "wall_modeled_s"):  # E0.1 accept: two runs differ by under 5%
        v = [r[k] for r in runs]
        assert (max(v) - min(v)) <= 0.05 * max(v), f"{k} is not repeatable: {v}"
    print(json.dumps({"mode": "plain_per_operation_tools", "runs": n, "result": runs[0],
                      "constants": {"token_chars": TOKEN_CHARS, "turn_base_s": TURN_BASE_S, "out_tps": OUT_TPS,
                                    "call_s": CALL_S}}, indent=1))


if __name__ == "__main__":
    main(sys.argv[1:])
