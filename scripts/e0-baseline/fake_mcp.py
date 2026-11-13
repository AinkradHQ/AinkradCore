#!/usr/bin/env python3
"""A stdio MCP server over the E0 fixtures (the same FakeCore the fake-harness run uses), for the live run."""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("e0", os.path.join(HERE, "..", "e0-baseline.py"))
e0 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e0)
core = e0.FakeCore(json.load(open(os.path.join(HERE, "tools.json"))), json.load(open(os.path.join(HERE, "data.json"))))
for line in sys.stdin:
    req = json.loads(line)
    if req.get("method") == "initialize":
        out = {"jsonrpc": "2.0", "id": req["id"], "result": {"protocolVersion": req["params"]["protocolVersion"],
               "capabilities": {"tools": {}}, "serverInfo": {"name": "e0", "version": "1"}}}
    elif "id" not in req:
        continue  # notifications
    elif req["method"] in ("tools/list", "tools/call"):
        out = json.loads(core.rpc(req))
    else:
        out = {"jsonrpc": "2.0", "id": req["id"], "result": {}}
    print(json.dumps(out), flush=True)
