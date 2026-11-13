#!/usr/bin/env python3
"""Regenerates tools.json and data.json (E0.1). Deterministic; standard library only.

tools.json: the tool list a session sees TODAY with plain per-operation MCP tools: the GitHub and Jira
operations exactly as `broker/tools.rs` words and `broker/schemas.rs` shapes them, plus the Brain
operations as plain tools (BM-41 shape). data.json: the fake Core's records.
"""
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
ARGS = {
    "github": "Arguments (an object): repo as owner/name, and as the operation needs number, path, query (an "
    "object of plain values) or body (an object). Any other name is refused.",
    "jira": "Arguments (an object): the issue key, project key, text and ids this operation takes. Any other "
    "name is refused.",
}


def obj(props, req):
    return {"type": "object", "properties": props, "required": req, "additionalProperties": False}


def text(n, what):
    return {"type": "string", "minLength": 1, "maxLength": n, "description": what}


def gh(number=False, path=False, body=False):
    p = {"repo": {"type": "string", "description": "The repository as owner/name"}}
    req = ["repo"]
    if number:
        req.append("number")
        p["number"] = {"type": "integer", "minimum": 1, "description": "The issue or pull request number"}
    if path:
        req.append("path")
        p["path"] = {"type": "string", "description": "A file path inside the repository"}
    p["query"] = {"type": "object", "description": "Query parameters: plain values (text, number, boolean), "
                  "at most 16", "additionalProperties": {"type": ["string", "number", "boolean"]}}
    if body:
        req.append("body")
        p["body"] = {"type": "object", "description": "The JSON body GitHub's API takes for this operation"}
    return obj(p, req)


def key():
    return text(32, "The issue key, like ABC-12")


def fields():
    return {"type": "array", "items": {"type": "string"}, "maxItems": 30,
            "description": "Field names to return, like summary or customfield_10010"}


def labels():
    return {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 255, "pattern": "^\\S+$"},
            "maxItems": 20, "description": "Labels (no spaces)"}


R = "Read repositories, issues and pull requests"
GH = [
    ("get_repo", R, gh()), ("list_branches", R, gh()), ("read_file", R, gh(path=True)),
    ("list_issues", R, gh()), ("get_issue", R, gh(number=True)), ("list_issue_comments", R, gh(number=True)),
    ("list_prs", R, gh()), ("get_pr", R, gh(number=True)), ("list_pr_files", R, gh(number=True)),
    ("list_pr_reviews", R, gh(number=True)),
    ("create_issue", "Create and edit issues and comment on them", gh(body=True)),
    ("update_issue", "Create and edit issues and comment on them", gh(number=True, body=True)),
    ("comment_issue", "Create and edit issues and comment on them", gh(number=True, body=True)),
    ("create_pr", "Open pull requests and comment on them", gh(body=True)),
    ("update_pr", "Open pull requests and comment on them", gh(number=True, body=True)),
    ("comment_pr", "Open pull requests and comment on them", gh(number=True, body=True)),
    ("create_branch", "Create branches and commit files", gh(body=True)),
    ("put_file", "Create branches and commit files", gh(path=True, body=True)),
]
RI, WI, TI = "Read issues and projects", "Create and edit issues, add comments", "Move issues through the workflow"
JIRA = [
    ("search_issues", RI, obj({"jql": text(4000, "A JQL query"), "project": text(10, "Limit the search to this project key"),
        "fields": fields(), "order_by": {"type": "array", "items": {"type": "string"}, "maxItems": 5,
        "description": "Terms like \"created desc\""}, "max_results": {"type": "integer", "minimum": 1, "maximum": 100},
        "next_page_token": text(4000, "The token a previous page gave")}, [])),
    ("get_issue", RI, obj({"key": key(), "fields": fields()}, ["key"])),
    ("list_transitions", RI, obj({"key": key()}, ["key"])),
    ("list_projects", RI, obj({"start_at": {"type": "integer", "minimum": 0, "maximum": 1000000},
        "max_results": {"type": "integer", "minimum": 1, "maximum": 50}}, [])),
    ("create_issue", WI, obj({"project": text(10, "The project key, like ABC"), "summary": text(255, "The summary"),
        "issue_type": text(60, "The issue type's name, like Task"),
        "description": text(30000, "The description, as plain text"), "labels": labels()},
        ["project", "summary", "issue_type"])),
    ("update_issue", WI, obj({"key": key(), "summary": text(255, "The new summary"),
        "description": text(30000, "The new description, as plain text"), "labels": labels()}, ["key"])),
    ("add_comment", WI, obj({"key": key(), "body": text(30000, "The comment, as plain text")}, ["key", "body"])),
    ("transition_issue", TI, obj({"key": key(), "transition_id": {"type": "string", "pattern": "^[0-9]{1,10}$",
        "description": "The id list_transitions gave"}}, ["key", "transition_id"])),
]
room = {"type": "string", "description": "The room id"}
BRAIN = [
    ("brain_list_rooms", "List the Brain rooms this session may see.", obj({}, [])),
    ("brain_search", "Full-text search one Brain room. Returns ranked hits with a short snippet.",
     obj({"room": room, "query": text(500, "The search text"), "kind": {"type": "string",
          "enum": ["decision", "fact", "note", "task"], "description": "Limit hits to one record kind"},
          "limit": {"type": "integer", "minimum": 1, "maximum": 50}}, ["room", "query"])),
    ("brain_read_record", "Read one Brain record in full.", obj({"room": room, "id": text(64, "The record id")},
                                                                  ["room", "id"])),
    ("brain_list_inbox", "List the proposals waiting in a room's inbox.", obj({"room": room}, ["room"])),
    ("brain_propose", "Propose a new record to a room's inbox. A person accepts or refuses it.",
     obj({"room": room, "kind": {"type": "string", "enum": ["decision", "fact", "note", "task"]},
          "title": text(255, "The record title"), "body": text(30000, "The record body, as Markdown"),
          "sources": {"type": "array", "items": {"type": "string"}, "maxItems": 20,
                      "description": "Ids or keys the record is based on"}}, ["room", "kind", "title", "body"])),
]


def tools():
    out = []
    for kind, rows in (("github", GH), ("jira", JIRA)):
        for op, title, schema in rows:
            out.append({"name": f"{kind}_{op}", "description": f"{title}: {kind}.{op}. {ARGS[kind]}",
                        "inputSchema": schema})
    out += [{"name": n, "description": d, "inputSchema": s} for n, d, s in BRAIN]
    return out


WORDS = ("runner session sandbox relay socket approval scope grant audit origin brain room claim inbox policy "
         "connection token budget account provider chain pool device pairing terminal transcript harness "
         "gateway egress filter limit retry timeout queue cursor idempotent schema contract module catalogue "
         "operation principal envelope untrusted review merge release migration index search record").split()


def prose(rng, n):
    return " ".join(rng.choice(WORDS) for _ in range(n)).capitalize() + "."


def data():
    rng = random.Random(7)
    topic = "approvals"
    hits = [{"id": f"rec_{i:02d}", "kind": rng.choice(["decision", "decision", "fact", "note"]),
             "title": f"{prose(rng, 5)[:-1]}", "snippet": prose(rng, 28), "score": round(1 - i * 0.04, 2),
             "created": f"2026-0{1 + i % 9}-1{i % 9}"} for i in range(12)]
    records = {h["id"]: {**h, "body": "\n\n".join(prose(rng, 60) for _ in range(5)),
                         "sources": [f"ABC-{100 + int(h['id'][4:])}"], "room": "room_core"} for h in hits}
    issues = {}
    for i in range(14):
        k = f"ABC-{100 + i}"
        issues[k] = {"key": k, "id": str(10000 + i), "self": f"https://acme.atlassian.net/rest/api/3/issue/{10000 + i}",
                     "fields": {"summary": prose(rng, 8)[:-1], "status": {"name": rng.choice(["To Do", "In Progress"])},
                                "priority": {"name": rng.choice(["High", "Medium", "Low"])},
                                "assignee": {"displayName": rng.choice(["Dana", "Lee", "Sam"])},
                                "labels": rng.sample(["core", "brain", "mcp", "ux", "infra"], 2),
                                "created": f"2026-10-{10 + i}T09:00:00.000+0000",
                                "description": "\n\n".join(prose(rng, 55) for _ in range(4)),
                                "comment": {"total": 3, "comments": [{"author": "Sam", "body": prose(rng, 30)}
                                                                      for _ in range(3)]}}}
    return {"topic": topic, "project": "ABC", "rooms": [
        {"id": "room_core", "name": "Core", "records": 214, "project": "ABC"},
        {"id": "room_app", "name": "App", "records": 97, "project": "APP"},
        {"id": "room_ops", "name": "Operations", "records": 58, "project": "OPS"}],
        "hits": hits, "records": records, "issues": issues}


if __name__ == "__main__":
    for name, obj_ in (("tools.json", tools()), ("data.json", data())):
        with open(os.path.join(HERE, name), "w") as f:
            json.dump(obj_, f, indent=1, sort_keys=True)
            f.write("\n")
