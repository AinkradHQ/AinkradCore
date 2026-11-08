#!/usr/bin/env python3
"""Breaking-change check for every contract file (E1-05.4, C-21).

    schema_compat.py <base-root> <new-root> <repo-relative file>...

The files are those of scripts/contracts.list. A file with no baseline is new and not compared; a
file that has a baseline but is gone is a break.

Walks old and new documents together. Within a major the contract is additive-only, so each of
these fails: a removed path, operation, schema, property, enum value or oneOf variant; a type that
is narrowed or changed; a property that is required now and was not (this also enforces the rule
that every NEW field is `required = false`: a new property listed in `required` is "required now,
not before"). A schema that is new as a whole is not compared: it has no old shape.

A deliberate break is allowed only by its exact message in `<new-root>/api/compat-allow.txt`.
"""
import json
import sys
from pathlib import Path

VARIANTS = ("oneOf", "anyOf")


def types(node):
    t = node.get("type")  # a property may be *named* "type": then this is a schema, not a type
    if isinstance(t, str):
        return {t}
    return set(t) if isinstance(t, list) and all(isinstance(x, str) for x in t) else None


def variant_key(item, index):
    tag = None
    if isinstance(item, dict):  # a unit enum value (`const`) or a tagged message (`properties.type.const`)
        tag = item.get("const") or item.get("properties", {}).get("type", {}).get("const")
    ref = item.get("$ref") if isinstance(item, dict) else None
    return tag or ref or f"#{index}"


def walk(old, new, path, out):
    if isinstance(old, dict) and isinstance(new, dict):
        for key in old:
            here = f"{path}/{key}"
            if key not in new:
                # An annotation may go; a structural key (a property, path, schema, ...) may not.
                if key not in ("description", "summary", "example", "examples", "default", "title",
                               "deprecated", "externalDocs", "tags", "$schema", "format"):
                    out.append(f"removed {here}")
                continue
            walk(old[key], new[key], here, out)
        ot, nt = types(old), types(new)
        if ot and nt and not nt >= ot:
            out.append(f"type narrowed at {path}: {sorted(ot)} -> {sorted(nt)}")
        if isinstance(old.get("enum"), list) and isinstance(new.get("enum"), list):
            for value in old["enum"]:
                if value not in new["enum"]:
                    out.append(f"enum value {value!r} removed at {path}")
        if "const" in old and "const" in new and old["const"] != new["const"]:
            out.append(f"const changed at {path}")
        req_old, req_new = old.get("required"), new.get("required")
        ok = isinstance(old.get("properties"), dict) and isinstance(req_new, list)
        newly = set(req_new) - set(req_old or []) if ok else set()
        for name in sorted(newly):
            out.append(f"{path}: {name!r} is required now (a new or changed field must be required = false)")
    elif isinstance(old, list) and isinstance(new, list):
        for key in VARIANTS:
            if path.endswith("/" + key):
                keyed = {variant_key(v, i): v for i, v in enumerate(new)}
                for i, v in enumerate(old):
                    k = variant_key(v, i)
                    if k not in keyed:
                        out.append(f"variant {k} removed at {path}")
                    else:
                        walk(v, keyed[k], f"{path}/{k}", out)
    elif type(old) is not type(new) and old is not None:
        out.append(f"{path} changed shape")


def main(base, new, *files):
    problems = []
    for rel in files:
        # api/ files keep their short name in messages (the allow-list lines say "runner.schema.json: ...")
        name = rel[len("api/"):] if rel.startswith("api/") else rel
        if not (Path(base) / rel).exists():  # the baseline predates this file: new, nothing to compare
            print(f"schema-compat: no baseline for {name}, new file accepted", file=sys.stderr)
            continue
        if not (Path(new) / rel).exists():
            problems.append(f"{name}: contract file removed")
            continue
        old = json.loads((Path(base) / rel).read_text())
        cur = json.loads((Path(new) / rel).read_text())
        found = []
        walk(old, cur, "", found)
        problems += [f"{name}: {p}" for p in found]
    allow_file = Path(new) / "api" / "compat-allow.txt"
    allowed = set()
    if allow_file.exists():
        allowed = {l.strip() for l in allow_file.read_text().splitlines() if l.strip() and not l.startswith("#")}
    for p in [p for p in problems if p in allowed]:
        print("schema-compat: allowed by api/compat-allow.txt:", p, file=sys.stderr)
    for a in sorted(allowed - set(problems)):
        print("schema-compat: unused line in api/compat-allow.txt (delete it):", a, file=sys.stderr)
    problems = [p for p in problems if p not in allowed]
    for p in problems:
        print("schema-compat:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
