#!/usr/bin/env python3
"""Breaking-change check for api/openapi.json, events.schema.json and runner.schema.json (E1-05.4).

    schema_compat.py <base-dir> <new-dir>

Walks old and new documents together. Within a major the contract is additive-only, so each of
these fails: a removed path, operation, schema, property, enum value or oneOf variant; a type that
is narrowed or changed; a property that is required now and was not (this also enforces the rule
that every NEW field is `required = false`: a new property listed in `required` is "required now,
not before"). A schema that is new as a whole is not compared: it has no old shape.
"""
import json
import sys
from pathlib import Path

FILES = ("openapi.json", "events.schema.json", "runner.schema.json")
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


def main(base, new):
    problems = []
    for name in FILES:
        if not (Path(base) / name).exists():  # the baseline predates this file
            print(f"schema-compat: no baseline for {name}, skipped", file=sys.stderr)
            continue
        old = json.loads((Path(base) / name).read_text())
        cur = json.loads((Path(new) / name).read_text())
        found = []
        walk(old, cur, "", found)
        problems += [f"{name}: {p}" for p in found]
    for p in problems:
        print("schema-compat:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
