#!/usr/bin/env bash
# E0.2: ONE live run of the reference task with a real claude, against the fake Core (same tools and data
# as the fake-harness run). Run it yourself on the Air, logged in to your own account. Costs a few cents.
# Prints num_turns, duration, tokens and cost; compare with `scripts/e0-baseline.py`.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/mcp.json" <<J
{"mcpServers":{"e0":{"command":"python3","args":["$here/fake_mcp.py"]}}}
J
task="$(python3 -c "
import json,sys;d=json.load(open('$here/data.json'))
print('Find the decisions about %s in the Brain, read the open Jira issues of project %s, summarise them in one paragraph, and propose one Brain record that captures the outcome.' % (d['topic'], d['project']))")"
cd "$tmp"
claude -p "$task" --mcp-config "$tmp/mcp.json" --strict-mcp-config --allowedTools 'mcp__e0__*' \
  --tools "" --output-format json --max-turns 20 --max-budget-usd 1 |
  python3 -c "
import json,sys;r=json.load(sys.stdin);u=r.get('usage',{})
print(json.dumps({k:r.get(k) for k in ('num_turns','duration_ms','duration_api_ms','total_cost_usd')}
  | {'input_tokens':u.get('input_tokens'),'cache_creation':u.get('cache_creation_input_tokens'),
     'cache_read':u.get('cache_read_input_tokens'),'output_tokens':u.get('output_tokens')},indent=1))"
