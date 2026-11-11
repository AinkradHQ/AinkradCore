#!/usr/bin/env bash
# The tools agents need on a runner host (N8, N39), shared by scripts/install.sh (the Core's built-in runner) and
# scripts/install/runner-only.sh (a runner on another machine). Sourced, never run. Needs `sha` (install.sh and runner-only.sh define it).
NODE_VERSION=22.22.1 CLAUDE_VERSION=2.1.318
NODE_SHA_X64=9a6bc82f9b491279147219f6a18add1e18424dce90d41d2a5fcd69d4924ba3aa NODE_SHA_ARM64=0f3550d58d45e5d3cf7103d9e3f69937f09fe82fb5dd474c66a5d816fa58c9ee
# Node 22 (pinned, checksum-verified tarball) and Claude Code at the pinned
# version with auto-update off. They live under /usr/local, which the agent sandbox binds read-only.
install_agent_tools() { local t rc=0; t=$(mktemp -d); install_agent_tools_in "$t" || rc=$?; rm -rf "$t"; return "$rc"; }
install_agent_tools_in() {
  umask 022
  local t=$1 arch sha node=/usr/local/lib/ainkrad-node
  case $(uname -m) in x86_64 | amd64) arch=x64 sha=$NODE_SHA_X64 ;; aarch64 | arm64) arch=arm64 sha=$NODE_SHA_ARM64 ;; *) echo "no Node build for $(uname -m)" >&2; return 1 ;; esac
  curl -fsSL --proto '=https' --tlsv1.3 -o "$t/node.tar.xz" "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$arch.tar.xz" || return 1
  [ "$(sha "$t/node.tar.xz")" = "$sha" ] || { echo "the Node download does not match the checksum pinned in this installer" >&2; return 1; }
  rm -rf "$node" && mkdir -p "$node" && tar -xJf "$t/node.tar.xz" -C "$node" --strip-components=1 || return 1
  ln -sf "$node/bin/node" /usr/local/bin/node
  PATH="$node/bin:$PATH" npm install -g --prefix "$node" --no-audit --no-fund "@anthropic-ai/claude-code@$CLAUDE_VERSION" || return 1
  ln -sf "$node/bin/claude" /usr/local/bin/claude
  mkdir -p /etc/claude-code
  printf '%s\n' '{"env":{"DISABLE_AUTOUPDATER":"1"}}' >/etc/claude-code/managed-settings.json
  chmod 0644 /etc/claude-code/managed-settings.json
  HOME=$t "$node/bin/node" --version | grep -q "^v22\." || { echo "Node 22 did not install" >&2; return 1; }
  HOME=$t /usr/local/bin/claude --version | grep -q "^$CLAUDE_VERSION" || { echo "claude $CLAUDE_VERSION did not install" >&2; return 1; }
}
