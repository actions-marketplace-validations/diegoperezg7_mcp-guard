#!/usr/bin/env bash
# Field study: scan public MCP servers with mcp-guard, each one inside a
# throwaway Docker container. See docs/field-study.md for the method and results.
#
#   npm run build && scripts/field-study.sh [out-dir]
#
# Static analysis only: no --probe, no --allow-unsafe, no tool is ever called.
# Each package is installed at build time (network on, install scripts off) and
# runs with no network, a read-only root filesystem, no capabilities, a non-root
# user, 512 MiB of memory and one CPU. Nothing from the host is mounted except,
# for the filesystem server, an empty temporary directory (read-only).
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${1:-field-study-results}"
mkdir -p "$OUT"

NODE_IMAGE="node:24-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c"
PY_IMAGE="python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"
PREFIX="mcp-guard-field"

# id | ecosystem | package | version | executable | arguments
SERVERS=(
  "filesystem|npm|@modelcontextprotocol/server-filesystem|2.0.1|mcp-server-filesystem|/data"
  "memory|npm|@modelcontextprotocol/server-memory|2.0.0|mcp-server-memory|"
  "everything|npm|@modelcontextprotocol/server-everything|2.0.1|mcp-server-everything|"
  "sequential-thinking|npm|@modelcontextprotocol/server-sequential-thinking|2.0.0|mcp-server-sequential-thinking|"
  "fetch|pypi|mcp-server-fetch|2026.10.24|mcp-server-fetch|"
  "git|pypi|mcp-server-git|2026.10.19|mcp-server-git|"
  "time|pypi|mcp-server-time|2026.10.19|mcp-server-time|--local-timezone UTC"
  "playwright|npm|@playwright/mcp|0.0.83|playwright-mcp|"
  "chrome-devtools|npm|chrome-devtools-mcp|1.12.0|chrome-devtools-mcp|"
  "context7|npm|@upstash/context7-mcp|4.4.4|context7-mcp|"
  "notion|npm|@notionhq/notion-mcp-server|2.6.0|notion-mcp-server|"
  "desktop-commander|npm|@wonderwhy-er/desktop-commander|0.3.1|desktop-commander|"
  "markitdown|pypi|markitdown-mcp|0.0.1a8|markitdown-mcp|"
  "duckduckgo|pypi|duckduckgo-mcp-server|0.7.0|duckduckgo-mcp-server|"
)

DATA_DIR="$(mktemp -d /tmp/mcp-guard-field.XXXXXX)"
cleanup() {
  for entry in "${SERVERS[@]}"; do
    docker image rm -f "$PREFIX-${entry%%|*}" >/dev/null 2>&1 || true
  done
  rmdir "$DATA_DIR" 2>/dev/null || true
}
trap cleanup EXIT

build() {
  local id=$1 eco=$2 pkg=$3 version=$4
  if [ "$eco" = npm ]; then
    docker build -q -t "$PREFIX-$id" - >/dev/null <<EOF
FROM $NODE_IMAGE
RUN npm install -g --ignore-scripts --no-audit --no-fund $pkg@$version && npm cache clean --force
USER node
EOF
  else
    docker build -q -t "$PREFIX-$id" - >/dev/null <<EOF
FROM $PY_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir --disable-pip-version-check $pkg==$version
USER nobody
EOF
  fi
}

run_cmd() {
  local id=$1 bin=$2 args=$3 mount=""
  [ "$id" = filesystem ] && mount="-v $DATA_DIR:/data:ro"
  echo "docker run -i --rm --network none --memory 512m --cpus 1 --pids-limit 256 --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges -e HOME=/tmp $mount $PREFIX-$id $bin $args"
}

STDIO_ARGS=()
for entry in "${SERVERS[@]}"; do
  IFS='|' read -r id eco pkg version bin args <<<"$entry"
  echo "== $id ($pkg $version)"
  build "$id" "$eco" "$pkg" "$version"
  cmd="$(run_cmd "$id" "$bin" "$args")"
  STDIO_ARGS+=(--stdio "$cmd")
  # --fail-on none: findings are the point here, not a reason to stop.
  node dist/cli/index.js scan --stdio "$cmd" --fail-on none --format json >"$OUT/$id.json" ||
    echo "   scan failed for $id (exit $?)"
done

# All servers in one scan: the per-server findings plus cross-server
# collisions (MCPG-010/011) that only show when servers are installed together.
node dist/cli/index.js scan "${STDIO_ARGS[@]}" --fail-on none --format json \
  -o "markdown:$OUT/combined.md" -r "$OUT/combined.html" >"$OUT/combined.json"
echo "Results in $OUT/"
