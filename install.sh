#!/usr/bin/env sh
#   Copyright (c) 2025-2026 Anton Kundenko <singaraiona@gmail.com>
#   All rights reserved.
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.

# raysense one-liner installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/RayforceDB/raysense/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/RayforceDB/raysense/main/install.sh | sh -s -- --no-mcp
#
# What it does:
#   1. Verifies prerequisites (cargo, git, make, a C compiler).
#   2. Runs `cargo install raysense` from crates.io.
#   3. Runs `raysense install` to register raysense across every Claude host
#      detected on this machine:
#        - Claude Desktop  (MCP server in claude_desktop_config.json)
#        - Claude Code     (raysense plugin in ~/.claude/settings.json:
#                           tools + prompts + slash commands + skills)
#        - Cowork          (Desktop research-preview agent mode: registers
#                           the marketplace; finish with `/plugin install
#                           raysense@raysense-marketplace` in your next
#                           Cowork session)
#
# Flags:
#   --no-mcp     Skip the `raysense install` step (binary only).
#   --version V  Pin a specific crates.io version (e.g. --version 0.8.1).
#
# Notes:
#   - This installer is deliberately "cargo install"-based today. There is no
#     prebuilt-binary pipeline yet. When that lands, the script will gain a
#     prebuilt fast path and fall back to cargo only if needed.
#   - All output is plain ASCII so it stays readable in any terminal.

set -eu

NO_MCP=0
VERSION=""

while [ $# -gt 0 ]; do
    case "$1" in
        --no-mcp) NO_MCP=1 ;;
        --version)
            shift
            [ $# -gt 0 ] || { echo "raysense-install: --version needs a value" >&2; exit 2; }
            VERSION="$1"
            ;;
        --version=*) VERSION="${1#--version=}" ;;
        -h|--help)
            sed -n '24,42p' "$0" 2>/dev/null || cat <<EOF
raysense one-liner installer.

  --no-mcp     Skip the MCP-host registration step.
  --version V  Pin a specific crates.io version.
EOF
            exit 0
            ;;
        *)
            echo "raysense-install: unknown flag: $1" >&2
            exit 2
            ;;
    esac
    shift
done

say()  { printf 'raysense-install: %s\n' "$*"; }
warn() { printf 'raysense-install: %s\n' "$*" >&2; }
die()  { warn "$*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

require() {
    have "$1" || die "missing required tool: $1. Please install it and re-run."
}

say "checking prerequisites"
require cargo
require git
require make
if ! have cc && ! have clang && ! have gcc; then
    die "missing C compiler (cc / clang / gcc). Please install one and re-run."
fi

if [ -n "$VERSION" ]; then
    say "running: cargo install raysense --version $VERSION"
    cargo install raysense --version "$VERSION"
else
    say "running: cargo install raysense"
    cargo install raysense
fi

# Make sure the cargo bin dir is on PATH so `raysense install` resolves.
CARGO_BIN="${CARGO_HOME:-$HOME/.cargo}/bin"
case ":$PATH:" in
    *":$CARGO_BIN:"*) ;;
    *) PATH="$CARGO_BIN:$PATH"; export PATH ;;
esac

if [ "$NO_MCP" -eq 1 ]; then
    say "skipping MCP registration (--no-mcp)"
    say "done. Run 'raysense install' later to register with Claude hosts."
    exit 0
fi

if ! have raysense; then
    warn "raysense not on PATH after install. Add $CARGO_BIN to PATH and run 'raysense install'."
    exit 0
fi

say "registering raysense across every detected Claude host"
raysense install || {
    warn "host registration did not complete cleanly."
    warn "You can re-run 'raysense install' at any time, or pass --desktop / --code / --cowork to target a specific host."
    exit 0
}

say "done. Restart Claude Desktop / reload Claude Code to pick up raysense."
