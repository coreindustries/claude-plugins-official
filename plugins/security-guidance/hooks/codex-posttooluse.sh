#!/usr/bin/env bash
set -euo pipefail
plugin_root="${CLAUDE_PLUGIN_ROOT:?CLAUDE_PLUGIN_ROOT must point to the plugin root}"
exec bash "${plugin_root}/hooks/sg-python.sh" "${plugin_root}/hooks/hook-output.py" --runtime codex --event PostToolUse
