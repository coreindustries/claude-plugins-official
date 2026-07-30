#!/usr/bin/env bash
# Codex requires every successful PostToolUse hook to emit valid JSON.
# The security-guidance handler intentionally emits nothing for clean edits
# and Bash commands other than commit/push. Preserve all real output and
# synthesize an empty JSON object only for those no-op paths.

set -euo pipefail

plugin_root="${CLAUDE_PLUGIN_ROOT:?CLAUDE_PLUGIN_ROOT must point to the plugin root}"

set +e
hook_output="$(
    bash "${plugin_root}/hooks/sg-python.sh" \
        "${plugin_root}/hooks/security_reminder_hook.py"
)"
hook_status=$?
set -e

if [[ -n "${hook_output//[[:space:]]/}" ]]; then
    printf '%s\n' "${hook_output}"
else
    printf '{}\n'
fi

exit "${hook_status}"
