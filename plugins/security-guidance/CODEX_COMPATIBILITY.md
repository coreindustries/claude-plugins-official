# Claude and Codex hook compatibility

Codex uses this personal package. Claude Code keeps its native
`security-guidance@claude-plugins-official` package. Both now use the scanner
from the locally installed upstream 2.0.8 release. Do not enable both packages
in the same agent runtime: that would duplicate reviews.

`hooks/hook-output.py` adapts every registered event with an explicit runtime
and event argument. Its Claude mode streams input/output and exit status
unchanged, including the bootstrap's initial async handshake. The native
Claude installation needs no adapter and remains unchanged.

| Event | Codex behavior |
| --- | --- |
| SessionStart | Bootstrap runs with native manifest `async: true`, timeout 180 seconds. Consume Claude's JSON-lines async handshake and return the final response with notices preserved. |
| UserPromptSubmit | Capture the git baseline; emit valid `{}` for no output. |
| PostToolUse | One Bash router handles commit/push/Graphite. Normalize string Bash responses. Translate `apply_patch` into per-file scanner inputs using actual resulting content and preserve baseline suppression. Aggregate findings across files. |
| Stop | Preserve findings and the upstream recursion guard. |
| SubagentStop | Use upstream 2.0.8's dedicated subagent path, which preserves the parent's pending review state. |

All Codex responses remove Claude-only `metrics` and `rewakeSummary`; retain
control fields, user notices, and review findings; and validate event-specific
shape before returning JSON. Exit 2 findings are also placed on stderr when
upstream supplied them only in JSON, because Codex reads stderr on that path.
Unknown fields and malformed output produce visible errors, not success.
Other nonzero statuses and stderr propagate unchanged.

Codex manifests use supported fields, not Claude `if` / `asyncRewake` options.
Reviews are synchronous in Codex so their feedback is consumed before the
turn/tool completes; only SDK setup runs in the background. Claude retains its
native asynchronous review behavior. No review feature is disabled by this adapter.

The old `codex-posttooluse.sh` and `stop-output.py` paths forward to the shared
adapter for existing callers.

## Packaging from this repository

The source distribution keeps Claude's native `hooks/hooks.json` and
`.claude-plugin/plugin.json`. Codex uses `hooks/codex-hooks.json` and the
`codex-plugin.json` metadata template. Build the separate Codex distribution:

```sh
python3 plugins/security-guidance/scripts/package-codex.py /tmp/build/security-guidance-codex
```

The destination must not exist. The builder copies the scanner, adapters,
license, docs, and tests; selects the Codex hook manifest as `hooks/hooks.json`;
and creates `.codex-plugin/plugin.json` without a Claude manifest. It does not
change the source tree, marketplace, installed package, or hook trust.
Validate this artifact before updating your local plugin source and using
the normal cachebuster/reinstall workflow.

## Verification

Create an isolated test environment and run:

```sh
python3 -m venv /tmp/sg-hook-tests
/tmp/sg-hook-tests/bin/pip install -r tests/requirements.txt
/tmp/sg-hook-tests/bin/python -m unittest discover -s tests -v
bash -n hooks/codex-posttooluse.sh hooks/sg-python.sh
```

Tests execute all five real handlers in both runtime modes, validate output
against official Codex schema snapshots, cover empty and malformed output,
verify exit 2 finding delivery, exercise patch add/update/move/delete and
multi-file findings, and test real git baseline suppression. SDK availability
is stubbed in isolated tests to avoid package installs; LLM review is disabled
only in the test environment. These tests do not establish live provider or
fresh agent-session behavior.

Schema snapshots in `tests/schemas/` were retrieved on 2026-09-27 from
`https://raw.githubusercontent.com/openai/codex/main/codex-rs/hooks/schema/generated/`.
Each `<event>.json` corresponds to `<event>.command.output.schema.json`.

Protocol references:
- https://learn.chatgpt.com/docs/hooks
- https://code.claude.com/docs/en/hooks

## Known boundaries

- Upstream registers `NotebookEdit` and records the notebook path but does not
  extract `new_source` for immediate regex scanning. This existing scanner
  limitation is preserved and covered explicitly by a no-op protocol test.
- Hosted tools do not emit local tool-hook events. Shell-driven file writes
  have no per-edit pattern event; turn-end git review remains supplementary.
- LLM reviews require the existing configured provider credentials and SDK.
- Changed Codex hook definitions may require review in `/hooks`. Start a new
  thread after reinstall; existing threads can retain old plugin definitions.

## Maintenance

Refresh upstream Python scanner modules and `sg-python.sh` from the same
Claude-installed release, retaining adapters, the Codex manifest, and tests.
Rebuild the standalone Codex package. Run compatibility tests before using the plugin-creator cachebuster helper
and `codex plugin add security-guidance-codex@personal`. Do not edit installed
cache files directly.
