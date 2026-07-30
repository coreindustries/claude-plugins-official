from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
WRAPPER = PLUGIN_ROOT / "hooks" / "codex-posttooluse.sh"


class CodexHookManifestTests(unittest.TestCase):
    def test_bash_uses_one_router_without_claude_if_filters(self) -> None:
        manifest = json.loads((PLUGIN_ROOT / "hooks" / "hooks.json").read_text())
        bash_groups = [
            group
            for group in manifest["hooks"]["PostToolUse"]
            if group.get("matcher") == "Bash"
        ]

        self.assertEqual(len(bash_groups), 1)
        self.assertEqual(len(bash_groups[0]["hooks"]), 1)
        self.assertNotIn("if", bash_groups[0]["hooks"][0])
        self.assertIn("codex-posttooluse.sh", bash_groups[0]["hooks"][0]["command"])


class CodexPostToolUseWrapperTests(unittest.TestCase):
    def run_hook(self, event: dict) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as state_dir:
            fake_sdk = Path(state_dir) / "claude_agent_sdk.py"
            fake_sdk.write_text("# prevents dependency bootstrapping during tests\n")
            env = {
                **os.environ,
                "CLAUDE_PLUGIN_ROOT": str(PLUGIN_ROOT),
                "PYTHONPATH": state_dir,
                "SECURITY_WARNINGS_STATE_DIR": state_dir,
                "SECURITY_GUIDANCE_DEBUG_LOG": str(Path(state_dir) / "debug.log"),
            }
            return subprocess.run(
                ["bash", str(WRAPPER)],
                input=json.dumps(event),
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )

    def test_unrelated_bash_command_returns_valid_empty_json(self) -> None:
        result = self.run_hook(
            {
                "session_id": "codex-test",
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git fetch origin main"},
            }
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {})

    def test_clean_edit_returns_valid_empty_json(self) -> None:
        result = self.run_hook(
            {
                "session_id": "codex-test",
                "hook_event_name": "PostToolUse",
                "tool_name": "Edit",
                "tool_input": {
                    "file_path": "/tmp/example.py",
                    "new_string": "answer = 42\n",
                },
            }
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {})


if __name__ == "__main__":
    unittest.main()
