import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    @unittest.skipUnless((ROOT / "scripts/package-codex.py").exists(), "source packaging test")
    def test_package_selects_only_codex_hooks_and_preserves_source(self):
        native = (ROOT / "hooks/hooks.json").read_bytes()
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "security-guidance-codex"
            command = [sys.executable, str(ROOT / "scripts/package-codex.py"), str(destination)]
            subprocess.run(command, check=True, capture_output=True)
            self.assertFalse((destination / ".claude-plugin").exists())
            self.assertEqual((destination / "hooks/hooks.json").read_bytes(),
                             (ROOT / "hooks/codex-hooks.json").read_bytes())
            self.assertEqual((ROOT / "hooks/hooks.json").read_bytes(), native)
            self.assertEqual(json.loads((destination / ".codex-plugin/plugin.json").read_text())["name"],
                             "security-guidance-codex")
            retry = subprocess.run(command, capture_output=True)
            self.assertNotEqual(retry.returncode, 0)

    @unittest.skipUnless((ROOT / ".claude-plugin/plugin.json").exists(), "source Claude manifest test")
    def test_claude_manifest_keeps_native_handlers(self):
        manifest = json.loads((ROOT / "hooks/hooks.json").read_text())
        self.assertEqual(set(manifest["hooks"]),
                         {"SessionStart", "UserPromptSubmit", "PostToolUse", "Stop", "SubagentStop"})
        for groups in manifest["hooks"].values():
            for group in groups:
                for hook in group["hooks"]:
                    self.assertNotIn("--runtime codex", hook["command"])
                    self.assertNotIn("hook-output.py", hook["command"])


if __name__ == "__main__":
    unittest.main()
