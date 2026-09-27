import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "hooks/hook-output.py"


class StopCompatibilityTests(unittest.TestCase):
    def run_fixture(self, runtime, stdout, status=0, stderr=""):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            shutil.copy2(ADAPTER, root / ADAPTER.name)
            (root / "security_reminder_hook.py").write_text(
                "import sys\n"
                "assert __import__('json').loads(sys.stdin.read())['hook_event_name'] == 'Stop'\n"
                f"sys.stdout.write({stdout!r})\n"
                f"sys.stderr.write({stderr!r})\n"
                f"sys.exit({status})\n"
            )
            return subprocess.run(
                [sys.executable, str(root / ADAPTER.name), "--runtime", runtime, "--event", "Stop"],
                input=json.dumps({"hook_event_name": "Stop"}), text=True, capture_output=True,
            )

    def test_codex_strips_claude_telemetry(self):
        result = self.run_fixture("codex", json.dumps({
            "metrics": {"skipped": True}, "rewakeSummary": "summary",
        }))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {})

    def test_empty_noop(self):
        for runtime, expected in (("claude", ""), ("codex", "{}\n")):
            with self.subTest(runtime=runtime):
                result = self.run_fixture(runtime, "")
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, expected)

    def test_findings_and_blocking_status_survive_both_runtimes(self):
        for runtime in ("claude", "codex"):
            for status in (0, 2):
                with self.subTest(runtime=runtime, status=status):
                    original = json.dumps({
                        "metrics": {"findings": 1}, "rewakeSummary": "review",
                        "decision": "block", "reason": "Fix injection",
                        "systemMessage": "Review found an issue",
                    })
                    result = self.run_fixture(runtime, original, status, "Fix injection")
                    self.assertEqual(result.returncode, status)
                    self.assertEqual(result.stderr, "Fix injection")
                    self.assertEqual(json.loads(result.stdout)["reason"], "Fix injection")
                    self.assertEqual(json.loads(result.stdout)["decision"], "block")
                    if runtime == "claude":
                        self.assertEqual(result.stdout, original)
                    else:
                        self.assertNotIn("metrics", json.loads(result.stdout))
                        self.assertNotIn("rewakeSummary", json.loads(result.stdout))

    def test_real_errors_are_not_hidden(self):
        for runtime in ("claude", "codex"):
            result = self.run_fixture(runtime, "partial output", 7, "review crashed")
            self.assertEqual(result.returncode, 7)
            self.assertEqual(result.stderr, "review crashed")
            self.assertEqual(result.stdout, "partial output")

    def test_invalid_success_output_is_an_error(self):
        for output in ("not json", "[]", "null", "{}\n{}"):
            result = self.run_fixture("codex", output)
            self.assertEqual(result.returncode, 1)
            self.assertIn("hook compatibility error", result.stderr)
            self.assertEqual(result.stdout, "")

    def test_real_stop_recursion_guard_for_both_runtimes(self):
        with tempfile.TemporaryDirectory() as folder:
            env = {**os.environ, "SECURITY_WARNINGS_STATE_DIR": folder,
                   "SECURITY_GUIDANCE_DEBUG_LOG": str(Path(folder) / "debug.log")}
            for runtime in ("claude", "codex"):
                result = subprocess.run(
                    [sys.executable, str(ADAPTER), "--runtime", runtime, "--event", "Stop"],
                    input=json.dumps({"hook_event_name": "Stop", "session_id": "compat-test",
                                      "stop_hook_active": True, "cwd": folder}),
                    text=True, capture_output=True, env=env,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                output = json.loads(result.stdout)
                if runtime == "claude":
                    self.assertTrue(output["metrics"]["skipped"])
                else:
                    self.assertEqual(output, {})

    def test_stop_manifest_routes_to_codex_adapter(self):
        manifest = json.loads((ROOT / "hooks/codex-hooks.json").read_text())
        command = manifest["hooks"]["Stop"][0]["hooks"][0]["command"]
        self.assertIn("hook-output.py", command)
        self.assertIn("--runtime codex", command)


if __name__ == "__main__":
    unittest.main()
