import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import jsonschema


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "hooks/hook-output.py"
spec = importlib.util.spec_from_file_location("hook_output", ADAPTER)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
SCHEMAS = dict(zip(adapter.EVENTS, ("session-start", "user-prompt-submit", "post-tool-use", "stop", "subagent-stop")))


def validate_schema(output, event):
    schema = json.loads((ROOT / "tests/schemas" / (SCHEMAS[event] + ".json")).read_text())
    jsonschema.Draft7Validator(schema).validate(output)


class AllHooksTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.repo = self.folder / "repo"
        self.repo.mkdir()
        self.state = self.folder / "state"
        # Exercise bootstrap's already-installed branch without installing packages.
        (self.folder / "claude_agent_sdk.py").write_text("# test SDK availability\n")
        self.env = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(ROOT),
                    "PYTHONPATH": str(self.folder),
                    "SECURITY_WARNINGS_STATE_DIR": str(self.state),
                    "SECURITY_GUIDANCE_DEBUG_LOG": str(self.folder / "debug.log"),
                    "ENABLE_CODE_SECURITY_REVIEW": "0"}
        self.env.pop("SECURITY_GUIDANCE_DISABLE", None)
        self.env.pop("ENABLE_SECURITY_REMINDER", None)

    def run_hook(self, event, runtime="codex", **fields):
        payload = {"hook_event_name": event, "session_id": "all-hooks-test",
                   "cwd": str(self.repo), **fields}
        result = subprocess.run(
            [sys.executable, str(ADAPTER), "--runtime", runtime, "--event", event],
            input=json.dumps(payload), capture_output=True, text=True, env=self.env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        if runtime == "codex":
            validate_schema(json.loads(result.stdout), event)
        return result

    def test_every_registered_event_executes_in_both_runtimes(self):
        for runtime in ("claude", "codex"):
            for event in adapter.EVENTS:
                with self.subTest(runtime=runtime, event=event):
                    self.run_hook(event, runtime, tool_name="Bash",
                                  tool_input={"command": "pwd"}, stop_hook_active=True)

    def test_session_start_converts_handshake_and_preserves_notice(self):
        notice = {"metrics": {"sdk_bootstrap": 4}, "systemMessage": "SDK unavailable",
                  "hookSpecificOutput": {"hookEventName": "SessionStart",
                                         "additionalContext": "SDK unavailable"}}
        output = adapter.codex_output('{"async":true,"asyncTimeout":180000}\n' + json.dumps(notice), "SessionStart")
        self.assertEqual(output["systemMessage"], "SDK unavailable")
        self.assertEqual(output["hookSpecificOutput"]["additionalContext"], "SDK unavailable")
        self.assertNotIn("metrics", output)
        validate_schema(output, "SessionStart")

    def test_blocking_findings_reach_stderr_for_all_review_events(self):
        fixture = self.folder / "fixture"
        fixture.mkdir()
        (fixture / ADAPTER.name).write_bytes(ADAPTER.read_bytes())
        for event in ("PostToolUse", "Stop", "SubagentStop"):
            response = {"metrics": {"findings": 1}, "rewakeSummary": "review"}
            if event == "PostToolUse":
                response["hookSpecificOutput"] = {"hookEventName": event, "additionalContext": "Fix SQL injection"}
            else:
                response.update(decision="block", reason="Fix SQL injection")
            (fixture / "security_reminder_hook.py").write_text(
                "import sys\nprint(" + repr(json.dumps(response)) + ")\nsys.exit(2)\n")
            result = subprocess.run(
                [sys.executable, str(fixture / ADAPTER.name), "--runtime", "codex", "--event", event],
                input=json.dumps({"hook_event_name": event}), text=True, capture_output=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("Fix SQL injection", result.stderr)
            validate_schema(json.loads(result.stdout), event)

    def test_real_pattern_warnings_for_claude_edit_write_multiedit(self):
        cases = {
            "Edit": {"new_string": "yaml.load(user_input)"},
            "Write": {"content": "yaml.load(user_input)"},
            "MultiEdit": {"edits": [{"new_string": "yaml.load(user_input)"}]},
        }
        for runtime in ("claude", "codex"):
            for tool, fields in cases.items():
                result = self.run_hook("PostToolUse", runtime,
                    session_id=runtime + tool, tool_name=tool,
                    tool_input={"file_path": str(self.repo / (tool + ".py")), **fields})
                output = json.loads(result.stdout)
                self.assertIn("yaml", output["hookSpecificOutput"]["additionalContext"].lower())

    def test_notebook_event_preserves_upstream_noop_behavior(self):
        # Upstream records the touched notebook but does not extract new_source
        # for regex scanning. Protocol adaptation must not claim extra coverage.
        for runtime in ("claude", "codex"):
            result = self.run_hook("PostToolUse", runtime,
                tool_name="NotebookEdit", tool_input={
                    "notebook_path": str(self.repo / "example.ipynb"),
                    "new_source": "yaml.load(user_input)"})
            self.assertEqual(result.stdout.strip(), "{}" if runtime == "codex" else "")

    def test_malformed_bootstrap_is_not_a_success(self):
        for output in ('{"async":true}', '{}\n{}', 'noise\n{}'):
            with self.assertRaises(ValueError):
                adapter.codex_output(output, "SessionStart")

    def test_unknown_fields_and_wrong_event_fail_visibly(self):
        for event in adapter.EVENTS:
            with self.assertRaises(ValueError):
                adapter.codex_output('{"newUnknownField":true}', event)
        with self.assertRaises(ValueError):
            adapter.codex_output('{"hookSpecificOutput":{"hookEventName":"Stop"}}', "Stop")

    def test_disabled_hook_returns_valid_noop_for_every_event(self):
        self.env["SECURITY_GUIDANCE_DISABLE"] = "1"
        for event in adapter.EVENTS:
            self.run_hook(event)

    def test_patch_add_update_move_delete_and_multiple_findings(self):
        (self.repo / "new.py").write_text("import yaml\nx = yaml.load(user_input)\n")
        (self.repo / "moved.py").write_text("import pickle\nx = pickle.loads(user_input)\n")
        patch = """*** Begin Patch
*** Add File: new.py
+import yaml
+x = yaml.load(user_input)
*** Update File: old.py
*** Move to: moved.py
@@
-pass
+import pickle
+x = pickle.loads(user_input)
*** Delete File: deleted.py
*** End Patch
"""
        result = self.run_hook("PostToolUse", tool_name="apply_patch", tool_input={"command": patch})
        context = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("yaml", context.lower())
        self.assertIn("pickle", context.lower())
        state_files = list(self.state.glob("*.json"))
        state_text = "\n".join(p.read_text() for p in state_files)
        for name in ("new.py", "old.py", "moved.py", "deleted.py"):
            self.assertIn(name, state_text)

    def test_prompt_baseline_suppresses_existing_patch_warning(self):
        def git(*args):
            subprocess.run(["git", *args], cwd=self.repo, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        git("init")
        file = self.repo / "existing.py"
        file.write_text("import yaml\nx = yaml.load(user_input)\n")
        git("add", "existing.py")
        git("-c", "user.name=Hook Test", "-c", "user.email=hook@example.invalid",
            "-c", "core.hooksPath=/dev/null", "commit", "-m", "fixture")
        self.run_hook("UserPromptSubmit")
        file.write_text(file.read_text() + "answer = 42\n")
        result = self.run_hook("PostToolUse", tool_name="apply_patch", tool_input={
            "command": "*** Begin Patch\n*** Update File: existing.py\n@@\n+answer = 42\n*** End Patch\n"})
        self.assertNotIn("hookSpecificOutput", json.loads(result.stdout))

    def test_missing_patch_file_is_not_silently_ignored(self):
        with self.assertRaises(OSError):
            adapter.patch_events({"cwd": str(self.repo), "tool_input": {
                "command": "*** Begin Patch\n*** Add File: missing.py\n+x\n*** End Patch\n"}})

    def test_bash_text_output_is_available_to_upstream_review(self):
        event = {"hook_event_name": "PostToolUse", "tool_name": "Bash",
                 "tool_input": {"command": "git commit -m example"},
                 "tool_response": "[main abc123] example"}
        result = adapter.normalize_inputs(event, "PostToolUse")[0]
        self.assertEqual(result["tool_response"]["stdout"], event["tool_response"])

    def test_commit_push_and_stop_no_review_paths(self):
        for runtime in ("claude", "codex"):
            for command in ("git commit -m example", "git push", "gt create", "gt modify", "gt submit"):
                self.run_hook("PostToolUse", runtime, tool_name="Bash",
                              tool_input={"command": command}, tool_response={"stdout": ""})
            for event in ("Stop", "SubagentStop"):
                self.run_hook(event, runtime, stop_hook_active=False)

    def test_manifest_covers_all_events_with_no_claude_only_options(self):
        manifest = json.loads((ROOT / "hooks/codex-hooks.json").read_text())
        self.assertEqual(set(manifest["hooks"]), set(adapter.EVENTS))
        for event, groups in manifest["hooks"].items():
            for group in groups:
                for hook in group["hooks"]:
                    self.assertIn("--event " + event, hook["command"])
                    self.assertFalse(set(hook) & {"if", "asyncRewake", "rewakeSummary", "rewakeMessage"})


if __name__ == "__main__":
    unittest.main()
