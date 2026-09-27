#!/usr/bin/env python3
"""Bridge Claude security-guidance hooks to Codex's event protocols."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

EVENTS = ("SessionStart", "UserPromptSubmit", "PostToolUse", "Stop", "SubagentStop")
COMMON = {"continue": bool, "stopReason": str, "suppressOutput": bool,
          "systemMessage": str}


def validate_output(output, event):
    if not isinstance(output, dict):
        raise ValueError("hook output must be an object")
    allowed = dict(COMMON)
    if event != "SessionStart":
        allowed.update(decision=str, reason=str)
    if event not in ("Stop", "SubagentStop"):
        allowed["hookSpecificOutput"] = dict
    for key, value in output.items():
        if key not in allowed or not isinstance(value, allowed[key]):
            raise ValueError("unsupported output field or type: " + key)
    if "decision" in output and output["decision"] != "block":
        raise ValueError("decision must be block")
    if output.get("decision") == "block" and not output.get("reason", "").strip():
        raise ValueError("blocking output requires a reason")
    specific = output.get("hookSpecificOutput")
    if specific is not None:
        keys = {"hookEventName", "additionalContext"}
        if event == "PostToolUse":
            keys.add("updatedMCPToolOutput")
        if set(specific) - keys or specific.get("hookEventName") != event:
            raise ValueError("invalid hookSpecificOutput for " + event)
        if "additionalContext" in specific and not isinstance(specific["additionalContext"], str):
            raise ValueError("additionalContext must be text")
    return output


def codex_output(stdout, event):
    if not stdout.strip():
        return {}
    if event == "SessionStart":
        records = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        # The bootstrap prints a Claude async handshake before its final response.
        if records and isinstance(records[0], dict) and records[0].get("async") is True:
            if set(records[0]) - {"async", "asyncTimeout"}:
                raise ValueError("unexpected fields in bootstrap handshake")
            records.pop(0)
        if len(records) != 1:
            raise ValueError("bootstrap must return one final response")
        output = records[0]
    else:
        output = json.loads(stdout)
    if not isinstance(output, dict):
        raise ValueError("hook output must be an object")
    for key in ("metrics", "rewakeSummary"):
        output.pop(key, None)
    return validate_output(output, event)


def patch_events(payload):
    patch = payload.get("tool_input", {}).get("command")
    if not isinstance(patch, str) or not patch.startswith("*** Begin Patch\n"):
        raise ValueError("apply_patch input is missing its patch command")
    paths = {}
    current = None
    for line in patch.splitlines():
        for marker in ("*** Add File: ", "*** Update File: ", "*** Delete File: "):
            if line.startswith(marker):
                current = line[len(marker):]
                paths[current] = marker == "*** Delete File: "
                break
        if line.startswith("*** Move to: "):
            if current is None:
                raise ValueError("patch move has no source")
            paths[current] = True
            current = line[len("*** Move to: "):]
            paths[current] = False
    if not paths or not patch.rstrip().endswith("*** End Patch"):
        raise ValueError("incomplete apply_patch input")
    cwd = Path(payload["cwd"])
    events = []
    for name, deleted in paths.items():
        path = Path(name)
        if not path.is_absolute():
            path = cwd / path
        # Read the actual resulting file; Write's baseline comparison suppresses
        # existing warnings and catches patterns spanning separate patch hunks.
        content = "" if deleted else path.read_text(encoding="utf-8")
        event = dict(payload)
        event["tool_name"] = "Edit" if deleted else "Write"
        event["tool_input"] = {"file_path": str(path),
                               "new_string" if deleted else "content": content}
        events.append(event)
    return events


def normalize_inputs(payload, event):
    if not isinstance(payload, dict) or payload.get("hook_event_name") != event:
        raise ValueError("input hook_event_name does not match adapter event")
    if event == "PostToolUse" and payload.get("tool_name") == "apply_patch":
        return patch_events(payload)
    if event == "PostToolUse" and payload.get("tool_name") == "Bash":
        response = payload.get("tool_response")
        if isinstance(response, str):
            payload = {**payload, "tool_response": {"stdout": response, "stderr": ""}}
    return [payload]


def merge_outputs(outputs, event):
    merged = {}
    contexts = []
    for output in outputs:
        for key, value in output.items():
            if key == "hookSpecificOutput":
                contexts.append(value.get("additionalContext", ""))
                merged.setdefault(key, {}).update(value)
            elif key in ("systemMessage", "reason", "stopReason") and key in merged:
                merged[key] += "\n\n" + value
            elif key in ("continue", "suppressOutput") and key in merged:
                merged[key] = merged[key] and value if key == "continue" else merged[key] or value
            else:
                merged[key] = value
    if contexts:
        merged["hookSpecificOutput"]["additionalContext"] = "\n\n".join(filter(None, contexts))
    return validate_output(merged, event)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", choices=("claude", "codex"), required=True)
    parser.add_argument("--event", choices=EVENTS, required=True)
    args = parser.parse_args(argv)
    script = "ensure_agent_sdk.py" if args.event == "SessionStart" else "security_reminder_hook.py"
    command = [sys.executable, str(Path(__file__).with_name(script))]
    if args.runtime == "claude":
        # Stream unchanged, including the bootstrap's early async handshake.
        result = subprocess.run(command, check=False)
        return result.returncode if result.returncode >= 0 else 128 - result.returncode
    try:
        payload = json.load(sys.stdin)
        inputs = normalize_inputs(payload, args.event)
        env = dict(os.environ)
        if payload.get("cwd"):
            env["CLAUDE_PROJECT_DIR"] = payload["cwd"]
        outputs = []
        status = 0
        for event in inputs:
            result = subprocess.run(command, input=json.dumps(event), text=True,
                                    capture_output=True, env=env, check=False)
            sys.stderr.write(result.stderr)
            if result.returncode not in (0, 2):
                sys.stdout.write(result.stdout)
                return result.returncode if result.returncode >= 0 else 128 - result.returncode
            try:
                output = codex_output(result.stdout, args.event)
            except (ValueError, TypeError) as error:
                print("security-guidance: hook compatibility error: " + str(error), file=sys.stderr)
                return result.returncode or 1
            if result.returncode == 2:
                status = 2
                # Codex consumes stderr for exit 2; upstream PostToolUse reviews
                # sometimes place their findings only in JSON on stdout.
                feedback = output.get("reason") or output.get("hookSpecificOutput", {}).get("additionalContext")
                if not result.stderr.strip() and feedback:
                    print(feedback, file=sys.stderr)
                elif not result.stderr.strip():
                    print("security-guidance: upstream blocked without a reason", file=sys.stderr)
            outputs.append(output)
        print(json.dumps(merge_outputs(outputs, args.event)))
        return status
    except (ValueError, TypeError, OSError, KeyError) as error:
        print("security-guidance: hook compatibility error: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
