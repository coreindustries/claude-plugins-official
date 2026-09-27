#!/usr/bin/env python3
"""Compatibility entrypoint retained for older Stop hook manifests."""
import runpy
import sys
from pathlib import Path
sys.argv.extend(["--event", "Stop"])
runpy.run_path(str(Path(__file__).with_name("hook-output.py")), run_name="__main__")
