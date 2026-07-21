#!/usr/bin/env python3
from pathlib import Path
import runpy
runpy.run_path(str(Path(__file__).with_name("paleramine_safe_calibration_patch.py")), run_name="__main__")
