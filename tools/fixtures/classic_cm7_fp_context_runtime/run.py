"""Explicit CM7/AN500 entry point for the shared bounded classic FP auditor."""
from pathlib import Path
import importlib.util
import sys

sys.dont_write_bytecode = True
shared_path = Path(__file__).resolve().parent.parent/"classic_fp_context_runtime/run.py"
spec = importlib.util.spec_from_file_location("classic_fp_context_runtime_shared", shared_path)
shared = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = shared
spec.loader.exec_module(shared)

if __name__ == "__main__":
    shared.main(profile=shared.CM7)
