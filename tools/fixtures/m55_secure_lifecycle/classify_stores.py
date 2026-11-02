"""Disassembly-only decoder controls; none of these instructions is executed."""
import importlib.util
import json
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location(
    "fiber_lifecycle_decoder", Path(__file__).with_name("run.py"))
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)

manifest, destination = map(Path, sys.argv[1:])
cases = json.loads(manifest.read_text(encoding="utf-8-sig"))
if len(cases) != 3 or {case["name"] for case in cases} != {"stl", "stlex", "stc"}:
    raise SystemExit("Missing exact compiled decoder controls")
results = []
for case in cases:
    item = case["instruction"]
    if item["Opcode"].removesuffix(".w").removesuffix(".n") != case["name"]:
        raise SystemExit("Compiled control opcode changed")
    if not lifecycle.requires_instruction_check(item):
        raise SystemExit("Compiled store escaped the breakpoint filter")
    try:
        lifecycle.decoded_stores(item, lambda _: 0)
    except lifecycle.StoreRejected as error:
        if error.kind != "unrecognized-store":
            raise SystemExit("Compiled control failed for an unrelated reason")
    else:
        raise SystemExit("Unqualified compiled store was accepted")
    results.append(dict(name=case["name"], instruction=item, result="REJECTED"))
destination.write_text(json.dumps(dict(result="PASS", execution=False,
    decoder="generic ARM force-thumb; not M55 instruction support", cases=results), indent=2)+"\n")
print("PASS compiled STL/STLEX/STC decoder controls (disassembly only)")
