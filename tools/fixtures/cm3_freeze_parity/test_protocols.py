"""Pure token/synthetic-reader mutations; no compiler, ELF execution or CPU proof."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = load("cm3_protocol_control", HERE / "check.py")
elf = load("cm3_reader_control", HERE.parent / "cm55_tfm_parity/elf.py")


def image(protocols, tail):
    bodies = {name: deepcopy(body) + [("nop", "")] * tail for name, body in protocols.items()}

    def function(name, *, literal_islands=False):
        if literal_islands is not True:
            raise RuntimeError("explicit literal-island representation required")
        return deepcopy(bodies[name])

    return SimpleNamespace(function=function, bodies=bodies)


def tiny(tail=1):
    """Synthetic function-decoder state, explicitly not a complete ELF parser test."""
    obj = object.__new__(elf.Object)
    obj.data = b"\x00\x48\x70\x47" + struct.pack("<I", 0x12345678) + b"\x00\xbf" * tail
    obj.sections = [None, (0, 1, 6, 0, 0, len(obj.data), 0, 0, 2, 0)]
    obj.names = ["", ".text.tiny"]
    obj.symbols = [dict(name="tiny", value=1, size=len(obj.data), info=18, section=1),
                   dict(name="$t", value=0, size=0, info=0, section=1),
                   dict(name="$d", value=4, size=0, info=0, section=1)]
    if tail:
        obj.symbols.append(dict(name="$t.1", value=8, size=0, info=0, section=1))
    obj.instructions = {(1, 0): ("ldr", "r0, [pc, #0]", b"\x00\x48"),
                        (1, 2): ("bx", "lr", b"\x70\x47")}
    obj.instructions.update({(1, 8+2*i): ("nop", "", b"\x00\xbf") for i in range(tail)})
    obj.relocations = {}
    return obj


def main():
    controls = []

    def test(name, action, accepted, reason=None):
        error = None
        try:
            action()
        except (check.Rejected, elf.Rejected) as failure:
            error = str(failure)
        if (error is None) is not accepted or reason is not None and reason not in (error or ""):
            raise RuntimeError("control failed: " + name + ": " + str(error))
        controls.append(dict(Name=name, Accepted=error is None, Rejection=error))

    for tail in (0, 1):
        native, reference = image(check._NATIVE, tail), image(check._REFERENCE, tail)
        test("complete-six-tail-" + str(tail), lambda: check.check_pair(native, reference), True)
        for side, selected in (("native", native), ("reference", reference)):
            for root, original in list(selected.bodies.items()):
                for index in range(len(original)):
                    for operation in ("delete", "change"):
                        changed = deepcopy(original)
                        if operation == "delete":
                            changed.pop(index)
                        else:
                            changed[index] = ("unexpected", "changed-token")
                        selected.bodies[root] = changed
                        test("%d/%s/%s/%s/%d" % (tail, side, root, operation, index),
                             lambda: check.check_pair(native, reference), False, "CM3-CLOSED-ROOTS")
                selected.bodies[root] = original + [("nop", ""), ("nop", "")]
                test("%d/%s/%s/extra-nops" % (tail, side, root),
                     lambda: check.check_pair(native, reference), False, "CM3-CLOSED-ROOTS")
                selected.bodies[root] = deepcopy(original)
                branch = next((i for i, (op, _) in enumerate(original) if op.startswith("b") and op != "bx"), None)
                if branch is not None:
                    selected.bodies[root][branch] = (original[branch][0], "@" + str(len(original)-1))
                    test("%d/%s/%s/branch-to-tail" % (tail, side, root),
                         lambda: check.check_pair(native, reference), False, "CM3-CLOSED-ROOTS")
                selected.bodies[root] = original
        native.bodies[next(iter(native.bodies))] += [("nop", "")]
        test("mixed-tail-layout-" + str(tail), lambda: check.check_pair(native, reference), False,
             "CM3-CLOSED-ROOTS")

    baseline = tiny().function("tiny", literal_islands=True)
    if [op for op, _ in baseline] != ["ldr", "bx", "@literal-island", "nop"]:
        raise RuntimeError("synthetic island/tail not retained")
    descriptor = json.loads(baseline[2][1])
    if descriptor != dict(Offset=4, Bytes="78563412", References=[dict(Instruction=0, Offset=0)], Relocations=[]):
        raise RuntimeError("synthetic literal descriptor differs")
    test("default-rejects-nontrailing-data", lambda: tiny().function("tiny"), False,
         "non-trailing naked data")
    for tail in (0, 1, 2):
        test("explicit-island-tail-" + str(tail), lambda t=tail: tiny(t).function("tiny", literal_islands=True), True)
    test("third-tail-nop", lambda: tiny(3).function("tiny", literal_islands=True), False, "executable tail")
    test("nonboolean-option", lambda: tiny().function("tiny", literal_islands=1), False, "must be boolean")
    obj = tiny()
    obj.instructions[(1, 8)] = ("movs", "r0, #0", b"\x00\x20")
    test("post-island-non-nop", lambda: obj.function("tiny", literal_islands=True), False, "executable tail")
    obj = tiny()
    obj.instructions[(1, 8)] = ("nop", "", b"\x00\x00")
    test("counterfeit-nop-bytes", lambda: obj.function("tiny", literal_islands=True), False, "executable tail")
    obj = tiny()
    obj.relocations[(1, 6)] = (2, dict(name="unused"))
    test("unconsumed-relocation", lambda: obj.function("tiny", literal_islands=True), False,
         "unconsumed function relocation")
    obj = tiny()
    obj.data = obj.data[:4] + struct.pack("<I", 0x87654321) + obj.data[8:]
    changed = obj.function("tiny", literal_islands=True)
    if changed == baseline or json.loads(changed[2][1])["Bytes"] == descriptor["Bytes"]:
        raise RuntimeError("literal bytes were silently normalized")
    # Opt-in describes structure, not reachability: the exact protocol owns rejection.
    obj = tiny()
    obj.instructions[(1, 2)] = ("b", "8 <tiny+0x8>", b"\x01\xe0")
    body = obj.function("tiny", literal_islands=True)
    if body[1] != ("b", "@3") or body == baseline:
        raise RuntimeError("descriptor-inclusive branch index was lost")
    print(json.dumps(dict(Verdict="PASS", Controls=len(controls), CompilerInvocations=0,
                          CpuExecution=False, SyntheticReaderOnly=True, Records=controls), indent=2))


if __name__ == "__main__":
    main()
