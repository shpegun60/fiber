"""Stdlib-only setup checker controls on tokens and retained ARM ELF bytes.

Only fresh external output files are written. No subprocesses, compiler,
objdump, CPU execution or source edits. These are child-checker controls,
not a replacement for the parent's inventory/source admission and receipt join.
"""
from collections import Counter
from copy import deepcopy
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import sys
import types

sys.dont_write_bytecode = True
if sys.flags.optimize or not __debug__:
    raise SystemExit("unoptimized Python required")

HERE = Path(__file__).resolve().parent
CHECKER = HERE / "check_setup.py"
READER = HERE.parent / "cm55_tfm_parity/elf.py"
STOPPED = {"cm33f_secure_transfer_reference", "m55_secure_closed_parity",
           "test_cm33f_secure_transfer_reference.ps1", "test_m55_secure_closed_parity.ps1"}
PINS = {
    "Native": ("E6A401727808D2D3FC353B707E95FDC9FD7933593ACD4D06CEC592C0D2F7E2E0",
               "199068E8880FABB612233FA393CEF3A97A2BC5CC1DCBE4456CC08B8387A6548F"),
    "Reference": ("690032B130C5B5E25880ECDA64D00109FCC154BFBAAFADEE82153FF0BF0594B9",
                  "246BC05B768CEF85115FBD2667688062B3E2816CB99F6604EB4D61AFA1DC094E"),
}
INVENTORY = "E99DFC023B9F11F19A6109E37338E81DBE37574B8831B99244378A21D52179A3"


def need(ok, detail):
    if not ok:
        raise AssertionError(detail)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def read(path):
    path = Path(path).absolute()
    need(not STOPPED.intersection(part.casefold() for part in path.parts), "protected path")
    for part in (path, *path.parents):
        need(not getattr(part.lstat(), "st_file_attributes", 0) &
             getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0), "reparse input: " + str(part))
    return path.read_bytes()


def pairs(items):
    result = {}
    for key, value in items:
        need(key.casefold() not in {k.casefold() for k in result}, "duplicate JSON key")
        result[key] = value
    return result


def parse(data):
    return json.loads(data, object_pairs_hook=pairs)


def load(data, path):
    module = types.ModuleType("setup_controls_" + path.stem)
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


class TokenProvider:
    """Synthetic unit input only, never an artifact-admission claim."""
    def __init__(self, protocols):
        self.bodies = deepcopy(protocols)

    def function(self, name, *, literal_islands=False):
        need(literal_islands is True, "full literal decoding must be explicit")
        return deepcopy(self.bodies[name])


def pure_controls(check):
    counts = Counter()

    def reject(pair, profile, mode):
        try:
            check.check_pair(*pair, profile, mode)
        except check.Rejected:
            counts["Negative"] += 1
            return
        raise AssertionError("pure mutant accepted")

    for profile in check.COHORTS:
        for mode in check.MODES:
            expected = check.protocols(profile, mode)

            def pair():
                return [TokenProvider(protocols) for protocols in expected]

            result = check.check_pair(*pair(), profile, mode)
            need(result["Verdict"] == "FP-SETUP-CLOSED-ROOTS-PASS" and result["ClosedBodies"] == 3,
                 "result contract")
            need(result["DistinctContractsChecked"] is True and result["FPCCR"]["NativeBits"] == 0x80000000
                 and result["FPCCR"]["ReferenceBits"] == 0xC0000000
                 and result["FPCCR"]["PolicyMask"] == 0xC0000000
                 and result["FPCCR"]["Address"] == 0xE000EF34
                 and result["CPACR"] == {"Address": 0xE000ED88, "AccessMask": 0x00F00000}, "policy contract")
            need("fpccr-eager-vs-lazy" in result["DifferenceIds"], "difference must remain explicit")
            need(type(result["RequiredCellsSatisfied"]) is int and result["RequiredCellsSatisfied"] == 0,
                 "required-cell counter")
            for key in ("RequiredCellSatisfied", "CompleteObjectProof", "InstructionEquivalence", "CpuExecution",
                        "BoardExecution", "FinalElfProof", "GlobalFreezeQualified", "StartupRoutingProven",
                        "CalleeBodiesProven", "UnreachabilityProven"):
                need(result[key] is False, "overclaim: " + key)
            for key in ("PolicyEquivalenceProven", "HardwareReadbackProven", "LspactHandlingProven"):
                need(result["FPCCR"][key] is False, "FP overclaim")
            counts["Positive"] += 1
            for side, protocols in enumerate(expected):
                for name, body in protocols.items():
                    for index in range(len(body)):
                        changed = pair()
                        changed[side].bodies[name][index] = ("unexpected", "instruction-or-data")
                        reject(changed, profile, mode)
                        counts["TokenMutations"] += 1
                        changed = pair()
                        del changed[side].bodies[name][index]
                        reject(changed, profile, mode)
                        counts["TokenDeletions"] += 1
                    changed = pair()
                    changed[side].bodies[name].append(("nop", ""))
                    reject(changed, profile, mode)
                    counts["ExtraTailNops"] += 1
                    for index, (op, arg) in enumerate(body):
                        if "@" in arg and op != "@literal-island":
                            changed = pair()
                            changed[side].bodies[name][index] = (op, re.sub(r"@\d+", "@0", arg))
                            if changed[side].bodies[name] != body:
                                reject(changed, profile, mode)
                                counts["BranchTargetMutations"] += 1
                    branches = [i for i, (op, arg) in enumerate(body)
                                if op.startswith("b") and "@" in arg]
                    if len(branches) >= 2:
                        first = branches[0]
                        second = next((i for i in branches[1:] if body[i] != body[first]), None)
                        if second is not None:
                            changed = pair()
                            b = changed[side].bodies[name]
                            b[first], b[second] = b[second], b[first]
                            reject(changed, profile, mode)
                            counts["BranchOrderMutations"] += 1
                    changed = pair()
                    first = next((i for i, (op, arg) in enumerate(body) if op == "bl"), None)
                    if first is not None:
                        second = next((i for i in range(first + 1, len(body)) if body[i][0] == "bl"
                                       and body[i] != body[first]), None)
                        if second is not None:
                            b = changed[side].bodies[name]
                            b[first], b[second] = b[second], b[first]
                            reject(changed, profile, mode)
                            counts["CallOrderMutations"] += 1
                    changed = pair()
                    del changed[side].bodies[name]
                    try:
                        check.check_pair(*changed, profile, mode)
                    except (check.Rejected, KeyError):
                        counts["Negative"] += 1
                    else:
                        raise AssertionError("missing root accepted")
            other = "CM7" if profile == "CM4" else "CM4"
            reject(pair(), other, mode)
    for profile in (None, False, 4, "cm4", "CM4F", " CM4", "CM7 ", [], {}):
        reject([TokenProvider(p) for p in check.protocols("CM4", "O0")], profile, "O0")
    for mode in (None, False, 0, "o0", " O0", "O1", "O2-LTO", [], {}):
        reject([TokenProvider(p) for p in check.protocols("CM4", "O0")], "CM4", mode)
    for bad in (None, False, "unbound", []):
        reject([bad, TokenProvider(check.protocols("CM4", "O0")[1])], "CM4", "O0")
    counts["Total"] = counts["Positive"] + counts["Negative"]
    return dict(counts)


def retained(check, reader, roots, bindings):
    cells, cohort_hashes = {}, {}
    for side, root in roots.items():
        metadata = [read(root / name) for name in ("results.json", "artifacts.json")]
        need(tuple(sha(raw) for raw in metadata) == PINS[side], "receipt pin mismatch")
        bindings.extend((root / name, sha(raw)) for name, raw in zip(("results.json", "artifacts.json"), metadata))
        receipt, index = map(parse, metadata)
        need(receipt["SourceInventorySha256"] == INVENTORY, "inventory mismatch")
        selected = [c for c in receipt["Cells"] if c["Cohort"] in check.COHORTS.values()]
        keys = [(c["Cohort"], c["ArtifactRole"], c["Mode"]) for c in selected]
        expected = {(cohort, "runtime", mode) for cohort in check.COHORTS.values() for mode in check.MODES}
        need(len(keys) == len(set(keys)) == 10 and set(keys) == expected, "exact ten cells per receipt")
        for cell in selected:
            profile = next(p for p, cohort in check.COHORTS.items() if cohort == cell["Cohort"])
            need(cell["SourceGroup"] == profile, "source group mismatch")
            key = (profile, cell["Mode"])
            if side == "Native":
                cohort_hashes[key] = cell["CohortSha256"]
            else:
                need(cohort_hashes[key] == cell["CohortSha256"], "cohort identity mismatch")
            elf = Path(cell["NativeGroup"])
            dis = elf.with_suffix(".dis")
            need(elf.is_absolute() and elf.is_relative_to(root), "escaped artifact")
            for path in (elf, dis):
                digest = sha(read(path))
                need(index["Artifacts"][path.relative_to(root).as_posix()] == digest, "artifact hash mismatch")
                bindings.append((path, digest))
            need(sha(read(elf)) == cell["NativeGroupSha256"], "cell ELF hash mismatch")
            cells[(profile, cell["Mode"], side)] = (elf, reader.Object(elf, dis))
    results = []
    for profile in check.COHORTS:
        for mode in check.MODES:
            pair = [cells[(profile, mode, side)][1] for side in ("Native", "Reference")]
            results.append(check.check_pair(*pair, profile, mode))
    need(len(results) == 10 and sum(r["ClosedBodies"] for r in results) == 30, "thirty full bodies required")
    return cells, results


class Mutant:
    def __init__(self, directory, source, reader):
        directory.mkdir()
        self.reader = reader
        self.elf, self.dis = directory / "mutant.o", directory / "mutant.dis"
        self.elf.write_bytes(read(source))
        self.dis.write_bytes(read(source.with_suffix(".dis")))

    def image(self):
        return self.reader.Object(self.elf, self.dis)

    def symbol(self, name):
        image = self.image()
        symbol = next(s for s in image.symbols if s["name"] == name and s["section"])
        return image, symbol

    def instructions(self, name):
        image, symbol = self.symbol(name)
        begin = symbol["value"] & ~1
        return [(address, op, arg, raw) for (section, address), (op, arg, raw) in sorted(image.instructions.items())
                if section == symbol["section"] and begin <= address < begin + symbol["size"]]

    def find(self, name, op, arg, occurrence=0):
        def canonical(row):
            value = self.reader.canonical(row[2])
            return "#15" if row[1] in ("dsb", "dmb", "isb") and value == "sy" else value
        matches = [row for row in self.instructions(name) if row[1] == op and canonical(row) == arg]
        need(len(matches) > occurrence, "mutation instruction missing: " + name + "/" + op + " " + arg)
        return matches[occurrence]

    def replace(self, name, row, replacement):
        address, _, _, original = row
        op, arg, raw = replacement
        need(len(raw) == len(original), "mutation must preserve instruction width")
        image, symbol = self.symbol(name)
        data = bytearray(image.data)
        offset = image.sections[symbol["section"]][4] + address
        data[offset:offset + len(raw)] = raw
        self.elf.write_bytes(data)
        lines, section, count = self.dis.read_text().splitlines(), None, 0
        for i, line in enumerate(lines):
            header = re.fullmatch(r"Disassembly of section (.+):", line)
            if header:
                section = header[1]
            match = re.match(r"^\s*([0-9a-f]+):\s+[0-9a-f]{4}(?:\s+[0-9a-f]{4})?\s+", line)
            if section == image.names[symbol["section"]] and match and int(match[1], 16) == address:
                words = " ".join("%04x" % struct.unpack_from("<H", raw, n)[0] for n in range(0, len(raw), 2))
                lines[i] = "%x: %s %s %s" % (address, words, op, arg)
                count += 1
        need(count == 1, "mutation disassembly instruction count")
        self.dis.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")

    def literal(self, name, row, value):
        image, symbol = self.symbol(name)
        match = re.match(r"r\d+,\[pc,#(\d+)\]", self.reader.canonical(row[2]))
        need(row[1] == "ldr" and match is not None, "PC-relative literal required")
        address = ((row[0] + 4) & ~3) + int(match[1])
        data = bytearray(image.data)
        offset = image.sections[symbol["section"]][4] + address
        struct.pack_into("<I", data, offset, value)
        self.elf.write_bytes(data)

    def swap_calls(self, name, first, second):
        image, symbol = self.symbol(name)
        wanted, found = {first[0], second[0]}, {}
        for section in image.sections:
            if section[1] != 9 or section[7] != symbol["section"]:
                continue
            for offset in range(section[4], section[4] + section[5], section[9]):
                address, info = struct.unpack_from("<II", image.data, offset)
                if address in wanted:
                    need(info & 255 == 10, "call relocation required")
                    found[address] = (offset + 4, info)
        need(set(found) == wanted, "two call relocations required")
        data = bytearray(image.data)
        a, b = found[first[0]], found[second[0]]
        struct.pack_into("<I", data, a[0], b[1])
        struct.pack_into("<I", data, b[0], a[1])
        self.elf.write_bytes(data)


def byte_controls(check, reader, cells, root):
    records = []
    for profile in check.COHORTS:
        for label in ("cpacr-address", "fpccr-address", "cpacr-mask", "aspen-bit", "lspen-clear",
                      "missing-dsb", "missing-isb", "cpacr-readback", "fpccr-readback",
                      "failure-branch", "branch-target-swap", "reference-cpacr-address", "reference-fpccr-address",
                      "reference-lazy-bit", "enable-start-order", "timer-enable-order",
                      "literal-relocation", "call-addend", "non-policy-guard"):
            side = "Reference" if label.startswith("reference-") or label in (
                "enable-start-order", "timer-enable-order", "literal-relocation", "call-addend") else "Native"
            source, original = cells[(profile, "O0", side)]
            mutant = Mutant(root / (profile + "-" + label), source, reader)
            name = check.NATIVE_ROOT if side == "Native" else "xPortStartScheduler"
            if label in ("cpacr-address", "fpccr-address", "reference-cpacr-address", "reference-fpccr-address"):
                if label == "reference-cpacr-address":
                    name = "vPortEnableVFP"
                value = {"cpacr-address": 0xE000ED8C, "fpccr-address": 0xE000EF34,
                         "reference-cpacr-address": 0xE000ED8C, "reference-fpccr-address": 0xE000EF38}[label]
                expected_value = {"cpacr-address": 0xE000ED88, "fpccr-address": 0xE000EF30,
                                  "reference-cpacr-address": 0xE000ED88, "reference-fpccr-address": 0xE000EF34}[label]
                image, symbol = mutant.symbol(name)
                row = next(row for row in mutant.instructions(name) if row[1] == "ldr" and
                           re.match(r"r\d+,\[pc,#", reader.canonical(row[2])) and
                           struct.unpack("<I", image.read(symbol["section"], ((row[0]+4)&~3) +
                               int(re.search(r"#(\d+)", reader.canonical(row[2]))[1]), 4))[0] == expected_value)
                mutant.literal(name, row, value)
            elif label in ("cpacr-mask", "aspen-bit", "lspen-clear", "missing-dsb", "missing-isb", "non-policy-guard"):
                selections = {
                    "cpacr-mask": (("mov", "r3,#15728640", 0), ("mov", "r3,#458752", 0)),
                    "aspen-bit": (("orr", "r3,r3,#2147483648", 1), ("orr", "r3,r3,#1073741824", 0)),
                    "lspen-clear": (("bic", "r3,r3,#1073741824", 0), ("orr", "r3,r3,#2147483648", 1)),
                    "missing-dsb": (("dsb", "#15", 3), ("isb", "#15", 3)),
                    "missing-isb": (("isb", "#15", 4), ("dsb", "#15", 4)),
                    "non-policy-guard": (("orr", "r3,r3,#512", 0), ("orr", "r3,r3,#16", 0)),
                }
                target, donor = selections[label]
                row, other = mutant.find(name, *target), mutant.find(name, *donor)
                mutant.replace(name, row, other[1:])
            elif label in ("cpacr-readback", "fpccr-readback"):
                if label == "cpacr-readback":
                    row = mutant.find(name, "ldr", "r2,[r3,#0]")
                else:
                    row = mutant.find(name, "ldr", "r2,[r3,#4]", 1)
                mutant.replace(name, row, ("movs", "r2, #0", struct.pack("<H", 0x2200)))
            elif label == "failure-branch":
                # The conditional immediately before panic('e') must not invert.
                instructions = mutant.instructions(name)
                panic_code = mutant.find(name, "movs", "r0,#101")
                row = next(row for i, row in enumerate(instructions[:-1]) if instructions[i + 1] == panic_code)
                need(row[1] == "beq" and len(row[3]) == 2, "expected readback success branch")
                raw = struct.pack("<H", struct.unpack("<H", row[3])[0] ^ 0x0100)
                mutant.replace(name, row, ("bne", row[2], raw))
            elif label == "branch-target-swap":
                instructions = mutant.instructions(name)
                panic_e = mutant.find(name, "movs", "r0,#101")
                cp = next(row for i, row in enumerate(instructions[:-1]) if instructions[i + 1] == panic_e)
                fp = [row for row in instructions if row[1] == "beq"][-1]
                targets = [int(re.match(r"([0-9a-f]+)\s+<", row[2].strip())[1], 16) for row in (cp, fp)]
                for row, target in ((cp, targets[1]), (fp, targets[0])):
                    delta = target - row[0] - 4
                    need(row[1] == "beq" and delta % 2 == 0 and -256 <= delta <= 254, "bounded branch mutation")
                    raw = struct.pack("<H", 0xD000 | ((delta // 2) & 255))
                    mutant.replace(name, row, ("beq", "%x <%s+0x%x>" % (target, name, target), raw))
            elif label == "reference-lazy-bit":
                row = mutant.find(name, "orr", "r3,r3,#3221225472")
                native = cells[(profile, "O0", "Native")][1]
                donor = next((op, arg, raw) for (section, address), (op, arg, raw) in native.instructions.items()
                             if op == "orr" and reader.canonical(arg) == "r3,r3,#2147483648")
                mutant.replace(name, row, donor)
            elif label in ("enable-start-order", "timer-enable-order"):
                image, symbol = mutant.symbol(name)
                calls = {image.relocations[(symbol["section"], row[0])][1]["name"]: row
                         for row in mutant.instructions(name) if row[1] == "bl"}
                mutant.swap_calls(name, calls["vPortEnableVFP"],
                                  calls["prvPortStartFirstTask" if label == "enable-start-order" else "vPortSetupTimerInterrupt"])
            elif label == "literal-relocation":
                image, symbol = mutant.symbol(name)
                data, changed = bytearray(image.data), 0
                for section in image.sections:
                    if section[1] != 9 or section[7] != symbol["section"]:
                        continue
                    for offset in range(section[4], section[4] + section[5], section[9]):
                        address, info = struct.unpack_from("<II", data, offset)
                        if info & 255 == 2:
                            struct.pack_into("<I", data, offset + 4, (info & ~255) | 3)
                            changed += 1
                            break
                need(changed == 1, "literal relocation mutation")
                mutant.elf.write_bytes(data)
            elif label == "call-addend":
                row = next(row for row in mutant.instructions(name) if row[1] == "bl")
                hi, lo = struct.unpack("<HH", row[3])
                mutant.replace(name, row, (row[1], row[2], struct.pack("<HH", hi, lo ^ 1)))
            need(read(mutant.elf) != read(source), "byte mutant did not change ELF")
            pair = [cells[(profile, "O0", s)][1] if s != side else None for s in ("Native", "Reference")]
            rejected_by = None
            try:
                pair[0 if side == "Native" else 1] = mutant.image()
                check.check_pair(*pair, profile, "O0")
            except (check.Rejected, reader.Rejected) as error:
                rejected_by = type(error).__name__ + ": " + str(error)
            need(rejected_by is not None, "byte mutant accepted: " + profile + "/" + label)
            records.append(dict(Profile=profile, Label=label, Side=side, Root=name,
                                ElfSha256=sha(read(mutant.elf)), DisassemblySha256=sha(read(mutant.dis)),
                                Rejection=rejected_by))
    return records


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--native", type=Path, default=Path("C:/fzcn-20261104-e4"))
    parser.add_argument("--reference", type=Path, default=Path("C:/fzrc-20261104-e5"))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    out = args.output_dir.absolute()
    repo = HERE.parents[2]
    need(not out.exists() and not any(out.is_relative_to(p.absolute()) for p in
                                    (repo, args.native, args.reference)), "fresh external output required")
    out.mkdir(parents=True)
    bindings = []
    modules = {}
    for name, path in (("check", CHECKER), ("reader", READER), ("test", Path(__file__))):
        raw = read(path)
        bindings.append((path, sha(raw)))
        (out / (name + ".py")).write_bytes(raw)
        if name != "test":
            modules[name] = load(raw, path)
    check, reader = modules["check"], modules["reader"]
    report = dict(Verdict="FAIL", Error=None, ProofScope="SETUP_CHILD_CHECKER_CONTROLS_ONLY",
                  RequiredCellSatisfied=False, RequiredCellsSatisfied=0, FinalElfProof=False,
                  CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
                  PolicyEquivalenceProven=False, CompilerInvocations=0, ObjdumpInvocations=0,
                  SourceInventorySha256=INVENTORY, ModuleBindings=[dict(Path=str(p), Sha256=h) for p, h in bindings])
    try:
        report["PureControls"] = pure_controls(check)
        roots = {"Native": args.native.absolute(), "Reference": args.reference.absolute()}
        cells, results = retained(check, reader, roots, bindings)
        report["RetainedPairs"], report["RetainedClosedBodies"] = len(results), sum(r["ClosedBodies"] for r in results)
        (out / "retained.json").write_bytes(encoded(results) + b"\n")
        mutants = out / "mutants"
        mutants.mkdir()
        mutations = byte_controls(check, reader, cells, mutants)
        (out / "mutations.json").write_bytes(encoded(mutations) + b"\n")
        report["ByteMutantsRejected"] = len(mutations)
        for path, digest in bindings:
            need(sha(read(path)) == digest, "closing input drift: " + str(path))
        (out / "inputs.json").write_bytes(encoded([dict(Path=str(p), Sha256=h) for p, h in bindings]) + b"\n")
        report.update(Verdict="FP-SETUP-CONTROLS-PASS", ClosingInputDrift=0,
                      BoundGroupFiles=40, BoundReceiptMetadataFiles=4)
    except Exception as error:
        report["Error"] = type(error).__name__ + ": " + str(error)
    (out / "results.json").write_bytes(encoded(report) + b"\n")
    artifacts = {p.relative_to(out).as_posix(): sha(read(p)) for p in out.rglob("*") if p.is_file()}
    (out / "artifacts.json").write_bytes(encoded(dict(Artifacts=artifacts)) + b"\n")
    need(parse(read(out / "artifacts.json")) == dict(Artifacts=artifacts), "output index readback")
    need(all(sha(read(out / name)) == digest for name, digest in artifacts.items()), "output hash drift")
    print(json.dumps(report, indent=2))
    return 0 if report["Verdict"] == "FP-SETUP-CONTROLS-PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
