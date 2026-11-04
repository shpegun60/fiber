"""Stdlib-only Thumb-1 tail controls and bounded retained CM0 reader replay.

Synthetic ELF controls qualify the reader contract, not source or CPU behavior.
The retained replay checks decoding only, never mechanism parity.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import stat
import struct
import sys
import types

sys.dont_write_bytecode = True
if sys.flags.optimize or not __debug__:
    raise SystemExit("unoptimized Python required")

READER = Path(__file__).resolve().parents[1] / "cm55_tfm_parity/elf.py"
MODES = ("O0", "Og", "O2", "Os", "O3")
COHORTS = (
    "cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default",
    "cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default",
    "cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default",
)
PINS = {
    "native": (
        "E6A401727808D2D3FC353B707E95FDC9FD7933593ACD4D06CEC592C0D2F7E2E0",
        "199068E8880FABB612233FA393CEF3A97A2BC5CC1DCBE4456CC08B8387A6548F",
    ),
    "reference": (
        "690032B130C5B5E25880ECDA64D00109FCC154BFBAAFADEE82153FF0BF0594B9",
        "246BC05B768CEF85115FBD2667688062B3E2816CB99F6604EB4D61AFA1DC094E",
    ),
}
INVENTORY = "E99DFC023B9F11F19A6109E37338E81DBE37574B8831B99244378A21D52179A3"
BASELINE = "4E9AAADE69D9394844F587BF862F916B7DF10DA0D718E1856042E6E3F11133AD"
STOPPED = {
    "cm33f_secure_transfer_reference", "m55_secure_closed_parity",
    "test_cm33f_secure_transfer_reference.ps1", "test_m55_secure_closed_parity.ps1",
}


def need(ok, message):
    if not ok:
        raise AssertionError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def read(path):
    path = Path(path).absolute()
    need(not STOPPED.intersection(p.casefold() for p in path.parts), "protected path")
    for part in (path, *path.parents):
        need(not getattr(part.lstat(), "st_file_attributes", 0) &
             getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0), "reparse input: " + str(part))
    return path.read_bytes()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def pairs(items):
    result = {}
    for key, value in items:
        need(key.casefold() not in {k.casefold() for k in result}, "duplicate JSON key")
        result[key] = value
    return result


def parse(data):
    return json.loads(data, object_pairs_hook=pairs)


def module(data, path):
    result = types.ModuleType("cm0_reader_under_test")
    result.__file__ = str(path)
    exec(compile(data, str(path), "exec"), result.__dict__)
    return result


def outcome(reader, elf, dis, options):
    try:
        return {"Tokens": reader.Object(elf, dis).function("root", **options)}
    except reader.Rejected as error:
        return {"Rejection": type(error).__module__ + "." + type(error).__qualname__,
                "Message": str(error)}


def fixture(directory, name, *, tails=("alias",), pool=b"\x78\x56\x34\x12",
            relocations=(), first=None, second=None, mapping=None, dis_tail=None):
    """Generate a small real ARM ET_REL and matching synthetic disassembly."""
    kinds = {
        "alias": (0x46C0, "mov", "r8, r8"),
        "bf": (0xBF00, "nop", ""),
        "other": (0x46C9, "mov", "r9, r9"),
        "add": (0x3001, "adds", "r0, #1"),
    }
    rows = [(0, 0x4800, "ldr", "r0, [pc, #0]"), (2, 0x4770, "bx", "lr")]
    if first is not None:
        rows[0] = (0, *first)
    if second is not None:
        rows[1] = (2, *second)
    rows += [(8 + i * 2, *kinds[kind]) for i, kind in enumerate(tails)]
    code = b"".join(struct.pack("<H", row[1]) for row in rows[:2]) + pool
    code += b"".join(struct.pack("<H", row[1]) for row in rows[2:])
    strings = bytearray(b"\0")

    def string(value):
        offset = len(strings)
        strings.extend(value.encode("ascii") + b"\0")
        return offset

    symbols = [b"\0" * 16, struct.pack("<IIIBBH", string("root"), 1, len(code), 0x12, 0, 1)]
    mappings = [(0, "$t"), (4, "$d")]
    if tails:
        mappings.append((8, "$t.1"))
    if mapping is not None:
        mappings = mapping
    for value, label in mappings:
        symbols.append(struct.pack("<IIIBBH", string(label), value, 0, 0, 0, 1))
    external_index = len(symbols)
    symbols.append(struct.pack("<IIIBBH", string("datum"), 0, 0, 0x10, 0, 0))
    rel = b"".join(struct.pack("<II", address, (external_index << 8) | kind)
                   for address, kind in relocations)
    names = b"\0.text\0.symtab\0.strtab\0.shstrtab\0.rel.text\0"
    payloads = (b"", code, b"".join(symbols), bytes(strings), names, rel)
    raw = bytearray(b"\0" * 52)
    sections = [(0,) * 10]
    for index in range(1, 6):
        raw.extend(b"\0" * (-len(raw) % 4))
        offset = len(raw)
        raw.extend(payloads[index])
        sections.append((names.index(("", ".text", ".symtab", ".strtab", ".shstrtab", ".rel.text")[index].encode() + b"\0"),
                         (0, 1, 2, 3, 3, 9)[index], 6 if index == 1 else 0, 0,
                         offset, len(payloads[index]), 3 if index == 2 else 2 if index == 5 else 0,
                         1 if index == 5 else 0, 4, 16 if index == 2 else 8 if index == 5 else 0))
    raw.extend(b"\0" * (-len(raw) % 4))
    shoff = len(raw)
    raw.extend(b"".join(struct.pack("<10I", *section) for section in sections))
    raw[:52] = struct.pack("<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01" + b"\0" * 9,
                           1, 40, 1, 0, 0, shoff, 0, 52, 0, 0, 40, 6, 4)
    text = ["Disassembly of section .text:"]
    for i, (address, word, op, arg) in enumerate(rows):
        if dis_tail is not None and i == len(rows) - 1:
            word, op, arg = dis_tail
        text.append(" %x: %04x %s %s" % (address, word, op, arg))
    elf, dis = directory / (name + ".o"), directory / (name + ".dis")
    elf.write_bytes(raw)
    dis.write_text("\n".join(text) + "\n", encoding="ascii", newline="\n")
    return elf, dis


def controls(reader, old, directory):
    records = []
    full = {"literal_islands": True, "thumb1_tail_nop": True}

    def check(name, fixture_options, options, rejection=None, tail=None):
        elf, dis = fixture(directory, name, **fixture_options)
        result = outcome(reader, elf, dis, options)
        if rejection is not None:
            need("Rejection" in result and result["Message"] == rejection, name + ": wrong rejection")
        else:
            need("Tokens" in result, name + ": unexpected rejection " + str(result))
            if tail is not None:
                need(result["Tokens"][-len(tail):] == tail, name + ": tail filtered/normalized")
        records.append({"Name": name, "ExpectedRejection": rejection, "Outcome": result})
        for legacy_options in ({}, {"literal_islands": True}):
            need(outcome(old, elf, dis, legacy_options) == outcome(reader, elf, dis, legacy_options),
                 name + ": pre-existing API changed")
        return result

    unsupported = "REJECT:DECODE:unsupported literal-island executable tail"
    check("one-alias", {}, full, tail=[("mov", "r8,r8")])
    check("gnu-nop-alias", {"dis_tail": (0x46C0, "nop", "@ (mov r8, r8)")}, full,
          tail=[("nop", "@ (mov r8, r8)")])
    check("plain-nop-alias", {"dis_tail": (0x46C0, "nop", "")}, full, tail=[("nop", "")])
    check("two-aliases", {"tails": ("alias", "alias")}, full,
          tail=[("mov", "r8,r8")] * 2)
    check("mixed-tail", {"tails": ("bf", "alias")}, full,
          tail=[("nop", ""), ("mov", "r8,r8")])
    check("mixed-reverse", {"tails": ("alias", "bf")}, full,
          tail=[("mov", "r8,r8"), ("nop", "")])
    check("ordinary-nop", {"tails": ("bf",)}, {"literal_islands": True}, tail=[("nop", "")])
    check("no-tail", {"tails": ()}, full)
    check("no-island", {"tails": (), "mapping": [(0, "$t")],
                        "pool": b"\xc0\x46\xc0\x46", "first": (0x46C0, "mov", "r8, r8")},
          full, rejection="REJECT:DECODE:root/undecoded executable bytes at 0x4")
    check("literal-relocation", {"relocations": ((4, 2),)}, full, tail=[("mov", "r8,r8")])
    branch = check("branch-to-tail", {"second": (0xE001, "b", "8 <root+0x8>")}, full,
                   tail=[("mov", "r8,r8")])
    need(branch["Tokens"][1] == ("b", "@3"), "descriptor must count in branch indices")
    check("unreferenced-data", {"first": (0x46C0, "mov", "r8, r8")}, full,
          rejection="REJECT:DECODE:unreferenced literal/data")
    check("alias-without-optin", {}, {"literal_islands": True}, rejection=unsupported)
    check("explicit-optout", {}, {"literal_islands": True, "thumb1_tail_nop": False}, rejection=unsupported)
    check("three-aliases", {"tails": ("alias",) * 3}, full, rejection=unsupported)
    check("wrong-self-move", {"tails": ("other",)}, full, rejection=unsupported)
    check("non-nop-after-alias", {"tails": ("alias", "add")}, full, rejection=unsupported)
    check("wrong-operands", {"dis_tail": (0x46C0, "mov", "r9, r9")}, full, rejection=unsupported)
    check("wrong-mnemonic", {"dis_tail": (0x46C0, "adds", "r0, #1")}, full, rejection=unsupported)
    check("nop-with-operands", {"dis_tail": (0x46C0, "nop", "r8, r8")}, full, rejection=unsupported)
    check("wrong-raw", {"tails": ("bf",), "dis_tail": (0xBF00, "mov", "r8, r8")}, full,
          rejection=unsupported)
    check("unconsumed-tail-relocation", {"relocations": ((8, 2),)}, full,
          rejection="REJECT:RELOC:unexpected instruction relocation")
    check("bad-literal-relocation", {"relocations": ((4, 3),)}, full,
          rejection="REJECT:RELOC:unsupported literal relocation")
    check("branch-into-data", {"first": (0xE000, "b", "4 <root+0x4>")}, full,
          rejection="REJECT:DECODE:non-local branch")
    check("literal-outside-section", {"first": (0x48FF, "ldr", "r0, [pc, #1020]")}, full,
          rejection="REJECT:DECODE:literal not mapped data")
    check("instruction-crosses-mapping", {"mapping": [(0, "$t"), (1, "$d"), (8, "$t.1")]}, full,
          rejection="REJECT:DECODE:instruction crosses mapping")
    check("elf-disagreement", {"dis_tail": (0x46C9, "mov", "r8, r8")}, full,
          rejection="REJECT:DECODE:disassembly bytes disagree with ELF")
    for value in (1, 0, None, "true", []):
        check("bad-option-" + str(len(records)), {}, {"literal_islands": True, "thumb1_tail_nop": value},
              rejection="REJECT:DECODE:thumb1-tail-nop option must be boolean")
    check("option-dependency", {}, {"thumb1_tail_nop": True},
          rejection="REJECT:DECODE:thumb1-tail-nop requires literal-islands")
    return records


def replay(reader, old, native, reference, bindings):
    records, identities, counts = [], {}, Counter()
    for side, root in (("native", native), ("reference", reference)):
        metadata = [read(root / name) for name in ("results.json", "artifacts.json")]
        need(tuple(sha(data) for data in metadata) == PINS[side], "receipt pin changed")
        bindings.extend((root / name, sha(data)) for name, data in zip(("results.json", "artifacts.json"), metadata))
        receipt, index = map(parse, metadata)
        need(receipt["SourceInventorySha256"] == INVENTORY, "inventory mismatch")
        selected = [cell for cell in receipt["Cells"] if cell["Cohort"] in COHORTS]
        keys = [(cell["Cohort"], cell["ArtifactRole"], cell["Mode"]) for cell in selected]
        expected = {(cohort, "runtime", mode) for cohort in COHORTS for mode in MODES}
        need(len(keys) == len(set(keys)) == 15 and set(keys) == expected, "exact 15 selected cells required")
        for cell in selected:
            need(cell["SourceGroup"] == "CM0", "non-CM0 source group")
            key = (cell["Cohort"], cell["Mode"])
            if side == "native":
                identities[key] = cell["CohortSha256"]
            else:
                need(identities[key] == cell["CohortSha256"], "cohort fingerprint mismatch")
            elf = Path(cell["NativeGroup"])
            dis = elf.with_suffix(".dis")
            need(elf.is_absolute() and elf.is_relative_to(root), "group outside receipt")
            for path in (elf, dis):
                digest = sha(read(path))
                need(index["Artifacts"][path.relative_to(root).as_posix()] == digest, "artifact hash mismatch")
                bindings.append((path, digest))
            need(sha(read(elf)) == cell["NativeGroupSha256"], "cell ELF hash mismatch")
            before, after = old.Object(elf, dis), reader.Object(elf, dis)
            roots = ("SVC_Handler", "PendSV_Handler", "fiber_port_start_first_context" if side == "native" else "vStartFirstTask")
            for name in roots:
                symbols = [s for s in after.symbols if s["name"] == name and s["section"]]
                need(len(symbols) == 1 and symbols[0]["info"] == 0x12 and symbols[0]["size"] > 0,
                     "actual global strong root required: " + name)
                outcomes = []
                for obj in (before, after):
                    local = []
                    for options in ({}, {"literal_islands": True}):
                        try:
                            local.append({"Tokens": obj.function(name, **options)})
                        except Exception as error:
                            local.append({"Class": type(error).__module__ + "." + type(error).__qualname__, "Message": str(error)})
                    outcomes.append(local)
                need(outcomes[0] == outcomes[1], "pre-existing API drift: " + name)
                try:
                    tokens = after.function(name, literal_islands=True, thumb1_tail_nop=True)
                except Exception as error:
                    raise AssertionError("extended decode: " + side + "/" + cell["Cohort"] +
                                         "/" + cell["Mode"] + "/" + name + ": " + str(error)) from error
                need(type(tokens) is list and tokens, "missing full tokens")
                counts["DecodedRoots"] += 1
                counts["PreExistingApiComparisons"] += 2
                symbol = symbols[0]
                end = (symbol["value"] & ~1) + symbol["size"]
                counts["AliasTailRoots"] += int(after.read(symbol["section"], end - 2, 2) == b"\xc0\x46")
                counts["PriorLiteralRejections"] += int("Class" in outcomes[0][1])
                records.append({"Side": side, "Cohort": cell["Cohort"], "Mode": cell["Mode"],
                                "Root": name, "Elf": str(elf), "Disassembly": str(dis),
                                "PreExistingOutcomes": outcomes[0], "ExtendedTokens": tokens})
            counts["Groups"] += 1
    need(counts["Groups"] == 30 and counts["DecodedRoots"] == 90 and counts["AliasTailRoots"] > 0,
         "bounded retained coverage mismatch")
    return records, dict(counts)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--baseline-reader", type=Path)
    parser.add_argument("--capture-baseline", action="store_true")
    parser.add_argument("--native", type=Path, default=Path("C:/fzcn-20261104-e4"))
    parser.add_argument("--reference", type=Path, default=Path("C:/fzrc-20261104-e5"))
    args = parser.parse_args()
    out = args.output_dir.absolute()
    need(not out.exists(), "fresh output directory required")
    repo = Path(__file__).resolve().parents[3]
    need(not any(out.is_relative_to(p.absolute()) for p in (repo, args.native, args.reference)), "external output required")
    out.mkdir(parents=True)
    reader_bytes, test_bytes = read(READER), read(__file__)
    (out / "reader.py").write_bytes(reader_bytes)
    (out / "test_decoder.py").write_bytes(test_bytes)
    if args.capture_baseline:
        need(args.baseline_reader is None and sha(reader_bytes) == BASELINE, "wrong baseline reader")
        print(json.dumps({"BaselineReader": str(out / "reader.py"), "Sha256": sha(reader_bytes)}))
        return 0
    need(args.baseline_reader is not None, "captured pre-edit baseline required")
    baseline_bytes = read(args.baseline_reader)
    need(sha(baseline_bytes) == BASELINE, "wrong baseline reader hash")
    (out / "baseline_reader.py").write_bytes(baseline_bytes)
    bindings = [(READER, sha(reader_bytes)), (Path(__file__), sha(test_bytes)),
                (args.baseline_reader, sha(baseline_bytes))]
    report = {"Verdict": "FAIL", "Error": None, "Scope": "CM0_READER_ONLY",
              "CompilerInvocations": 0, "ObjdumpInvocations": 0, "CpuExecution": False,
              "BoardExecution": False, "MechanismParity": False, "RequiredCellsSatisfied": 0,
              "GlobalFreezeQualified": False, "TailUnreachabilityProven": False,
              "ReaderSha256": sha(reader_bytes), "TestSha256": sha(test_bytes),
              "BaselineReaderSha256": sha(baseline_bytes), "Cohorts": list(COHORTS)}
    try:
        reader, old = module(reader_bytes, READER), module(baseline_bytes, args.baseline_reader)
        pure = out / "synthetic"
        pure.mkdir()
        control_rows = controls(reader, old, pure)
        report["Controls"] = {"Total": len(control_rows),
                              "Positive": sum(row["ExpectedRejection"] is None for row in control_rows),
                              "Negative": sum(row["ExpectedRejection"] is not None for row in control_rows)}
        (out / "controls.json").write_bytes(encoded(control_rows) + b"\n")
        rows, counts = replay(reader, old, args.native.absolute(), args.reference.absolute(), bindings)
        (out / "roots.json").write_bytes(encoded(rows) + b"\n")
        report["Retained"] = counts
        for path, digest in bindings:
            need(sha(read(path)) == digest, "closing original/input drift: " + str(path))
        report.update(Verdict="CM0-DECODER-CONTRACT-PASS", ClosingInputDrift=0,
                      OriginalBindings=[{"Path": str(path), "Sha256": digest} for path, digest in bindings])
    except Exception as error:
        report["Error"] = type(error).__name__ + ": " + str(error)
    (out / "results.json").write_bytes(encoded(report) + b"\n")
    artifacts = {path.relative_to(out).as_posix(): sha(read(path)) for path in out.rglob("*") if path.is_file()}
    (out / "artifacts.json").write_bytes(encoded({"Artifacts": artifacts}) + b"\n")
    need(parse(read(out / "artifacts.json")) == {"Artifacts": artifacts}, "output index readback")
    need(all(sha(read(out / path)) == digest for path, digest in artifacts.items()), "output hash drift")
    print(json.dumps({key: value for key, value in report.items() if key != "OriginalBindings"}, indent=2))
    return 0 if report["Verdict"] == "CM0-DECODER-CONTRACT-PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
