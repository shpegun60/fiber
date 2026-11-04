"""Replay a captured classic-FP reference image and retain actual ELF mutants.

No native tool or target image is executed. Source-transcribed prelink
protocols, pinned source identity and build receipts are separate obligations.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
FIRST = "prvPortStartFirstTask"
SVC = "vPortSVCHandler"
PENDSV = "xPortPendSVHandler"
CALLEE = "vTaskSwitchContext"
SLOT = "pxCurrentTCB"
PROFILES = ("CM4", "CM7")
MODES = ("O0", "Og", "O2", "Os", "O3")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def need(ok, message):
    if not ok:
        raise ValueError("reference-final-witness: " + message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def selection(profile, mode):
    need(type(profile) is str and profile in PROFILES and type(mode) is str and mode in MODES,
         "only CM4/CM7 and five ordinary modes are admitted")
    size, instructions = {"CM4": (164, 48), "CM7": (168, 50)}[profile]
    if mode == "O0":
        size, instructions = size + 6, instructions + 3
    return size, instructions


def require_input_identity(inputs, providers):
    need(set(inputs) == {"Prelink", "Final", "Disassembly", "Plain", "LinkMap"}, "exact witness roles")
    need(len(providers) == len(set(providers)) == 4 and inputs["Prelink"] in providers,
         "exact four providers including prelink")
    need(len(set(inputs.values())) == 5, "witness roles must have distinct paths")
    originals = list(dict.fromkeys((*inputs.values(), *providers)))
    need(len(originals) == 8, "only prelink/provider path overlap is permitted")
    for index, path in enumerate(originals):
        need(all(not path.samefile(other) for other in originals[:index]),
             "distinct physical inputs required; hard-link aliases are unsupported")
    return originals


def mutate(name, files, image, proofs, edits, patch):
    first, svc, pend = (proofs[n] for n in (FIRST, SVC, PENDSV))
    call = next(row for row in pend["References"] if row["Kind"] == 10)
    slot = next(row for row in svc["References"] if row["Kind"] == 2)
    twins = files["Final"], files["Plain"]

    def section(root):
        symbol = next(s for s in image.final.symbols if s["name"] == root and s["section"] != "SHN_UNDEF")
        return image.final.names[symbol["section"]]

    def change_instruction(root, address, raw, op, operands):
        for path in twins:
            patch._patch_vma(path, address, raw, edits)
        patch._patch_disassembly(files["Disassembly"], section(root), address, raw, op, operands)

    if name == "ordinary-byte":
        row = next(row for row in first["Instructions"] if row["Mnemonic"] == "cpsie" and
                   row["Operands"] == "i" and row["Bytes"] == "62b6")
        change_instruction(FIRST, first["Address"] + row["Offset"], bytes.fromhex("72b6"), "cpsid", "i")
    elif name == "BL-target-plus-two":
        target = call["ResolvedValue"] + 2
        change_instruction(PENDSV, call["Place"], patch.branch_link(call["Place"], target), "bl",
                           "%x <%s+0x2>" % (target, CALLEE))
    elif name == "slot-ABS32-plus-four":
        value = slot["ResolvedValue"] + 4
        change_instruction(SVC, slot["Place"], struct.pack("<I", value), ".word", "0x%x" % value)
    elif name == "applied-REL-kind":
        patch._patch_relocation(files["Final"], call["Place"], kind=30, edits=edits)
    elif name == "applied-REL-target":
        patch._patch_relocation(files["Final"], call["Place"], symbol="xTaskIncrementTick", edits=edits)
    elif name == "original-BL-addend":
        patch._patch_prelink(files["Prelink"], PENDSV, call["Offset"], patch.branch_link(0, 2), edits)
    elif name == "original-slot-addend":
        patch._patch_prelink(files["Prelink"], SVC, slot["Offset"], struct.pack("<I", 4), edits)
    elif name == "local-root-global-binding":
        for path in twins:
            patch._patch_symbol(path, FIRST, "info", 0x12, edits)
    elif name == "root-size":
        for path in twins:
            patch._patch_symbol(path, FIRST, "size", first["Size"] - 2, edits)
    elif name == "mapping-boundary":
        address = svc["Address"] + svc["LiteralIslands"][0]["Offset"]
        for path in twins:
            elf = patch._structured(path)
            matches = [table.header.sh_offset + i * table.header.sh_entsize + 4
                       for table in elf.iter_sections() if isinstance(table, patch.reader.SymbolTableSection)
                       for i, item in enumerate(table.iter_symbols())
                       if re.fullmatch(r"\$d(?:\..*)?", item.name) and item.entry.st_value == address]
            need(matches, "actual data mapping boundary required")
            for offset in matches:
                patch._edit(path, offset, struct.pack("<I", address - 2), edits)
    elif name == "callee-symbol-and-BL-padding-retarget":
        occupied = [(s["value"] & ~1, (s["value"] & ~1) + s["size"]) for s in image.final.symbols
                    if s["kind"] == "STT_FUNC" and type(s["section"]) is int and s["section"] > 0]
        candidates = [address for (sec, address), row in image.instructions.items()
                      if row is not None and row[0] == "nop" and row[2] in (b"\x00\xbf", b"\xc0\x46")
                      and not any(a < address + 2 and address < b for a, b in occupied)
                      and image.final.mapping(sec, address)[0] == "t"
                      and any(load["Flags"] & 1 and load["Vaddr"] <= address and
                              address + 2 <= load["Vaddr"] + load["FileSize"] for load in image.final.loads)]
        need(candidates, "actual unowned Thumb NOP padding required")
        address = min(candidates)
        for path in twins:
            patch._patch_symbol(path, CALLEE, "value", address | 1, edits)
            patch._patch_symbol(path, CALLEE, "size", 2, edits)
        change_instruction(PENDSV, call["Place"], patch.branch_link(call["Place"], address),
                           "bl", "%x <%s>" % (address, CALLEE))
    elif name == "NOBITS-slot-over-file-backed-text":
        address = first["Address"]
        for path in twins:
            elf = patch._structured(path)
            _, _, symbol = patch._symbol_field(path, SLOT, "value")
            owner = elf.get_section(symbol.st_shndx).header
            text = elf.get_section_by_name(section(FIRST)).header
            need(address + owner.sh_size <= text.sh_addr + text.sh_size, "bounded NOBITS mutant")
            patch._patch_symbol(path, SLOT, "value", address, edits)
            patch._edit(path, elf.header.e_shoff + symbol.st_shndx * elf.header.e_shentsize + 12,
                        struct.pack("<I", address), edits)
        for proof in proofs.values():
            for ref in proof["References"]:
                if ref["Kind"] == 2:
                    change_instruction(proof["Name"], ref["Place"], struct.pack("<I", address),
                                       ".word", "0x%x" % address)
    elif name == "RAM-owner-not-writable":
        for path in twins:
            elf = patch._structured(path)
            matches = [(i, segment.header) for i, segment in enumerate(elf.iter_segments())
                       if segment.header.p_type == "PT_LOAD" and segment.header.p_vaddr <= slot["ResolvedValue"]
                       and slot["ResolvedValue"] + 4 <= segment.header.p_vaddr + segment.header.p_memsz]
            need(len(matches) == 1 and matches[0][1].p_flags & 2, "one writable current-TCB owner")
            index, header = matches[0]
            patch._edit(path, elf.header.e_phoff + index * elf.header.e_phentsize + 24,
                        struct.pack("<I", header.p_flags & ~2), edits)
    else:
        raise ValueError("unknown reference mutant")


CASES = (
    ("ordinary-byte", FIRST, "Root", "PRESERVATION:non-relocation bytes changed"),
    ("BL-target-plus-two", PENDSV, "Root", "RELOC:applied BL destination"),
    ("slot-ABS32-plus-four", SVC, "Root", "RELOC:applied ABS32 word"),
    ("applied-REL-kind", PENDSV, "Root", "RELOC:relocation kind/identity"),
    ("applied-REL-target", PENDSV, "Root", "RELOC:relocation kind/identity"),
    ("original-BL-addend", PENDSV, "Root", "RELOC:only original BL addend"),
    ("original-slot-addend", SVC, "Root", "RELOC:only current-slot ABS32"),
    ("local-root-global-binding", FIRST, "Root", "SYMBOL:"),
    ("root-size", FIRST, "Root", "PRESERVATION:root extent changed"),
    ("mapping-boundary", SVC, "Root", "PRESERVATION:mapping/layout changed"),
    ("callee-symbol-and-BL-padding-retarget", PENDSV, "Root", "ORIGIN:original section/offset/size"),
    ("NOBITS-slot-over-file-backed-text", SVC, "TwinComparison", "ELF:overlapping allocated sections"),
    ("RAM-owner-not-writable", SVC, "TwinComparison", "ELF:writable allocated section owner lacks PF_W"),
)


def witness(args, directory, reader, core, patch):
    expected_size, expected_instructions = selection(args.profile, args.mode)
    reader_class = {"CM4": reader.ReferenceCM4FinalImage, "CM7": reader.ReferenceCM7FinalImage}[args.profile]
    report = dict(Status="FAIL", Scope="REFERENCE_CLASSIC_FP_PRELINK_BOUND_FINAL_ROOT_PRESERVATION_ONLY",
                  Profile=args.profile, Mode=args.mode,
                  RequiredCellsSatisfied=0, FinalParity=False, GlobalProof=False, CPUProof=False,
                  BoardExecution=False, NativeCommandsExecuted=0, PositiveRoots=[], Mutants=[])
    inputs = dict(Prelink=Path(args.prelink_object).resolve(strict=True), Final=Path(args.final_elf).resolve(strict=True),
                  Disassembly=Path(args.disassembly).resolve(strict=True), Plain=Path(args.plain_elf).resolve(strict=True),
                  LinkMap=Path(args.link_map).resolve(strict=True))
    providers = [Path(path).resolve(strict=True) for path in args.provider_object]
    originals = require_input_identity(inputs, providers)
    snapshots = {path: path.read_bytes() for path in originals}
    captured = directory / "witness-inputs"
    captured.mkdir()
    copies = {}
    for index, (path, data) in enumerate(snapshots.items()):
        copy = captured / ("%02d-" % index + path.name)
        copy.write_bytes(data)
        copies[path] = copy
    report["Inputs"] = [dict(Original=str(path), Captured=str(copies[path]),
                             Sha256=hashlib.sha256(data).hexdigest().upper()) for path, data in snapshots.items()]
    files = {key: copies[path] for key, path in inputs.items()}
    bindings = {str(path): copies[path] for path in providers}
    try:
        def construct(selected, provider_bindings):
            return reader_class(selected["Prelink"], selected["Final"], selected["Disassembly"],
                        provider_objects=provider_bindings, link_map=selected["LinkMap"], mode=args.mode)
        image = construct(files, bindings)
        report["Twins"] = core.compare_load_images(files["Plain"], files["Final"])
        proofs = {name: image.function(name) for name in (FIRST, SVC, PENDSV)}
        report["PositiveRoots"] = list(proofs.values())
        need(sum(row["Size"] for row in proofs.values()) == expected_size and
             sum(row["InstructionCount"] for row in proofs.values()) == expected_instructions and
             sum(len(row["References"]) for row in proofs.values()) == 3, "fixed complete reference roots")
        for name, root, expected_stage, expected in CASES:
            case_directory = directory / "mutants" / name
            case_directory.mkdir(parents=True)
            case = {key: case_directory / (key + path.suffix) for key, path in files.items()}
            for key, path in files.items():
                case[key].write_bytes(path.read_bytes())
            case_bindings = {identity: case["Prelink"] if path == files["Prelink"] else path
                             for identity, path in bindings.items()}
            record = dict(Name=name, Root=root, Expected=expected, ExpectedStage=expected_stage,
                          Status="FAIL", TwinComparisonPass=False, ReaderRejected=False, Edits=[])
            report["Mutants"].append(record)
            try:
                mutate(name, case, image, proofs, record["Edits"], patch)
                need(record["Edits"], "actual bounded ELF edit required")
                stage = "TwinComparison"
                try:
                    core.compare_load_images(case["Plain"], case["Final"])
                    record["TwinComparisonPass"] = True
                    stage = "FinalImage"
                    altered = construct(case, case_bindings)
                    stage = "Root"
                    altered.function(root)
                except core.Rejected as error:
                    record.update(ReaderRejected=True, Rejection=str(error), Stage=stage)
                    if stage == expected_stage and re.search(expected, str(error)):
                        record["Status"] = "PASS"
            except Exception as error:
                record["Error"] = type(error).__name__ + ": " + str(error)
            record["Files"] = [dict(Path=str(path), Sha256=digest(path)) for path in case.values()]
        report.update(PositiveRootCount=len(proofs), RootBytes=sum(r["Size"] for r in proofs.values()),
                      Instructions=sum(r["InstructionCount"] for r in proofs.values()),
                      AppliedReferences=sum(len(r["References"]) for r in proofs.values()),
                      MutantControls=len(CASES), MutantsPassed=sum(r["Status"] == "PASS" for r in report["Mutants"]))
        if report["MutantsPassed"] == len(CASES):
            report["Status"] = "PASS"
    except Exception as error:
        report["Error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["InputDrift"] = [str(path) for path, data in snapshots.items() if path.read_bytes() != data]
        report["CapturedInputDrift"] = [str(path) for path, data in snapshots.items() if copies[path].read_bytes() != data]
        report["MutantFileDrift"] = [r["Path"] for case in report["Mutants"] for r in case.get("Files", [])
                                      if digest(r["Path"]) != r["Sha256"]]
        if any(report[field] for field in ("InputDrift", "CapturedInputDrift", "MutantFileDrift")):
            report["Status"] = "FAIL"
    return report


def require_output_directory(path):
    directory = Path(path).resolve()
    repo = HERE.parents[2]
    need(not directory.is_relative_to(repo) and not repo.is_relative_to(directory),
         "output must be external to repository")
    need(not directory.exists(), "fresh output directory required")
    return directory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("prelink-object", "final-elf", "disassembly", "plain-elf", "link-map", "output-dir"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--provider-object", action="append", required=True)
    parser.add_argument("--profile", choices=PROFILES, default="CM4")
    parser.add_argument("--mode", choices=MODES, default="O2")
    args = parser.parse_args(argv)
    need(not sys.flags.optimize, "unoptimized Python required")
    directory = require_output_directory(args.output_dir)
    directory.mkdir(parents=True)
    sources = (Path(__file__).resolve(), HERE / "reference_elf.py", HERE / "elf.py", HERE / "test_elf.py")
    hashes = {str(path): digest(path) for path in sources}
    report = dict(Status="FAIL", RequiredCellsSatisfied=0, FinalParity=False, GlobalProof=False,
                  CPUProof=False, BoardExecution=False, NativeCommandsExecuted=0)
    try:
        reader = load("reference_final_witness_reader", HERE / "reference_elf.py")
        patch = load("reference_final_witness_patch", HERE / "test_elf.py")
        report = witness(args, directory, reader, reader.core, patch)
    except Exception as error:
        report["Error"] = type(error).__name__ + ": " + str(error)
    report["SourceHashes"] = hashes
    report["SourceDrift"] = [str(path) for path in sources if digest(path) != hashes[str(path)]]
    if report["SourceDrift"]:
        report["Status"] = "FAIL"
    (directory / "results.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(report["Status"], str(directory))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
