"""Retained CM0 reference final-root witnesses and actual private ELF mutations.

The caller separately authenticates producer receipts, pins and five complete
owning-object protocols. This gate never launches tools or executes an image.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CLASSIC = HERE.with_name("classic_final_image")
FIRST, SVC, C_SVC = "vStartFirstTask", "SVC_Handler", "vPortSVCHandler_C"
RESTORE, PENDSV = "vRestoreContextOfFirstTask", "PendSV_Handler"
ROOTS = (FIRST, SVC, C_SVC, RESTORE, PENDSV)
PROFILES = ("CM0", "CM0PLUS", "CM0PLUSVTOR")
MODES = ("O0", "Og", "O2", "Os", "O3")
SLOT, CALLEE = "pxCurrentTCB", "vTaskSwitchContext"


def need(ok, detail):
    if not ok:
        raise ValueError("cm0-final-witness: " + detail)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def digest(path):
    return sha(Path(path).read_bytes())


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    exec(compile(path.read_bytes(), str(path), "exec"), result.__dict__)
    return result


def selection(profile, mode):
    need(type(profile) is str and profile in PROFILES and type(mode) is str and mode in MODES,
         "exact three profiles and five ordinary modes required")
    return 206 if mode == "O0" else 164


def regular(value):
    path = Path(os.path.abspath(value))
    forbidden = {"cm33f_secure_transfer_reference", "m55_secure_closed_parity",
                 "test_cm33f_secure_transfer_reference.ps1", "test_m55_secure_closed_parity.ps1"}
    need(not any(part.lower() in forbidden for part in path.parts), "protected input")
    for parent in (path, *path.parents):
        info = parent.lstat()
        need(not parent.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400, "input reparse/symlink")
    need(path.is_file(), "regular input file required")
    return path.resolve(strict=True)


def require_input_identity(inputs, providers):
    need(set(inputs) == {"Port", "Asm", "Final", "Plain", "Disassembly", "LinkMap"}, "exact six input roles")
    need(len(set(inputs.values())) == 6 and len(providers) == len(set(providers)) == 5 and
         inputs["Port"] in providers and inputs["Asm"] in providers, "five providers including both prelinks")
    originals = list(dict.fromkeys((*inputs.values(), *providers)))
    need(len(originals) == 9, "only two intended prelink/provider overlaps")
    for index, path in enumerate(originals):
        need(all(not path.samefile(other) for other in originals[:index]), "distinct physical input roles required")
    return originals


def require_output_directory(value, originals):
    lexical = Path(os.path.abspath(value))
    for path in (lexical, *lexical.parents):
        if path.exists() or path.is_symlink():
            info = path.lstat()
            need(not path.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400, "output reparse/symlink")
    output, repo = lexical.resolve(strict=False), HERE.parents[2]
    need(not output.exists() and not output.is_relative_to(repo) and not repo.is_relative_to(output), "fresh external output")
    need(all(not output.is_relative_to(path.parent) and not path.is_relative_to(output) for path in originals),
         "output must not alter frozen input memberships")
    return output


CASES = (
    ("ordinary-byte", FIRST, "Root", "PRESERVATION:"),
    ("BL-target-plus-two", PENDSV, "Root", "RELOC:"),
    ("slot-ABS32-plus-four", RESTORE, "Root", "RELOC:"),
    ("helper-Thumb-tag-cleared", SVC, "Root", "RELOC:"),
    ("applied-REL-kind", PENDSV, "Root", "RELOC:"),
    ("applied-REL-target", PENDSV, "Root", "RELOC:"),
    ("original-BL-addend", PENDSV, "Root", "RELOC:"),
    ("original-pool-addend", SVC, "Root", "RELOC:"),
    ("root-size", FIRST, "Root", "ORIGIN:original section/offset/size"),
    ("external-pool-mapping", SVC, "Root", "(?:PRESERVATION|MAPPING|POOL):"),
    ("SVC-BX-register", SVC, "Root", "(?:PRESERVATION|DECODE):"),
    ("restore-BX-register", RESTORE, "Root", "(?:PRESERVATION|DECODE):"),
    ("PendSV-BX-register", PENDSV, "Root", "(?:PRESERVATION|DECODE):"),
    ("literal-target-plus-four", SVC, "Root", "(?:PRESERVATION|DECODE|POOL):"),
    ("callee-symbol-and-BL-swap", PENDSV, "Root", "ORIGIN:"),
    ("NOBITS-slot-over-text", RESTORE, "TwinComparison", "ELF:overlapping allocated sections"),
    ("RAM-owner-not-writable", RESTORE, "TwinComparison", "ELF:writable allocated section owner lacks PF_W"),
)


def mutation_cases(mode):
    need(type(mode) is str and mode in MODES, "ordinary mutation mode required")
    return CASES + ((
        ("first-outside-function-NOP", FIRST, "Root", "PRESERVATION:"),
        ("external-pool-alignment-byte", SVC, "Root", "PRESERVATION:"),
    ) if mode == "O0" else ())


def mutate(name, files, image, proofs, edits, patch):
    call = next(ref for ref in proofs[PENDSV]["References"] if ref["Kind"] == 10)
    slot = next(ref for ref in proofs[RESTORE]["References"] if ref["Kind"] == 2)
    helper = next(ref for ref in proofs[SVC]["References"] if ref["Kind"] == 2)
    twins = files["Final"], files["Plain"]

    def section(root):
        symbol = image.final.symbol(root, "STT_FUNC", root=True)
        return image.final.names[symbol["section"]]

    def change(root, address, raw, mnemonic, operands):
        for path in twins:
            patch._patch_vma(path, address, raw, edits)
        patch._patch_disassembly(files["Disassembly"], section(root), address, raw, mnemonic, operands)

    if name == "ordinary-byte":
        row = next(row for row in proofs[FIRST]["Instructions"] if row["Mnemonic"] == "cpsie" and row["Operands"] == "i")
        change(FIRST, proofs[FIRST]["Address"] + row["Offset"], bytes.fromhex("72b6"), "cpsid", "i")
    elif name == "BL-target-plus-two":
        target = call["ResolvedValue"] + 2
        change(PENDSV, call["Place"], patch.branch_link(call["Place"], target), "bl", "%x <%s+0x2>" % (target, CALLEE))
    elif name in ("slot-ABS32-plus-four", "helper-Thumb-tag-cleared"):
        root, ref = (RESTORE, slot) if name.startswith("slot") else (SVC, helper)
        value = ref["ResolvedValue"] + 4 if root == RESTORE else ref["ResolvedValue"] & ~1
        change(root, ref["Place"], struct.pack("<I", value), ".word", "0x%x" % value)
    elif name == "applied-REL-kind":
        patch._patch_relocation(files["Final"], call["Place"], kind=30, edits=edits)
    elif name == "applied-REL-target":
        patch._patch_relocation(files["Final"], call["Place"], symbol="xTaskIncrementTick", edits=edits)
    elif name == "original-BL-addend":
        patch._patch_prelink(files["Asm"], PENDSV, call["Offset"], patch.branch_link(0, 2), edits)
    elif name == "original-pool-addend":
        patch._patch_prelink(files["Asm"], SVC, helper["Offset"], struct.pack("<I", 4), edits)
    elif name == "root-size":
        for path in twins:
            patch._patch_symbol(path, FIRST, "size", proofs[FIRST]["Size"] - 2, edits)
    elif name == "external-pool-mapping":
        for path in twins:
            elf = patch._structured(path)
            positions = [table.header.sh_offset + index * table.header.sh_entsize + 4
                for table in elf.iter_sections() if isinstance(table, patch.reader.SymbolTableSection)
                for index, item in enumerate(table.iter_symbols())
                if re.fullmatch(r"\$d(?:\..*)?", item.name) and item.entry.st_value == helper["Place"]]
            need(positions, "one actual external pool data mapping required")
            for offset in positions:
                patch._edit(path, offset, struct.pack("<I", helper["Place"] - 2), edits)
    elif name == "first-outside-function-NOP":
        root = proofs[FIRST]
        change(FIRST, root["Address"] + root["Size"], bytes.fromhex("00bf"), "nop", "")
    elif name == "external-pool-alignment-byte":
        root = proofs[SVC]
        need(helper["Offset"] == root["Size"] + 2, "exact O0 external pool alignment")
        change(SVC, root["Address"] + root["Size"], bytes.fromhex("0100"), ".short", "0x0001")
    elif name in ("SVC-BX-register", "restore-BX-register", "PendSV-BX-register"):
        root = {"SVC-BX-register": SVC, "restore-BX-register": RESTORE, "PendSV-BX-register": PENDSV}[name]
        row = next(row for row in proofs[root]["Instructions"] if row["Mnemonic"] == "bx")
        need(row["Operands"] in ("r2", "r3"), "fixed stack/helper-derived BX required")
        change(root, proofs[root]["Address"] + row["Offset"], bytes.fromhex("2047"), "bx", "r4")
    elif name == "literal-target-plus-four":
        row = next(row for row in proofs[SVC]["Instructions"] if row["Mnemonic"] == "ldr" and "[pc," in row["Operands"])
        half = struct.unpack("<H", bytes.fromhex(row["Bytes"]))[0]
        need(half & 0xF800 == 0x4800 and half & 255 < 255, "bounded Thumb-1 literal encoding")
        raw = struct.pack("<H", half + 1)
        operands = "r%d, [pc, #%d]" % ((half >> 8) & 7, ((half & 255) + 1) * 4)
        change(SVC, proofs[SVC]["Address"] + row["Offset"], raw, "ldr", operands)
    elif name == "callee-symbol-and-BL-swap":
        other = image.final.symbol("xTaskIncrementTick", "STT_FUNC", root=True)
        original = image.final.symbol(CALLEE, "STT_FUNC", root=True)
        for path in twins:
            for field in ("value", "size"):
                if other[field] != original[field]:
                    patch._patch_symbol(path, CALLEE, field, other[field], edits)
                    patch._patch_symbol(path, "xTaskIncrementTick", field, original[field], edits)
        target = other["value"] & ~1
        change(PENDSV, call["Place"], patch.branch_link(call["Place"], target), "bl", "%x <%s>" % (target, CALLEE))
    elif name == "NOBITS-slot-over-text":
        address = proofs[FIRST]["Address"]
        for path in twins:
            elf = patch._structured(path)
            _, _, symbol = patch._symbol_field(path, SLOT, "value")
            patch._patch_symbol(path, SLOT, "value", address, edits)
            patch._edit(path, elf.header.e_shoff + symbol.st_shndx * elf.header.e_shentsize + 12,
                        struct.pack("<I", address), edits)
        for root, proof in proofs.items():
            for ref in proof["References"]:
                if ref["Kind"] == 2 and ref["Symbol"] == SLOT:
                    change(root, ref["Place"], struct.pack("<I", address), ".word", "0x%x" % address)
    elif name == "RAM-owner-not-writable":
        for path in twins:
            elf = patch._structured(path)
            matches = [(index, segment.header) for index, segment in enumerate(elf.iter_segments())
                if segment.header.p_type == "PT_LOAD" and segment.header.p_vaddr <= slot["ResolvedValue"] and
                slot["ResolvedValue"] + 4 <= segment.header.p_vaddr + segment.header.p_memsz]
            need(len(matches) == 1 and matches[0][1].p_flags & 2, "one writable slot load owner required")
            index, header = matches[0]
            patch._edit(path, elf.header.e_phoff + index * elf.header.e_phentsize + 24,
                        struct.pack("<I", header.p_flags & ~2), edits)
    else:
        raise ValueError("unknown CM0 actual ELF mutant")


def witness(args, directory, inputs, providers, reader, patch):
    report = dict(Status="FAIL", Profile=args.profile, Mode=args.mode,
        Scope="CM0_FIVE_PRELINK_BOUND_REFERENCE_FINAL_ROOTS_ONLY", RequiredCellsSatisfied=0,
        FinalParity=False, GlobalProof=False, CPUProof=False, BoardExecution=False,
        NativeCommandsExecuted=0, DynamicExceptionTargetProven=False, CSourceSemanticProof=False,
        KernelSemanticsProven=False, ArchiveExtraction=False, LTO=False,
        PrelinkProtocolProof=False, PositiveRoots=[], Mutants=[])
    originals = require_input_identity(inputs, providers)
    snapshots = {path: path.read_bytes() for path in originals}
    capture = directory / "witness-inputs"
    capture.mkdir()
    copies = {}
    for index, (path, data) in enumerate(snapshots.items()):
        target = capture / ("%02d-" % index + path.name)
        target.write_bytes(data)
        copies[path] = target
    files = {key: copies[path] for key, path in inputs.items()}
    bindings = {str(path): copies[path] for path in providers}
    report["Inputs"] = [dict(Original=str(path), Captured=str(copies[path]), Sha256=sha(data)) for path, data in snapshots.items()]
    try:
        def construct(selected, bound):
            return reader.ReferenceCM0FinalImage(selected["Port"], selected["Asm"], selected["Final"], selected["Disassembly"],
                provider_objects=bound, link_map=selected["LinkMap"], mode=args.mode)
        image = construct(files, bindings)
        report["Twins"] = reader.compare_load_images(files["Plain"], files["Final"])
        proofs = {name: image.function(name) for name in ROOTS}
        report["PositiveRoots"] = list(proofs.values())
        need(all(row["Complete"] is True and row["InstructionCount"] == len(row["Instructions"]) for row in proofs.values()) and
             sum(row["Size"] for row in proofs.values()) == selection(args.profile, args.mode) and
             sum(row["InstructionCount"] for row in proofs.values()) == (92 if args.mode == "O0" else 71) and
             sum(len(row["References"]) for row in proofs.values()) == 5, "five complete fixed roots and five unique references")
        pools = [ref for row in proofs.values() for ref in row["References"] if ref["Kind"] == 2]
        need(len(pools) == 3 and len({ref["Place"] for ref in pools}) == 3 and
             all(ref["Offset"] >= next(row["Size"] for row in proofs.values() if ref in row["References"]) for ref in pools),
             "three separately owned external pool words")
        cases = mutation_cases(args.mode)
        for name, root, expected_stage, expected in cases:
            case_directory = directory / "mutants" / name
            case_directory.mkdir(parents=True)
            case = {key: case_directory / (key + path.suffix) for key, path in files.items()}
            for key, path in files.items():
                case[key].write_bytes(path.read_bytes())
            case_bindings = {identity: case["Port"] if path == files["Port"] else case["Asm"] if path == files["Asm"] else path
                             for identity, path in bindings.items()}
            record = dict(Name=name, Root=root, Expected=expected, ExpectedStage=expected_stage, Status="FAIL",
                TwinComparisonPass=False, ReaderRejected=False, Edits=[])
            report["Mutants"].append(record)
            try:
                mutate(name, case, image, proofs, record["Edits"], patch)
                need(record["Edits"], "actual bounded edits required")
                stage = "TwinComparison"
                try:
                    reader.compare_load_images(case["Plain"], case["Final"])
                    record["TwinComparisonPass"] = True
                    stage = "FinalImage"
                    altered = construct(case, case_bindings)
                    stage = "Root"
                    altered.function(root)
                except reader.Rejected as error:
                    record.update(ReaderRejected=True, Rejection=str(error), Stage=stage)
                    if stage == expected_stage and re.search(expected, str(error)):
                        record["Status"] = "PASS"
            except Exception as error:
                record["Error"] = type(error).__name__ + ": " + str(error)
            record["Files"] = [dict(Path=str(path), Sha256=digest(path)) for path in case.values()]
        report.update(PositiveRootCount=5, RootBytes=sum(row["Size"] for row in proofs.values()),
            Instructions=sum(row["InstructionCount"] for row in proofs.values()), AppliedReferences=5,
            ExternalPoolWords=3, MutantControls=len(cases), MutantsPassed=sum(row["Status"] == "PASS" for row in report["Mutants"]))
        if report["MutantsPassed"] == len(cases):
            report["Status"] = "PASS"
    except Exception as error:
        report["Error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["InputDrift"] = [str(path) for path, data in snapshots.items() if path.read_bytes() != data]
        report["CapturedInputDrift"] = [str(path) for path, data in snapshots.items() if copies[path].read_bytes() != data]
        report["MutantFileDrift"] = [row["Path"] for case in report["Mutants"] for row in case.get("Files", []) if digest(row["Path"]) != row["Sha256"]]
        if any(report[key] for key in ("InputDrift", "CapturedInputDrift", "MutantFileDrift")):
            report["Status"] = "FAIL"
    return report


def artifact_inventory(directory):
    return {p.relative_to(directory).as_posix(): digest(p) for p in directory.rglob("*") if p.is_file() and p != directory / "artifacts.json"}


def finish(directory, report):
    def save(name, value):
        (directory / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")
    try:
        save("results.json", report)
        expected = artifact_inventory(directory)
        save("artifacts.json", dict(Artifacts=expected))
        need(artifact_inventory(directory) == expected and json.loads((directory / "artifacts.json").read_bytes()) == dict(Artifacts=expected),
             "artifact closure")
    except Exception as error:
        report.update(Status="FAIL", Error="artifact finalization: " + type(error).__name__ + ": " + str(error))
        save("results.json", report)
        save("artifacts.json", dict(Artifacts=artifact_inventory(directory)))
    return report["Status"] == "PASS"


def main(argv=None):
    need(not sys.flags.optimize, "unoptimized Python required")
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("port-object", "portasm-object", "final-elf", "plain-elf", "disassembly", "link-map", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--provider-object", action="append", required=True)
    parser.add_argument("--profile", choices=PROFILES, default="CM0")
    parser.add_argument("--mode", choices=MODES, default="O2")
    args = parser.parse_args(argv)
    selection(args.profile, args.mode)
    inputs = dict(Port=regular(args.port_object), Asm=regular(args.portasm_object), Final=regular(args.final_elf),
        Plain=regular(args.plain_elf), Disassembly=regular(args.disassembly), LinkMap=regular(args.link_map))
    providers = [regular(path) for path in args.provider_object]
    originals = require_input_identity(inputs, providers)
    directory = require_output_directory(args.output_dir, originals)
    directory.mkdir(parents=True)
    sources = (Path(__file__).resolve(), HERE / "reference_elf.py", CLASSIC / "elf.py", CLASSIC / "test_elf.py")
    hashes = {str(path): digest(path) for path in sources}
    report = dict(Status="FAIL", RequiredCellsSatisfied=0, FinalParity=False, GlobalProof=False,
        CPUProof=False, BoardExecution=False, NativeCommandsExecuted=0)
    try:
        reader = load("cm0_final_witness_reader", HERE / "reference_elf.py")
        patch = load("cm0_final_witness_mutations", CLASSIC / "test_elf.py")
        report = witness(args, directory, inputs, providers, reader, patch)
    except Exception as error:
        report["Error"] = type(error).__name__ + ": " + str(error)
    report["SourceHashes"] = hashes
    report["SourceDrift"] = [str(path) for path in sources if digest(path) != hashes[str(path)]]
    if report["SourceDrift"]:
        report["Status"] = "FAIL"
    passed = finish(directory, report)
    print(report["Status"] + " " + str(directory), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
