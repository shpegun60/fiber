"""Retained CM3 reference roots and actual private ELF mutations, never execution.

The enclosing gate authenticates producer/pin/cohort/recipe/protocol evidence.
This witness preserves independent file roles and does not supply those facts.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.abc
import importlib.util
import json
from pathlib import Path
import re
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CLASSIC = HERE.with_name("classic_final_image")
MODES = ("O0", "Og", "O2", "Os", "O3")
ROOTS = ("prvPortStartFirstTask", "vPortSVCHandler", "xPortPendSVHandler")
SUPPORT = (CLASSIC / "reference_witness.py", HERE.with_name("cm0_final_roots") / "reference_witness.py")


def need(ok, detail):
    if not ok:
        raise ValueError("cm3-final-witness: " + detail)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def digest(path):
    return sha(Path(path).read_bytes())


class FrozenSources:
    """Execute the closed local helper graph from the exact hashed buffers.

    Nested legacy spec loaders use this same buffer loader. No reader/model
    globals change, and no bytecode cache supplies local helper code.
    """
    def __init__(self, buffers):
        need(type(buffers) is dict and buffers and all(type(data) is bytes for data in buffers.values()),
             "nonempty immutable source buffers required")
        self.buffers = {Path(path).resolve(): data for path, data in buffers.items()}
        need(len(self.buffers) == len(buffers), "source identity alias")
        self.executed = []
        self.original_spec = importlib.util.spec_from_file_location

    def spec(self, name, location, *, loader=None, submodule_search_locations=None):
        path = Path(location).resolve()
        need(path in self.buffers and loader is None and submodule_search_locations is None,
             "local helper escaped authenticated source closure")
        data, owner = self.buffers[path], self
        class BufferLoader(importlib.abc.Loader):
            def create_module(self, spec):
                return None

            def exec_module(self, module):
                owner.executed.append(dict(Name=name, Path=str(path), Sha256=sha(data)))
                exec(compile(data, str(path), "exec"), module.__dict__)
        return self.original_spec(name, path, loader=BufferLoader())

    def load(self, name, path):
        spec = self.spec(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    @contextmanager
    def active(self):
        with patch("importlib.util.spec_from_file_location", side_effect=self.spec):
            yield self


def selection(profile, mode):
    need(type(profile) is str and profile == "CM3" and type(mode) is str and mode in MODES,
         "exact CM3 and five ordinary modes required")
    return (142, 42) if mode == "O0" else (136, 39)


def require_input_identity(inputs, providers):
    need(type(inputs) is dict and set(inputs) == {"Prelink", "Final", "Disassembly", "Plain", "LinkMap"},
         "exact five input roles required")
    need(type(providers) is list and len(providers) == len(set(providers)) == 4 and
         len(set(inputs.values())) == 5 and providers[0] == inputs["Prelink"],
         "four ordered providers, actual port prelink first, and distinct roles required")
    originals = list(dict.fromkeys((*inputs.values(), *providers)))
    need(len(originals) == 8, "only intended prelink/provider overlap admitted")
    for index, path in enumerate(originals):
        need(all(not path.samefile(other) for other in originals[:index]), "physical role alias forbidden")
    return originals


def scope(profile, mode):
    selection(profile, mode)
    return dict(Status="FAIL", Scope="CM3_REFERENCE_THREE_PRELINK_BOUND_FINAL_ROOTS_ONLY",
        Profile=profile, Mode=mode, RequiredCellsSatisfied=0, FinalParity=False, GlobalProof=False,
        CPUProof=False, BoardExecution=False, NativeCommandsExecuted=0, PositiveRoots=[], Mutants=[])


def witness(args, directory, reader, core, patch, mutations, paths):
    expected_size, expected_instructions = selection(args.profile, args.mode)
    report = scope(args.profile, args.mode)
    inputs = {name: paths.regular(value) for name, value in dict(
        Prelink=args.prelink_object, Final=args.final_elf, Disassembly=args.disassembly,
        Plain=args.plain_elf, LinkMap=args.link_map).items()}
    providers = [paths.regular(value) for value in args.provider_object]
    originals = require_input_identity(inputs, providers)
    snapshots = {path: path.read_bytes() for path in originals}
    capture = directory / "witness-inputs"
    capture.mkdir()
    copies = {}
    for index, (path, data) in enumerate(snapshots.items()):
        copy = capture / ("%02d-" % index + path.name)
        copy.write_bytes(data)
        copies[path] = copy
    report["Inputs"] = [dict(Original=str(path), Captured=str(copies[path]), Sha256=sha(data))
                        for path, data in snapshots.items()]
    files = {key: copies[path] for key, path in inputs.items()}
    bindings = {str(path): copies[path] for path in providers}
    try:
        def construct(selected, bound):
            return reader.ReferenceCM3FinalImage(selected["Prelink"], selected["Final"], selected["Disassembly"],
                provider_objects=bound, link_map=selected["LinkMap"], mode=args.mode)
        image = construct(files, bindings)
        report["Twins"] = core.compare_load_images(files["Plain"], files["Final"])
        need(report["Twins"]["Identical"] is True, "identical original twins required")
        proofs = {name: image.function(name) for name in ROOTS}
        report["PositiveRoots"] = list(proofs.values())
        need(sum(row["Size"] for row in proofs.values()) == expected_size and
             sum(row["InstructionCount"] for row in proofs.values()) == expected_instructions and
             sum(len(row["References"]) for row in proofs.values()) == 3, "exact fixed CM3 final roots")
        cases = mutations.CASES
        need(len(cases) == 13 and len({row[0] for row in cases}) == 13 and
             all(row[1] in ROOTS for row in cases), "fixed thirteen applicable mutation classes")
        for name, root, expected_stage, expected in cases:
            case_directory = directory / "mutants" / name
            case_directory.mkdir(parents=True)
            case = {key: case_directory / (key + path.suffix) for key, path in files.items()}
            for key, path in files.items():
                case[key].write_bytes(path.read_bytes())
            bound = {identity: case["Prelink"] if path == files["Prelink"] else path
                     for identity, path in bindings.items()}
            record = dict(Name=name, Root=root, Expected=expected, ExpectedStage=expected_stage,
                Status="FAIL", TwinComparisonPass=False, ReaderRejected=False, Edits=[])
            report["Mutants"].append(record)
            try:
                mutations.mutate(name, case, image, proofs, record["Edits"], patch)
                need(record["Edits"], "actual bounded ELF edits required")
                stage = "TwinComparison"
                try:
                    twins = core.compare_load_images(case["Plain"], case["Final"])
                    need(twins["Identical"] is True, "identical mutant twins required")
                    record["TwinComparisonPass"] = True
                    stage = "FinalImage"
                    altered = construct(case, bound)
                    stage = "Root"
                    altered.function(root)
                except core.Rejected as error:
                    record.update(ReaderRejected=True, Rejection=str(error), Stage=stage)
                    if stage == expected_stage and re.search(expected, str(error)):
                        record["Status"] = "PASS"
            except Exception as error:
                record["Error"] = type(error).__name__ + ": " + str(error)
            record["Files"] = [dict(Path=str(path), Sha256=digest(path)) for path in case.values()]
        report.update(PositiveRootCount=len(proofs), RootBytes=sum(row["Size"] for row in proofs.values()),
            Instructions=sum(row["InstructionCount"] for row in proofs.values()),
            AppliedReferences=sum(len(row["References"]) for row in proofs.values()),
            MutantControls=len(cases), MutantsPassed=sum(row["Status"] == "PASS" for row in report["Mutants"]))
        if report["MutantsPassed"] == len(cases):
            report["Status"] = "PASS"
    except Exception as error:
        report["Error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["InputDrift"] = [str(path) for path, data in snapshots.items() if path.read_bytes() != data]
        report["CapturedInputDrift"] = [str(path) for path, data in snapshots.items() if copies[path].read_bytes() != data]
        report["MutantFileDrift"] = [row["Path"] for case in report["Mutants"] for row in case.get("Files", [])
                                    if digest(row["Path"]) != row["Sha256"]]
        if any(report[key] for key in ("InputDrift", "CapturedInputDrift", "MutantFileDrift")):
            report["Status"] = "FAIL"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("prelink-object", "final-elf", "disassembly", "plain-elf", "link-map", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--provider-object", action="append", required=True)
    parser.add_argument("--profile", choices=("CM3",), default="CM3")
    parser.add_argument("--mode", choices=MODES, default="O2")
    args = parser.parse_args(argv)
    need(not sys.flags.optimize, "unoptimized Python required")
    selection(args.profile, args.mode)
    sources = (Path(__file__), HERE / "reference_elf.py", CLASSIC / "reference_elf.py",
               CLASSIC / "elf.py", CLASSIC / "test_elf.py", *SUPPORT)
    buffers = {path: path.read_bytes() for path in sources}
    hashes = {str(path): sha(data) for path, data in buffers.items()}
    frozen = FrozenSources(buffers)
    with frozen.active():
        paths = frozen.load("cm3_witness_paths", SUPPORT[1])
        inputs = {name: paths.regular(value) for name, value in dict(
            Prelink=args.prelink_object, Final=args.final_elf, Disassembly=args.disassembly,
            Plain=args.plain_elf, LinkMap=args.link_map).items()}
        providers = [paths.regular(value) for value in args.provider_object]
        originals = require_input_identity(inputs, providers)
        directory = paths.require_output_directory(args.output_dir, originals)
        directory.mkdir(parents=True)
        report = scope(args.profile, args.mode)
        try:
            reader = frozen.load("cm3_reference_witness_reader", HERE / "reference_elf.py")
            patcher = frozen.load("cm3_reference_witness_patch", CLASSIC / "test_elf.py")
            mutations = frozen.load("cm3_reference_witness_mutations", SUPPORT[0])
            report = witness(args, directory, reader, reader.core, patcher, mutations, paths)
        except Exception as error:
            report["Error"] = type(error).__name__ + ": " + str(error)
    report["SourceHashes"] = hashes
    report["ExecutedSourceBuffers"] = frozen.executed
    report["SourceDrift"] = [str(path) for path in sources if digest(path) != hashes[str(path)]]
    if report["SourceDrift"]:
        report["Status"] = "FAIL"
    (directory / "results.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(report["Status"], str(directory / "results.json"))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
