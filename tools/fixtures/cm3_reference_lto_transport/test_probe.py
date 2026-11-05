"""Pure reference CM3 LTO probe controls; no tools or actual build claims."""
import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PROBE = HERE / "probe.py"
COMMON = HERE.with_name("cm3_lto_transport") / "probe.py"
PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
NAMES = ("prvPortStartFirstTask", "vPortSVCHandler", "xPortPendSVHandler", "pxCurrentTCB",
         "vTaskSwitchContext", "xTaskIncrementTick", "reference_fail_stop")
FALSE_FLAGS = ("NativeBuilt", "ReferenceKernelAvailable", "SchedulerSemanticsProven", "CSourceSemanticProof",
    "HandlerRoutingProven", "CanonicalProtocolValidated", "FinalRootRelocationProof", "FinalReferenceParity",
    "CompleteObjectProof", "SourceToMachineSemanticProof", "OrdinaryOwnerContractSatisfied", "PolicyEquivalence",
    "ArchiveExtraction", "CpuExecution", "BoardExecution", "RequiredCellSatisfied", "GlobalFreezeQualified")
BUFFERS = {}
p = common = None
ATTEMPTS = []


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def forbidden(*args, **kwargs):
    ATTEMPTS.append("process/tool invocation")
    raise AssertionError("pure controls cannot invoke processes or tools")


def setUpModule():
    global p, common
    if not BUFFERS:
        BUFFERS.update({path: path.read_bytes() for path in (Path(__file__).resolve(), PROBE, COMMON)})

    def load(name, path):
        module = ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        exec(compile(BUFFERS[path], str(path), "exec"), module.__dict__)
        return module

    with patch("subprocess.Popen", side_effect=forbidden):
        common = load("reference_lto_pure_common", COMMON)
        p = load("reference_lto_pure_subject", PROBE)


class PureCase(unittest.TestCase):
    def setUp(self):
        for target in (patch("subprocess.Popen", side_effect=forbidden),
                       patch.object(common.Probe, "command", side_effect=forbidden)):
            target.start()
            self.addCleanup(target.stop)

    def nonclaims(self, row):
        for key in FALSE_FLAGS:
            with self.subTest(nonclaim=key):
                self.assertIs(row[key], False)
        self.assertIs(type(row["RequiredCellsSatisfied"]), int)
        self.assertEqual(row["RequiredCellsSatisfied"], 0)


class ScopeTests(PureCase):
    def test_fixed_reference_scope_and_pin(self):
        row = p.scope_report(common)
        self.assertEqual((row["Status"], row["Profile"], row["Mode"], row["Linkage"]),
                         ("FAIL", "CM3", "O2-lto", "direct"))
        self.assertEqual(row["Scope"], "PINNED_REFERENCE_CM3_O2_LTO_CAPTURE_FEASIBILITY_ONLY")
        self.assertEqual(row["ReferenceCommit"], PIN)
        self.assertIs(row["LTO"], True)
        self.assertIs(row["ReferenceBuilt"], False)
        self.nonclaims(row)

    def test_initial_counters_are_literal_zero_and_containers_are_fresh(self):
        first, second = p.scope_report(common), p.scope_report(common)
        for name in ("TranslationUnits", "SlimIRObjects", "FinalExecutableLinks", "SavedMachineObjects"):
            self.assertIs(type(first[name]), int)
            self.assertEqual(first[name], 0)
        for name in ("Commands", "Sources", "Links"):
            first[name].append({"synthetic": True})
            self.assertEqual(second[name], [])

    def test_shared_plumbing_is_the_declared_captured_source(self):
        self.assertEqual(p.COMMON.resolve(), COMMON.resolve())
        self.assertEqual(p.COMMON_SHA, sha(BUFFERS[COMMON]))


def symbol_fixture():
    sections = [dict(Index=1, Name=".text"), dict(Index=2, Name=".bss")]
    rows, expected = [], []
    for index, name in enumerate(NAMES):
        slot = name == "pxCurrentTCB"
        kind, binding = ("OBJECT", "GLOBAL") if slot else ("FUNC", "LOCAL" if index == 0 else "GLOBAL")
        value, size, section = index * 32, 4 if slot else 16 + index * 2, 2 if slot else 1
        size_text = hex(size) if index % 2 else str(size)
        rows.append(" %d: %08x %s %s %s DEFAULT %d %s" %
                    (index + 1, value, size_text, kind, binding, section, name))
        expected.append(dict(Name=name, Value=value, Size=size, Type=kind, Binding=binding,
            Visibility="DEFAULT", Section=section, SectionName=".bss" if slot else ".text", SymbolOriginBound=False))
    return rows, sections, expected


class SymbolTests(PureCase):
    def test_exact_seven_facts_preserve_static_and_global_metadata(self):
        rows, sections, expected = symbol_fixture()
        self.assertEqual(tuple(p.NAMES), NAMES)
        self.assertEqual(p.symbol_records("\n".join(reversed(rows)), sections), expected)

    def test_localized_or_weak_binding_is_captured_not_normalized(self):
        rows, sections, expected = symbol_fixture()
        rows[3] = rows[3].replace("GLOBAL", "LOCAL")
        expected[3]["Binding"] = "LOCAL"
        rows[6] = rows[6].replace("GLOBAL DEFAULT", "WEAK HIDDEN")
        expected[6].update(Binding="WEAK", Visibility="HIDDEN")
        self.assertEqual(p.symbol_records("\n".join(rows), sections), expected)

    def test_missing_or_duplicate_fixed_fact_rejects(self):
        rows, sections, _ = symbol_fixture()
        for index in range(7):
            for text in (rows[:index] + rows[index + 1:], rows + [rows[index]]):
                with self.subTest(index=index, duplicate=len(text) == 8), \
                        self.assertRaisesRegex(ValueError, "exactly one actual symbol fact"):
                    p.symbol_records("\n".join(text), sections)

    def test_malformed_readelf_shape_cannot_supply_a_required_fact(self):
        rows, sections, _ = symbol_fixture()
        for bad in (rows[0].replace("1:", "1"), rows[0] + " extra", rows[0].replace("00000000", "NOTHEX"),
                    rows[0].replace("16 FUNC", "bad FUNC"), rows[0].replace(" LOCAL", ""), ""):
            with self.subTest(line=bad), self.assertRaisesRegex(ValueError, "exactly one actual symbol fact"):
                p.symbol_records("\n".join([bad, *rows[1:]]), sections)

    def test_readelf_headers_and_unrelated_symbols_do_not_supply_facts(self):
        rows, sections, expected = symbol_fixture()
        text = "Symbol table '.symtab' contains 20 entries:\n Num: Value Size Type Bind Vis Ndx Name\n"
        text += " 90: 00000010 4 OBJECT GLOBAL DEFAULT 2 unrelated\n" + "\n".join(rows)
        self.assertEqual(p.symbol_records(text, sections), expected)
        with self.assertRaisesRegex(ValueError, "exactly one actual symbol fact"):
            p.symbol_records(text.split(rows[0])[0], sections)


def args():
    return SimpleNamespace(reference_build="synthetic-reference-seed", reference_receipt_sha256="A" * 64,
                           reference_artifacts_sha256="B" * 64, output_dir="synthetic-output")


def bare_probe():
    output = Path(tempfile.gettempdir()).resolve() / "reference-lto-pure-memory-only" / "output"
    seed = SimpleNamespace(output=output, closure=common.Closure())
    return p.probe_type(common)(seed, args())


class ConstructorAndObjectsTests(PureCase):
    def test_reference_arguments_only_gain_internal_receipt_aliases(self):
        supplied = args()
        before = vars(supplied).copy()
        probe = p.probe_type(common)(SimpleNamespace(output=Path("not-created")), supplied)
        self.assertEqual(vars(supplied), before)
        self.assertEqual(vars(probe.args), dict(before, native_receipt_sha256="A" * 64,
                                               native_artifacts_sha256="B" * 64))
        self.assertFalse(hasattr(probe.args, "native_build"))
        self.assertFalse(probe.complete)
        self.assertFalse(probe.twins_verified)
        self.nonclaims(probe.report)
        self.assertEqual(probe.report["Scope"], "PINNED_REFERENCE_CM3_O2_LTO_CAPTURE_FEASIBILITY_ONLY")

    def test_four_exact_object_hashes_pass_and_record_stage(self):
        probe, data = complete_fixture()
        with memory_io(probe, data):
            probe.verify_objects("synthetic-stage")
        self.assertEqual(probe.report["ObjectChecks"], [dict(Stage="synthetic-stage", Status="PASS")])

    def test_each_changed_or_missing_object_rejects(self):
        for index in range(4):
            for delete in (False, True):
                probe, data = complete_fixture()
                if delete:
                    del data[probe.objects[index]]
                else:
                    data[probe.objects[index]] += b"changed"
                with self.subTest(index=index, delete=delete), memory_io(probe, data), \
                        self.assertRaises((ValueError, FileNotFoundError)):
                    probe.verify_objects("mutation")

    def test_partial_extra_or_duplicate_object_membership_rejects(self):
        for change in ("partial", "extra", "duplicate"):
            probe, data = complete_fixture()
            if change == "partial":
                probe.objects.pop()
            elif change == "extra":
                probe.object_hashes[probe.output / "foreign.o"] = "C" * 64
            else:
                probe.objects[3] = probe.objects[0]
                del probe.object_hashes[probe.output / "objects/3.o"]
            with self.subTest(change=change), memory_io(probe, data), self.assertRaises(ValueError):
                probe.verify_objects("membership")


def complete_fixture():
    """In-memory orchestration only: these bytes are intentionally not ELF/IR."""
    probe, data = bare_probe(), {}
    for index in range(4):
        original = probe.output.parent / "originals" / ("%d.txt" % index)
        captured, obj = probe.output / "input-bytes" / original.name, probe.output / "objects" / ("%d.o" % index)
        data[original] = data[captured] = ("synthetic source %d" % index).encode("ascii")
        data[obj] = ("synthetic non-ELF object %d" % index).encode("ascii")
        probe.seed.closure.hashes[original] = sha(data[original])
        probe.inputs.append(dict(Original=str(original), Captured=str(captured), Sha256=sha(data[original])))
        probe.objects.append(obj)
        probe.object_hashes[obj] = sha(data[obj])
        probe.report["Sources"].append(dict(Source=str(original), Object=str(obj), SlimIR=index != 3))
    for kind in ("ordinary", "emit-relocs"):
        image = probe.output / kind / "image.elf"
        data[image] = b"synthetic final, not ELF"
        probe.report["Links"].append(dict(Kind=kind, Path=str(image), Sha256=sha(data[image])))
    probe.report["Commands"] = [dict(Label="synthetic-not-executed", Status="PASS")]
    twins = dict(Identical=True, Synthetic=True)
    twin_path = probe.output / "load-image.json"
    data[twin_path] = (json.dumps(twins, sort_keys=True) + "\n").encode("ascii")
    probe.seed.closure.hashes[twin_path] = sha(data[twin_path])
    probe.report.update(TranslationUnits=4, SlimIRObjects=3, SavedMachineObjects=2, FinalExecutableLinks=2,
        ReferenceBuilt=True, TwinLoadImageCompared=True, TwinLoadImages=twins,
        TwinLoadImagesPath=str(twin_path), TwinLoadImagesSha256=sha(data[twin_path]))
    probe.complete = probe.twins_verified = True
    return probe, data


def memory_io(probe, data, *, on_save=None, on_close=None):
    stack, writes = ExitStack(), {}
    real_close = probe.seed.closure.close
    close_count = 0

    def regular(path):
        path = Path(path)
        if path not in data:
            raise FileNotFoundError(str(path))
        return path

    def save(path, value):
        path = Path(path)
        writes[path] = writes.get(path, 0) + 1
        if on_save:
            on_save("before", path, writes[path], data)
        data[path] = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("ascii")
        if on_save:
            on_save("after", path, writes[path], data)

    def close():
        nonlocal close_count
        close_count += 1
        if on_close:
            on_close(close_count, data)
        real_close()

    stack.enter_context(patch.object(common, "regular", side_effect=regular))
    stack.enter_context(patch.object(common, "files_under", side_effect=lambda root: {
        path.relative_to(root).as_posix(): path for path in data if path.is_relative_to(root)}))
    stack.enter_context(patch.object(common, "save", side_effect=save))
    stack.enter_context(patch.object(Path, "read_bytes", lambda path: data[regular(path)]))
    stack.enter_context(patch.object(probe.seed.closure, "close", side_effect=close))
    return stack


class FinishTests(PureCase):
    def finish(self, probe, data, **kwargs):
        error = kwargs.pop("error", None)
        with memory_io(probe, data, **kwargs):
            return probe.finish(error)

    def receipt(self, probe, data, status, sealed=True):
        row = json.loads(data[probe.output / "results.json"])
        self.assertEqual(row["Status"], status)
        self.assertIs(row["OutputSealVerified"], sealed)
        self.nonclaims(row)
        if sealed:
            actual = {path.relative_to(probe.output).as_posix(): sha(value) for path, value in data.items()
                      if path.is_relative_to(probe.output) and path.name != "artifacts.json"}
            self.assertEqual(json.loads(data[probe.output / "artifacts.json"]), dict(Artifacts=actual))
        return row

    def test_complete_synthetic_envelope_seals_without_root_or_kernel_credit(self):
        probe, data = complete_fixture()
        self.assertIs(self.finish(probe, data), True)
        row = self.receipt(probe, data, "PASS")
        self.assertIs(row["InputClosureVerified"], True)
        self.assertIs(row["ReferenceBuilt"], True)
        self.assertEqual(row["ClosingFilesVerified"], 5)

    def test_unbuilt_or_explicit_build_error_never_promotes(self):
        probe, data = complete_fixture()
        self.assertIs(self.finish(probe, data, error=RuntimeError("synthetic build error")), False)
        self.assertIn("synthetic build error", self.receipt(probe, data, "FAIL")["Error"])
        probe, data = bare_probe(), {}
        self.assertIs(self.finish(probe, data), False)
        self.receipt(probe, data, "FAIL")

    def test_required_counts_and_private_completion_reject_mutations(self):
        for change in ("sources", "links", "slim", "machines", "finals", "translation-units", "complete", "built"):
            probe, data = complete_fixture()
            if change in ("sources", "links"):
                probe.report[change.title()].pop()
            elif change == "complete":
                probe.complete = False
            elif change == "built":
                probe.report["ReferenceBuilt"] = False
            else:
                key = dict(slim="SlimIRObjects", machines="SavedMachineObjects", finals="FinalExecutableLinks",
                           **{"translation-units": "TranslationUnits"})[change]
                probe.report[key] -= 1
            with self.subTest(change=change):
                self.assertIs(self.finish(probe, data), False)
                self.receipt(probe, data, "FAIL")

    def test_empty_nonlist_or_failed_commands_cannot_promote(self):
        for commands in ([], (), None, [dict(Status="FAIL")], [dict(Status="ATTEMPT")]):
            probe, data = complete_fixture()
            probe.report["Commands"] = commands
            with self.subTest(commands=commands):
                self.assertIs(self.finish(probe, data), False)
                self.receipt(probe, data, "FAIL")

    def test_literal_twin_success_and_private_marker_are_required(self):
        for change in ("marker", "flag", "flag-alias", "empty", "different", "identical-alias"):
            probe, data = complete_fixture()
            if change == "marker":
                probe.twins_verified = False
            elif change.startswith("flag"):
                probe.report["TwinLoadImageCompared"] = 1 if change == "flag-alias" else False
            else:
                value = {} if change == "empty" else dict(Identical=1 if change == "identical-alias" else False)
                probe.report["TwinLoadImages"] = value
                path = probe.output / "load-image.json"
                data[path] = json.dumps(value).encode("ascii")
                probe.seed.closure.hashes[path] = probe.report["TwinLoadImagesSha256"] = sha(data[path])
            with self.subTest(change=change):
                self.assertIs(self.finish(probe, data), False)
                self.receipt(probe, data, "FAIL")

    def test_changed_or_missing_saved_twins_fail_before_seal(self):
        for delete in (False, True):
            probe, data = complete_fixture()
            path = probe.output / "load-image.json"
            if delete:
                del data[path]
            else:
                data[path] += b"changed"
            with self.subTest(delete=delete):
                self.assertIs(self.finish(probe, data), False)
                self.receipt(probe, data, "FAIL")

    def test_preexisting_or_late_input_drift_forces_failure(self):
        for late in (False, True):
            probe, data = complete_fixture()
            original = Path(probe.inputs[0]["Original"])
            if not late:
                data[original] += b"changed"

            def mutate(count, values):
                if late and count == 2:
                    values[original] += b"late change"

            with self.subTest(late=late):
                self.assertIs(self.finish(probe, data, on_close=mutate), False)
                self.receipt(probe, data, "FAIL")

    def test_late_artifact_addition_change_or_deletion_refreshes_fail_manifest(self):
        for change in ("add", "change", "delete"):
            probe, data = complete_fixture()
            target = Path(probe.report["Links"][0]["Path"])

            def mutate(count, values):
                if count == 2:
                    if change == "add":
                        values[probe.output / "late.extra"] = b"late"
                    elif change == "change":
                        values[target] += b"changed"
                    else:
                        del values[target]

            with self.subTest(change=change):
                self.assertIs(self.finish(probe, data, on_close=mutate), False)
                row = self.receipt(probe, data, "FAIL")
                self.assertIn("sealing:", row["Error"])

    def test_manifest_write_failure_forces_saved_failure(self):
        for permanent in (False, True):
            probe, data = complete_fixture()

            def fail(phase, path, attempt, values):
                if phase == "before" and path == probe.output / "artifacts.json" and (permanent or attempt == 1):
                    raise OSError("synthetic manifest failure")

            with self.subTest(permanent=permanent):
                self.assertIs(self.finish(probe, data, on_save=fail), False)
                self.receipt(probe, data, "FAIL", sealed=not permanent)

    def test_late_raw_manifest_change_forces_failure(self):
        probe, data = complete_fixture()

        def mutate(count, values):
            if count == 2:
                values[probe.output / "artifacts.json"] += b" \n"

        self.assertIs(self.finish(probe, data, on_close=mutate), False)
        self.receipt(probe, data, "FAIL")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve(strict=False)
    if output.exists() or output.is_relative_to(REPO) or REPO.is_relative_to(output):
        parser.error("fresh external output directory required")
    protected = {"cm33f_secure_transfer_reference", "m55_secure_closed_parity",
                 "test_cm33f_secure_transfer_reference.ps1", "test_m55_secure_closed_parity.ps1"}
    if protected.intersection(part.lower() for part in output.parts):
        parser.error("protected output forbidden")
    for ancestor in (args.output_dir.absolute(), *args.output_dir.absolute().parents):
        if ancestor.is_symlink() or (ancestor.exists() and getattr(ancestor.lstat(), "st_file_attributes", 0) & 0x400):
            parser.error("reparse/symlink output forbidden")
    report = dict(Status="FAIL", Tests=0, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        Scope="PURE_REFERENCE_CM3_LTO_PROBE_CONTROLS_ONLY", ToolInvocations=0, ActualLTOTested=False,
        FinalRootRelocationProof=False, FullABIProven=False, NativeReferenceJoin=False, CpuExecution=False,
        BoardExecution=False, GlobalFreezeQualified=False, RequiredCellsSatisfied=0, Error=None)
    paths = (Path(__file__).resolve(), PROBE, COMMON)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("unoptimized Python required")
        BUFFERS.update({path: path.read_bytes() for path in paths})
        report["SourceHashes"] = {str(path): sha(data) for path, data in BUFFERS.items()}
        with patch("subprocess.Popen", side_effect=forbidden):
            suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
            count = suite.countTestCases()
            if count == 0:
                raise ValueError("nonempty pure controls required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == count and not result.skipped and not ATTEMPTS:
            report["Status"] = "PASS"
    except BaseException:
        report.update(Status="FAIL", Errors=report["Errors"] + 1, Error=traceback.format_exc())
    report["SourceDrift"] = [str(path) for path in paths
        if path not in BUFFERS or not path.is_file() or sha(path.read_bytes()) != sha(BUFFERS[path])]
    report["ToolInvocations"] = len(ATTEMPTS)
    if report["SourceDrift"] or ATTEMPTS:
        report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / "results.json"
    with receipt.open("x", encoding="ascii") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print("Receipt:", receipt, sha(receipt.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
