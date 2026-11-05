"""Pure synthetic cohort recorder controls; fake tools never start processes."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SOURCE = HERE / "probe.py"
IDENTITY = HERE / "identity.py"
ENGINE = HERE.with_name("cm3_lto_link_controls") / "probe.py"
EXPECTED_METHODS = 14
p = None
i = None
PRIVATE16 = ("fiber_port_context_cohort_armv7m_p0x434D3033u_l0x00010001u_"
    "f0_e0_h1_j1_v1_d0_r0_z8u_y0_w2_g4_u00010000_i0_"
    "o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0")
PRIVATE32 = PRIVATE16.replace("_u00010000_", "_u00100000_")
STORAGE = "fiber_port_storage_cohort_arm_cm3_v1_r0"
FUNCTIONS = ("fiber_port_init_context_frame", "fiber_port_panic_wait",
    "fiber_port_require_scheduler_configuration_environment", "fiber_port_runtime_memory_barrier",
    "fiber_port_runtime_prepare_start", "fiber_port_runtime_schedule", "fiber_port_runtime_select_first",
    "fiber_port_runtime_start_first", "fiber_port_scheduler_pick_first_from_start",
    "fiber_port_scheduler_pick_next_from_pendsv", "fiber_port_start_first_context", "PendSV_Handler", "SVC_Handler")


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def same(actual, expected, label):
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError("synthetic mismatch: " + label)


def save(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True) + "\n", encoding="ascii")


def files_under(root):
    return {path.relative_to(root).as_posix(): path for path in root.rglob("*") if path.is_file()}


class Watch:
    def __init__(self):
        self.hashes = {}

    def read(self, path, expected=None):
        path = Path(path)
        data = path.read_bytes()
        value = sha(data)
        if expected is not None and value != expected:
            raise ValueError("synthetic expected hash mismatch")
        if path in self.hashes and self.hashes[path] != value:
            raise ValueError("synthetic watched bytes changed")
        self.hashes[path] = value
        return data

    def structured(self, path, expected=None):
        return json.loads(self.read(path, expected))


class FakeTools:
    def __init__(self, fixture):
        self.fixture = fixture
        self.report = dict(Commands=[])
        self.tools = dict(gcc="synthetic-gcc-never-executed")
        self.exit = 0
        self.timed_out = False
        self.error = None
        self.stderr = b""
        self.skip_stream = None
        self.mutate_raw = None
        self.create_output = False

    def command(self, argv, label, *, cwd=None):
        index = len(self.report["Commands"])
        record = dict(Label=label, Argv=[str(arg) for arg in argv], Cwd=str(cwd or self.fixture.output),
                      Status="FAIL" if self.error is not None else "PASS", Exit=self.exit,
                      TimedOut=self.timed_out, Seconds=0.0, Error=str(self.error) if self.error else None)
        self.report["Commands"].append(record)
        path = self.fixture.output / ("command-%04d.json" % index)
        raw = copy.deepcopy(record)
        if self.mutate_raw:
            self.mutate_raw(raw)
        save(path, raw)
        for suffix, data in ((".stdout", b""), (".stderr", self.stderr)):
            if suffix != self.skip_stream:
                path.with_suffix(suffix).write_bytes(data)
        if self.create_output:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"synthetic stale final; not an ELF")
        if self.error is not None:
            raise self.error
        return record


def recorder(root):
    probe = p.Probe.__new__(p.Probe)
    probe.output = root
    probe.sha = sha
    probe.watch = Watch()
    probe.report = dict(Status="FAIL", Commands=[], NegativeControls=[])
    probe.api = SimpleNamespace(save=save, same=same, unique_object=dict, files_under=files_under)
    probe.admission = SimpleNamespace(identities={}, close=Mock(),
        identity=lambda path: (Path(path).stat().st_ino, Path(path).stat().st_size))
    probe.tools = FakeTools(probe)
    return probe


def negative_recorder(root):
    probe = recorder(root)
    original = [root / "original" / ("%02d.o" % index) for index in range(9)]
    changed = list(original)
    for index in (3, 4, 5, 6):
        changed[index] = root / "variant32" / ("%02d.o" % index)
    probe.variants = {16: original, 32: changed}
    probe.identities = dict(Private16=PRIVATE16, Private32=PRIVATE32)
    probe.identity = i
    probe.script = root / "synthetic-link.ld"
    probe.api.TARGET_FLAGS = ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft"]
    def link_flags(artifact, objects, script, image, link_map, emit):
        return [*artifact["compile_flags"], "-O2", "-flto", "-flto-partition=one", "-save-temps=obj", "-v",
                "-Wl,--gc-sections,--no-undefined,--build-id=none", "-T" + str(script),
                *map(str, objects), "-o", str(image)] + (["-Wl,--emit-relocs"] if emit else [])
    probe.api.link_flags = link_flags
    return probe


def expected_link_failure(probe, threshold, role, private):
    foreign = 32 if threshold == 16 else 16
    label = "link intended cohort mismatch base%d-swap-%s-to%d" % (threshold, role, foreign)
    probe.tools.exit = 1
    probe.tools.stderr = diagnostic(private).encode("ascii")
    probe.tools.error = ValueError("cm3-lto-probe: command failed/timeout: " + label)


def nm_rows(private):
    return ([private + " D 0"] + [name + " T 0" for name in FUNCTIONS[:-2]]
            + [STORAGE + " D 0"] + [name + " T 0" for name in FUNCTIONS[-2:]])


def nm_text(private):
    return "\n".join(nm_rows(private)) + "\n"


def diagnostic(private):
    return ("C:/synthetic/ld.exe: fake.ltrans.o: in function `caller':\n"
            "C:/synthetic/ld.exe: (.text+0x4): undefined reference to `" + private + "'\n"
            "C:/synthetic/ld.exe: (.text+0xc): undefined reference to `" + private + "'\n"
            "C:/synthetic/collect2.exe: error: ld returned 1 exit status\n")


class IdentityTests(unittest.TestCase):
    def reject_pair(self, first, second):
        with self.assertRaisesRegex(ValueError, r"^cm3-lto-cohort-identity: "):
            i.cohort_pair(first, second)

    def reject_diagnostic(self, text, expected=PRIVATE16):
        with self.assertRaisesRegex(ValueError, r"^cm3-lto-cohort-identity: "):
            i.require_mismatch(text, expected)

    def test_exact_pair_fifteen_rows_and_typed_nonclaims(self):
        result = i.cohort_pair(nm_text(PRIVATE16), nm_text(PRIVATE32))
        self.assertEqual((result["Private16"], result["Private32"], result["Storage"]), (PRIVATE16, PRIVATE32, STORAGE))
        self.assertEqual(len(result["Rows16"]), 15)
        self.assertEqual(len(result["Rows32"]), 15)
        self.assertEqual(result["Rows16"][1:], result["Rows32"][1:])
        self.assertEqual([row["Name"] for row in result["Rows16"]],
                         [PRIVATE16, *FUNCTIONS[:-2], STORAGE, *FUNCTIONS[-2:]])
        self.assertIs(result["PolicyDifferenceOnly"], True)
        for key in ("StorageIdentityChanged", "ELFValidated", "FullABIProof", "SourceToMachineSemanticProof",
                    "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
            self.assertIs(result[key], False)
        self.assertIs(type(result["RequiredCellsSatisfied"]), int)
        self.assertEqual(result["RequiredCellsSatisfied"], 0)
        for row in result["Rows16"] + result["Rows32"]:
            self.assertIs(type(row["PluginValue"]), int)
            self.assertEqual(row["PluginValue"], 0)

    def test_row_membership_duplicates_and_order_are_exact(self):
        rows = nm_rows(PRIVATE32)
        variants = (rows[:-1], rows + ["unexpected T 0"], rows + [rows[0]], [rows[1], rows[0], *rows[2:]],
                    [*rows[:-2], rows[-1], rows[-2]])
        for changed in variants:
            with self.subTest(rows=changed):
                self.reject_pair(nm_text(PRIVATE16), "\n".join(changed) + "\n")

    def test_other_definitions_and_storage_cannot_change(self):
        text = nm_text(PRIVATE32)
        for old, new in ((FUNCTIONS[0], "foreign_init"), (" T 0", " D 0"),
                         (" T 0", " T 1"), (STORAGE, "fiber_port_storage_cohort_arm_cm3_v2_r0")):
            with self.subTest(old=old, new=new):
                self.reject_pair(nm_text(PRIVATE16), text.replace(old, new, 1))
        self.reject_pair(nm_text(PRIVATE16).replace(" T 0", " D 0", 1), text.replace(" T 0", " D 0", 1))

    def test_only_fixed_sixteen_then_thirtytwo_private_pair(self):
        for first, second in ((PRIVATE32, PRIVATE16), (PRIVATE16, PRIVATE16), (PRIVATE32, PRIVATE32),
                              (PRIVATE16, PRIVATE32.replace("_g4_", "_g3_")),
                              (PRIVATE16, PRIVATE32.replace("_u00100000_", "_u00110000_"))):
            with self.subTest(first=first, second=second):
                self.reject_pair(nm_text(first), nm_text(second))

    def test_nm_literal_text_and_complete_plugin_grammar(self):
        for value in (None, True, False, 16, 32.0, [], {}, b"not text", "", "\x00", "\u00e9"):
            with self.subTest(value=value):
                self.reject_pair(value, nm_text(PRIVATE32))
                self.reject_pair(nm_text(PRIVATE16), value)
        text = nm_text(PRIVATE16)
        for old, new in ((" D 0", " R 0"), (" D 0", " D 0 1"), (" D 0", " D 00"),
                         (" D 0", " D 0.0"), (" D 0", " D False"), (" D 0", "  D 0")):
            with self.subTest(row=new):
                self.reject_pair(text.replace(old, new, 1), nm_text(PRIVATE32))

    def test_intended_diagnostic_complete_rows_and_bounded_nonclaims(self):
        for private in (PRIVATE16, PRIVATE32):
            result = i.require_mismatch(diagnostic(private), private)
            self.assertEqual(result["MissingSymbols"], [private])
            for key, value in (("ReferenceCount", 2), ("FunctionHeaders", 1), ("LinkerExitRecords", 1),
                               ("RequiredCellsSatisfied", 0)):
                self.assertIs(type(result[key]), int)
                self.assertEqual(result[key], value)
            self.assertIs(result["IntendedPrivateCohortMismatch"], True)
            for key in ("StorageMismatchProven", "RuntimeABIVersionMismatchProven", "FullABIProof",
                        "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
                self.assertIs(result[key], False)

    def test_missing_extra_or_unrecognized_undefined_diagnostics_reject(self):
        text = diagnostic(PRIVATE16)
        for changed in (text.replace(PRIVATE16, PRIVATE32), text.replace(PRIVATE16, STORAGE, 1),
                        text + "C:/ld.exe: undefined reference to `unrelated'\n",
                        text + "unrelated linker error\n", text.replace("1 exit status", "2 exit status"),
                        text.replace("collect2.exe: error: ld returned 1 exit status\n", ""),
                        text + "collect2.exe: error: ld returned 1 exit status\n",
                        "collect2.exe: error: ld returned 1 exit status\n"):
            with self.subTest(changed=changed):
                self.reject_diagnostic(changed)
        for value in (None, True, False, 16, 32.0, b"not text", "", "\x00", "\u00e9"):
            with self.subTest(text=value):
                self.reject_diagnostic(value)
        for expected in (None, True, False, 16, 32.0, STORAGE, "foreign"):
            with self.subTest(expected=expected):
                self.reject_diagnostic(text, expected)

    def test_helpers_are_pure_detached_and_accept_actual_crlf_form(self):
        first, second, text = nm_text(PRIVATE16), nm_text(PRIVATE32), diagnostic(PRIVATE16)
        with patch("builtins.open", side_effect=AssertionError("pure identity helper opened file")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("pure identity helper read file")), \
                patch("subprocess.Popen", side_effect=AssertionError("pure identity helper spawned process")):
            result = i.cohort_pair(first.replace("\n", "\r\n"), second.replace("\n", "\r\n"))
            mismatch = i.require_mismatch(text.replace("\n", "\r\n"), PRIVATE16)
        result["Rows16"][0]["Name"] = "mutated-result"
        mismatch["MissingSymbols"].clear()
        self.assertEqual(i.cohort_pair(first, second)["Rows16"][0]["Name"], PRIVATE16)
        self.assertEqual(i.require_mismatch(text, PRIVATE16)["MissingSymbols"], [PRIVATE16])


class RecorderTests(unittest.TestCase):
    def test_successful_fake_command_pins_catalog_and_both_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            probe = recorder(Path(directory))
            record = probe.command(["fake compiler never executed", "-c"], "compile synthetic variant")
            self.assertEqual(record["Status"], "PASS")
            self.assertEqual(len(probe.report["Commands"]), 1)
            self.assertEqual(probe.report["Commands"], probe.tools.report["Commands"])
            self.assertEqual(set(probe.watch.hashes), {probe.output / ("command-0000" + suffix)
                             for suffix in (".json", ".stdout", ".stderr")})
            self.assertEqual(probe.admission.close.call_count, 2)

    def test_failed_fake_command_still_retains_actual_failure_record(self):
        with tempfile.TemporaryDirectory() as directory:
            probe = recorder(Path(directory))
            message = "cm3-lto-probe: command failed/timeout: link intended synthetic mismatch"
            probe.tools.exit = 1
            probe.tools.stderr = diagnostic(PRIVATE16).encode("ascii")
            probe.tools.error = ValueError(message)
            with self.assertRaisesRegex(ValueError, "^" + message + "$"):
                probe.command(["fake linker never executed"], "link intended synthetic mismatch")
            self.assertEqual(probe.report["Commands"][0]["Status"], "FAIL")
            self.assertEqual(probe.report["Commands"][0]["Exit"], 1)
            self.assertEqual(probe.report["NegativeControls"], [])
            self.assertEqual(len(probe.watch.hashes), 3)

    def test_closing_failure_is_not_the_expected_negative_link_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            probe = negative_recorder(Path(directory))
            expected_link_failure(probe, 16, "runtime", PRIVATE16)
            probe.admission.close.side_effect = [None, ValueError("synthetic unexpected closing drift")]
            with self.assertRaisesRegex(ValueError, "^synthetic unexpected closing drift$"):
                probe._negative(16, 3, "runtime")
            self.assertEqual(probe.report["NegativeControls"], [])
            self.assertEqual(len(probe.report["Commands"]), 1)
            self.assertEqual(len(probe.watch.hashes), 3)

    def test_missing_stream_and_mismatched_raw_record_fail_before_control_credit(self):
        for change in (".stdout", ".stderr", "raw-record"):
            with tempfile.TemporaryDirectory() as directory:
                probe = recorder(Path(directory))
                if change == "raw-record":
                    probe.tools.mutate_raw = lambda row: row.update(Argv=["foreign command"])
                else:
                    probe.tools.skip_stream = change
                with self.subTest(change=change), self.assertRaises(ValueError):
                    probe.command(["fake compiler never executed"], "compile synthetic variant")
                self.assertEqual(probe.report["NegativeControls"], [])

    def test_four_provider_eight_swap_plan_and_strict_link_negative_outcomes(self):
        expected_roles = ((3, "runtime"), (4, "boot"), (5, "exception"), (6, "expectation"))
        self.assertEqual(p.POLICY_SOURCES, expected_roles)
        original_flags = ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2",
                          "-DFIBER_SCHEDULER_BASEPRI=16", "-flto", "-fno-fat-lto-objects"]
        flags = p.threshold32_flags(original_flags)
        self.assertEqual(flags, [*original_flags[:4], "-DFIBER_SCHEDULER_BASEPRI=32", *original_flags[5:]])
        self.assertEqual(original_flags[4], "-DFIBER_SCHEDULER_BASEPRI=16")
        invalid = (True, 32.0, original_flags + ["-DFIBER_SCHEDULER_BASEPRI=32"],
                   original_flags + ["-DFIBER_PORT_SCHEDULER_BASEPRI=16"],
                   original_flags + ["-DFIBER_PORT_SCHEDULER_BASEPRI=32"],
                   original_flags + ["-O3"], [*original_flags[:-2], "-flto", "-ffat-lto-objects"])
        for value in invalid:
            with self.subTest(flags=value), self.assertRaises(ValueError):
                p.threshold32_flags(value)
        table = ((16, 3, "runtime", PRIVATE16), (16, 4, "boot", PRIVATE32),
                 (16, 5, "exception", PRIVATE32), (16, 6, "expectation", PRIVATE32),
                 (32, 3, "runtime", PRIVATE32), (32, 4, "boot", PRIVATE16),
                 (32, 5, "exception", PRIVATE16), (32, 6, "expectation", PRIVATE16))
        with tempfile.TemporaryDirectory() as directory:
            probe = negative_recorder(Path(directory))
            for threshold, index, role, private in table:
                expected_link_failure(probe, threshold, role, private)
                probe._negative(threshold, index, role)
                record = probe.report["NegativeControls"][-1]
                expected_objects = list(probe.variants[threshold])
                expected_objects[index] = probe.variants[32 if threshold == 16 else 16][index]
                self.assertEqual(record["Objects"], list(map(str, expected_objects)))
                self.assertEqual(record["ExpectedMissingSymbol"], private)
                self.assertEqual(record["SwappedSourceIndex"], index)
                self.assertEqual(record["SwappedRole"], role)
                self.assertEqual(record["LinkFlags"], [flag for flag in record["FullVerboseLinkFlags"] if flag != "-v"])
                self.assertEqual(record["RemovedLinkFlags"], ["-v"])
                self.assertEqual(record["CommandStatus"], "FAIL")
                self.assertEqual(record["Status"], "PASS")
                self.assertEqual(record["Exit"], 1)
                self.assertIs(type(record["Exit"]), int)
                self.assertIs(record["FinalImageAbsent"], True)
            self.assertEqual(len(probe.report["NegativeControls"]), 8)
            self.assertEqual(len(probe.report["Commands"]), 8)
        for mode in ("exit-zero", "timeout", "unexpected-error", "successful-link", "wrong-symbol", "final-exists"):
            with tempfile.TemporaryDirectory() as directory:
                probe = negative_recorder(Path(directory))
                expected_link_failure(probe, 16, "runtime", PRIVATE16)
                if mode == "exit-zero":
                    probe.tools.exit = 0
                elif mode == "timeout":
                    probe.tools.timed_out = True
                elif mode == "unexpected-error":
                    probe.tools.error = ValueError("synthetic unrelated containment error")
                elif mode == "successful-link":
                    probe.tools.error = None
                    probe.tools.exit = 0
                elif mode == "wrong-symbol":
                    probe.tools.stderr = diagnostic(PRIVATE32).encode("ascii")
                else:
                    probe.tools.create_output = True
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    probe._negative(16, 3, "runtime")
                self.assertEqual(probe.report["NegativeControls"], [])
        with tempfile.TemporaryDirectory() as directory:
            probe = recorder(Path(directory))
            probe.report.update(AddedSources=[{} for _ in range(4)], Links=[], NegativeControls=[],
                Commands=[dict(Status="PASS") for _ in range(44)] + [dict(Status="FAIL") for _ in range(8)])
            positive_calls, negative_calls = [], []
            def positive(*args):
                positive_calls.append(args)
                probe.report["Links"].append({})
            def negative(*args):
                negative_calls.append(args)
                probe.report["NegativeControls"].append({})
            probe._positive, probe._negative = positive, negative
            save(probe.output / "commands.json", probe.report["Commands"])
            probe.links()
            self.assertEqual(positive_calls, [(16, "ordinary", False), (16, "emit-relocs", True),
                                             (32, "ordinary", False), (32, "emit-relocs", True)])
            self.assertEqual(negative_calls, [(threshold, index, role) for threshold in (16, 32) for index, role in expected_roles])

    def test_failed_variant_compilation_never_counts_as_link_negative(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "runtime.c"
            source.write_bytes(b"/* synthetic source, never compiled */\n")
            probe = recorder(root / "output")
            probe.watch.read(source)
            flags = ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2",
                     "-DFIBER_SCHEDULER_BASEPRI=16", "-flto", "-fno-fat-lto-objects"]
            rows = [{} for _ in range(9)]
            rows[3] = dict(Source=str(source), SourceSha256=sha(source.read_bytes()), CompileFlags=flags)
            probe.capture = dict(Sources=rows)
            probe.report.update(AddedSources=[], Links=[])
            def copy_source(relative, data):
                destination = probe.output / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                return destination
            probe.admission.copy = copy_source
            probe.prepare = Mock()
            probe.links = Mock()
            probe.seal = Mock()
            probe.tools.exit = 1
            probe.tools.error = ValueError("cm3-lto-probe: command failed/timeout: compile policy32 runtime")
            self.assertIs(probe.run(), False)
            self.assertEqual(probe.report["Status"], "FAIL")
            self.assertIs(probe.report["InputClosureVerified"], False)
            self.assertEqual(probe.report["NegativeControls"], [])
            self.assertEqual(probe.report["AddedSources"], [])
            self.assertEqual(probe.report["Commands"][0]["Status"], "FAIL")
            self.assertIn("compile policy32 runtime", probe.report["Error"])
            probe.links.assert_not_called()
            probe.seal.assert_called_once()


def load_module(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or output.is_relative_to(REPO)
            or REPO.is_relative_to(output) or not output.is_relative_to(temporary)):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        Scope="PURE_SYNTHETIC_CM3_LTO_COHORT_IDENTITY_AND_RECORDER_CONTROLS_ONLY", SyntheticInputs=True,
        ActualELFTested=False, ActualCompileTested=False, ActualLinkTested=False, Qualification=False,
        NativeCommandsExecuted=0, ToolInvocations=0, FullABIProof=False, SourceIRProof=False,
        SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False, CanonicalProtocolValidated=False,
        InstructionEquivalence=False, PolicyEquivalence=False, FinalReferenceParity=False, CompleteObjectProof=False,
        KernelRuntimeProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    paths = (Path(__file__).resolve(), SOURCE, IDENTITY, ENGINE)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {item: item.read_bytes() for item in paths}
        report["SourceHashes"] = {str(item): sha(data) for item, data in buffers.items()}
        global p, i
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("pure controls cannot execute processes")):
            i = load_module("synthetic_cm3_cohort_identity", IDENTITY, buffers[IDENTITY])
            def source_read(path):
                if path not in buffers:
                    raise AssertionError("unexpected producer module input: " + str(path))
                return buffers[path]
            with patch.object(Path, "read_bytes", source_read):
                p = load_module("synthetic_cm3_cohort_probe", SOURCE, buffers[SOURCE])
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                                       for case in (IdentityTests, RecorderTests))
            count = suite.countTestCases()
            if count != EXPECTED_METHODS:
                raise ValueError("exact fourteen synthetic cohort-control methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
            for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == count and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for path, expected in report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) != expected:
                    report["SourceDrift"].append(path)
                else:
                    report["ClosingFilesVerified"] += 1
            except OSError:
                report["SourceDrift"].append(path)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 4 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
