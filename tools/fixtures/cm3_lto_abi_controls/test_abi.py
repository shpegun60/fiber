"""Pure synthetic CM3 LTO declaration controls, not compiler/ELF evidence."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import traceback
import types
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / "abi.py"
ORDINARY = HERE.parent / "ordinary_final_cell" / "abi.py"
CORE = HERE.parent / "cm0_final_cell" / "abi.py"
PINS = {ORDINARY: "43F2E49D638D0E586A24AD2B32D0B8D86C58CC9A63E134EF6AF064437278CAE5",
        CORE: "F5AA5CE6BD21130249D571D0AA03BD72C735DA04832C2B6DBF13EFD548CB4F4B"}
HEADERS = ("context/context_port_abi.h", "context/context_runtime_port_abi.h",
           "context/context_api_attributes.h", "context/context_api_types.h", "context/context_panic.h",
           "context/context_runtime_state.h", "fiber/fiber_api_attributes.h", "fiber/fiber_runtime_port_abi.h",
           "fiber/port/fiber_port_runtime_abi.h")
ORDER = ("context/context_core.c", "context/context_runtime_state.c", "context/context_panic.c",
         "fiber/port/ARM_CM3/fiber_port.c", "fiber/port/ARM_CM3/fiber_port_boot.c",
         "fiber/port/ARM_CM3/fiber_port_exception.c", "fiber/port/fiber_port_context_cohort_expectation.c",
         "tools/fixtures/classic_final_image/application.c", "tools/fixtures/classic_final_image/startup.S")
SOURCE_ROOT = "C:/synthetic/seed/Native/source"
CAPTURE_ROOT = "C:/synthetic/capture/native-O2-lto"
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
INVENTORY = "69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313"
SLOT = "fiber_internal_runtime_current_context_slot"
PROTOTYPES = (
    "void fiber_port_context_init(CtxrtContextV1 *context, void *stack_begin, void *stack_end, CtxrtEntryFnV1 entry, void *arg);",
    "void fiber_port_runtime_memory_barrier(void);",
    "void fiber_port_panic_wait(void);",
    "void fiber_port_require_scheduler_configuration_environment(void);",
    "void fiber_port_runtime_prepare_start(void);",
    "CtxrtContextV1 *fiber_port_runtime_select_first(void);",
    "void fiber_port_runtime_start_first(CtxrtContextV1 *first);",
    "void fiber_port_runtime_schedule(void);",
    "CtxrtContextV1 *fiber_internal_runtime_select_scheduler_candidate(CtxrtContextV1 *current);",
    "void fiber_internal_runtime_publish_current_context(CtxrtContextV1 *next);",
    "void fiber_internal_runtime_require_current_context(void);",
    "void fiber_internal_task_return(void);",
)
NAMES = ("fiber_port_context_init", "fiber_port_runtime_memory_barrier", "fiber_port_panic_wait",
         "fiber_port_require_scheduler_configuration_environment", "fiber_port_runtime_prepare_start",
         "fiber_port_runtime_select_first", "fiber_port_runtime_start_first", "fiber_port_runtime_schedule",
         "fiber_internal_runtime_select_scheduler_candidate", "fiber_internal_runtime_publish_current_context",
         "fiber_internal_runtime_require_current_context", "fiber_internal_task_return")
ATTRIBUTE = '__attribute__((no_sanitize("address", "undefined", "thread"))) '
BUFFERS = {}
ABI = None
EXPECTED_METHODS = 12


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return json.dumps(value, sort_keys=True).encode("ascii")


def sources():
    return {name: BUFFERS[ROOT / name] for name in HEADERS + ORDER}


def cpp():
    return ('# 1 "' + SOURCE_ROOT + '/context/context_port_abi.h" 1\n'
            + "\n".join(ATTRIBUTE + row for row in PROTOTYPES[:8])
            + '\n# 1 "' + SOURCE_ROOT + '/context/context_runtime_port_abi.h" 1\n'
            + "\n".join(ATTRIBUTE + row for row in PROTOTYPES[8:]) + "\n").encode("ascii")


def flags(index):
    if index == 8:
        return ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-g0", "-DPILOT_HAS_VTOR=1"]
    return ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-std=gnu11", "-g0",
        "-ffreestanding", "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra",
        "-Werror=implicit-function-declaration", "-Werror=attributes", "-Werror=ignored-attributes",
        "-DFIBER_PORT_ARMV7M=1", "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_SCHEDULER_BASEPRI=16",
        "-I" + SOURCE_ROOT + "/tools/fixtures/classic_final_image", "-I" + SOURCE_ROOT + "/fiber/port/ARM_CM3",
        "-I" + SOURCE_ROOT + "/fiber/port", "-I" + SOURCE_ROOT + "/fiber", "-I" + SOURCE_ROOT + "/context",
        "-I" + SOURCE_ROOT, "-IC:/synthetic/seed/Native/cmsis", "-include",
        SOURCE_ROOT + "/tools/fixtures/classic_final_image/main.h",
        "-I" + SOURCE_ROOT + "/" + ORDER[index].rsplit("/", 1)[0], "-flto", "-fno-fat-lto-objects"]


def receipt():
    data, rows, inputs = sources(), [], {}
    for index, name in enumerate(ORDER):
        names = {name}
        if index <= 4:
            names.update(("context/context_port_abi.h", "context/context_api_attributes.h",
                          "context/context_api_types.h", "fiber/fiber_api_attributes.h"))
        if index in (0, 1, 3, 4):
            names.add("context/context_runtime_port_abi.h")
        dependencies = [{"Path": SOURCE_ROOT + "/" + item, "Sha256": sha(data[item])} for item in sorted(names)]
        dependencies.append({"Path": CAPTURE_ROOT + "/toolchain/include/stdint.h", "Sha256": "B" * 64})
        inputs.update({row["Path"]: row["Sha256"] for row in dependencies})
        stem = name.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        obj = CAPTURE_ROOT + "/objects/" + format(index, "02d") + "-" + stem + ".o"
        rows.append(dict(Source=SOURCE_ROOT + "/" + name, SourceSha256=sha(data[name]),
            Object=obj, DependencyFile=obj[:-2] + ".d", ObjectSha256="A" * 64,
            CompileFlags=flags(index), SlimIR=index != 8, CompileDependenciesVerified=True,
            ActualCompileDependencies=dependencies))
    return dict(Profile="CM3", Cohort=COHORT, Mode="O2-lto", Linkage="direct", LTO=True,
                TranslationUnits=9, SlimIRObjects=8, Sources=rows, InputHashes=inputs,
                SourceInventorySha256=INVENTORY)


class AbiTests(unittest.TestCase):
    def inspect(self, value=None, source_bytes=None, **kwargs):
        return ABI.inspect_provider_dependencies(sources() if source_bytes is None else source_bytes,
            encoded(receipt() if value is None else value), source_root=kwargs.get("source_root", SOURCE_ROOT),
            capture_root=kwargs.get("capture_root", CAPTURE_ROOT))

    def no_credit(self, record):
        self.assertEqual(record["Mode"], "O2-lto")
        self.assertIs(record["LTO"], True)
        self.assertEqual(record["AllowedModes"], ["O2-lto"])
        self.assertEqual(record["TargetContract"]["AllowedModes"], ["O2-lto"])
        self.assertIs(type(record["Scope"]["RequiredCellsSatisfied"]), int)
        self.assertEqual(record["Scope"]["RequiredCellsSatisfied"], 0)
        for key, value in record["Scope"].items():
            if key != "RequiredCellsSatisfied":
                self.assertIs(value, False, key)

    def test_fixed_lto_contract_does_not_change_ordinary_modes_or_globals(self):
        before = ABI._ordinary.profile_contract("CM3")
        self.assertEqual(before["AllowedModes"], ["O0", "Og", "O2", "Os", "O3"])
        contract = ABI.profile_contract()
        self.assertEqual((contract["Profile"], contract["Mode"], contract["Cohort"]), ("CM3", "O2-lto", COHORT))
        self.assertEqual((contract["Architecture"], contract["FloatABI"], contract["SchedulerBASEPRI"]),
                         ("ARMV7M", "soft", 16))
        self.assertEqual(contract["AllowedModes"], ["O2-lto"])
        self.assertIs(contract["LTO"], True)
        contract["AllowedModes"].append("Os-lto")
        ABI.emit_probes()
        ABI.inspect_sources(sources())
        ABI.inspect_preprocessed_attributes(cpp())
        self.inspect()
        self.assertEqual(ABI._ordinary.profile_contract("CM3"), before)
        self.assertEqual(ABI.profile_contract()["AllowedModes"], ["O2-lto"])

    def test_exact_five_independent_type_and_specific_slot_probes(self):
        probes = ABI.emit_probes()
        self.assertEqual(tuple(probes), ("types.c", "attributes.c", "slot_read.c", "slot_write.c", "slot_address.c"))
        expected = ("init", "void", "noreturn_void", "void", "void", "first", "noreturn_start", "void",
                    "select", "publish", "void", "noreturn_void")
        body = probes["types.c"]["Source"]
        for name, kind in zip(NAMES, expected):
            self.assertIn("__builtin_types_compatible_p(__typeof__(&" + name + "), cm0_expected_" + kind + ")", body)
        for signature in ("typedef void (*cm0_expected_entry)(void *);",
                "typedef struct FiberContext *(*cm0_expected_dispatch)(struct FiberContext *, void *);",
                "typedef void (*cm0_expected_init)(struct FiberContext *, void *, void *, cm0_expected_entry, void *);",
                "typedef void (*cm0_expected_noreturn_void)(void) __attribute__((noreturn));",
                "typedef void (*cm0_expected_noreturn_start)(struct FiberContext *) __attribute__((noreturn));"):
            self.assertIn(signature, body)
        self.assertIn("!defined(__ARM_ARCH_7M__)", body)
        self.assertIn("|| defined(__ARM_PCS_VFP) || defined(__ARM_FP)", body)
        for name, record in probes.items():
            self.no_credit(record)
            self.assertEqual(record["SourceSha256"], sha(record["Source"].encode("ascii")))
            self.assertEqual(record["Source"], ABI._ordinary.emit_probes("CM3")[name]["Source"])
            self.assertIs(record["ExpectedCompile"], name in ("types.c", "attributes.c"))
            self.assertIs(record["CompilerExecuted"], False)
        for kind, statement in (("read", "(void)" + SLOT + ";"), ("write", SLOT + " = value;"),
                                ("address", "(void)&" + SLOT + ";")):
            self.assertIn(statement, probes["slot_" + kind + ".c"]["Source"])
            self.assertIn("void cm0_abi_slot_" + kind + "(", probes["slot_" + kind + ".c"]["Source"])
            self.assertEqual(probes["slot_" + kind + ".c"]["DiagnosticIdentifier"], SLOT)

    def test_attribute_queries_and_cpp_scan_preserve_sanitizer_limitation(self):
        probe = ABI.emit_probes()["attributes.c"]
        for name in NAMES:
            for query in ("noinline", "noipa", "noclone", "no_icf", "used", "no_instrument_function",
                    "no_stack_protector", "no_profile_instrument_function", "no_sanitize_coverage",
                    'target("general-regs-only")'):
                self.assertIn("__builtin_has_attribute(" + name + ", " + query + ")", probe["Source"])
        self.assertNotIn(', no_sanitize("address"', probe["Source"])
        self.assertIn("ICE", str(probe["UnprovenAttributes"]))
        record = ABI.inspect_preprocessed_attributes(cpp())
        self.no_credit(record)
        self.assertEqual((record["ForwardDeclarations"], record["ReverseDeclarations"]), (8, 4))
        self.assertEqual(len(record["Declarations"]), 12)
        self.assertIs(record["PreprocessedNoSanitizeDeclarationsChecked"], True)
        for raw in (cpp().replace(b'"thread"', b'"memory"', 1), cpp() + ATTRIBUTE.encode() + PROTOTYPES[8].encode(),
                    cpp().replace(b'context/context_port_abi.h', b'context/foreign.h'),
                    cpp().replace(b'no_sanitize', b'no_instrument_function', 1)):
            with self.subTest(raw=raw[:80]), self.assertRaises(ABI.Rejected):
                ABI.inspect_preprocessed_attributes(raw)

    def test_eighteen_e9_source_pins_missing_changed_and_path_alias_reject(self):
        result = ABI.inspect_sources(sources())
        self.no_credit(result)
        self.assertEqual(len(result["Sources"]), 18)
        self.assertEqual(tuple(ABI.source_order()), ORDER)
        for kind in ("missing", "changed", "alias", "nonbytes", "traversal"):
            value = sources()
            if kind == "missing":
                del value[HEADERS[0]]
            elif kind == "changed":
                value[HEADERS[0]] += b" "
            elif kind == "alias":
                value[HEADERS[0].upper()] = value[HEADERS[0]]
            elif kind == "nonbytes":
                value[HEADERS[0]] = bytearray(value[HEADERS[0]])
            else:
                value["context/../context/x.h"] = b""
            with self.subTest(kind=kind), self.assertRaises(ABI.Rejected):
                ABI.inspect_sources(value)

    def test_real_lto_schema_positive_has_eight_slim_and_distinct_startup(self):
        value = receipt()
        self.assertNotIn("Dependencies", value["Sources"][0])
        result = self.inspect(value)
        self.no_credit(result)
        self.assertEqual(result["DeclaredDependencyAuthority"], "CAPTURE_INPUT_HASHES")
        self.assertIs(result["SeedDiscoveryDependencySetCompared"], False)
        self.assertIs(result["DeclaredProviderDependenciesBound"], True)
        self.assertEqual(len(result["Providers"]), 9)
        self.assertEqual([row["DeclaredSlimIR"] for row in result["Providers"]], [True] * 8 + [False])
        self.assertEqual([row["Source"] for row in result["Providers"]], list(ORDER))
        self.assertEqual(result["ReceiptSha256"], sha(encoded(value)))
        self.assertEqual(result["UnverifiedExternalDependencies"],
                         [{"Path": CAPTURE_ROOT + "/toolchain/include/stdint.h", "Sha256": "B" * 64}])

    def test_wrong_modes_profiles_cohorts_and_nonliteral_counts_reject(self):
        for field, bad in (("Profile", "CM4"), ("Mode", "O2"), ("Mode", "Os-lto"), ("Mode", True),
                ("Cohort", COHORT.replace("b16", "b32")), ("Linkage", "archive"), ("LTO", 1),
                ("LTO", False), ("TranslationUnits", 9.0), ("TranslationUnits", True),
                ("SlimIRObjects", 8.0), ("SlimIRObjects", 7), ("SourceInventorySha256", "A" * 64)):
            value = receipt()
            value[field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ABI.Rejected):
                self.inspect(value)
        for rows in (receipt()["Sources"][:-1], receipt()["Sources"] + [receipt()["Sources"][0]]):
            value = receipt()
            value["Sources"] = rows
            with self.assertRaises(ABI.Rejected):
                self.inspect(value)

    def test_source_order_object_dependency_paths_and_roots_fail_closed(self):
        for kind in ("order", "source", "hash", "object", "depfile", "object-hash", "case", "traversal"):
            value = receipt()
            row = value["Sources"][0]
            if kind == "order":
                value["Sources"][0], value["Sources"][1] = value["Sources"][1], value["Sources"][0]
            elif kind == "source":
                row["Source"] = CAPTURE_ROOT + "/source/" + ORDER[0]
            elif kind == "hash":
                row["SourceSha256"] = "F" * 64
            elif kind == "object":
                row["Object"] = row["Object"].replace("00-", "01-")
            elif kind == "depfile":
                row["DependencyFile"] = SOURCE_ROOT + "/00-context_core.d"
            elif kind == "object-hash":
                row["ObjectSha256"] = True
            elif kind == "case":
                row["Source"] = row["Source"].replace("/seed/", "/SEED/")
            else:
                row["Object"] = CAPTURE_ROOT + "/objects/../objects/00-context_core.o"
            with self.subTest(kind=kind), self.assertRaises(ABI.Rejected):
                self.inspect(value)
        for options in (dict(source_root=CAPTURE_ROOT), dict(capture_root=SOURCE_ROOT),
                        dict(capture_root=SOURCE_ROOT + "/child"), dict(source_root=True)):
            with self.subTest(options=options), self.assertRaises(ABI.Rejected):
                self.inspect(**options)

    def test_exact_compile_flags_reject_overrides_fat_and_lto_startup(self):
        for index, change in ((0, "-O3"), (0, "-mcpu=cortex-m4"), (0, "-DFIBER_SCHEDULER_BASEPRI=32"),
                (0, "-ffat-lto-objects"), (0, "-DFIBER_PORT_SCHEDULER_BASEPRI=16"), (8, "-flto")):
            value = receipt()
            value["Sources"][index]["CompileFlags"].append(change)
            with self.subTest(index=index, change=change), self.assertRaises(ABI.Rejected):
                self.inspect(value)
        for field, bad in (("SlimIR", 1), ("SlimIR", False), ("CompileDependenciesVerified", 1),
                           ("CompileFlags", [True]), ("CompileFlags", flags(0)[:-2])):
            value = receipt()
            value["Sources"][0][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ABI.Rejected):
                self.inspect(value)

    def test_own_and_canonical_header_actual_dependencies_required(self):
        for target in (ORDER[0], "context/context_port_abi.h", "context/context_runtime_port_abi.h",
                       "context/context_api_attributes.h", "fiber/fiber_api_attributes.h"):
            value = receipt()
            value["Sources"][0]["ActualCompileDependencies"] = [row for row in
                value["Sources"][0]["ActualCompileDependencies"] if row["Path"] != SOURCE_ROOT + "/" + target]
            with self.subTest(target=target), self.assertRaises(ABI.Rejected):
                self.inspect(value)
        for kind in ("changed", "duplicate", "alias", "missing-bytes", "ill-typed"):
            value, data = receipt(), sources()
            dependencies = value["Sources"][0]["ActualCompileDependencies"]
            if kind == "changed":
                dependencies[0]["Sha256"] = "F" * 64
            elif kind == "duplicate":
                dependencies.append(copy.deepcopy(dependencies[0]))
            elif kind == "alias":
                dependencies.append(dict(dependencies[0], Path=dependencies[0]["Path"].upper()))
            elif kind == "missing-bytes":
                path = SOURCE_ROOT + "/extra.h"
                dependencies.append(dict(Path=path, Sha256="A" * 64))
                value["InputHashes"][path] = "A" * 64
            else:
                dependencies[0]["Sha256"] = False
            with self.subTest(kind=kind), self.assertRaises(ABI.Rejected):
                self.inspect(value, data)

    def test_capture_declared_actual_dependency_binding_and_optional_records(self):
        for kind in ("missing-input", "changed-input", "aliased-input", "wrong-optional", "empty-inputs"):
            value = receipt()
            row = value["Sources"][0]
            path = row["ActualCompileDependencies"][0]["Path"]
            if kind == "missing-input":
                del value["InputHashes"][path]
            elif kind == "changed-input":
                value["InputHashes"][path] = "F" * 64
            elif kind == "aliased-input":
                value["InputHashes"][path.upper()] = value["InputHashes"][path]
            elif kind == "empty-inputs":
                value["InputHashes"] = {}
            else:
                row["Dependencies"] = copy.deepcopy(row["ActualCompileDependencies"])
                row["Dependencies"][0]["Sha256"] = "F" * 64
            with self.subTest(kind=kind), self.assertRaises(ABI.Rejected):
                self.inspect(value)
        value = receipt()
        for row in value["Sources"]:
            row["Dependencies"] = copy.deepcopy(row["ActualCompileDependencies"])
        self.inspect(value)

    def test_pure_calls_input_purity_and_dependency_loader_authentication(self):
        data, value = sources(), receipt()
        before, old_modes = copy.deepcopy(value), ABI._ordinary.MODES
        with patch("builtins.open", side_effect=AssertionError("pure call opened file")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("pure call read file")), \
                patch("subprocess.Popen", side_effect=AssertionError("pure call started process")):
            self.inspect(value, data)
            ABI.inspect_preprocessed_attributes(cpp())
            ABI.emit_probes()
        self.assertEqual(value, before)
        self.assertEqual(data, sources())
        self.assertIs(ABI._ordinary.MODES, old_modes)
        self.assertEqual(old_modes, ("O0", "Og", "O2", "Os", "O3"))
        with patch.object(Path, "read_bytes", return_value=b"raise AssertionError('executed unauthenticated helper')\n"), \
                self.assertRaisesRegex(ValueError, "source identity"):
            ABI._load_ordinary()

    def test_malformed_json_nonfinite_duplicate_and_nonbytes_receipts_reject(self):
        for raw in (b"[]", b"null", b"true", b"{", b"\xff", b'{"Mode":1,"mode":2}',
                    b'{"x":NaN}', b'{"x":Infinity}', "not bytes", bytearray(b"{}")):
            with self.subTest(raw=raw), self.assertRaises(ABI.Rejected):
                ABI.inspect_provider_dependencies(sources(), raw, source_root=SOURCE_ROOT, capture_root=CAPTURE_ROOT)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if (output.exists() or args.output_dir.is_symlink() or output.is_relative_to(ROOT)
            or ROOT.is_relative_to(output) or not output.is_relative_to(Path(tempfile.gettempdir()).resolve())):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Errors=0, Failures=0,
        Skipped=0, SourceHashes={}, SourceDrift=[], ClosingFilesVerified=0, SourceClosureVerified=False,
        Scope="PURE_SYNTHETIC_CM3_O2_LTO_ABI_ADAPTER_CONTROLS_ONLY", SyntheticReceipts=True,
        ActualCaptureRead=False, ActualCompilerExecuted=False, ActualELFTested=False, TargetExecuted=False,
        FullABIProof=False, FullSemanticABIProof=False, GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("unoptimized host Python required")
        paths = (Path(__file__).resolve(), SUBJECT, ORDINARY, CORE) + tuple(ROOT / name for name in HEADERS + ORDER)
        BUFFERS.update({path: path.read_bytes() for path in paths})
        report["SourceHashes"] = {str(path): sha(raw) for path, raw in BUFFERS.items()}
        for path, expected in PINS.items():
            if sha(BUFFERS[path]) != expected:
                raise ValueError("frozen helper source identity mismatch: " + str(path))
        global ABI
        ABI = types.ModuleType("_synthetic_cm3_lto_abi_subject")
        ABI.__file__ = str(SUBJECT)
        with patch("subprocess.Popen", side_effect=AssertionError("synthetic controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("synthetic controls cannot execute commands")):
            exec(compile(BUFFERS[SUBJECT], str(SUBJECT), "exec"), ABI.__dict__)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(AbiTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact twelve implemented methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Errors=len(result.errors), Failures=len(result.failures),
            Skipped=len(result.skipped), Details=[dict(Test=str(test), Error=error)
                for test, error in result.errors + result.failures])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Errors=report["Errors"] + 1, Error=traceback.format_exc())
    finally:
        for path, expected in report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) != expected:
                    report["SourceDrift"].append(path)
                else:
                    report["ClosingFilesVerified"] += 1
            except OSError:
                report["SourceDrift"].append(path)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 22 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_bytes((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("ascii"))
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
