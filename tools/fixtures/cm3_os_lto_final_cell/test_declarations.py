"""Pure Os declaration-adapter controls; no compiler, ELF or target execution."""

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
SUBJECT = HERE / "declarations.py"
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
CAPTURE_ROOT = "C:/synthetic/capture/native-Os-lto"
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
INVENTORY = "69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313"
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
NAMES = tuple(row.split("(", 1)[0].split()[-1].lstrip("*") for row in PROTOTYPES)
ATTRIBUTE = '__attribute__((no_sanitize("address", "undefined", "thread"))) '
BUFFERS, ADAPTER, ORDINARY_API = {}, None, None
EXPECTED_METHODS = 16


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


def seed_flags(index):
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
        "-I" + SOURCE_ROOT + "/" + ORDER[index].rsplit("/", 1)[0]]


def receipt():
    data, rows, inputs = sources(), [], {}
    for index, name in enumerate(ORDER):
        mandatory = {name}
        if index <= 4:
            mandatory.update(("context/context_port_abi.h", "context/context_api_attributes.h",
                              "context/context_api_types.h", "fiber/fiber_api_attributes.h"))
        if index in (0, 1, 3, 4):
            mandatory.add("context/context_runtime_port_abi.h")
        dependencies = [{"Path": SOURCE_ROOT + "/" + item, "Sha256": sha(data[item])}
                        for item in sorted(mandatory)]
        dependencies.append(dict(Path=CAPTURE_ROOT + "/toolchain/include/stdint.h", Sha256="B" * 64))
        inputs.update({row["Path"]: row["Sha256"] for row in dependencies})
        obj = CAPTURE_ROOT + "/objects/" + format(index, "02d") + "-" + name.rsplit("/", 1)[-1].rsplit(".", 1)[0] + ".o"
        flags = ["-Os" if flag == "-O2" else flag for flag in seed_flags(index)]
        if index != 8:
            flags += ["-flto", "-fno-fat-lto-objects"]
        rows.append(dict(Source=SOURCE_ROOT + "/" + name, SourceSha256=sha(data[name]),
            Object=obj, DependencyFile=obj[:-2] + ".d", ObjectSha256="A" * 64,
            SeedCompileFlags=seed_flags(index), CompileFlags=flags, SlimIR=index != 8,
            CompileDependenciesVerified=True, ActualCompileDependencies=dependencies))
    return dict(Profile="CM3", Cohort=COHORT, Mode="Os-lto", SeedMode="O2", Linkage="direct", LTO=True,
                SeedBuild=SOURCE_ROOT[:-7], TranslationUnits=9, SlimIRObjects=8, Sources=rows,
                InputHashes=inputs, SourceInventorySha256=INVENTORY)


class DeclarationTests(unittest.TestCase):
    def inspect(self, value=None, data=None, **options):
        return ADAPTER.inspect_provider_dependencies(sources() if data is None else data,
            encoded(receipt() if value is None else value), ordinary=ORDINARY_API,
            source_root=options.get("source_root", SOURCE_ROOT),
            capture_root=options.get("capture_root", CAPTURE_ROOT))

    def no_credit(self, record):
        self.assertEqual((record["Profile"], record["Mode"], record["Linkage"]), ("CM3", "Os-lto", "direct"))
        self.assertIs(record["LTO"], True)
        self.assertEqual(record["AllowedModes"], ["Os-lto"])
        self.assertEqual(record["TargetContract"]["AllowedModes"], ["Os-lto"])
        self.assertIs(type(record["Scope"]["RequiredCellsSatisfied"]), int)
        self.assertEqual(record["Scope"]["RequiredCellsSatisfied"], 0)
        for key, value in record["Scope"].items():
            if key != "RequiredCellsSatisfied":
                self.assertIs(value, False, key)

    def test_fresh_os_contract_preserves_mode_neutral_helper(self):
        before = ORDINARY_API.profile_contract("CM3")
        result = ADAPTER.profile_contract(ordinary=ORDINARY_API)
        self.assertEqual((result["Mode"], result["Cohort"], result["SourceGroup"]), ("Os-lto", COHORT, "CM3"))
        self.assertEqual((result["Architecture"], result["FloatABI"], result["SchedulerBASEPRI"]), ("ARMV7M", "soft", 16))
        self.assertEqual(result["SourceInventorySha256"], INVENTORY)
        result["AllowedModes"].append("O2-lto")
        self.assertEqual(ADAPTER.profile_contract(ordinary=ORDINARY_API)["AllowedModes"], ["Os-lto"])
        self.assertEqual(ORDINARY_API.profile_contract("CM3"), before)
        self.assertEqual(before["AllowedModes"], ["O0", "Og", "O2", "Os", "O3"])

    def test_independent_five_probe_bytes_and_noreturn_oracle(self):
        probes = ADAPTER.emit_probes(ordinary=ORDINARY_API)
        original = ORDINARY_API.emit_probes("CM3")
        self.assertEqual(tuple(probes), ("types.c", "attributes.c", "slot_read.c", "slot_write.c", "slot_address.c"))
        expected = ("init", "void", "noreturn_void", "void", "void", "first", "noreturn_start", "void",
                    "select", "publish", "void", "noreturn_void")
        for name, kind in zip(NAMES, expected):
            self.assertIn("__builtin_types_compatible_p(__typeof__(&" + name + "), cm0_expected_" + kind + ")",
                          probes["types.c"]["Source"])
        for name, record in probes.items():
            self.no_credit(record)
            self.assertEqual(record["Source"], original[name]["Source"])
            self.assertEqual(record["SourceSha256"], sha(record["Source"].encode("ascii")))
            self.assertIs(record["ExpectedCompile"], name in ("types.c", "attributes.c"))
            self.assertIs(record["CompilerExecuted"], False)
        self.assertIn("!defined(__ARM_ARCH_7M__)", probes["types.c"]["Source"])
        self.assertIn("|| defined(__ARM_PCS_VFP) || defined(__ARM_FP)", probes["types.c"]["Source"])

    def test_attribute_queries_keep_unproven_sanitizer_reflection_explicit(self):
        probe = ADAPTER.emit_probes(ordinary=ORDINARY_API)["attributes.c"]
        for name in NAMES:
            for query in ("noinline", "noipa", "noclone", "no_icf", "used", "no_instrument_function",
                    "no_stack_protector", "no_profile_instrument_function", "no_sanitize_coverage",
                    'target("general-regs-only")'):
                self.assertIn("__builtin_has_attribute(" + name + ", " + query + ")", probe["Source"])
        self.assertNotIn(', no_sanitize("address"', probe["Source"])
        self.assertIn("ICE", str(probe["UnprovenAttributes"]))

    def test_cpp_canonical_attributes_missing_changed_and_foreign_origins(self):
        result = ADAPTER.inspect_preprocessed_attributes(cpp(), ordinary=ORDINARY_API)
        self.no_credit(result)
        self.assertEqual((result["ForwardDeclarations"], result["ReverseDeclarations"]), (8, 4))
        self.assertIs(result["PreprocessedNoSanitizeDeclarationsChecked"], True)
        for raw in (cpp().replace(b'"thread"', b'"memory"', 1),
                    cpp().replace(ATTRIBUTE.encode(), b"", 1),
                    cpp().replace(b'context/context_port_abi.h', b'context/foreign.h'),
                    cpp() + ATTRIBUTE.encode() + PROTOTYPES[8].encode(),
                    cpp().replace(PROTOTYPES[0].encode(), b"")):
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                ADAPTER.inspect_preprocessed_attributes(raw, ordinary=ORDINARY_API)

    def test_fixed_source_catalog_rejects_missing_changed_foreign_and_aliases(self):
        result = ADAPTER.inspect_sources(sources(), ordinary=ORDINARY_API)
        self.no_credit(result)
        self.assertEqual(len(result["Sources"]), 18)
        self.assertEqual(ADAPTER.source_order(ordinary=ORDINARY_API), ORDER)
        self.assertEqual(len(ADAPTER.source_hashes(ordinary=ORDINARY_API)), 18)
        for kind in ("missing", "changed", "alias", "nonbytes", "foreign", "traversal"):
            data = sources()
            if kind == "missing":
                del data[HEADERS[0]]
            elif kind == "changed":
                data[HEADERS[0]] += b" "
            elif kind == "alias":
                data[HEADERS[0].upper()] = data[HEADERS[0]]
            elif kind == "nonbytes":
                data[HEADERS[0]] = bytearray(data[HEADERS[0]])
            elif kind == "foreign":
                data[ORDER[3].replace("ARM_CM3", "ARM_CM4")] = data.pop(ORDER[3])
            else:
                data["context/../context/x.h"] = b""
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                ADAPTER.inspect_sources(data, ordinary=ORDINARY_API)

    def test_os_nine_providers_with_exact_seed_transform(self):
        value = receipt()
        result = self.inspect(value)
        self.no_credit(result)
        self.assertIs(result["DeclaredProviderDependenciesBound"], True)
        self.assertIs(result["SeedFlagsTransformVerified"], True)
        self.assertEqual(result["DeclaredDependencyAuthority"], "CAPTURE_INPUT_HASHES")
        self.assertEqual([row["DeclaredSlimIR"] for row in result["Providers"]], [True] * 8 + [False])
        self.assertEqual([row["Source"] for row in result["Providers"]], list(ORDER))
        self.assertEqual(result["ReceiptSha256"], sha(encoded(value)))
        for index, row in enumerate(result["Providers"]):
            self.assertEqual(row["SeedCompileFlags"], seed_flags(index))
            self.assertIn("-Os", row["CompileFlags"])
            self.assertNotIn("-O2", row["CompileFlags"])

    def test_wrong_route_mode_seed_mode_and_inventory(self):
        for key, bad in (("Profile", "CM4"), ("Mode", "O2-lto"), ("Mode", "Os"), ("Mode", True),
                ("SeedMode", "Os"), ("SeedMode", None), ("Linkage", "archive"),
                ("Cohort", COHORT.replace("b16", "b32")), ("SourceInventorySha256", "A" * 64),
                ("SeedBuild", "C:/foreign/Native")):
            value = receipt()
            value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                self.inspect(value)

    def test_literal_counts_booleans_and_source_cardinality(self):
        for key, bad in (("LTO", 1), ("LTO", False), ("TranslationUnits", 9.0), ("TranslationUnits", True),
                         ("SlimIRObjects", 8.0), ("SlimIRObjects", False), ("SlimIRObjects", 7)):
            value = receipt()
            value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                self.inspect(value)
        for count in (0, 8, 10):
            value = receipt()
            value["Sources"] = (value["Sources"] + [value["Sources"][0]])[:count]
            with self.subTest(count=count), self.assertRaises(ValueError):
                self.inspect(value)
        for key, bad in (("SlimIR", 1), ("SlimIR", False), ("CompileDependenciesVerified", 1)):
            value = receipt()
            value["Sources"][0][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.inspect(value)

    def test_only_documented_flags_transform_no_counterflags_or_o2(self):
        for index, flag in ((0, "-O2"), (0, "-O3"), (0, "-mcpu=cortex-m4"), (0, "-fno-instrument-functions"),
                (0, "-ffat-lto-objects"), (0, "-DFIBER_SCHEDULER_BASEPRI=32"), (8, "-flto")):
            value = receipt()
            value["Sources"][index]["CompileFlags"].append(flag)
            with self.subTest(index=index, flag=flag), self.assertRaises(ValueError):
                self.inspect(value)
        for field, flags in (("CompileFlags", seed_flags(0)), ("SeedCompileFlags", [True]),
                ("SeedCompileFlags", receipt()["Sources"][0]["CompileFlags"]), ("CompileFlags", ["-include"]),
                ("CompileFlags", receipt()["Sources"][0]["CompileFlags"][:-1])):
            value = receipt()
            value["Sources"][0][field] = flags
            with self.subTest(field=field, flags=flags), self.assertRaises(ValueError):
                self.inspect(value)
        value = receipt()
        del value["Sources"][0]["SeedCompileFlags"]
        with self.assertRaises(ValueError):
            self.inspect(value)

    def test_provider_order_paths_hashes_and_own_source_identity(self):
        for kind in ("order", "foreign-source", "source-hash", "object", "depfile", "object-hash", "case", "dot"):
            value = receipt()
            row = value["Sources"][0]
            if kind == "order":
                value["Sources"][0], value["Sources"][1] = value["Sources"][1], value["Sources"][0]
            elif kind == "foreign-source":
                row["Source"] = row["Source"].replace("context_core.c", "foreign.c")
            elif kind == "source-hash":
                row["SourceSha256"] = "F" * 64
            elif kind == "object":
                row["Object"] = row["Object"].replace("00-", "01-")
            elif kind == "depfile":
                row["DependencyFile"] = SOURCE_ROOT + "/00-context_core.d"
            elif kind == "object-hash":
                row["ObjectSha256"] = True
            elif kind == "case":
                row["Source"] = row["Source"].upper()
            else:
                row["Object"] = row["Object"].replace("/objects/", "/objects/../objects/")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.inspect(value)

    def test_both_canonical_provider_header_dependencies_are_mandatory(self):
        for index in (0, 1, 3, 4):
            for target in (ORDER[index], "context/context_port_abi.h", "context/context_runtime_port_abi.h"):
                value = receipt()
                value["Sources"][index]["ActualCompileDependencies"] = [row for row in
                    value["Sources"][index]["ActualCompileDependencies"] if row["Path"] != SOURCE_ROOT + "/" + target]
                with self.subTest(index=index, target=target), self.assertRaises(ValueError):
                    self.inspect(value)

    def test_actual_dependency_schema_hash_and_optional_declared_binding(self):
        for kind in ("changed", "duplicate", "alias", "missing-bytes", "ill-typed", "optional"):
            value, data = receipt(), sources()
            row = value["Sources"][0]
            dependencies = row["ActualCompileDependencies"]
            if kind == "changed":
                dependencies[0]["Sha256"] = "F" * 64
            elif kind == "duplicate":
                dependencies.append(copy.deepcopy(dependencies[0]))
            elif kind == "alias":
                dependencies.append(dict(dependencies[0], Path=dependencies[0]["Path"].upper()))
            elif kind == "missing-bytes":
                name = SOURCE_ROOT + "/extra.h"
                dependencies.append(dict(Path=name, Sha256="A" * 64))
                value["InputHashes"][name] = "A" * 64
            elif kind == "ill-typed":
                dependencies[0]["Sha256"] = False
            else:
                row["Dependencies"] = copy.deepcopy(dependencies)
                row["Dependencies"][0]["Sha256"] = "F" * 64
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.inspect(value, data)
        value = receipt()
        for row in value["Sources"]:
            row["Dependencies"] = copy.deepcopy(row["ActualCompileDependencies"])
        self.inspect(value)

    def test_capture_input_hash_authority_and_disjoint_roots(self):
        for kind in ("missing", "changed", "alias", "empty"):
            value = receipt()
            name = value["Sources"][0]["ActualCompileDependencies"][0]["Path"]
            if kind == "missing":
                del value["InputHashes"][name]
            elif kind == "changed":
                value["InputHashes"][name] = "F" * 64
            elif kind == "alias":
                value["InputHashes"][name.upper()] = value["InputHashes"][name]
            else:
                value["InputHashes"] = {}
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.inspect(value)
        for options in (dict(source_root=True), dict(source_root=CAPTURE_ROOT),
                        dict(capture_root=SOURCE_ROOT), dict(capture_root=SOURCE_ROOT + "/child")):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.inspect(**options)

    def test_malformed_nonbytes_duplicate_nonfinite_json_fails_closed(self):
        for raw in (b"[]", b"null", b"true", b"{", b"\xff", b'{"Mode":1,"mode":2}',
                    b'{"x":NaN}', b'{"x":Infinity}', "not bytes", bytearray(b"{}")):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                ADAPTER.inspect_provider_dependencies(sources(), raw, ordinary=ORDINARY_API,
                    source_root=SOURCE_ROOT, capture_root=CAPTURE_ROOT)

    def test_pure_calls_do_not_load_helpers_or_mutate_inputs_or_globals(self):
        data, value = sources(), receipt()
        before, old_modes = copy.deepcopy(value), ORDINARY_API.MODES
        with patch("builtins.open", side_effect=AssertionError("pure adapter opened file")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("pure adapter read file")), \
                patch("subprocess.Popen", side_effect=AssertionError("pure adapter spawned")), \
                patch.object(ORDINARY_API, "inspect_provider_dependencies", side_effect=AssertionError("ordinary receipt admission called")):
            self.inspect(value, data)
            ADAPTER.inspect_preprocessed_attributes(cpp(), ordinary=ORDINARY_API)
            ADAPTER.emit_probes(ordinary=ORDINARY_API)
            fresh = types.ModuleType("_declarations_no_import_io")
            exec(compile(BUFFERS[SUBJECT], str(SUBJECT), "exec"), fresh.__dict__)
        self.assertEqual(value, before)
        self.assertEqual(data, sources())
        self.assertIs(ORDINARY_API.MODES, old_modes)
        self.assertFalse(any(name in vars(ADAPTER) for name in ("Path", "os", "subprocess", "importlib")))

    def test_metadata_only_external_bytes_and_capture_status_not_qualified(self):
        value = receipt()
        value["Status"] = "FAIL"
        result = self.inspect(value)
        self.no_credit(result)
        self.assertIs(result["SeedDiscoveryDependencySetCompared"], False)
        self.assertEqual(result["UnverifiedExternalDependencies"],
                         [dict(Path=CAPTURE_ROOT + "/toolchain/include/stdint.h", Sha256="B" * 64)])
        self.assertIs(result["Scope"]["ActualDependencyClosureProven"], False)
        self.assertIs(result["Scope"]["ProviderObjectIdentityProven"], False)
        result["Providers"][0]["CompileFlags"].append("-O2")
        self.assertNotIn("-O2", self.inspect()["Providers"][0]["CompileFlags"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or output.is_relative_to(ROOT)
            or ROOT.is_relative_to(output) or not output.is_relative_to(temporary)):
        parser.error("fresh external TEMP output directory required")
    paths = (Path(__file__).resolve(), SUBJECT, ORDINARY, CORE) + tuple(ROOT / name for name in HEADERS + ORDER)
    report = dict(Status="FAIL", Scope="PURE_CM3_OS_LTO_DECLARATION_ADAPTER_CONTROLS_ONLY", Tests=0,
        ExpectedTestMethods=EXPECTED_METHODS, Errors=0, Failures=0, Skipped=0, SourceHashes={},
        SourceDrift=[], ClosingFilesVerified=0, SourceClosureVerified=False, SyntheticReceipts=True,
        ActualCaptureRead=False, ActualCompilerExecuted=False, ActualELFTested=False, TargetExecuted=False,
        FullABIProof=False, FullSemanticABIProof=False, GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("unoptimized host Python required")
        BUFFERS.update({path: path.read_bytes() for path in paths})
        report["SourceHashes"] = {str(path): sha(raw) for path, raw in BUFFERS.items()}
        for path, expected in PINS.items():
            if sha(BUFFERS[path]) != expected:
                raise ValueError("frozen helper source identity mismatch: " + str(path))
        global ADAPTER, ORDINARY_API
        ADAPTER = types.ModuleType("_os_declarations_subject")
        ADAPTER.__file__ = str(SUBJECT)
        ORDINARY_API = types.ModuleType("_os_declarations_ordinary")
        ORDINARY_API.__file__ = str(ORDINARY)
        def buffered_read(path):
            if path not in (ORDINARY, CORE):
                raise AssertionError("unenrolled helper read: " + str(path))
            return BUFFERS[path]
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("pure controls cannot execute commands")):
            exec(compile(BUFFERS[SUBJECT], str(SUBJECT), "exec"), ADAPTER.__dict__)
            with patch.object(Path, "read_bytes", buffered_read):
                exec(compile(BUFFERS[ORDINARY], str(ORDINARY), "exec"), ORDINARY_API.__dict__)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(DeclarationTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError("exact sixteen implemented methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Errors=len(result.errors), Failures=len(result.failures),
            Skipped=len(result.skipped), Details=[dict(Test=str(case), Error=error)
                for case, error in result.errors + result.failures])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Errors=report["Errors"] + 1, Error=traceback.format_exc())
    finally:
        for path, expected in report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) == expected:
                    report["ClosingFilesVerified"] += 1
                else:
                    report["SourceDrift"].append(path)
            except OSError:
                report["SourceDrift"].append(path)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == len(paths) and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / "results.json"
    receipt.write_bytes((json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("ascii"))
    print("Receipt:", receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
