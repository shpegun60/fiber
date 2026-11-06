"""Synthetic declaration/dependency controls, not compiler or cell evidence.

Run: python -B tools/fixtures/ordinary_final_cell/test_abi.py
Fixtures use explicit independent prototypes and fake nine-provider receipts.
Repository input bytes, both ABI modules and this test are closed after use.
No compiler, process, qualified ELF parser or historical PASS is executed.
"""

import copy
import hashlib
import json
from pathlib import Path
import re
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PROFILES = ("CM0", "CM0PLUS", "CM0PLUSVTOR", "CM3", "CM4", "CM7")
MODES = ("O0", "Og", "O2", "Os", "O3")
INVENTORY = "69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313"
MANIFEST = "BC6B8EADABCAA6637FDD121D03B5CA341EEE31848D7E007D1D027AEE63EC8CBE"
CORE_SHA256 = "F5AA5CE6BD21130249D571D0AA03BD72C735DA04832C2B6DBF13EFD548CB4F4B"
SLOT = "fiber_internal_runtime_current_context_slot"
SOURCE_ROOT = "C:/synthetic/Native/source"
COMMON_HEADERS = (
    "context/context_port_abi.h", "context/context_runtime_port_abi.h",
    "context/context_api_attributes.h", "context/context_api_types.h",
    "context/context_panic.h", "context/context_runtime_state.h",
    "fiber/fiber_api_attributes.h", "fiber/fiber_runtime_port_abi.h",
    "fiber/port/fiber_port_runtime_abi.h",
)
COMMON_SOURCES = (
    "context/context_core.c", "context/context_runtime_state.c", "context/context_panic.c",
    "fiber/port/fiber_port_context_cohort_expectation.c",
    "tools/fixtures/classic_final_image/application.c",
    "tools/fixtures/classic_final_image/startup.S",
)
DIRECTORIES = {"CM0": "ARM_CM0", "CM0PLUS": "ARM_CM0", "CM0PLUSVTOR": "ARM_CM0",
               "CM3": "ARM_CM3", "CM4": "ARM_CM4", "CM7": "ARM_CM7/r0p1"}
COHORTS = {
    "CM0": "cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default",
    "CM0PLUS": "cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default",
    "CM0PLUSVTOR": "cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default",
    "CM3": "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default",
    "CM4": "cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default",
    "CM7": "cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default",
}

# Deliberately independent of the subject's private type and scanner arrays.
FORWARD = (
    "void fiber_port_context_init(CtxrtContextV1 *context, void *stack_begin, void *stack_end, CtxrtEntryFnV1 entry, void *arg);",
    "void fiber_port_runtime_memory_barrier(void);",
    "void fiber_port_panic_wait(void);",
    "void fiber_port_require_scheduler_configuration_environment(void);",
    "void fiber_port_runtime_prepare_start(void);",
    "CtxrtContextV1 *fiber_port_runtime_select_first(void);",
    "void fiber_port_runtime_start_first(CtxrtContextV1 *first);",
    "void fiber_port_runtime_schedule(void);",
)
REVERSE = (
    "CtxrtContextV1 *fiber_internal_runtime_select_scheduler_candidate(CtxrtContextV1 *current);",
    "void fiber_internal_runtime_publish_current_context(CtxrtContextV1 *next);",
    "void fiber_internal_runtime_require_current_context(void);",
    "void fiber_internal_task_return(void);",
)
NAMES = tuple(re.search(r"([A-Za-z_][A-Za-z_0-9]*)\(", row)[1] for row in FORWARD + REVERSE)
ATTRIBUTE = '__attribute__((no_sanitize("address", "undefined", "thread"))) '
BUFFERED = {}
ABI = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def source_order(profile):
    ports = tuple("fiber/port/" + DIRECTORIES[profile] + "/" + name for name in (
        "fiber_port.c", "fiber_port_boot.c", "fiber_port_exception.c"))
    return COMMON_SOURCES[:3] + ports + COMMON_SOURCES[3:]


def setUpModule():
    global ABI
    names = set(COMMON_HEADERS + COMMON_SOURCES)
    for profile in PROFILES:
        names.update(source_order(profile))
    paths = {ROOT / name for name in names}
    paths.update((Path(__file__), HERE / "abi.py", HERE.parent / "cm0_final_cell" / "abi.py"))
    for path in paths:
        BUFFERED[path] = path.read_bytes()
    core_path = HERE.parent / "cm0_final_cell" / "abi.py"
    if sha(BUFFERED[core_path]) != CORE_SHA256:
        raise AssertionError("frozen common ABI helper drift")
    ABI = types.ModuleType("ordinary_cell_abi_test_subject")
    ABI.__file__ = str(HERE / "abi.py")
    exec(compile(BUFFERED[HERE / "abi.py"], ABI.__file__, "exec"), ABI.__dict__)


def tearDownModule():
    drift = [str(path) for path, raw in BUFFERED.items() if path.read_bytes() != raw]
    if drift:
        raise AssertionError("source closure drift: " + repr(drift))


def sources(profile):
    return {name: BUFFERED[ROOT / name] for name in COMMON_HEADERS + source_order(profile)}


def cpp(root="C:/synthetic/Native/source"):
    return ('# 1 "' + root + '/context/context_port_abi.h" 1\n'
            + "\n".join(ATTRIBUTE + declaration for declaration in FORWARD)
            + '\n# 1 "' + root + '/context/context_runtime_port_abi.h" 1\n'
            + "\n".join(ATTRIBUTE + declaration for declaration in REVERSE) + "\n")


def encoded(value):
    return json.dumps(value, sort_keys=True).encode("ascii")


def receipt(profile, mode="O2"):
    fixture = sources(profile)
    records = []
    for index, name in enumerate(source_order(profile)):
        headers = {name}
        if index <= 4:
            headers.update(("context/context_port_abi.h", "context/context_api_attributes.h",
                            "context/context_api_types.h", "fiber/fiber_api_attributes.h"))
        if index in (0, 1, 3, 4):
            headers.add("context/context_runtime_port_abi.h")
        dependencies = [{"Path": SOURCE_ROOT + "/" + header, "Sha256": sha(fixture[header])}
                        for header in sorted(headers)]
        dependencies.append({"Path": "C:/synthetic/gcc/include/stdint.h", "Sha256": "B" * 64})
        stem = name.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        records.append({"Source": SOURCE_ROOT + "/" + name, "SourceSha256": sha(fixture[name]),
                        "Object": "C:/synthetic/Native/objects/" + format(index, "02d") + "-" + stem + ".o",
                        "ObjectSha256": "A" * 64, "CompileDependenciesVerified": True,
                        "Dependencies": dependencies, "ActualCompileDependencies": copy.deepcopy(dependencies)})
    return {"Profile": profile, "Cohort": COHORTS[profile], "Mode": mode,
            "SourceInventorySha256": INVENTORY, "Linkage": "direct", "LTO": False,
            "TranslationUnits": 9, "Sources": records}


class AbiTests(unittest.TestCase):
    def scope_false(self, scope):
        self.assertIs(type(scope["RequiredCellsSatisfied"]), int)
        self.assertEqual(scope["RequiredCellsSatisfied"], 0)
        for key, value in scope.items():
            if key != "RequiredCellsSatisfied":
                self.assertIs(value, False, key)
        for key in ("FullABIProof", "FullSemanticABIProof", "CompilerExecuted",
                    "CellContractSatisfied", "RequiredCellSatisfied", "GlobalFreezeQualified",
                    "DeclarationTypesProven", "PublishedAttributeBundleProven", "CpuExecution"):
            self.assertIn(key, scope)

    def inspect_receipt(self, profile, value):
        return ABI.inspect_provider_dependencies(profile, sources(profile), encoded(value), source_root=SOURCE_ROOT)

    def test_exact_profiles_and_target_guards(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                facts = ABI.profile_contract(profile)
                self.assertEqual(facts["Cohort"], COHORTS[profile])
                self.assertEqual(facts["SourceInventorySha256"], INVENTORY)
                self.assertEqual(facts["InventoryManifestSha256"], MANIFEST)
                expected_arch = "6M" if profile.startswith("CM0") else ("7M" if profile == "CM3" else "7EM")
                body = ABI.emit_probes(profile)["types.c"]["Source"]
                self.assertIn("!defined(__ARM_ARCH_" + expected_arch + "__)", body)
                self.assertIn("!defined(__thumb__)", body)
                if profile in ("CM4", "CM7"):
                    self.assertIn("!defined(__ARM_PCS_VFP)", body)
                    self.assertIn("!defined(__ARM_FP)", body)
                    self.assertIn("((__ARM_FP & 8) != " + ("8" if profile == "CM7" else "0") + ")", body)
                else:
                    self.assertIn("|| defined(__ARM_PCS_VFP) || defined(__ARM_FP)", body)
                self.assertEqual(facts["FloatABI"], "hard" if profile in ("CM4", "CM7") else "soft")
        for bad in (None, True, 0, 1.0, "cm0", "CM0PLUS-NOVTOR", "CM33", {}, {"Profile": "CM0"}):
            for function in (ABI.profile_contract, ABI.emit_probes):
                with self.subTest(bad=bad, function=function.__name__), self.assertRaises(ABI.Rejected):
                    function(bad)

    def test_independently_spelled_type_oracle(self):
        signatures = (
            "typedef void (*cm0_expected_entry)(void *);",
            "typedef struct FiberContext *(*cm0_expected_dispatch)(struct FiberContext *, void *);",
            "typedef void (*cm0_expected_init)(struct FiberContext *, void *, void *, cm0_expected_entry, void *);",
            "typedef void (*cm0_expected_void)(void);",
            "typedef struct FiberContext *(*cm0_expected_first)(void);",
            "typedef void (*cm0_expected_noreturn_void)(void) __attribute__((noreturn));",
            "typedef void (*cm0_expected_noreturn_start)(struct FiberContext *) __attribute__((noreturn));",
            "typedef struct FiberContext *(*cm0_expected_select)(struct FiberContext *);",
            "typedef void (*cm0_expected_publish)(struct FiberContext *);",
        )
        expected_types = ("init", "void", "noreturn_void", "void", "void", "first", "noreturn_start", "void",
                          "select", "publish", "void", "noreturn_void")
        for profile in PROFILES:
            body = ABI.emit_probes(profile)["types.c"]["Source"]
            for signature in signatures:
                self.assertIn(signature, body)
            for index, (name, expected) in enumerate(zip(NAMES, expected_types)):
                self.assertIn("__builtin_types_compatible_p(__typeof__(&" + name + "), cm0_expected_" + expected + ")", body)
                self.assertIn("cm0_abi_reference_" + str(index) + " __attribute__((used)) = &" + name + ";", body)
            self.assertIn("!__builtin_types_compatible_p(cm0_expected_noreturn_void, cm0_expected_void)", body)
            self.assertIn("!__builtin_types_compatible_p(cm0_expected_noreturn_start, cm0_expected_start)", body)
            self.assertIn("FIBER_RUNTIME_PORT_ABI_RETAIN_V1();", body)
            self.assertIn("FIBER_RUNTIME_PORT_ABI_VERSION == 1u", body)

    def test_attribute_queries_and_sanitizer_limitation(self):
        queries = ("noinline", "noipa", "noclone", "no_icf", "used", "no_instrument_function",
                   "no_stack_protector", "no_profile_instrument_function", "no_sanitize_coverage",
                   'target("general-regs-only")')
        noreturn_names = ("fiber_port_panic_wait", "fiber_port_runtime_start_first", "fiber_internal_task_return")
        for profile in PROFILES:
            probe = ABI.emit_probes(profile)["attributes.c"]
            for name in NAMES:
                for query in queries:
                    self.assertIn("__builtin_has_attribute(" + name + ", " + query + ")", probe["Source"])
            for name in noreturn_names:
                self.assertIn("__builtin_has_attribute(" + name + ", noreturn)", probe["Source"])
            self.assertNotRegex(probe["Source"], r"__builtin_has_attribute\([^\n]*, no_sanitize\(")
            self.assertEqual(len(probe["UnprovenAttributes"]), 1)
            self.assertIn("ICE", str(probe["UnprovenAttributes"]))
            self.scope_false(probe["Scope"])

    def test_exact_five_sources_and_specific_slot_negatives(self):
        for profile in PROFILES:
            probes = ABI.emit_probes(profile)
            self.assertEqual(tuple(probes), ("types.c", "attributes.c", "slot_read.c", "slot_write.c", "slot_address.c"))
            for name, probe in probes.items():
                self.assertIs(probe["ExpectedCompile"], name in ("types.c", "attributes.c"))
                self.assertEqual(probe["SourceSha256"], sha(probe["Source"].encode("ascii")))
                self.assertEqual(probe["RequiredCFlags"], ["-std=gnu11", "-Werror=incompatible-pointer-types", "-Werror=attributes"])
                self.assertIs(probe["CompilerExecuted"], False)
                self.assertIs(probe["CompileOnly"], True)
            for kind, parameters, statement in (
                    ("read", "void", "(void)" + SLOT + ";"),
                    ("write", "struct FiberContext *value", SLOT + " = value;"),
                    ("address", "void", "(void)&" + SLOT + ";")):
                probe = probes["slot_" + kind + ".c"]
                self.assertEqual(probe["DiagnosticIdentifier"], SLOT)
                self.assertIn("void cm0_abi_slot_" + kind + "(" + parameters + ")", probe["Source"])
                self.assertIn(statement, probe["Source"])
                self.assertNotIn("return ", probe["Source"])

    def test_all_profile_source_identities_and_owners(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                result = ABI.inspect_sources(profile, sources(profile))
                self.assertEqual(result["Profile"], profile)
                self.assertEqual(result["Cohort"], COHORTS[profile])
                self.assertEqual(len(result["Sources"]), 18)
                self.assertEqual({row["Path"] for row in result["Sources"]}, set(COMMON_HEADERS + source_order(profile)))
                self.assertEqual(ABI.source_order(profile), source_order(profile))
                owners = result["ExpectedOwners"]
                self.assertEqual([row["Name"] for row in owners], list(NAMES))
                self.assertEqual([row["ObjectIndex"] for row in owners], [4, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 0])
                self.assertEqual([row["Direction"] for row in owners], ["forward"] * 8 + ["reverse"] * 4)
                self.scope_false(result["Scope"])

    def test_source_identity_tampering_and_aliases_reject(self):
        for profile in PROFILES:
            original = sources(profile)
            for name in ("context/context_port_abi.h", source_order(profile)[3]):
                for action in ("missing", "changed", "text"):
                    data = original.copy()
                    if action == "missing":
                        del data[name]
                    else:
                        data[name] = data[name] + b" " if action == "changed" else data[name].decode("ascii")
                    with self.subTest(profile=profile, name=name, action=action), self.assertRaises(ABI.Rejected):
                        ABI.inspect_sources(profile, data)
            for bad_name in ("../bad.h", "context/./bad.h", "/bad.h", "context\\bad.h", "C:/bad.h",
                             "Context/context_port_abi.h"):
                data = original.copy()
                data[bad_name] = b"synthetic"
                with self.subTest(profile=profile, path=bad_name), self.assertRaises(ABI.Rejected):
                    ABI.inspect_sources(profile, data)
        with self.assertRaises(ABI.Rejected):
            ABI.inspect_sources("CM4", sources("CM3"))

    def test_thirty_ordinary_provider_receipts(self):
        for profile in PROFILES:
            for mode in MODES:
                with self.subTest(profile=profile, mode=mode):
                    result = self.inspect_receipt(profile, receipt(profile, mode))
                    self.assertEqual(result["Mode"], mode)
                    self.assertEqual(result["Cohort"], COHORTS[profile])
                    self.assertEqual(result["ReceiptSha256"], sha(encoded(receipt(profile, mode))))
                    self.assertEqual(len(result["Providers"]), 9)
                    self.assertEqual(len(result["UnverifiedExternalDependencies"]), 1)
                    self.assertIs(result["DeclaredProviderDependenciesBound"], True)
                    self.scope_false(result["Scope"])

    def test_receipt_scope_types_and_json_reject(self):
        mutations = (("Profile", "CM3"), ("Cohort", COHORTS["CM3"]), ("Mode", "O2-lto"),
                     ("Mode", True), ("Mode", 2), ("Linkage", "archive"),
                     ("LTO", 0), ("LTO", True), ("TranslationUnits", True),
                     ("TranslationUnits", 9.0), ("SourceInventorySha256", "0" * 64))
        for field, value in mutations:
            data = receipt("CM0")
            data[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ABI.Rejected):
                self.inspect_receipt("CM0", data)
        for raw in (b"[]", b"null", b"{", b"\xff", b'{"X":1,"x":2}', b'{"a":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ABI.Rejected):
                ABI.inspect_provider_dependencies("CM0", sources("CM0"), raw, source_root=SOURCE_ROOT)
        for root in ("C:/synthetic/Native", "C:relative/source", "C:/bad/../source", True):
            with self.subTest(root=root), self.assertRaises(ABI.Rejected):
                ABI.inspect_provider_dependencies("CM0", sources("CM0"), encoded(receipt("CM0")), source_root=root)

    def test_provider_dependency_and_object_near_misses(self):
        for profile in ("CM0", "CM3", "CM4", "CM7"):
            for case in ("order", "count", "sourcehash", "object", "objecthash", "verified", "actual",
                         "own", "header", "alias", "capturedhash", "externalconflict"):
                value = receipt(profile)
                rows = value["Sources"]
                if case == "order":
                    rows[3], rows[4] = rows[4], rows[3]
                elif case == "count":
                    rows.pop()
                elif case == "sourcehash":
                    rows[3]["SourceSha256"] = "0" * 64
                elif case == "object":
                    rows[3]["Object"] = rows[4]["Object"]
                elif case == "objecthash":
                    rows[3]["ObjectSha256"] = True
                elif case == "verified":
                    rows[3]["CompileDependenciesVerified"] = 1
                elif case == "actual":
                    rows[3]["ActualCompileDependencies"].pop()
                elif case in ("own", "header"):
                    target = source_order(profile)[3] if case == "own" else "context/context_port_abi.h"
                    for key in ("Dependencies", "ActualCompileDependencies"):
                        rows[3][key] = [row for row in rows[3][key] if row["Path"] != SOURCE_ROOT + "/" + target]
                elif case == "alias":
                    for key in ("Dependencies", "ActualCompileDependencies"):
                        rows[3][key].append(dict(rows[3][key][0]))
                elif case == "capturedhash":
                    for key in ("Dependencies", "ActualCompileDependencies"):
                        rows[3][key][0]["Sha256"] = "0" * 64
                else:
                    for key in ("Dependencies", "ActualCompileDependencies"):
                        rows[3][key][-1]["Sha256"] = "0" * 64
                with self.subTest(profile=profile, case=case), self.assertRaises(ABI.Rejected):
                    self.inspect_receipt(profile, value)

    def test_cpp_common_oracle_and_lexical_origins(self):
        for profile in PROFILES:
            for root in ("C:/synthetic/Native/source", "C:/synthetic/Native/source/context/..",
                         "/synthetic/Native/source", "relative/source"):
                with self.subTest(profile=profile, root=root):
                    raw = cpp(root).encode("ascii")
                    result = ABI.inspect_preprocessed_attributes(profile, raw)
                    self.assertEqual(result["Profile"], profile)
                    self.assertEqual(result["Cohort"], COHORTS[profile])
                    self.assertNotIn("Mode", result)
                    self.assertEqual(result["AllowedModes"], list(MODES))
                    self.assertEqual([row["Name"] for row in result["Declarations"]], list(NAMES))
                    self.assertEqual((result["ForwardDeclarations"], result["ReverseDeclarations"]), (8, 4))
                    self.assertEqual(result["PreprocessedSha256"], sha(raw))
                    self.assertIs(result["AuthenticatedHeaderBindingRequired"], True)
                    self.assertIs(result["SameAttemptReflectionRequired"], True)
                    self.scope_false(result["Scope"])

    def test_cpp_fail_closed_near_misses(self):
        original = cpp()
        candidates = (
            original.replace(ATTRIBUTE + FORWARD[0], "", 1),
            original.replace(ATTRIBUTE + FORWARD[0], (ATTRIBUTE + FORWARD[0]) * 2, 1),
            original.replace('"address", "undefined", "thread"', '"address", "thread", "undefined"', 1),
            original.replace(ATTRIBUTE, "", 1),
            original.replace("void *arg", "const void *arg", 1),
            original.replace("context/context_port_abi.h", "fiber/context_port_abi.h", 1),
            original.replace("C:/synthetic/Native/source/context/context_runtime_port_abi.h",
                             "C:/foreign/context/context_runtime_port_abi.h", 1),
            original.replace("C:/synthetic/Native/source", "../unbound", 1),
            original + "\x00",
        )
        for profile in PROFILES:
            for index, candidate in enumerate(candidates):
                with self.subTest(profile=profile, case=index), self.assertRaises(ABI.Rejected):
                    ABI.inspect_preprocessed_attributes(profile, candidate.encode("ascii"))
        for raw in (None, "not bytes", b"", b"\xff"):
            with self.subTest(raw=raw), self.assertRaises(ABI.Rejected):
                ABI.inspect_preprocessed_attributes("CM4", raw)

    def test_no_io_no_global_mutation_fresh_records_and_false_claims(self):
        core_before = (ABI._core.COHORT, ABI._core.SOURCE_ORDER, ABI._core.SOURCE_HASHES, ABI._core._TARGET)
        fixture = sources("CM7")
        before = copy.deepcopy(fixture)
        raw_receipt = encoded(receipt("CM7", "Os"))
        raw_cpp = cpp().encode("ascii")
        with mock.patch("builtins.open", side_effect=AssertionError("unexpected open")), \
             mock.patch.object(Path, "open", side_effect=AssertionError("unexpected Path.open")), \
             mock.patch.object(Path, "resolve", side_effect=AssertionError("unexpected filesystem resolution")):
            probes = ABI.emit_probes("CM7")
            records = [ABI.inspect_sources("CM7", fixture),
                       ABI.inspect_provider_dependencies("CM7", fixture, raw_receipt, source_root=SOURCE_ROOT),
                       ABI.inspect_preprocessed_attributes("CM7", raw_cpp)]
        self.assertEqual(fixture, before)
        self.assertEqual(core_before, (ABI._core.COHORT, ABI._core.SOURCE_ORDER, ABI._core.SOURCE_HASHES, ABI._core._TARGET))
        for record in records + list(probes.values()):
            self.scope_false(record["Scope"])
            self.assertNotIn("PASS", record.values())
            record["Scope"]["FullSemanticABIProof"] = True
        probes["types.c"]["Source"] = "mutated returned copy"
        probes["types.c"]["TargetContract"]["Profile"] = "foreign"
        self.assertNotEqual(ABI.emit_probes("CM7")["types.c"]["Source"], "mutated returned copy")
        self.scope_false(ABI.inspect_sources("CM7", fixture)["Scope"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
