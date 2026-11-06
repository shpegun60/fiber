"""Pure ABI-oracle controls; synthetic CPP/receipts are not compiler evidence.

Run with the host Python: python -B tools/fixtures/cm0_final_cell/test_abi.py
No compiler, ELF parser, child process, historical receipt or target is used.
The current repository source fixtures, subject and tests are hash-closed.
"""

import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
ABI_PATH = HERE / "abi.py"
ABI_SHA256 = "F5AA5CE6BD21130249D571D0AA03BD72C735DA04832C2B6DBF13EFD548CB4F4B"
COHORT = "cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default"
INVENTORY = "69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313"
SLOT = "fiber_internal_runtime_current_context_slot"

# Independent fixtures, not the subject's signature/owner/source arrays.
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
NAMES = tuple(re.search(r"([A-Za-z_][A-Za-z_0-9]*)\(", text)[1]
              for text in FORWARD + REVERSE)
SOURCE_ORDER = (
    "context/context_core.c", "context/context_runtime_state.c",
    "context/context_panic.c", "fiber/port/ARM_CM0/fiber_port.c",
    "fiber/port/ARM_CM0/fiber_port_boot.c", "fiber/port/ARM_CM0/fiber_port_exception.c",
    "fiber/port/fiber_port_context_cohort_expectation.c",
    "tools/fixtures/classic_final_image/application.c",
    "tools/fixtures/classic_final_image/startup.S",
)
FIXTURE_PATHS = (
    "context/context_port_abi.h", "context/context_runtime_port_abi.h",
    "context/context_api_attributes.h", "context/context_api_types.h",
    "context/context_panic.h", "context/context_runtime_state.h",
    "fiber/fiber_api_attributes.h", "fiber/fiber_runtime_port_abi.h",
    "fiber/port/fiber_port_runtime_abi.h",
) + SOURCE_ORDER
FORWARD_HEADER = '# 1 "C:/synthetic/Native/source/context/context_port_abi.h" 1\n'
REVERSE_HEADER = '# 1 "C:/synthetic/Native/source/context/context_runtime_port_abi.h" 1\n'
ATTRIBUTE = '__attribute__((noinline)) __attribute__((no_sanitize("address", "undefined", "thread"))) '
ATTRIBUTE_ONLY = '__attribute__((no_sanitize("address", "undefined", "thread"))) '
SOURCE_ROOT = "C:/synthetic/Native/source"
EXTERNAL = "C:/synthetic/toolchain/include/stdint.h"
BUFFERS = {}
SOURCE_HASHES = {}
ABI = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def setUpModule():
    global ABI
    for path in (Path(__file__), ABI_PATH, *(REPO / name for name in FIXTURE_PATHS)):
        data = path.read_bytes()
        BUFFERS[path] = data
        SOURCE_HASHES[str(path)] = sha(data)
    if SOURCE_HASHES[str(ABI_PATH)] != ABI_SHA256:
        raise AssertionError("subject differs from the pinned ABI freeze")
    ABI = types.ModuleType("cm0_cell_abi_test_subject")
    ABI.__file__ = str(ABI_PATH)
    exec(compile(BUFFERS[ABI_PATH], str(ABI_PATH), "exec"), ABI.__dict__)


def tearDownModule():
    drift = [str(path) for path, data in BUFFERS.items() if path.read_bytes() != data]
    if drift:
        raise AssertionError("source fixture drift: " + repr(drift))


def fixture_sources():
    return {name: BUFFERS[REPO / name] for name in FIXTURE_PATHS}


def cpp_fixture():
    return (FORWARD_HEADER + "\n".join(ATTRIBUTE + declaration for declaration in FORWARD)
            + "\n" + REVERSE_HEADER
            + "\n".join(ATTRIBUTE + declaration for declaration in REVERSE) + "\n")


def encoded(value):
    return json.dumps(value, sort_keys=True).encode("ascii")


def provider_receipt(sources):
    """Declared dependency fixture only; fake object/external bytes are NOT proved."""
    records = []
    for index, relative in enumerate(SOURCE_ORDER):
        names = {relative}
        if index <= 4:
            names.update(("context/context_port_abi.h", "context/context_api_attributes.h",
                          "context/context_api_types.h", "fiber/fiber_api_attributes.h"))
        if index in (0, 1, 3, 4):
            names.add("context/context_runtime_port_abi.h")
        if index in (0, 1, 2):
            names.add("context/context_panic.h")
        if index in (0, 1):
            names.add("context/context_runtime_state.h")
        if index in (3, 4):
            names.update(("fiber/fiber_runtime_port_abi.h", "fiber/port/fiber_port_runtime_abi.h"))
        dependencies = [{"Path": SOURCE_ROOT + "/" + name, "Sha256": sha(sources[name])}
                        for name in sorted(names)]
        dependencies.append({"Path": EXTERNAL, "Sha256": sha(b"unverified synthetic external bytes")})
        stem = relative.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        records.append({"Source": SOURCE_ROOT + "/" + relative,
                        "SourceSha256": sha(sources[relative]),
                        "Object": "C:/synthetic/Native/objects/" + format(index, "02d") + "-" + stem + ".o",
                        "ObjectSha256": "A" * 64, "CompileDependenciesVerified": True,
                        "Dependencies": dependencies,
                        "ActualCompileDependencies": copy.deepcopy(dependencies)})
    return {"Profile": "CM0", "Mode": "O2", "Cohort": COHORT, "Linkage": "direct",
            "LTO": False, "TranslationUnits": 9, "SourceInventorySha256": INVENTORY,
            "Sources": records}


class AbiTests(unittest.TestCase):
    def assert_scope(self, record):
        scope = record["Scope"]
        self.assertIs(type(scope["RequiredCellsSatisfied"]), int)
        self.assertEqual(scope["RequiredCellsSatisfied"], 0)
        required = {
            "CompilerExecuted", "DeclarationTypesProven", "DeclarationAttributesProven",
            "PublishedAttributeBundleProven", "ProviderObjectIdentityProven",
            "ActualDependencyClosureProven", "SourceBodyIsolationProven",
            "GeneratedSlotIsolationProven", "ColdAnchorReadProven", "FullABIProof",
            "FullSemanticABIProof", "WholeProviderEquivalence", "InstructionEquivalence",
            "PolicyEquivalence", "SourceIRProof", "SourceToMachineSemanticProof",
            "KernelRuntimeProof", "HandlerRoutingProven", "CpuExecution", "BoardExecution",
            "HostedCIQualified", "ArchiveQualification", "GlobalFreezeQualified",
            "CellContractSatisfied", "RequiredCellSatisfied",
        }
        self.assertEqual(set(scope), required | {"RequiredCellsSatisfied"})
        for name in required:
            self.assertIs(scope[name], False, name)

    def test_cpp_four_independent_acceptances(self):
        base = cpp_fixture()
        variants = {
            "fixed_twelve": base,
            "CRLF_whitespace": base.replace("\n", "\r\n"),
            "comments_and_probe_expressions": base + '''# 1 "C:/synthetic/types.c" 2
/* no_sanitize(irrelevant) */
_Static_assert(__builtin_types_compatible_p(__typeof__(&fiber_port_runtime_schedule), expected), "type");
static const void *p = &fiber_port_runtime_schedule;
static void anchor(void) { (void)*(volatile const unsigned char *)&fiber_internal_runtime_port_abi_v1_anchor; }
''',
            "combined_attribute_group": base.replace(
                ATTRIBUTE, '__attribute__((noinline, no_sanitize("address", "undefined", "thread"))) '),
        }
        self.assertEqual(len(variants), 4)
        for name, text in variants.items():
            with self.subTest(name=name):
                data = text.encode("ascii")
                record = ABI.inspect_preprocessed_attributes(data)
                self.assertEqual(record["PreprocessedSha256"], sha(data))
                self.assertEqual((record["ForwardDeclarations"], record["ReverseDeclarations"]), (8, 4))
                self.assertIs(type(record["ForwardDeclarations"]), int)
                self.assertIs(type(record["ReverseDeclarations"]), int)
                self.assertEqual(tuple(row["Name"] for row in record["Declarations"]), NAMES)
                for row in record["Declarations"]:
                    self.assertEqual(row["NoSanitizeArguments"], ["address", "undefined", "thread"])
                    self.assertIs(type(row["Line"]), int)
                for flag in ("LineMarkerProvenanceOnly", "AcceptedCompileRequired",
                             "SameAttemptReflectionRequired", "AuthenticatedHeaderBindingRequired"):
                    self.assertIs(record[flag], True)
                self.assert_scope(record)
        normalization_cases = (
            (r"C:\synthetic\Native\source/context/./context_port_abi.h",
             r"C:\synthetic\Native\source/context/unused/../context_runtime_port_abi.h",
             "C:/synthetic/Native/source/context/"),
            ("/synthetic/source/context/./context_port_abi.h",
             "/synthetic/source/context/temporary/../context_runtime_port_abi.h",
             "/synthetic/source/context/"),
            ("context/./context_port_abi.h", "include/../context/context_runtime_port_abi.h", "context/"),
            (r"\\server\share\source\context\.\context_port_abi.h",
             r"\\server\share\source/context/temporary/../context_runtime_port_abi.h",
             "//server/share/source/context/"),
        )
        for forward, reverse, expected_prefix in normalization_cases:
            with self.subTest(normalized_marker=forward):
                text = base.replace(FORWARD_HEADER, "# 1 " + json.dumps(forward) + " 1\n")
                text = text.replace(REVERSE_HEADER, "# 1 " + json.dumps(reverse) + " 1\n")
                system_prefix = '# 1 ' + json.dumps(r"C:\toolchain\bin\../lib/gcc/stdint.h") + ' 1 3 4\n'
                system_prefix += 'typedef unsigned int uint32_t;\n'
                system_prefix += '# 1 "C:/synthetic/cmsis/cmsis_gcc.h" 1\n'
                system_prefix += '#pragma GCC diagnostic push\n#pragma GCC diagnostic ignored "-Wattributes"\n'
                system_prefix += 'struct __attribute__((packed)) T { unsigned int v; };\n#pragma GCC diagnostic pop\n'
                record = ABI.inspect_preprocessed_attributes((system_prefix + text).encode("ascii"))
                self.assertEqual(record["CanonicalHeaders"], {
                    "forward": expected_prefix + "context_port_abi.h",
                    "reverse": expected_prefix + "context_runtime_port_abi.h",
                })
                self.assert_scope(record)
        # Without an expected source_root input, paired markers cannot establish
        # header authenticity. An escape to a different shared root must remain
        # visible for the mandatory OUTER dependency/path comparison, not rebase.
        escaped = base.replace("C:/synthetic/Native/source/", "C:/synthetic/Native/source/../../elsewhere/source/")
        record = ABI.inspect_preprocessed_attributes(escaped.encode("ascii"))
        self.assertEqual(record["CanonicalHeaders"]["forward"],
                         "C:/synthetic/elsewhere/source/context/context_port_abi.h")
        self.assertNotEqual(record["CanonicalHeaders"]["forward"], SOURCE_ROOT + "/context/context_port_abi.h")
        self.assertIs(record["AuthenticatedHeaderBindingRequired"], True)
        self.assert_scope(record)

    def test_cpp_twenty_six_fail_closed_controls(self):
        base = cpp_fixture()
        variants = {
            "missing_declaration": base.replace(ATTRIBUTE + FORWARD[0] + "\n", "", 1),
            "duplicate_declaration": base + FORWARD_HEADER + ATTRIBUTE + FORWARD[0] + "\n",
            "missing_attribute": base.replace(ATTRIBUTE, "__attribute__((noinline)) ", 1),
            "unrelated_function_attribute": base.replace(ATTRIBUTE, "__attribute__((noinline)) ", 1)
                + FORWARD_HEADER + ATTRIBUTE + "void unrelated(void);\n",
            "duplicate_no_sanitize": base.replace(ATTRIBUTE, ATTRIBUTE + ATTRIBUTE_ONLY, 1),
            "wrong_argument": base.replace('"thread"', '"memory"', 1),
            "missing_argument": base.replace(', "thread"', "", 1),
            "extra_argument": base.replace('"thread"', '"thread", "kernel-address"', 1),
            "reordered_arguments": base.replace('"address", "undefined"', '"undefined", "address"', 1),
            "adjacent_string_spelling": base.replace('"address"', '"add" "ress"', 1),
            "comment_only_attribute": base.replace(ATTRIBUTE, "/* " + ATTRIBUTE + " */ ", 1),
            "wrong_header": base.replace("context/context_port_abi.h", "context/not_port_abi.h", 1),
            "different_header_root": base.replace("source/context/context_runtime_port_abi.h",
                                                  "different/context/context_runtime_port_abi.h", 1),
            "split_header": base.replace(ATTRIBUTE + FORWARD[0],
                ATTRIBUTE + '\n# 2 "C:/other/header.h"\n' + FORWARD[0], 1),
            "no_markers": base.replace(FORWARD_HEADER, "").replace(REVERSE_HEADER, ""),
            "malformed_marker": base.replace("# 1 ", "# nope ", 1),
            "relative_root_escape": base.replace("C:/synthetic/Native/", "../escape/Native/", 1),
            "function_definition": base.replace(FORWARD[0], FORWARD[0][:-1] + " {}", 1),
            "wrong_prototype": base.replace("CtxrtContextV1 *context", "void *context", 1),
            "attribute_on_parameter": base.replace(ATTRIBUTE + FORWARD[0],
                "void fiber_port_context_init(" + ATTRIBUTE
                + "CtxrtContextV1 *context, void *stack_begin, void *stack_end, CtxrtEntryFnV1 entry, void *arg);", 1),
            "aliased_attribute_spelling": base.replace("no_sanitize(", "__no_sanitize__(", 1),
            "unclosed_comment": base + "/*",
            "nonbytes_none": None,
            "nonbytes_bool": False,
            "nonbytes_bytearray": bytearray(base.encode("ascii")),
            "NUL": base + "\x00",
        }
        self.assertEqual(len(variants), 26)
        for name, value in variants.items():
            with self.subTest(name=name):
                data = value.encode("ascii") if type(value) is str else value
                with self.assertRaises(ABI.Rejected):
                    ABI.inspect_preprocessed_attributes(data)
        additional = {
            "one_header_root_escape": base.replace(
                "C:/synthetic/Native/source/context/context_port_abi.h",
                "C:/synthetic/Native/source/context/../../elsewhere/context/context_port_abi.h", 1),
            "suffix_is_not_origin": base.replace(
                "context/context_port_abi.h", "context/context_port_abi.h/../foreign.h", 1),
            "bare_basename_is_not_origin": base.replace(
                "source/context/context_port_abi.h", "source/foreign/../context_port_abi.h", 1),
            "drive_relative": base.replace("C:/synthetic/", "C:synthetic/", 1),
            "canonical_header_diagnostic_pragma": base.replace(
                FORWARD_HEADER, FORWARD_HEADER + '#pragma GCC diagnostic ignored "-Wattributes"\n', 1),
            "unknown_pragma": '# 1 "C:/synthetic/cmsis.h"\n#pragma GCC target("thumb")\n' + base,
        }
        for name, text in additional.items():
            with self.subTest(marker_origin=name), self.assertRaises(ABI.Rejected):
                ABI.inspect_preprocessed_attributes(text.encode("ascii"))

    def test_cpp_current_header_fixture_and_thirteen_rejections(self):
        # Independently extract the captured header spelling, not the subject's
        # private expected-signature table. This synthetic expansion is NOT GCC.
        parts = []
        for relative, marker, expected_count in (
            ("context/context_port_abi.h", FORWARD_HEADER, 8),
            ("context/context_runtime_port_abi.h", REVERSE_HEADER, 4),
        ):
            header = BUFFERS[REPO / relative].decode("utf-8")
            declarations = re.findall(
                r"(?:CTXRT_API_NORETURN\s+)?CTXRT_API_ATTR_SENSITIVE\s+CTXRT_GENERAL_REGS_ONLY\s+([^;]+;)", header)
            self.assertEqual(len(declarations), expected_count)
            parts.append(marker + "\n".join(ATTRIBUTE_ONLY + declaration for declaration in declarations) + "\n")
        fixture = "".join(parts)
        record = ABI.inspect_preprocessed_attributes(fixture.encode("ascii"))
        self.assertEqual(tuple(row["Name"] for row in record["Declarations"]), NAMES)
        positions = [match.start() for match in re.finditer(re.escape(ATTRIBUTE_ONLY), fixture)]
        self.assertEqual(len(positions), 12)
        for index, position in enumerate(positions):
            with self.subTest(missing_attribute_index=index):
                mutant = fixture[:position] + "__attribute__((noinline)) " + fixture[position + len(ATTRIBUTE_ONLY):]
                with self.assertRaisesRegex(ABI.Rejected, "exact single no_sanitize argument list"):
                    ABI.inspect_preprocessed_attributes(mutant.encode("ascii"))
        split = fixture.replace(ATTRIBUTE_ONLY, ATTRIBUTE_ONLY + '\n# 2 "C:/other/header.h"\n', 1)
        with self.assertRaisesRegex(ABI.Rejected, "split declaration/header provenance"):
            ABI.inspect_preprocessed_attributes(split.encode("ascii"))

    def test_exact_five_probe_records_and_independent_types(self):
        probes = ABI.emit_probes()
        self.assertEqual(set(probes), {"types.c", "attributes.c", "slot_read.c", "slot_write.c", "slot_address.c"})
        for name, record in probes.items():
            self.assertEqual(set(record), {"Source", "SourceSha256", "ExpectedCompile", "DiagnosticIdentifier",
                                           "RequiredCFlags", "CompileOnly", "CompilerExecuted", "UnprovenAttributes"})
            self.assertEqual(record["SourceSha256"], sha(record["Source"].encode("ascii")))
            self.assertIs(record["CompileOnly"], True)
            self.assertIs(record["CompilerExecuted"], False)
            self.assertIs(record["ExpectedCompile"], not name.startswith("slot_"))
            self.assertEqual(record["RequiredCFlags"], ["-std=gnu11", "-Werror=incompatible-pointer-types", "-Werror=attributes"])
        source = probes["types.c"]["Source"]
        for expected in (
            "typedef void (*cm0_expected_entry)(void *);",
            "typedef struct FiberContext *(*cm0_expected_dispatch)(struct FiberContext *, void *);",
            "typedef void (*cm0_expected_init)(struct FiberContext *, void *, void *, cm0_expected_entry, void *);",
            "typedef void (*cm0_expected_void)(void);",
            "typedef struct FiberContext *(*cm0_expected_first)(void);",
            "typedef void (*cm0_expected_start)(struct FiberContext *);",
            "typedef void (*cm0_expected_noreturn_void)(void) __attribute__((noreturn));",
            "typedef void (*cm0_expected_noreturn_start)(struct FiberContext *) __attribute__((noreturn));",
            "typedef struct FiberContext *(*cm0_expected_select)(struct FiberContext *);",
            "typedef void (*cm0_expected_publish)(struct FiberContext *);",
        ):
            self.assertIn(expected, source)
        typedefs = [line for line in source.splitlines() if line.startswith("typedef ")]
        self.assertEqual(len(typedefs), 10)
        self.assertTrue(all("Ctxrt" not in line and "__typeof__" not in line for line in typedefs))
        expected_types = (
            "cm0_expected_init", "cm0_expected_void", "cm0_expected_noreturn_void",
            "cm0_expected_void", "cm0_expected_void", "cm0_expected_first",
            "cm0_expected_noreturn_start", "cm0_expected_void", "cm0_expected_select",
            "cm0_expected_publish", "cm0_expected_void", "cm0_expected_noreturn_void",
        )
        references = re.findall(r"static (\w+) const cm0_abi_reference_(\d+) __attribute__\(\(used\)\) = &(\w+);", source)
        self.assertEqual(references, [(expected_types[index], str(index), name)
                                      for index, name in enumerate(NAMES)])
        for name, expected in zip(NAMES, expected_types):
            self.assertIn("__builtin_types_compatible_p(__typeof__(&" + name + "), " + expected + ")", source)
        for suffix in ("void", "start"):
            self.assertIn("!__builtin_types_compatible_p(cm0_expected_noreturn_" + suffix
                          + ", cm0_expected_" + suffix + ")", source)
        self.assertIn("FIBER_RUNTIME_PORT_ABI_VERSION == 1u", source)
        self.assertIn("const unsigned char *", source)
        self.assertIn("FIBER_RUNTIME_PORT_ABI_RETAIN_V1();", source)

    def test_attribute_queries_and_three_precise_slot_negatives(self):
        probes = ABI.emit_probes()
        attribute_source = probes["attributes.c"]["Source"]
        queries = (
            "noinline", "noipa", "noclone", "no_icf", "used", "no_instrument_function",
            "no_stack_protector", "no_profile_instrument_function", "no_sanitize_coverage",
            'target("general-regs-only")',
        )
        for name in NAMES:
            for attribute in queries:
                self.assertIn("__builtin_has_attribute(" + name + ", " + attribute + ")", attribute_source)
        noreturn = re.findall(r"__builtin_has_attribute\((\w+), noreturn\)", attribute_source)
        self.assertEqual(noreturn, ["fiber_port_panic_wait", "fiber_port_runtime_start_first", "fiber_internal_task_return"])
        self.assertNotIn('no_sanitize("address"', attribute_source)
        unproved = probes["attributes.c"]["UnprovenAttributes"]
        self.assertEqual(len(unproved), 1)
        self.assertEqual(unproved[0]["Attribute"], 'no_sanitize("address", "undefined", "thread")')
        self.assertIn("inspect_preprocessed_attributes", unproved[0]["Reason"])
        expected = {
            "slot_read.c": "(void)" + SLOT + ";",
            "slot_write.c": SLOT + " = value;",
            "slot_address.c": "(void)&" + SLOT + ";",
        }
        for name, statement in expected.items():
            source = probes[name]["Source"]
            self.assertIn(statement, source)
            self.assertRegex(source, r"\nvoid cm0_abi_slot_\w+\(")
            self.assertNotIn("return", source)
            self.assertNotIn("context_runtime_state.h", source)
            self.assertEqual(re.findall(r'#include "([^"]+)"', source),
                             ["context/context_port_abi.h", "context/context_runtime_port_abi.h"])
            self.assertEqual(probes[name]["DiagnosticIdentifier"], SLOT)

    def test_current_source_identities_and_exact_expected_owners(self):
        sources = fixture_sources()
        record = ABI.inspect_sources(sources)
        self.assertEqual(len(record["Sources"]), 18)
        self.assertEqual({row["Path"]: row["Sha256"] for row in record["Sources"]},
                         {name: sha(data) for name, data in sources.items()})
        self.assertIs(record["RawSourceIdentitiesChecked"], True)
        self.assertEqual(tuple(row["Name"] for row in record["ExpectedOwners"]), NAMES)
        expected_indices = (4, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 0)
        self.assertEqual(tuple(row["ObjectIndex"] for row in record["ExpectedOwners"]), expected_indices)
        for index, owner in enumerate(record["ExpectedOwners"]):
            self.assertEqual(owner["Direction"], "forward" if index < 8 else "reverse")
            self.assertEqual(owner["Source"], SOURCE_ORDER[expected_indices[index]])
            self.assertIs(owner["NoReturn"], index in (2, 6, 11))
        self.assert_scope(record)

    def test_source_identity_is_raw_and_rejects_missing_or_aliases(self):
        for name in FIXTURE_PATHS:
            for action in ("missing", "changed"):
                with self.subTest(path=name, action=action):
                    sources = fixture_sources()
                    if action == "missing":
                        del sources[name]
                    else:
                        sources[name] += b"\n"
                    with self.assertRaises(ABI.Rejected):
                        ABI.inspect_sources(sources)
        sources = fixture_sources()
        variants = [None, [], dict(sources, **{"../escape.h": b"x"}),
                    dict(sources, **{"context\\alias.h": b"x"}),
                    dict(sources, **{"context/./alias.h": b"x"}),
                    dict(sources, **{"CONTEXT/CONTEXT_PORT_ABI.H": b"x"})]
        wrong_type = dict(sources)
        wrong_type["context/context_port_abi.h"] = wrong_type["context/context_port_abi.h"].decode("utf-8")
        variants.append(wrong_type)
        for index, value in enumerate(variants):
            with self.subTest(invalid_source_map=index), self.assertRaises(ABI.Rejected):
                ABI.inspect_sources(value)

    def test_declared_provider_bindings_preserve_unverified_evidence(self):
        sources = fixture_sources()
        receipt = provider_receipt(sources)
        raw = encoded(receipt)
        record = ABI.inspect_provider_dependencies(sources, raw, source_root=SOURCE_ROOT)
        self.assertEqual(record["ReceiptSha256"], sha(raw))
        self.assertIs(record["DeclaredProviderDependenciesBound"], True)
        self.assertEqual(len(record["Providers"]), 9)
        self.assertEqual([row["Source"] for row in record["Providers"]], list(SOURCE_ORDER))
        self.assertEqual(record["UnverifiedExternalDependencies"],
                         [{"Path": EXTERNAL, "Sha256": sha(b"unverified synthetic external bytes")}])
        self.assert_scope(record)
        self.assert_scope(record["SourceInspection"])
        windows = copy.deepcopy(receipt)
        for row in windows["Sources"]:
            for key in ("Source", "Object"):
                row[key] = row[key].replace("/", "\\\\")
            for key in ("Dependencies", "ActualCompileDependencies"):
                for dependency in row[key]:
                    dependency["Path"] = dependency["Path"].replace("/", "\\\\")
        normalized = ABI.inspect_provider_dependencies(sources, encoded(windows), source_root=SOURCE_ROOT)
        self.assertEqual(normalized["Providers"], record["Providers"])

    def test_provider_receipt_exact_cell_typed_counts_and_json(self):
        sources = fixture_sources()
        base = provider_receipt(sources)
        changes = [("Profile", "CM0PLUS"), ("Mode", "O0"), ("Cohort", "other"),
                   ("Linkage", "archive"), ("SourceInventorySha256", "0" * 64),
                   ("LTO", True), ("LTO", 0), ("TranslationUnits", True),
                   ("TranslationUnits", 9.0), ("TranslationUnits", 8)]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                receipt = copy.deepcopy(base)
                receipt[key] = value
                with self.assertRaises(ABI.Rejected):
                    ABI.inspect_provider_dependencies(sources, encoded(receipt), source_root=SOURCE_ROOT)
        variants = [b"{}", b"[]", b"not json", b"\xff", False, bytearray(encoded(base))]
        text = encoded(base).decode("ascii")
        variants.extend((('{"Mode":"O2",' + text[1:]).encode("ascii"),
                         ('{"mode":"O2",' + text[1:]).encode("ascii"),
                         ('{"unused":NaN,' + text[1:]).encode("ascii")))
        for index, value in enumerate(variants):
            with self.subTest(invalid_json=index), self.assertRaises(ABI.Rejected):
                ABI.inspect_provider_dependencies(sources, value, source_root=SOURCE_ROOT)
        for rows in (base["Sources"][:-1], base["Sources"] + [base["Sources"][0]],
                     list(reversed(base["Sources"]))):
            receipt = copy.deepcopy(base)
            receipt["Sources"] = rows
            with self.subTest(source_count_or_order=len(rows)), self.assertRaises(ABI.Rejected):
                ABI.inspect_provider_dependencies(sources, encoded(receipt), source_root=SOURCE_ROOT)

    def test_provider_dependency_source_object_and_header_tampering(self):
        sources = fixture_sources()
        base = provider_receipt(sources)
        changes = (("Source", SOURCE_ROOT + "/context/foreign.c"),
                   ("SourceSha256", "0" * 64), ("Object", "C:/synthetic/Native/objects/01-context_core.o"),
                   ("ObjectSha256", True), ("CompileDependenciesVerified", 1))
        for key, value in changes:
            receipt = copy.deepcopy(base)
            receipt["Sources"][0][key] = value
            with self.subTest(field=key), self.assertRaises(ABI.Rejected):
                ABI.inspect_provider_dependencies(sources, encoded(receipt), source_root=SOURCE_ROOT)
        for change in ("different_lists", "missing_own", "missing_canonical", "wrong_bytes",
                       "duplicate_dependency", "case_alias", "unknown_source", "traversal", "external_conflict"):
            receipt = copy.deepcopy(base)
            row = receipt["Sources"][0]
            if change == "different_lists":
                row["ActualCompileDependencies"][0]["Sha256"] = "B" * 64
            else:
                for key in ("Dependencies", "ActualCompileDependencies"):
                    dependencies = row[key]
                    if change in ("missing_own", "missing_canonical"):
                        name = SOURCE_ORDER[0] if change == "missing_own" else "context/context_runtime_port_abi.h"
                        row[key] = [d for d in dependencies if d["Path"] != SOURCE_ROOT + "/" + name]
                    elif change == "wrong_bytes":
                        next(d for d in dependencies if d["Path"].endswith("context_port_abi.h"))["Sha256"] = "B" * 64
                    elif change == "duplicate_dependency":
                        dependencies.append(copy.deepcopy(dependencies[0]))
                    elif change == "case_alias":
                        duplicate = copy.deepcopy(dependencies[0])
                        duplicate["Path"] = duplicate["Path"].upper()
                        dependencies.append(duplicate)
                    elif change == "unknown_source":
                        dependencies.append({"Path": SOURCE_ROOT + "/context/missing.h", "Sha256": "C" * 64})
                    elif change == "traversal":
                        dependencies.append({"Path": SOURCE_ROOT + "/../escape.h", "Sha256": "C" * 64})
                    elif change == "external_conflict":
                        next(d for d in receipt["Sources"][1][key] if d["Path"] == EXTERNAL)["Sha256"] = "D" * 64
            with self.subTest(change=change), self.assertRaises(ABI.Rejected):
                ABI.inspect_provider_dependencies(sources, encoded(receipt), source_root=SOURCE_ROOT)

    def test_returned_containers_are_fresh_and_never_promote(self):
        probes = ABI.emit_probes()
        probes["types.c"]["RequiredCFlags"].append("-flto")
        probes["types.c"]["Source"] = "mutant"
        probes["attributes.c"]["UnprovenAttributes"][0]["Reason"] = "mutant"
        fresh = ABI.emit_probes()
        self.assertNotIn("-flto", fresh["types.c"]["RequiredCFlags"])
        self.assertNotEqual(fresh["types.c"]["Source"], "mutant")
        self.assertNotEqual(fresh["attributes.c"]["UnprovenAttributes"][0]["Reason"], "mutant")
        sources = fixture_sources()
        inspections = [ABI.inspect_sources(sources), ABI.inspect_preprocessed_attributes(cpp_fixture().encode("ascii")),
                       ABI.inspect_provider_dependencies(sources, encoded(provider_receipt(sources)), source_root=SOURCE_ROOT)]
        for record in inspections:
            self.assert_scope(record)
            self.assertNotIn("PASS", record.values())
            record["Scope"]["FullSemanticABIProof"] = True
        self.assert_scope(ABI.inspect_sources(sources))
        self.assert_scope(ABI.inspect_preprocessed_attributes(cpp_fixture().encode("ascii")))

    def test_public_functions_have_no_io_and_preserve_inputs(self):
        sources = fixture_sources()
        receipt = encoded(provider_receipt(sources))
        cpp = cpp_fixture().encode("ascii")
        before = copy.deepcopy(sources)
        with mock.patch("builtins.open", side_effect=AssertionError("unexpected open")), \
             mock.patch.object(Path, "open", side_effect=AssertionError("unexpected Path.open")):
            ABI.emit_probes()
            ABI.inspect_sources(sources)
            ABI.inspect_provider_dependencies(sources, receipt, source_root=SOURCE_ROOT)
            ABI.inspect_preprocessed_attributes(cpp)
        self.assertEqual(sources, before)
        self.assertEqual(receipt, encoded(provider_receipt(sources)))
        self.assertEqual(cpp, cpp_fixture().encode("ascii"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
