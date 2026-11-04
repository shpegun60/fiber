"""Pure CM3 reference producer controls; no compiler, Git, or target execution."""
import argparse
import ast
import copy
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location("cm3_reference_producer_controls", HERE / "reference_run.py")
r = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = r
SPEC.loader.exec_module(r)
MANIFEST_PATH = Path("C:/fzin-20261104-e8/inputs/tools/freeze_cohorts.json")
MANIFEST_SHA256 = "A988CD5D7A2BFA197E43950AB42A1E09CAD6BF5AE2A585165E676F76C904B689"
MANIFEST = None


def authenticated_manifest(data, digest):
    if type(data) is not bytes or type(digest) is not str or not re.fullmatch(r"[A-Fa-f0-9]{64}", digest):
        raise ValueError("inventory bytes and independently supplied SHA256 required")
    if r.sha(data) != digest.upper():
        raise ValueError("inventory byte hash mismatch")
    def pairs(items):
        result, seen = {}, set()
        for key, value in items:
            if key.casefold() in seen:
                raise ValueError("duplicate/case-aliased inventory key")
            seen.add(key.casefold())
            result[key] = value
        return result
    def invalid(value):
        raise ValueError("non-finite inventory constant: " + value)
    value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    if (type(value) is not dict or type(value.get("schema_version")) is not int or value["schema_version"] != 1
            or value.get("reference_commit") != r.PIN or value.get("compiler_baseline") != "GNU Arm GCC 14.3.1"
            or value.get("required_object_modes") != list(r.MODES)):
        raise ValueError("inventory schema/pin/compiler/modes")
    return value


class ContractControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = r.load("cm3_reference_control_model", REPO / r.MODEL)
        cls.recipe = r.load("cm3_reference_control_recipe", REPO / r.RECIPE)
        cls.checker = r.load("cm3_reference_control_protocols", REPO / r.CHECKER)
        cls.manifest = MANIFEST

    def test_exact_profile_modes_and_early_rejection(self):
        self.assertEqual(r.MODES, ("O0", "Og", "O2", "Os", "O3"))
        for mode in r.MODES:
            self.assertEqual(r.selection("CM3", mode), r.COHORT)
        for profile, mode in (("CM0", "O2"), ("CM4", "O2"), ("CM3", "O1"),
                              ("CM3", "O2-LTO"), (True, "O2"), ("CM3", True)):
            with self.subTest(profile=profile, mode=mode), patch.object(Path, "mkdir", side_effect=AssertionError("mkdir")):
                with self.assertRaises(RuntimeError):
                    r.Reference(SimpleNamespace(profile=profile, mode=mode))

    def test_cli_defaults_and_five_selections(self):
        base = ["--gcc", "not-run", "--git", "not-run", "--freertos", "not-read",
                "--inventory", "not-read", "--output-dir", "not-created"]
        for extra, mode in [([], "O2"), *[(["--profile", "CM3", "--mode", mode], mode) for mode in r.MODES]]:
            pilot = SimpleNamespace(prepare=Mock(), build=Mock(), finish=Mock(return_value=True),
                                    report=dict(Verdict=r.PASS), output="not-created")
            with patch.object(r, "Reference", return_value=pilot) as constructor, patch("builtins.print"):
                self.assertEqual(r.main(base + extra), 0)
            self.assertEqual((constructor.call_args.args[0].profile, constructor.call_args.args[0].mode), ("CM3", mode))

    def test_import_does_not_spawn_write_or_patch_shared_globals(self):
        spec = importlib.util.spec_from_file_location("cm3_reference_import_control", HERE / "reference_run.py")
        module = importlib.util.module_from_spec(spec)
        before = (r.common.PIN, copy.deepcopy(r.native.PROFILES), r.common.PASS)
        with patch("subprocess.Popen", side_effect=AssertionError("spawn")), \
             patch.object(Path, "mkdir", side_effect=AssertionError("mkdir")), \
             patch.object(Path, "write_bytes", side_effect=AssertionError("write")), \
             patch.object(Path, "write_text", side_effect=AssertionError("write")):
            spec.loader.exec_module(module)
        self.assertEqual(before, (r.common.PIN, r.native.PROFILES, r.common.PASS))

    def test_reuses_only_generic_managed_envelope_methods(self):
        for name in ("command", "capture", "generated_file", "verify_objects", "link_twin", "inspect"):
            self.assertIs(getattr(r.Reference, name), getattr(r.native.Pilot, name))
        for name in ("git_bytes", "reference_identity", "dependencies", "freeze_objects"):
            self.assertIs(getattr(r.Reference, name), getattr(r.common.Reference, name))
        self.assertNotEqual(r.PASS, r.common.PASS)

    def test_no_partial_link_final_root_reader_or_process_bypass(self):
        source = (HERE / "reference_run.py").read_text()
        tree = ast.parse(source)
        strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        self.assertNotIn("-r", strings)
        self.assertFalse(any(isinstance(n, ast.Attribute) and n.attr in ("Popen", "FinalImage") for n in ast.walk(tree)))
        for text in ('self.sources = [self.kernel / PORT', '("providers.c", "consumer.c", "startup.S")',
                     'port = self.objects[0]', '"-T", self.fixture_copy / "link.ld", *self.objects',
                     '(("ordinary", []), ("emit-relocs", ["-Wl,--emit-relocs"]))'):
            self.assertIn(text, source)

    def test_typed_fixture_roots_inline_assert_and_upstream_vectors(self):
        consumer = (HERE / "reference/consumer.c").read_text()
        header = (HERE / "reference/reference.h").read_text()
        providers = (HERE / "reference/providers.c").read_text()
        startup = (HERE / "reference/startup.S").read_text()
        script = (HERE / "reference/link.ld").read_text()
        base = (REPO / r.BASE_CONFIG).read_text()
        self.assertIn('TaskHandle_t volatile pxCurrentTCB', header)
        self.assertIn('TaskHandle_t volatile pxCurrentTCB = NULL;', providers)
        self.assertNotIn('portasm.h', header)
        self.assertNotIn('reference_assert_failed', providers)
        self.assertIn('#define configASSERT(x) do { if (!(x)) { for (;;) { } } } while (0)', base)
        for name in ("pxPortInitialiseStack", "xPortStartScheduler"):
            self.assertIn(name, consumer)
        for forbidden in ("__ARM_FP", "__ARM_PCS_VFP", "target(", "core_cm"):
            self.assertNotIn(forbidden, consumer + header)
        for name in r.ROOTS:
            self.assertIn('KEEP(*(.text.' + name + '))', script)
        for name in ("vPortSVCHandler", "xPortPendSVHandler", "xPortSysTickHandler"):
            self.assertIn('.word ' + name, startup)
        self.assertIn('SIZEOF(.reference_roots) == 8', script)
        self.assertIn('SIZEOF(.reference_contract) == 40', script)
        self.assertIn('KEEP(*(.text.reference_origin_padding))', script)
        self.assertEqual(startup.count('    nop'), 2)

    def test_scope_is_explicitly_nonpromoting(self):
        for mode in r.MODES:
            row = r.scope_report("CM3", mode)
            self.assertEqual((row["Profile"], row["Mode"], row["Cohort"], row["SourceGroup"]), ("CM3", mode, r.COHORT, "CM3"))
            self.assertEqual(row["ReferenceCommit"], r.PIN)
            self.assertEqual(row["SchedulerThreshold"], 16)
            self.assertEqual(row["FPPolicy"], "NOT-APPLICABLE-NO-FPU")
            self.assertIs(type(row["RequiredCellsSatisfied"]), int)
            self.assertEqual(row["RequiredCellsSatisfied"], 0)
            for key in ("NativeBuilt", "FinalElfProof", "FinalRootRelocationProof", "FinalReferenceParity", "CompleteObjectProof",
                        "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified", "RequiredCellSatisfied",
                        "SchedulerSemanticsProven", "CSourceSemanticProof", "ReferenceKernelAvailable", "HandlerRoutingProven", "UnreachabilityProven"):
                self.assertIs(row[key], False)

    def test_actual_inventory_all_five_exact_recipes(self):
        for mode in r.MODES:
            before = copy.deepcopy(self.manifest)
            artifact = r.require_artifact(self.manifest, self.model, "CM3", mode)
            self.assertEqual(artifact["upstream_sources"], [r.PORT])
            self.assertEqual(artifact["upstream_defines"], dict(FIBER_FREERTOS_PARITY_ENABLE_MPU="0",
                FIBER_FREERTOS_PARITY_ENABLE_FPU="0", FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE="0"))
            binding = self.recipe.reference_recipe(artifact, mode, "fixture", "kernel")
            self.assertEqual(binding["Flags"][:4], [*artifact["compile_flags"], "-" + mode])
            self.assertNotIn("-include", binding["Flags"])
            self.assertFalse(any(f.startswith(("-mfpu=", "-flto")) for f in binding["Flags"]))
            self.assertEqual(binding["PortmacroProvider"], r.PORTMACRO)
            self.assertEqual(binding["ExtraIncludes"], [])
            self.assertIs(binding["ExactTargetRecipe"], True)
            self.assertEqual(binding["WitnessKind"], "none")
            config = r.configuration_text(binding["ConfigText"])
            self.assertIn('#define configMAX_SYSCALL_INTERRUPT_PRIORITY 16U', config)
            self.assertEqual(self.manifest, before)

    def test_foreign_artifact_sources_defines_targets_and_source_group_reject(self):
        changes = (
            lambda a: a.update(upstream_sources=["portable/GCC/ARM_CM4F/port.c"]),
            lambda a: a["upstream_sources"].append("portable/GCC/ARM_CM0/portasm.c"),
            lambda a: a["upstream_defines"].update(configENABLE_ERRATA_837070_WORKAROUND="1"),
            lambda a: a["upstream_defines"].update(FIBER_FREERTOS_PARITY_ENABLE_FPU="1"),
            lambda a: a["target"].update(nvic_priority_bits=8),
            lambda a: a["target"].update(scheduler_basepri=2),
            lambda a: a["target"].update(vtor=1),
            lambda a: a["compile_flags"].append("-flto"),
            lambda a: a["defines"].update(FIBER_SCHEDULER_BASEPRI="2"),
        )
        for change in changes:
            manifest = copy.deepcopy(self.manifest)
            artifact = next(c for c in manifest["cohorts"] if c["id"] == r.COHORT)["artifacts"][0]
            change(artifact)
            with self.subTest(change=change), self.assertRaises((RuntimeError, ValueError)):
                r.require_artifact(manifest, self.model)
        manifest = copy.deepcopy(self.manifest)
        next(g for g in manifest["source_groups"] if g["id"] == "CM3")["sources"].reverse()
        with self.assertRaises(RuntimeError):
            r.require_artifact(manifest, self.model)

    def test_config_binding_and_inline_assert_not_overridden(self):
        artifact = r.require_artifact(self.manifest, self.model)
        text = self.recipe.reference_recipe(artifact, "O2", "fixture", "kernel")["ConfigText"]
        value = r.configuration_text(text)
        self.assertIn('#include "freeze_base_FreeRTOSConfig.h"', value)
        self.assertIn('#define configCHECK_HANDLER_INSTALLATION 1\n', value)
        self.assertIn('#define configPRIO_BITS 4\n', value)
        self.assertIn('#define __NVIC_PRIO_BITS 4\n', value)
        self.assertNotIn('configASSERT', value)
        for bad in (text.replace('16U', '128U'), text + '\n', text.replace('#endif\n', '#define FOREIGN 1\n#endif\n'), None):
            with self.assertRaises(RuntimeError):
                r.configuration_text(bad)

    def test_exact_no_fp_header_facts(self):
        facts = [1, 4, 4, 4, 8, 0, 0, 16, 16, 4]
        r.require_header_facts(struct.pack("<10I", *facts))
        for index in range(10):
            changed = list(facts)
            changed[index] += 1
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                r.require_header_facts(struct.pack("<10I", *changed))
        for value in (bytes(36), bytes(44), bytearray(40), None):
            with self.assertRaises(RuntimeError):
                r.require_header_facts(value)

    def test_exact_portmacro_config_dependency_roles(self):
        fixture, kernel = Path("fixture"), Path("kernel")
        required = [fixture / "FreeRTOSConfig.h", fixture / "freeze_base_FreeRTOSConfig.h", kernel / r.PORTMACRO]
        for source in (kernel / r.PORT, fixture / "providers.c", fixture / "consumer.c"):
            paths = [source, *required]
            r.require_dependency_roles(paths, source, fixture, kernel)
            for missing in paths:
                with self.assertRaises(RuntimeError):
                    r.require_dependency_roles([p for p in paths if p != missing], source, fixture, kernel)
            for foreign in (Path("foreign/portmacro.h"), Path("foreign/portasm.h"), Path("foreign/FreeRTOSConfig.h")):
                with self.assertRaises(RuntimeError):
                    r.require_dependency_roles([*paths, foreign], source, fixture, kernel)
        r.require_dependency_roles([Path("startup.S")], Path("startup.S"), fixture, kernel)

    def test_three_complete_protocols_and_mode_tail_binding(self):
        self.assertEqual(tuple(self.checker._REFERENCE), r.ROOTS)
        for mode in r.MODES:
            bodies = {name: copy.deepcopy(body) + [("nop", "")] * int(mode == "O0") for name, body in self.checker._REFERENCE.items()}
            calls = []
            def function(name, **kwargs):
                self.assertEqual(kwargs, dict(literal_islands=True))
                calls.append(name)
                return bodies[name]
            proof = r.match_reference_protocols(SimpleNamespace(function=function), self.checker, mode)
            self.assertEqual(calls, list(r.ROOTS))
            self.assertEqual([row["TailNops"] for row in proof], [int(mode == "O0")] * 3)
            other = "O2" if mode == "O0" else "O0"
            with self.assertRaises(RuntimeError):
                r.match_reference_protocols(SimpleNamespace(function=function), self.checker, other)

    def test_missing_extra_and_mutated_complete_tokens_reject(self):
        for mode in r.MODES:
            for name in r.ROOTS:
                for mutation in ("missing", "extra", "changed", "literal"):
                    bodies = {n: copy.deepcopy(b) + [("nop", "")] * int(mode == "O0") for n, b in self.checker._REFERENCE.items()}
                    if mutation == "missing":
                        bodies[name].pop(0)
                    elif mutation == "extra":
                        bodies[name].insert(0, ("nop", ""))
                    elif mutation == "changed":
                        bodies[name][0] = ("udf", "#90")
                    else:
                        index = next(i for i, token in enumerate(bodies[name]) if token[0] == "@literal-island")
                        descriptor = json.loads(bodies[name][index][1])
                        descriptor["Bytes"] = "ff" + descriptor["Bytes"][2:]
                        bodies[name][index] = ("@literal-island", json.dumps(descriptor, sort_keys=True, separators=(",", ":")))
                    image = SimpleNamespace(function=lambda root, **kwargs: bodies[root])
                    with self.subTest(mode=mode, root=name, mutation=mutation), self.assertRaises(RuntimeError):
                        r.match_reference_protocols(image, self.checker, mode)

    def test_whole_owning_section_metadata_does_not_enlarge_root(self):
        source = (HERE / "reference_run.py").read_text()
        for text in ('Sha256=sha(section.data())', 'RootOffset=offset, RootSize=symbol["size"]',
                     'MappingSymbols=', 'Relocations=relocs', 'WholeSectionRecorded=True',
                     'SymbolExtentUnchanged=True', 'AppliedRelocationProof=False',
                     'expected["pxCurrentTCB"] = (1, "STT_OBJECT", "STB_GLOBAL")'):
            self.assertIn(text, source)

    def test_inventory_hash_is_checked_before_parse(self):
        with patch("json.loads", side_effect=AssertionError("unverified parse")):
            with self.assertRaisesRegex(ValueError, "byte hash mismatch"):
                authenticated_manifest(b"not-json", "A" * 64)
        for data in (b'{"cohorts":[],"COHORTS":[]}', b'{"x":NaN}'):
            with self.assertRaises(ValueError):
                authenticated_manifest(data, r.sha(data))


class LocalDefinitionControls(unittest.TestCase):
    def image(self):
        symbol = dict(name=r.ROOTS[0], kind="STT_FUNC", binding="STB_LOCAL", section=1, size=32, value=0x101)
        header = SimpleNamespace(sh_type="SHT_PROGBITS", sh_flags=6, sh_addr=0x100, sh_size=64)
        return SimpleNamespace(symbols=[symbol], sections=[None, SimpleNamespace(header=header)],
            read=Mock(return_value=bytes(32)), mapping=Mock(return_value=("t", 0x140)),
            loads=[dict(Flags=5, Vaddr=0x100, FileSize=64)])

    def test_actual_local_binding_is_required_without_promoting_to_global(self):
        image = self.image()
        self.assertIs(r.local_start(image), image.symbols[0])
        image.read.assert_called_once_with(0x100, 32)
        image.mapping.assert_called_once_with(1, 0x100)
        for change in (dict(binding="STB_GLOBAL"), dict(binding="STB_WEAK"), dict(kind="STT_OBJECT"),
                       dict(section="SHN_UNDEF"), dict(section=True), dict(value=0x100), dict(size=0), dict(size=66)):
            image = self.image()
            image.symbols[0].update(change)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                r.local_start(image)

    def test_duplicate_definition_data_mapping_and_nonexecutable_load_reject(self):
        image = self.image()
        image.symbols.append(dict(image.symbols[0]))
        with self.assertRaises(RuntimeError):
            r.local_start(image)
        image = self.image()
        image.mapping.return_value = ("d", 0x140)
        with self.assertRaises(RuntimeError):
            r.local_start(image)
        image = self.image()
        image.loads[0]["Flags"] = 4
        with self.assertRaises(RuntimeError):
            r.local_start(image)


class EnvelopeControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cm3-reference-envelope-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pilot = r.Reference.__new__(r.Reference)
        self.pilot.profile, self.pilot.mode = "CM3", "O2"
        self.pilot.output, self.pilot.repo = self.root, REPO
        self.pilot.inputs, self.pilot.generated, self.pilot.commands = {}, {}, []
        self.pilot.full_memberships = []
        self.pilot.report = r.scope_report()
        self.pilot._prepared = self.pilot._built = self.pilot._prelink_verified = self.pilot._twins_verified = False
        self.pilot._reference_opened = self.pilot._reference_closed = False
        self.pilot.environment = {}

    def objects(self, count=4):
        self.pilot.objects = []
        for index in range(count):
            path = self.root / ("%02d.o" % index)
            path.write_bytes(bytes([index]) * 8)
            self.pilot.objects.append(path)
            self.pilot.report["Sources"].append(dict(Object=str(path), ObjectSha256=r.sha(path.read_bytes()), CompileDependenciesVerified=True))

    def ready(self):
        self.objects()
        self.pilot.freeze_objects()
        for stage in r.CHECKPOINTS[:-1]:
            self.pilot.verify_objects(stage)
        self.pilot._prepared = self.pilot._built = self.pilot._prelink_verified = self.pilot._twins_verified = True
        self.pilot._reference_closed = True
        self.pilot.commands = [dict(Status="PASS", Label="synthetic pure envelope; no tool executed")]
        self.pilot.report.update(ReferenceBuilt=True, Links=[dict(Kind="ordinary"), dict(Kind="emit-relocs")],
                                PrelinkReferenceRoots=[dict(Name=name) for name in r.ROOTS])
        self.payload = self.root / "listed.bin"
        self.payload.write_bytes(b"original")

    def receipt(self, verdict):
        row = json.loads((self.root / "results.json").read_bytes())
        self.assertEqual(row["Verdict"], verdict)
        self.assertEqual(json.loads((self.root / "artifacts.json").read_bytes()), dict(Artifacts=r.common.artifact_inventory(self.root)))
        self.assertIs(row["FinalElfProof"], False)
        self.assertIs(row["CpuExecution"], False)
        return row

    def test_exact_four_object_freeze_and_drift(self):
        self.objects()
        self.pilot.freeze_objects()
        self.assertEqual(len(self.pilot.object_hashes), 4)
        self.pilot.objects[0].write_bytes(b"changed")
        with self.assertRaises(RuntimeError):
            self.pilot.verify_objects("before-prelink")

    def test_wrong_object_count_or_unverified_dependencies_reject(self):
        self.objects(3)
        with self.assertRaises(RuntimeError):
            self.pilot.freeze_objects()
        self.pilot.objects.clear()
        self.pilot.report["Sources"].clear()
        self.objects()
        self.pilot.report["Sources"][0]["CompileDependenciesVerified"] = False
        with self.assertRaises(RuntimeError):
            self.pilot.freeze_objects()

    def test_empty_build_cannot_pass(self):
        self.assertFalse(self.pilot.finish(None))
        self.receipt("FAIL")

    def test_positive_closure_has_seven_checkpoints(self):
        self.ready()
        self.assertTrue(self.pilot.finish(None))
        row = self.receipt(r.PASS)
        self.assertEqual([check["Stage"] for check in row["ObjectChecks"]], list(r.CHECKPOINTS))
        self.assertIs(row["ArtifactSealVerified"], True)
        self.assertEqual(row["InputDrift"], [])

    def fault(self, kind):
        self.ready()
        original_save = r.common.save
        count = 0
        def inject(path, value):
            nonlocal count
            if path.name == "artifacts.json":
                count += 1
                if count == 2 and kind == "write":
                    raise OSError("injected manifest write failure")
            original_save(path, value)
            if path.name == "artifacts.json" and count == 2:
                if kind == "add":
                    (self.root / "late.bin").write_bytes(b"late")
                elif kind == "change":
                    self.payload.write_bytes(b"changed")
                elif kind == "delete":
                    self.payload.unlink()
        with patch.object(r.common, "save", side_effect=inject):
            self.assertFalse(self.pilot.finish(None))
        row = self.receipt("FAIL")
        self.assertIn("artifact closure", row["Error"])
        self.assertIs(row["ArtifactSealVerified"], False)

    def test_late_addition_rolls_back_pass(self):
        self.fault("add")

    def test_late_mutation_rolls_back_pass(self):
        self.fault("change")

    def test_late_removal_rolls_back_pass(self):
        self.fault("delete")

    def test_manifest_write_failure_rolls_back_pass(self):
        self.fault("write")

    def test_missing_root_rejects_finalization(self):
        self.ready()
        self.pilot.report["PrelinkReferenceRoots"].pop()
        self.assertFalse(self.pilot.finish(None))
        self.receipt("FAIL")

    def test_original_input_drift_rejects(self):
        self.ready()
        original, captured = self.root / "original.h", self.root / "captured.h"
        original.write_bytes(b"before")
        captured.write_bytes(b"before")
        self.pilot.inputs[str(original)] = dict(Original=str(original), Captured=str(captured), Sha256=r.sha(b"before"))
        original.write_bytes(b"after")
        self.assertFalse(self.pilot.finish(None))
        self.assertTrue(self.receipt("FAIL")["InputDrift"])

    def test_membership_addition_of_non_source_file_rejects(self):
        self.ready()
        folder = self.root / "captured"
        folder.mkdir()
        self.pilot.full_memberships.append((folder, r.file_membership(folder)))
        (folder / "injected.bin").write_bytes(b"not a C/H/PY file")
        self.assertFalse(self.pilot.finish(None))
        self.assertTrue(self.receipt("FAIL")["InputDrift"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--inventory-manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--inventory-sha256", default=MANIFEST_SHA256)
    args = parser.parse_args(argv)
    report_path = args.report.resolve()
    if report_path.exists() or not report_path.is_relative_to(Path(tempfile.gettempdir()).resolve()) or report_path.is_relative_to(REPO):
        parser.error("fresh TEMP report outside repository required")
    sources = [Path(__file__).resolve(), HERE / "reference_run.py", HERE / "REFERENCE_CONTRACT.md",
               r.CLASSIC / "reference_run.py", r.CLASSIC / "run.py", *[REPO / relative for relative in r.HELPERS], REPO / r.BASE_CONFIG]
    sources += [HERE / "reference" / name for name in r.FIXTURE_FILES]
    report = dict(Status="FAIL", Tests=0, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        Scope="PURE_CM3_REFERENCE_PRODUCER_ENVELOPE_CONTROLS_ONLY", ExpectedManifestSha256=args.inventory_sha256,
        ManifestSha256=None, ActualInventoryArtifactUsed=False, ToolInvocations=0, NativeCommandsExecuted=0,
        RequiredCellsSatisfied=0, FinalElfProof=False, FinalRootRelocationProof=False, FinalReferenceParity=False,
        PolicyEquivalence=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, Error=None)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized Python unsupported")
        report["SourceHashes"] = {str(path): r.sha(path.read_bytes()) for path in sources}
        for path, data in ((HERE / "reference_run.py", r.SELF_BYTES), (r.CLASSIC / "reference_run.py", r.COMMON_BYTES),
                           (r.CLASSIC / "run.py", r.common.NATIVE_BYTES)):
            if report["SourceHashes"][str(path)] != r.sha(data):
                raise ValueError("loaded producer/envelope source drift: " + str(path))
        global MANIFEST
        manifest_path = args.inventory_manifest.resolve(strict=True)
        data = manifest_path.read_bytes()
        MANIFEST = authenticated_manifest(data, args.inventory_sha256)
        sources.append(manifest_path)
        report["SourceHashes"][str(manifest_path)] = r.sha(data)
        report.update(ManifestSha256=r.sha(data), ActualInventoryArtifactUsed=True)
        suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
        count = suite.countTestCases()
        with patch("subprocess.Popen", side_effect=AssertionError("process execution forbidden in pure controls")):
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        report["SourceDrift"] = [str(path) for path in sources if not path.is_file() or r.sha(path.read_bytes()) != report["SourceHashes"][str(path)]]
        if result.wasSuccessful() and result.testsRun == count > 0 and not result.skipped and not report["SourceDrift"]:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Errors=report["Errors"] + 1, Error=traceback.format_exc())
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("x", encoding="ascii") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Receipt:", report_path, r.sha(report_path.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
