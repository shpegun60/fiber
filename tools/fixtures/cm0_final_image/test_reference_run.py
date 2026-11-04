"""Pure CM0 reference producer controls; never launches a native tool or target."""
import argparse
import ast
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


if sys.flags.optimize or not __debug__:
    raise SystemExit("optimized Python unsupported")
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cm0_reference_producer_controls", HERE / "reference_run.py")
r = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = r
SPEC.loader.exec_module(r)


class ContractControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = HERE.parents[2]
        cls.admission = r.load("cm0_reference_control_admission", cls.repo / r.ADMISSION)
        cls.recipe = r.load("cm0_reference_control_recipe", cls.repo / r.RECIPE)
        cls.checker = r.load("cm0_reference_control_protocols", cls.repo / r.CHECKER)
        cls.manifest = json.loads((cls.repo / "tools/freeze_cohorts.json").read_bytes())

    def test_exact_three_profiles_and_five_modes(self):
        self.assertEqual(tuple(r.PROFILES), ("CM0", "CM0PLUS", "CM0PLUSVTOR"))
        self.assertEqual(r.MODES, ("O0", "Og", "O2", "Os", "O3"))
        for profile in r.PROFILES:
            for mode in r.MODES:
                self.assertEqual(r.selection(profile, mode), r.native.PROFILES[profile][0])
        for profile, mode in (("CM4", "O2"), ("CM0", "O1"), ("CM0", "O2-LTO"),
                              (True, "O2"), ("CM0", True), (None, "O0")):
            with self.subTest(profile=profile, mode=mode), patch.object(Path, "mkdir", side_effect=AssertionError("mkdir")):
                with self.assertRaises(RuntimeError):
                    r.Reference(SimpleNamespace(profile=profile, mode=mode))

    def test_cli_defaults_and_all_fifteen_selections(self):
        base = ["--gcc", "not-run", "--git", "not-run", "--freertos", "not-read",
                "--inventory", "not-read", "--output-dir", "not-created"]
        cases = [([], ("CM0", "O2"))] + [(["--profile", p, "--mode", m], (p, m)) for p in r.PROFILES for m in r.MODES]
        for extra, expected in cases:
            pilot = SimpleNamespace(prepare=Mock(), build=Mock(), finish=Mock(return_value=True),
                                    report=dict(Verdict=r.PASS), output="not-created")
            with patch.object(r, "Reference", return_value=pilot) as constructor, patch("builtins.print"):
                self.assertEqual(r.main(base + extra), 0)
            args = constructor.call_args.args[0]
            self.assertEqual((args.profile, args.mode), expected)

    def test_import_does_not_spawn_or_write(self):
        spec = importlib.util.spec_from_file_location("cm0_reference_import_control", HERE / "reference_run.py")
        module = importlib.util.module_from_spec(spec)
        with patch("subprocess.Popen", side_effect=AssertionError("spawn")), \
             patch.object(Path, "mkdir", side_effect=AssertionError("mkdir")), \
             patch.object(Path, "write_bytes", side_effect=AssertionError("write")), \
             patch.object(Path, "write_text", side_effect=AssertionError("write")):
            spec.loader.exec_module(module)

    def test_reuses_managed_native_envelope(self):
        for name in ("command", "capture", "generated_file", "verify_objects", "link_twin", "inspect"):
            self.assertIs(getattr(r.Reference, name), getattr(r.native.Pilot, name))
        for name in ("git_bytes", "reference_identity", "dependencies"):
            self.assertIs(getattr(r.Reference, name), getattr(r.common.Reference, name))

    def test_builder_has_no_final_root_reader_or_partial_link(self):
        source = (HERE / "reference_run.py").read_text()
        tree = ast.parse(source)
        strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        self.assertNotIn("-r", strings)
        self.assertFalse(any(isinstance(n, ast.Attribute) and n.attr in ("Popen", "FinalImage") for n in ast.walk(tree)))
        self.assertIn('*(self.kernel / relative for relative in PORT_SOURCES)', source)
        self.assertIn('("providers.c", "consumer.c", "startup.S")', source)
        self.assertIn('self.objects[0]', source)
        self.assertIn('self.objects[1]', source)
        self.assertIn('"-T", self.fixture_copy / "link.ld", *self.objects', source)
        self.assertIn('(("ordinary", []), ("emit-relocs", ["-Wl,--emit-relocs"]))', source)

    def test_fixture_seven_typed_roots_vectors_and_inline_assert(self):
        consumer = (HERE / "reference/consumer.c").read_text()
        header = (HERE / "reference/reference.h").read_text()
        providers = (HERE / "reference/providers.c").read_text()
        startup = (HERE / "reference/startup.S").read_text()
        script = (HERE / "reference/link.ld").read_text()
        base = (self.repo / r.BASE_CONFIG).read_text()
        self.assertIn('#include "portasm.h"', header)
        for name in ("pxPortInitialiseStack", "xPortStartScheduler", *r.ROOTS):
            self.assertIn(name, consumer)
        self.assertIn('SIZEOF(.reference_roots) == 28', script)
        self.assertIn('SIZEOF(.reference_contract) == 40', script)
        for name in r.ROOTS:
            self.assertIn('KEEP(*(.text.' + name + '))', script)
        for name in ("SVC_Handler", "PendSV_Handler", "SysTick_Handler"):
            self.assertIn('.word ' + name, startup)
        self.assertNotIn('reference_assert_failed', providers)
        self.assertIn('#define configASSERT(x) do { if (!(x)) { for (;;) { } } } while (0)', base)
        self.assertIn('reference_fail_stop', providers)

    def test_scope_never_promotes_final_or_cpu_proof(self):
        for profile in r.PROFILES:
            for mode in r.MODES:
                report = r.scope_report(profile, mode)
                self.assertEqual((report["Profile"], report["Mode"], report["Cohort"]), (profile, mode, r.PROFILES[profile]))
                self.assertEqual(report["SourceGroup"], "CM0")
                self.assertEqual(report["ReferenceCommit"], "a50edad08b29052631aa469d4df6e6ec7ff68878")
                self.assertEqual(report["FixtureHandlerInstallationCheck"], int(profile == "CM0PLUSVTOR"))
                self.assertIs(type(report["RequiredCellsSatisfied"]), int)
                self.assertEqual(report["RequiredCellsSatisfied"], 0)
                for key in ("FinalElfProof", "FinalRootRelocationProof", "FinalReferenceParity", "CompleteObjectProof",
                            "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified",
                            "SchedulerSemanticsProven", "CSourceSemanticProof", "HandlerRoutingProven", "UnreachabilityProven"):
                    self.assertIs(report[key], False)

    def test_real_manifest_exact_fifteen_recipes(self):
        for profile in r.PROFILES:
            for mode in r.MODES:
                with self.subTest(profile=profile, mode=mode):
                    before = copy.deepcopy(self.manifest)
                    artifact = r.require_artifact(self.manifest, self.admission, profile, mode)
                    self.assertEqual(artifact["upstream_sources"], ["portable/GCC/ARM_CM0/port.c", "portable/GCC/ARM_CM0/portasm.c"])
                    self.assertEqual(artifact["upstream_defines"], dict(FIBER_FREERTOS_PARITY_ENABLE_MPU="0",
                        FIBER_FREERTOS_PARITY_ENABLE_FPU="0", FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE="0"))
                    binding = self.recipe.reference_recipe(artifact, mode, "fixture", "kernel")
                    self.assertEqual(binding["Flags"][:4], [*artifact["compile_flags"], "-" + mode])
                    self.assertNotIn("-include", binding["Flags"])
                    self.assertEqual(binding["PortmacroProvider"], "portable/GCC/ARM_CM0/portmacro.h")
                    self.assertEqual(binding["ExtraIncludes"], [])
                    self.assertIs(binding["ExactTargetRecipe"], True)
                    self.assertEqual(binding["WitnessKind"], "none")
                    self.assertIn("threshold-not-applicable", [row["Kind"] for row in binding["Differences"]])
                    config = r.configuration_text(binding["ConfigText"], vtor=artifact["target"]["vtor"])
                    self.assertIn('#define configCHECK_HANDLER_INSTALLATION %d\n' % int(profile == "CM0PLUSVTOR"), config)
                    self.assertEqual(self.manifest, before)

    def test_foreign_manifest_sources_defines_and_targets_reject(self):
        changes = (
            lambda a: a.update(upstream_sources=[r.PORT_SOURCES[0]]),
            lambda a: a.update(upstream_sources=list(reversed(r.PORT_SOURCES))),
            lambda a: a["upstream_defines"].update(configENABLE_ERRATA_837070_WORKAROUND="1"),
            lambda a: a["upstream_defines"].update(FIBER_FREERTOS_PARITY_ENABLE_FPU="1"),
            lambda a: a["target"].update(nvic_priority_bits=4),
            lambda a: a["target"].update(scheduler_basepri=16),
            lambda a: a["target"].update(vtor=1),
            lambda a: a["compile_flags"].append("-flto"),
        )
        for profile in r.PROFILES:
            for change in changes:
                manifest = copy.deepcopy(self.manifest)
                artifact = next(c for c in manifest["cohorts"] if c["id"] == r.PROFILES[profile])["artifacts"][0]
                change(artifact)
                with self.subTest(profile=profile, mutation=change), self.assertRaises(RuntimeError):
                    r.require_artifact(manifest, self.admission, profile, "O2")

    def test_config_vtor_bool_binding_and_baseline_assert_unchanged(self):
        artifact = r.require_artifact(self.manifest, self.admission, "CM0", "O2")
        recipe_text = self.recipe.reference_recipe(artifact, "O2", "fixture", "kernel")["ConfigText"]
        for vtor in (False, True):
            text = r.configuration_text(recipe_text, vtor=vtor)
            self.assertIn('#include "freeze_base_FreeRTOSConfig.h"', text)
            self.assertNotIn('configASSERT', text)
            self.assertIn('#define configCHECK_HANDLER_INSTALLATION %d\n' % int(vtor), text)
        for value in (0, 1, None, "false"):
            with self.assertRaises(RuntimeError):
                r.configuration_text(recipe_text, vtor=value)
        with self.assertRaises(RuntimeError):
            r.configuration_text(recipe_text.replace('0U', '16U'), vtor=False)

    def test_exact_no_fp_header_facts(self):
        facts = [1, 4, 4, 4, 8, 0, 0, 0, 0, 2]
        r.require_header_facts(struct.pack("<10I", *facts))
        for index in range(10):
            changed = list(facts)
            changed[index] += 1
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                r.require_header_facts(struct.pack("<10I", *changed))
        for value in (bytes(36), bytes(44), None):
            with self.assertRaises(RuntimeError):
                r.require_header_facts(value)

    def test_exact_portasm_header_dependency_roles(self):
        fixture, kernel = Path("fixture"), Path("kernel")
        required = [fixture / "FreeRTOSConfig.h", fixture / "freeze_base_FreeRTOSConfig.h", *(kernel / p for p in r.PORT_HEADERS)]
        for name in r.PORT_SOURCES:
            source = kernel / name
            paths = [source, *required]
            r.require_dependency_roles(paths, source, fixture, kernel)
            for missing in paths:
                with self.assertRaises(RuntimeError):
                    r.require_dependency_roles([p for p in paths if p != missing], source, fixture, kernel)
            for foreign in (Path("foreign/portasm.h"), Path("foreign/portmacro.h"), Path("foreign/FreeRTOSConfig.h")):
                with self.assertRaises(RuntimeError):
                    r.require_dependency_roles([*paths, foreign], source, fixture, kernel)
        r.require_dependency_roles([Path("startup.S")], Path("startup.S"), fixture, kernel)

    def test_five_protocols_routed_to_own_objects_all_modes(self):
        self.assertEqual(r.ROOT_OWNERS, dict(vStartFirstTask=1, SVC_Handler=1, vPortSVCHandler_C=0,
                                          vRestoreContextOfFirstTask=1, PendSV_Handler=1))
        for mode in r.MODES:
            bodies = self.checker._protocols(mode)["Reference"]
            calls = []
            def function(owner):
                def read(name, **kwargs):
                    self.assertEqual(r.ROOT_OWNERS[name], owner)
                    self.assertEqual(kwargs, dict(literal_islands=True, thumb1_tail_nop=True))
                    calls.append(name)
                    return copy.deepcopy(bodies[name])
                return read
            proof = r.match_reference_protocols(SimpleNamespace(function=function(0)), SimpleNamespace(function=function(1)), self.checker, mode)
            self.assertEqual([row["Name"] for row in proof], list(r.ROOTS))
            self.assertEqual(calls, list(r.ROOTS))

    def test_missing_extra_mutated_protocol_tokens_reject(self):
        for mode in r.MODES:
            for root in r.ROOTS:
                for mutation in ("missing", "extra", "changed"):
                    bodies = copy.deepcopy(self.checker._protocols(mode)["Reference"])
                    if mutation == "missing":
                        bodies[root].pop()
                    elif mutation == "extra":
                        bodies[root].append(("nop", "@ (mov r8, r8)"))
                    else:
                        bodies[root][0] = ("udf", "#90")
                    image = SimpleNamespace(function=lambda name, **kwargs: bodies[name])
                    with self.subTest(mode=mode, root=root, mutation=mutation), self.assertRaises(RuntimeError):
                        r.match_reference_protocols(image, image, self.checker, mode)

    def test_whole_owning_section_metadata_is_not_symbol_enlargement(self):
        source = (HERE / "reference_run.py").read_text()
        for text in ('Sha256=sha(section.data())', 'RootOffset=offset, RootSize=symbol["size"]',
                     'MappingSymbols=', 'Relocations=relocs', 'IncludesOutOfSymbolPools=True',
                     'AppliedRelocationProof=False', 'expected["pxCurrentTCB"] = (2, "STT_OBJECT")'):
            self.assertIn(text, source)


class EnvelopeControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cm0-reference-envelope-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pilot = r.Reference.__new__(r.Reference)
        self.pilot.profile, self.pilot.mode = "CM0", "O2"
        self.pilot.output, self.pilot.repo = self.root, HERE.parents[2]
        self.pilot.inputs, self.pilot.generated, self.pilot.commands = {}, {}, []
        self.pilot.memberships = []
        self.pilot.report = r.scope_report()
        self.pilot._prepared = self.pilot._built = self.pilot._prelink_verified = self.pilot._twins_verified = False
        self.pilot._reference_opened = self.pilot._reference_closed = False
        self.pilot.environment = {}

    def objects(self, count=5):
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

    def test_exact_five_object_freeze_and_drift(self):
        self.objects()
        self.pilot.freeze_objects()
        self.assertEqual(len(self.pilot.object_hashes), 5)
        self.pilot.objects[0].write_bytes(b"changed")
        with self.assertRaises(RuntimeError):
            self.pilot.verify_objects("before-prelink")

    def test_wrong_count_or_unverified_object_rejects(self):
        self.objects(4)
        with self.assertRaises(RuntimeError):
            self.pilot.freeze_objects()
        self.pilot.objects.clear()
        self.pilot.report["Sources"].clear()
        self.objects()
        self.pilot.report["Sources"][0]["CompileDependenciesVerified"] = False
        with self.assertRaises(RuntimeError):
            self.pilot.freeze_objects()

    def test_empty_or_incomplete_build_cannot_pass(self):
        self.assertFalse(self.pilot.finish(None))
        self.receipt("FAIL")

    def test_positive_closure_has_seven_checkpoints(self):
        self.ready()
        self.assertTrue(self.pilot.finish(None))
        row = self.receipt(r.PASS)
        self.assertEqual([check["Stage"] for check in row["ObjectChecks"]], list(r.CHECKPOINTS))
        self.assertIs(row["ArtifactSealVerified"], True)

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

    def test_original_and_captured_input_drift_rejects(self):
        self.ready()
        original, captured = self.root / "original.h", self.root / "captured.h"
        original.write_bytes(b"before")
        captured.write_bytes(b"before")
        self.pilot.inputs[str(original)] = dict(Original=str(original), Captured=str(captured), Sha256=r.sha(b"before"))
        original.write_bytes(b"after")
        self.assertFalse(self.pilot.finish(None))
        self.assertTrue(self.receipt("FAIL")["InputDrift"])


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = args.report.resolve()
    if report.exists() or not report.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        parser.error("fresh report inside TEMP required")
    sources = [HERE / "reference_run.py", Path(__file__).resolve(), HERE.parents[2] / "tools/freeze_cohorts.json"]
    sources += [HERE / "reference" / name for name in r.FIXTURE_FILES]
    hashes = {str(path): r.sha(path.read_bytes()) for path in sources}
    with patch("subprocess.Popen", side_effect=AssertionError("native execution forbidden in pure controls")):
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    drift = [str(path) for path in sources if r.sha(path.read_bytes()) != hashes[str(path)]]
    value = dict(Status="PASS" if result.wasSuccessful() and not drift else "FAIL", Tests=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped), SourceHashes=hashes, SourceDrift=drift,
        ToolInvocations=0, CpuExecution=False, BoardExecution=False, FinalElfProof=False,
        Scope="PURE_CM0_REFERENCE_PRODUCER_ENVELOPE_CONTROLS_ONLY",
        FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(json.dumps(value, sort_keys=True))
    return 0 if value["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
