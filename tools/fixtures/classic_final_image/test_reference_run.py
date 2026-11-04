"""Pure envelopes for pinned CM4/CM7 reference twins; no native tools."""
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
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("reference_final_controls", HERE / "reference_run.py")
r = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = r
SPEC.loader.exec_module(r)


class ScopeControls(unittest.TestCase):
    def test_fixed_selection_only(self):
        self.assertEqual(r.selection("CM4", "O2"), r.COHORT)
        self.assertEqual(set(r.PROFILES), {"CM4", "CM7"})
        self.assertEqual(r.MODES, ("O0", "Og", "O2", "Os", "O3"))
        for profile in r.PROFILES:
            for mode in r.MODES:
                self.assertEqual(r.selection(profile, mode), r.native.PROFILES[profile][0])
        for profile, mode in (("CM4", "O1"), ("CM7", "Ofast"), ("CM7/r0p1", "O2"),
                              ("CM4", "O2-LTO"), ("CM7", "Os-LTO"), ("CM0", "O2"),
                              (None, "O2"), ("CM4", True), (True, "O2")):
            with self.subTest(profile=profile, mode=mode), patch.object(Path, "mkdir", side_effect=AssertionError("mkdir")):
                with self.assertRaisesRegex(RuntimeError, "reference selection"):
                    r.Reference(SimpleNamespace(profile=profile, mode=mode))

    def test_exact_profile_paths_configs_and_fp_facts(self):
        self.assertEqual(r.PROFILES, {
            "CM4": (r.native.PROFILES["CM4"][0], "portable/GCC/ARM_CM4F",
                "tools/fixtures/classic_fp_context_runtime/reference/FreeRTOSConfig.h", 4),
            "CM7": (r.native.PROFILES["CM7"][0], "portable/GCC/ARM_CM7/r0p1",
                "tools/fixtures/classic_cm7_fp_context_runtime/reference/FreeRTOSConfig.h", 14)})
        for profile, (_, directory, config, fp) in r.PROFILES.items():
            self.assertEqual(r.port_paths(profile), (directory + "/port.c", directory + "/portmacro.h"))
            text = (HERE.parents[2] / config).read_text()
            self.assertIn('__ARM_PCS_VFP', text)
            self.assertIn('(__ARM_FP & 12) != 12' if profile == "CM7" else '(__ARM_FP & 4) == 0', text)
            self.assertNotIn('WORKAROUND_PMU_CM001', text)
            r.require_header_facts(struct.pack("<10I", 1, 4, 4, 4, 8, fp, 1, 16, 16, 4), profile)

    def test_ten_scope_reports_are_explicit_without_promotion(self):
        self.assertEqual(r.PASS, "REFERENCE-CLASSIC-FP-FINAL-TWIN-BUILD-PASS")
        for profile in r.PROFILES:
            for mode in r.MODES:
                report = r.scope_report(profile, mode)
                self.assertEqual((report["Profile"], report["Mode"], report["Cohort"]),
                                 (profile, mode, r.native.PROFILES[profile][0]))
                self.assertEqual(report["ProofScope"], "PINNED_REFERENCE_" + profile + "_" + mode + "_DIRECT_TWIN_BUILD_ONLY")
                self.assertEqual(report["RecipeVersion"], 2)
                self.assertEqual(report["RequiredCellsSatisfied"], 0)
                self.assertIs(type(report["RequiredCellsSatisfied"]), int)
                for key in ("FinalElfProof", "FinalRootRelocationProof", "FinalReferenceParity", "CompleteObjectProof",
                            "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified", "SchedulerSemanticsProven"):
                    self.assertIs(report[key], False)
                self.assertEqual(report["FPCCRPolicy"]["ReferencePolicy"], "upstream-lazy")
                self.assertEqual(report["DifferenceIds"], ["FAP-FP-SETUP-POLICY"] +
                                 (["FAP-CM7-ERRATA-PRIMASK"] if profile == "CM7" else []))

    def test_cli_defaults_and_all_ten_explicit_selections(self):
        base = ["--gcc", "not-run", "--git", "not-run", "--freertos", "not-read",
                "--inventory", "not-read", "--output-dir", "not-created"]
        for extra, expected in [([], ("CM4", "O2"))] + [
                (["--profile", profile, "--mode", mode], (profile, mode)) for profile in r.PROFILES for mode in r.MODES]:
            pilot = SimpleNamespace(prepare=Mock(), build=Mock(), finish=Mock(return_value=True),
                                    report=dict(Verdict=r.PASS), output="not-created")
            with patch.object(r, "Reference", return_value=pilot) as constructor, patch("builtins.print"):
                self.assertEqual(r.main(base + extra), 0)
            args = constructor.call_args.args[0]
            self.assertEqual((args.profile, args.mode), expected)

    def test_fixed_pin_and_no_policy_cpu_or_parity_promotion(self):
        report = r.scope_report()
        self.assertEqual(r.PIN, "a50edad08b29052631aa469d4df6e6ec7ff68878")
        self.assertEqual((report["Profile"], report["Mode"], report["Cohort"]), ("CM4", "O2", r.COHORT))
        self.assertIs(type(report["RequiredCellsSatisfied"]), int)
        self.assertEqual(report["RequiredCellsSatisfied"], 0)
        for key in ("ReferenceBuilt", "NativeBuilt", "LTO", "RequiredCellSatisfied", "FinalElfProof",
                    "FinalRootRelocationProof", "FinalReferenceParity", "CompleteObjectProof", "PolicyEquivalence",
                    "CpuExecution", "BoardExecution", "GlobalFreezeQualified", "SchedulerSemanticsProven", "ReferenceKernelAvailable"):
            self.assertIs(report[key], False)
        policy = report["FPCCRPolicy"]
        self.assertEqual((policy["DeclaredNativePolicy"], policy["ReferencePolicy"]), ("eager", "upstream-lazy"))
        self.assertEqual((policy["ReferenceASPEN"], policy["ReferenceLSPEN"], policy["ReferenceBits"]), (1, 1, 0xC0000000))
        self.assertEqual(policy["DifferenceId"], "FAP-FP-SETUP-POLICY")
        self.assertIs(policy["PolicyEquivalenceProven"], False)

    def test_reports_do_not_share_mutable_state(self):
        a, b = r.scope_report(), r.scope_report()
        a["Sources"].append("changed")
        a["FPCCRPolicy"]["ReferenceBits"] = 0
        self.assertEqual(b["Sources"], [])
        self.assertEqual(b["FPCCRPolicy"]["ReferenceBits"], 0xC0000000)

    def test_import_has_no_process_or_output_side_effect(self):
        spec = importlib.util.spec_from_file_location("reference_final_import_control", HERE / "reference_run.py")
        module = importlib.util.module_from_spec(spec)
        with patch("subprocess.Popen", side_effect=AssertionError("spawn")), \
             patch.object(Path, "mkdir", side_effect=AssertionError("mkdir")), \
             patch.object(Path, "write_bytes", side_effect=AssertionError("write")), \
             patch.object(Path, "write_text", side_effect=AssertionError("write")):
            spec.loader.exec_module(module)

    def test_native_generic_functions_are_reused_not_replaced(self):
        for name in ("command", "capture", "generated_file", "verify_objects", "link_twin", "inspect"):
            self.assertIs(getattr(r.Reference, name), getattr(r.native.Pilot, name))

    def test_builder_does_not_invoke_witness_or_partial_link(self):
        tree = ast.parse((HERE / "reference_run.py").read_text())
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr in ("Popen", "run", "system")
                             for node in ast.walk(tree)))
        strings = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        self.assertNotIn("-r", strings)
        self.assertFalse(any("-flto" in value for value in strings if value.startswith("-Wl,")))
        self.assertFalse(any("reference_witness" in value or "reference_elf" in value for value in strings))

    def test_four_tu_order_and_direct_twin_link_envelope(self):
        source = (HERE / "reference_run.py").read_text()
        tree = ast.parse(source)
        assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                       and any(isinstance(t, ast.Attribute) and t.attr == "sources" for t in node.targets)]
        self.assertEqual(len(assignments), 1)
        text = ast.get_source_segment(source, assignments[0])
        self.assertIn('self.kernel / self.port', text)
        self.assertIn('("providers.c", "consumer.c", "startup.S")', text)
        self.assertIn('self.report["Links"].append', source)
        self.assertIn('(("ordinary", []), ("emit-relocs", ["-Wl,--emit-relocs"]))', source)
        self.assertIn('"-T", self.fixture_copy / "link.ld", *self.objects', source)
        self.assertIn('"ET_EXEC"', source)
        self.assertIn('expected=sha(NATIVE_BYTES)', source)
        strings = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        self.assertNotIn('-O2', strings)
        self.assertIn('self.recipe.reference_recipe(self.artifact, self.mode,', source)
        self.assertIn('self.admission.require_attributes(port.with_suffix(".attributes").read_text(), self.profile)', source)
        self.assertIn('self.admission.require_attributes(path.with_suffix(".attributes").read_text(), self.profile)', source)


class ManifestControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo = HERE.parents[2]
        cls.admission = r.load("reference_final_test_admission", repo / r.HELPERS[0])
        cls.recipe = r.load("reference_final_test_recipe", repo / r.HELPERS[3])
        cls.checker = r.load("reference_final_test_protocols", repo / r.HELPERS[6])

    def manifest(self, profile="CM4"):
        cpu, fpu, errata = ("cortex-m4", "fpv4-sp-d16", "none") if profile == "CM4" else (
            "cortex-m7", "fpv5-d16", "837070-primask-preserving")
        target = dict(cpu=cpu, architecture="ARMV7EM", float_abi="hard", fpu_present=True,
            fpu_used=True, fpu_unit=fpu, fp_stacking="eager", vtor=True, mpu_regions=0,
            security_role="classic", psplim_slot=False, psplim_register=False, mve="none", pac=False,
            bti=False, errata_policy=errata, r9_abi="aapcs", nvic_priority_bits=4, scheduler_basepri=16)
        artifact = dict(role="runtime", source_group_id=profile, abi_contract="forward8", target=target,
            compile_flags=["-mcpu=" + cpu, "-mthumb", "-mfloat-abi=hard", "-mfpu=" + fpu],
            defines=dict(FIBER_FPU_LAZY="0", FIBER_PORT_ARMV7EM="1", FIBER_PORT_BUILD_SELECTED="1", FIBER_SCHEDULER_BASEPRI="16"),
            upstream_sources=[r.port_paths(profile)[0]], upstream_defines=dict(FIBER_FREERTOS_PARITY_ENABLE_MPU="0",
                FIBER_FREERTOS_PARITY_ENABLE_FPU="1", FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE="0"))
        if profile == "CM7":
            artifact["upstream_defines"]["configENABLE_ERRATA_837070_WORKAROUND"] = "1"
        return dict(cohorts=[dict(id=r.PROFILES[profile][0], artifacts=[artifact])], source_groups=[dict(id=profile,
            sources=list(r.native.selection(profile, "O2")[3]))])

    def test_actual_manifest_all_ten_profile_modes(self):
        # The e1 failure used captured e8 inventory, not the formerly incomplete synthetic CM7 row.
        manifest = json.loads((HERE.parents[2] / "tools/freeze_cohorts.json").read_bytes())
        self.assertEqual(self.admission.shared.inventory.PIN, "a50edad08b29052631aa469d4df6e6ec7ff68878")
        for profile in ("CM4", "CM7"):
            expected = dict(FIBER_FREERTOS_PARITY_ENABLE_MPU="0", FIBER_FREERTOS_PARITY_ENABLE_FPU="1",
                            FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE="0")
            if profile == "CM7":
                expected["configENABLE_ERRATA_837070_WORKAROUND"] = "1"
            for mode in ("O0", "Og", "O2", "Os", "O3"):
                with self.subTest(profile=profile, mode=mode):
                    before = copy.deepcopy(manifest)
                    artifact = r.require_artifact(manifest, self.admission, profile, mode)
                    self.assertEqual(artifact["upstream_defines"], expected)
                    self.assertEqual(artifact, self.manifest(profile)["cohorts"][0]["artifacts"][0])
                    binding = self.recipe.reference_recipe(artifact, mode, "fixture", "kernel")
                    defines = [flag for flag in binding["Flags"] if flag.startswith("-D")]
                    self.assertEqual(defines, ["-D%s=%s" % item for item in sorted(expected.items())])
                    self.assertEqual(binding["PortmacroProvider"], r.port_paths(profile)[1])
                    self.assertEqual(manifest, before)

    def test_actual_manifest_exact_define_mutations_reject(self):
        manifest = json.loads((HERE.parents[2] / "tools/freeze_cohorts.json").read_bytes())
        for profile in ("CM4", "CM7"):
            cohort = next(row for row in manifest["cohorts"] if row["id"] == r.PROFILES[profile][0])
            actual = cohort["artifacts"][0]["upstream_defines"]
            mutations = []
            for key in actual:
                missing = dict(actual)
                del missing[key]
                mutations.append(("missing-" + key, missing))
                for value in ("0" if actual[key] == "1" else "1", 1, True, "01"):
                    mutations.append(("changed-" + key + "-" + repr(value), dict(actual, **{key: value})))
            for key in ("UNDECLARED_REFERENCE_DEFINE", "WORKAROUND_PMU_CM001"):
                mutations.append(("extra-" + key, dict(actual, **{key: "1"})))
            if profile == "CM4":
                mutations.append(("foreign-CM7-metadata", dict(actual, configENABLE_ERRATA_837070_WORKAROUND="1")))
            for label, definitions in mutations:
                changed = copy.deepcopy(manifest)
                selected = next(row for row in changed["cohorts"] if row["id"] == cohort["id"])
                selected["artifacts"][0]["upstream_defines"] = definitions
                with self.subTest(profile=profile, mutation=label), self.assertRaisesRegex(RuntimeError, "exact reference source/defines"):
                    r.require_artifact(changed, self.admission, profile, "O2")

    def test_exact_artifact_and_raw_threshold_config(self):
        for profile in r.PROFILES:
            for mode in r.MODES:
                with self.subTest(profile=profile, mode=mode):
                    artifact = r.require_artifact(self.manifest(profile), self.admission, profile, mode)
                    binding = self.recipe.reference_recipe(artifact, mode, "fixture", "kernel")
                    self.assertEqual(binding["PortmacroProvider"], r.port_paths(profile)[1])
                    self.assertEqual(binding["ExtraIncludes"], [])
                    self.assertIs(binding["ExactTargetRecipe"], True)
                    self.assertEqual(binding["WitnessKind"], "none")
                    for macro in ("configMAX_SYSCALL_INTERRUPT_PRIORITY", "configMAX_API_CALL_INTERRUPT_PRIORITY"):
                        self.assertIn("#undef " + macro + "\n#define " + macro + " 16U", binding["ConfigText"])
                    self.assertIn('#include "freeze_base_FreeRTOSConfig.h"', binding["ConfigText"])
                    self.assertEqual(binding["Flags"][:5], [*artifact["compile_flags"], "-" + mode])
                    self.assertNotIn("-include", binding["Flags"])
                    self.assertFalse(any("WORKAROUND_PMU_CM001" in flag for flag in binding["Flags"]))
                    self.assertTrue(any(row["Kind"] == "fpccr-eager-vs-lazy" for row in binding["Differences"]))

    def test_cross_profile_source_flags_and_abi_cannot_be_aliased(self):
        for profile, other in (("CM4", "CM7"), ("CM7", "CM4")):
            original = self.manifest(profile)
            foreign = self.manifest(other)["cohorts"][0]["artifacts"][0]
            for field in ("source_group_id", "compile_flags", "upstream_sources", "target"):
                manifest = copy.deepcopy(original)
                manifest["cohorts"][0]["artifacts"][0][field] = copy.deepcopy(foreign[field])
                with self.subTest(profile=profile, field=field), self.assertRaises(RuntimeError):
                    r.require_artifact(manifest, self.admission, profile, "O2")
            for field, value in (("defines", dict(original["cohorts"][0]["artifacts"][0]["defines"], WORKAROUND_PMU_CM001="1")),
                                 ("upstream_defines", dict(foreign["upstream_defines"], WORKAROUND_PMU_CM001="1"))):
                manifest = copy.deepcopy(original)
                manifest["cohorts"][0]["artifacts"][0][field] = value
                with self.subTest(profile=profile, field=field), self.assertRaises(RuntimeError):
                    r.require_artifact(manifest, self.admission, profile, "O2")

    def test_foreign_targets_flags_sources_and_defines_reject(self):
        for field, value in (("scheduler_basepri", 128), ("nvic_priority_bits", 8), ("vtor", False),
                             ("float_abi", "softfp"), ("cpu", "cortex-m7"), ("fp_stacking", "lazy")):
            manifest = self.manifest()
            manifest["cohorts"][0]["artifacts"][0]["target"][field] = value
            with self.subTest(target=field), self.assertRaises(RuntimeError):
                r.require_artifact(manifest, self.admission)
        for field, value in (("upstream_sources", [r.PORT, "tasks.c"]), ("upstream_sources", [r.PORT, r.PORT]),
                             ("upstream_sources", ["portable/GCC/ARM_CM7/r0p1/port.c"]),
                             ("upstream_defines", {}), ("compile_flags", ["-mcpu=cortex-m4", "-mthumb", "-mfloat-abi=hard"]),
                             ("source_group_id", "CM7")):
            manifest = self.manifest()
            manifest["cohorts"][0]["artifacts"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                r.require_artifact(manifest, self.admission)

    def test_canonical_complete_reference_protocols(self):
        for profile in r.PROFILES:
            for mode in r.MODES:
                bodies = self.checker._REFERENCE[profile]
                calls = []
                def function(name, **kwargs):
                    calls.append((name, kwargs))
                    return copy.deepcopy(bodies[name]) + [("nop", "")] * int(mode == "O0")
                result = r.match_reference_protocols(SimpleNamespace(function=function), self.checker, profile, mode)
                self.assertEqual([row["Name"] for row in result], list(r.ROOTS))
                self.assertEqual([row["TailNops"] for row in result], [int(mode == "O0")] * 3)
                self.assertEqual(calls, [(name, dict(literal_islands=True)) for name in r.ROOTS])

    def test_other_profile_mask_protocol_and_wrong_mode_tails_reject(self):
        for profile, other in (("CM4", "CM7"), ("CM7", "CM4")):
            for mode in r.MODES:
                for kind in ("other-profile", "wrong-tail", "mixed-tail"):
                    bodies = copy.deepcopy(self.checker._REFERENCE[other if kind == "other-profile" else profile])
                    for name in bodies:
                        count = int(mode == "O0")
                        if kind == "wrong-tail" or (kind == "mixed-tail" and name == r.ROOTS[0]):
                            count = 1 - count
                        bodies[name] += [("nop", "")] * count
                    image = SimpleNamespace(function=lambda name, **kwargs: bodies[name])
                    with self.subTest(profile=profile, mode=mode, mutation=kind), self.assertRaises(RuntimeError):
                        r.match_reference_protocols(image, self.checker, profile, mode)

    def test_profile_header_facts_are_exact_not_just_hard_abi(self):
        for profile in r.PROFILES:
            expected = [1, 4, 4, 4, 8, 4 if profile == "CM4" else 14, 1, 16, 16, 4]
            r.require_header_facts(struct.pack("<10I", *expected), profile)
            for index, value in ((5, 14 if profile == "CM4" else 4), (1, 8), (6, 0), (7, 128), (8, 128), (9, 8)):
                changed = list(expected)
                changed[index] = value
                with self.subTest(profile=profile, field=index), self.assertRaisesRegex(RuntimeError, "header facts"):
                    r.require_header_facts(struct.pack("<10I", *changed), profile)
            with self.assertRaisesRegex(RuntimeError, "header facts"):
                r.require_header_facts(bytes(36), profile)

    def test_attribute_gate_remains_profile_specific(self):
        for profile, fp in (("CM4", "VFPv4-D16"), ("CM7", "FPv5/FP-D16 for ARMv8")):
            attributes = ('Tag_CPU_name: "7E-M"\nTag_CPU_arch: v7E-M\nTag_CPU_arch_profile: Microcontroller\n'
                          'Tag_THUMB_ISA_use: Thumb-2\nTag_ABI_VFP_args: VFP registers\nTag_FP_arch: ' + fp + '\n')
            self.admission.require_attributes(attributes, profile)
            with self.assertRaises(RuntimeError):
                self.admission.require_attributes(attributes, "CM7" if profile == "CM4" else "CM4")

    def test_complete_reference_protocols_reject_every_partial_root(self):
        for root in r.ROOTS:
            for kind in ("missing", "extra", "changed"):
                bodies = copy.deepcopy(self.checker._REFERENCE["CM4"])
                if kind == "missing":
                    bodies[root].pop()
                elif kind == "extra":
                    bodies[root].append(("nop", ""))
                else:
                    bodies[root][0] = ("nop", "")
                image = SimpleNamespace(function=lambda name, **kwargs: bodies[name])
                with self.subTest(root=root, mutation=kind), self.assertRaises(RuntimeError):
                    r.match_reference_protocols(image, self.checker)

    def test_exact_root_set_and_integer_o2_padding(self):
        bodies = self.checker._REFERENCE["CM4"]
        for value in (True, False, 1, -1, None):
            checker = SimpleNamespace(_REFERENCE=dict(CM4=bodies), _match=lambda *args: dict(TailNops=value))
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "tail layout"):
                r.match_reference_protocols(None, checker)
        checker = SimpleNamespace(_REFERENCE=dict(CM4={k: v for k, v in bodies.items() if k != r.ROOTS[0]}))
        with self.assertRaisesRegex(RuntimeError, "exact reference protocol roots"):
            r.match_reference_protocols(None, checker)

    def test_reference_byte_pin_only_exact_or_full_crlf_expansion(self):
        match = self.admission.shared.inventory.reference_bytes_match
        blob = b"first\nsecond\n"
        self.assertEqual(match(blob, blob), "exact")
        self.assertEqual(match(blob.replace(b"\n", b"\r\n"), blob), "git-lf-worktree-crlf")
        for data in (b"first\r\nsecond\n", b"first\rsecond\n", b"changed\nsecond\n"):
            with self.subTest(data=data), self.assertRaises(RuntimeError):
                match(data, blob)

    def test_config_portmacro_and_source_dependency_roles(self):
        fixture, kernel = Path("fixture"), Path("kernel")
        for profile in r.PROFILES:
            port, portmacro = r.port_paths(profile)
            source = kernel / port
            paths = [source, kernel / portmacro, fixture / "FreeRTOSConfig.h", fixture / "freeze_base_FreeRTOSConfig.h"]
            r.require_dependency_roles(paths, source, fixture, kernel, profile)
            for missing in paths:
                with self.subTest(profile=profile, missing=missing), self.assertRaises(RuntimeError):
                    r.require_dependency_roles([p for p in paths if p != missing], source, fixture, kernel, profile)
            for foreign in (Path("foreign/portmacro.h"), kernel / r.port_paths("CM7" if profile == "CM4" else "CM4")[1]):
                with self.subTest(profile=profile, foreign=foreign), self.assertRaisesRegex(RuntimeError, "providers"):
                    r.require_dependency_roles([*paths, foreign], source, fixture, kernel, profile)
            r.require_dependency_roles([Path("fixture/startup.S")], Path("fixture/startup.S"), fixture, kernel, profile)


class FixtureControls(unittest.TestCase):
    def test_typed_failstop_boundaries_do_not_return_success(self):
        source = (HERE / "reference/providers.c").read_text()
        header = (HERE / "reference/reference.h").read_text()
        self.assertIn('TaskHandle_t volatile pxCurrentTCB = NULL;', source)
        self.assertIn('#include "task.h"', header)
        self.assertIn('REFERENCE_BOUNDARY BaseType_t xTaskIncrementTick(void)', source)
        self.assertIn('REFERENCE_BOUNDARY void vTaskSwitchContext(void)', source)
        self.assertIn('reference_fail_stop(0x5449434Bu);', source)
        self.assertIn('reference_fail_stop(0x53574348u);', source)
        self.assertIn('__asm volatile("udf #90"', source)
        self.assertNotRegex(source, r"\breturn\s+(?:0|1|pdTRUE|pdFALSE)")
        self.assertNotIn('struct tskTaskControlBlock {', source)

    def test_typed_consumer_retains_real_port_and_threshold_facts(self):
        source = (HERE / "reference/consumer.c").read_text()
        self.assertIn('StackType_t *(*initialise_stack)(StackType_t *, TaskFunction_t, void *);', source)
        self.assertIn('BaseType_t (*start_scheduler)(void);', source)
        self.assertIn('pxPortInitialiseStack,\n    xPortStartScheduler', source)
        for macro in ("configMAX_SYSCALL_INTERRUPT_PRIORITY", "configMAX_API_CALL_INTERRUPT_PRIORITY"):
            self.assertIn('_Static_assert(' + macro + ' == 16,', source)
        self.assertNotRegex(source, r"\bxPortStartScheduler\s*\(")

    def test_strong_vectors_include_systick_alternative_target(self):
        source = (HERE / "reference/startup.S").read_text()
        body = source.split("reference_vector_table:\n", 1)[1].split(".size reference_vector_table", 1)[0]
        words, repeat = [], 1
        for line in body.splitlines():
            line = line.strip()
            if line.startswith(".rept "):
                repeat = int(line.split()[1])
            elif line == ".endr":
                repeat = 1
            elif line.startswith(".word "):
                words.extend([word.strip() for word in line[6:].split(",")] * repeat)
        self.assertEqual(len(words), 256)
        self.assertEqual([words[i] for i in (0, 1, 11, 14, 15)],
            ["__reference_stack_top", "reference_reset_handler", "vPortSVCHandler", "xPortPendSVHandler", "xPortSysTickHandler"])
        self.assertIn('bl reference_reset_forbidden', source)
        self.assertNotRegex(source, r"(?m)^\s*\.(?:cpu|fpu|arch)\s")

    def test_two_unowned_nops_are_kept_outside_reset_extent(self):
        source = (HERE / "reference/startup.S").read_text()
        script = (HERE / "reference/link.ld").read_text()
        self.assertLess(source.index(".size reference_reset_handler"), source.index(".section .text.reference_origin_padding"))
        self.assertRegex(source, r'[.]section [.]text[.]reference_origin_padding,"ax",%progbits\s+[.]balign 2\s+nop\s+nop\s+[.]section')
        self.assertIn('KEEP(*(.text.reference_origin_padding))', script)
        self.assertNotRegex(source, r"(?m)^\s*[.]type\s+reference_origin_padding")
        self.assertIn('ENTRY(reference_reset_handler)', script)
        self.assertIn('SIZEOF(.reference_contract) == 40', script)


class EnvelopeControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="reference-final-envelope-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pilot = r.Reference.__new__(r.Reference)
        self.pilot.profile, self.pilot.mode = "CM4", "O2"
        self.pilot.output, self.pilot.repo = self.root, HERE.parents[2]
        self.pilot.inputs, self.pilot.generated, self.pilot.commands = {}, {}, []
        self.pilot.memberships = []
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
            self.pilot.report["Sources"].append(dict(Object=str(path), ObjectSha256=r.sha(path.read_bytes()),
                                                     CompileDependenciesVerified=True))

    def test_four_actual_objects_and_hash_checkpoints(self):
        self.objects()
        self.pilot.freeze_objects()
        self.pilot.verify_objects("before-prelink")
        self.assertEqual(len(self.pilot.object_hashes), 4)
        self.assertEqual(self.pilot.report["ObjectChecks"][0]["Status"], "PASS")
        self.pilot.objects[0].write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "frozen object drift"):
            self.pilot.verify_objects("after-prelink")

    def test_empty_extra_duplicate_and_unverified_objects_reject(self):
        self.objects(5)
        with self.assertRaisesRegex(RuntimeError, "four-object"):
            self.pilot.freeze_objects()
        self.pilot.objects.pop()
        self.pilot.report["Sources"].pop()
        self.pilot.objects[-1] = self.pilot.objects[0]
        with self.assertRaisesRegex(RuntimeError, "four-object"):
            self.pilot.freeze_objects()
        self.pilot.objects.clear()
        self.pilot.report["Sources"].clear()
        self.objects()
        self.pilot.report["Sources"][0]["CompileDependenciesVerified"] = False
        with self.assertRaisesRegex(RuntimeError, "unverified compilation"):
            self.pilot.freeze_objects()

    def test_unbuilt_or_empty_proof_cannot_finalize_pass(self):
        self.assertFalse(self.pilot.finish(None))
        self.assertEqual(self.pilot.report["Verdict"], "FAIL")
        self.assertEqual(self.pilot.report["Error"], "incomplete reference build stages")

    def ready_to_close(self):
        self.objects()
        self.pilot.freeze_objects()
        for stage in r.CHECKPOINTS[:-1]:
            self.pilot.verify_objects(stage)
        self.pilot._prepared = self.pilot._built = self.pilot._prelink_verified = self.pilot._twins_verified = True
        self.pilot._reference_closed = True
        self.pilot.commands = [dict(Status="PASS", Label="pure envelope, no actual tool")]
        self.pilot.report.update(ReferenceBuilt=True, Links=[dict(Kind="ordinary"), dict(Kind="emit-relocs")],
                                PrelinkReferenceRoots=[dict(Name=name) for name in r.ROOTS])
        self.original, self.captured = self.root / "original-input.c", self.root / "copied-input.c"
        for path in (self.original, self.captured):
            path.write_bytes(b"unchanged source input\n")
        self.pilot.inputs[str(self.original)] = dict(Original=str(self.original), Captured=str(self.captured),
                                                    Sha256=r.sha(self.original.read_bytes()))
        self.payload = self.root / "listed-payload.bin"
        self.payload.write_bytes(b"original artifact")

    def assert_consistent_receipt(self, verdict):
        receipt = json.loads((self.root / "results.json").read_bytes())
        self.assertEqual(receipt["Verdict"], verdict)
        self.assertEqual(json.loads((self.root / "artifacts.json").read_bytes()),
                         dict(Artifacts=r.artifact_inventory(self.root)))
        self.assertEqual(receipt["InputDrift"], [])
        self.assertEqual(self.original.read_bytes(), b"unchanged source input\n")
        self.assertEqual(self.captured.read_bytes(), self.original.read_bytes())
        return receipt

    def test_success_is_published_only_after_initial_seal_and_final_reseal(self):
        self.ready_to_close()
        save = r.save
        observed = []
        def watch(path, value):
            save(path, value)
            if path.name == "artifacts.json":
                observed.append(json.loads((self.root / "results.json").read_bytes())["Verdict"])
        with patch.object(r, "save", side_effect=watch):
            self.assertTrue(self.pilot.finish(None))
        self.assertEqual(observed, ["FAIL", r.PASS])
        receipt = self.assert_consistent_receipt(r.PASS)
        self.assertIs(receipt["ArtifactSealVerified"], True)

    def reject_seal_fault(self, kind, phase):
        self.ready_to_close()
        save = r.save
        manifests = 0
        def inject(path, value):
            nonlocal manifests
            save(path, value)
            if path.name != "artifacts.json":
                return
            manifests += 1
            if manifests != phase:
                return
            if kind == "addition":
                (self.root / "late-added-artifact.bin").write_bytes(b"late addition")
            elif kind == "mutation":
                self.payload.write_bytes(b"late mutation")
            else:
                self.payload.unlink()
        with patch.object(r, "save", side_effect=inject):
            self.assertFalse(self.pilot.finish(None))
        receipt = self.assert_consistent_receipt("FAIL")
        self.assertIn("reference artifact seal path/hash drift", receipt["Error"])
        self.assertIs(receipt["ArtifactSealVerified"], False)
        self.assertGreater(manifests, phase)

    def test_artifact_added_during_manifest_write_leaves_consistent_failure(self):
        self.reject_seal_fault("addition", 1)

    def test_listed_mutation_after_pass_write_rolls_back_to_failure(self):
        self.reject_seal_fault("mutation", 2)

    def test_listed_removal_during_manifest_write_leaves_consistent_failure(self):
        self.reject_seal_fault("removal", 1)

    def test_manifest_write_error_after_pass_persists_failure(self):
        self.ready_to_close()
        save = r.save
        manifests = 0
        def inject(path, value):
            nonlocal manifests
            if path.name == "artifacts.json":
                manifests += 1
                if manifests == 2:
                    raise OSError("injected manifest write failure")
            save(path, value)
        with patch.object(r, "save", side_effect=inject):
            self.assertFalse(self.pilot.finish(None))
        receipt = self.assert_consistent_receipt("FAIL")
        self.assertIn("injected manifest write failure", receipt["Error"])
        self.assertIs(receipt["ArtifactSealVerified"], False)
        self.assertGreaterEqual(manifests, 3)

    def test_managed_attempt_and_binary_output_without_process(self):
        tool = self.root / "not-executed.exe"
        tool.write_bytes(b"pure test")
        self.pilot.inputs[str(tool.resolve())] = dict(Sha256=r.sha(tool.read_bytes()))
        def run(argv, **kwargs):
            record = json.loads((self.root / "command-0000.json").read_text())
            self.assertEqual(record["Status"], "ATTEMPT")
            self.assertEqual(argv, [str(tool), "argument with spaces"])
            self.assertEqual(kwargs["timeout"], 3)
            return SimpleNamespace(returncode=0, timed_out=False, elapsed=0.1, stdout=b"\x00\xff", stderr=b"\xfe")
        self.pilot.process = SimpleNamespace(run=run)
        with patch("subprocess.Popen", side_effect=AssertionError("must not spawn")):
            self.pilot.command([tool, "argument with spaces"], "pure command", timeout=3)
        self.assertEqual((self.root / "command-0000.stdout").read_bytes(), b"\x00\xff")
        self.assertEqual(self.pilot.commands[0]["Status"], "PASS")

    def test_timeout_is_recorded_as_failure_with_zero_exit(self):
        tool = self.root / "not-executed.exe"
        tool.write_bytes(b"pure test")
        self.pilot.inputs[str(tool.resolve())] = dict(Sha256=r.sha(tool.read_bytes()))
        self.pilot.process = SimpleNamespace(run=Mock(return_value=SimpleNamespace(
            returncode=0, timed_out=True, elapsed=1, stdout=b"partial", stderr=b"timeout")))
        with self.assertRaisesRegex(RuntimeError, "tool failed/timeout"):
            self.pilot.command([tool], "pure timeout")
        self.assertEqual(self.pilot.commands[0]["Status"], "FAIL")
        self.assertEqual((self.root / "command-0000.stdout").read_bytes(), b"partial")


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    report = Path(args.report).resolve()
    if report.exists() or not report.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        raise SystemExit("requires a fresh report inside TEMP")
    sources = [HERE / name for name in ("reference_run.py", "test_reference_run.py")]
    sources += [HERE / "reference" / name for name in r.FIXTURE_FILES]
    sources.append(HERE.parents[2] / "tools/freeze_cohorts.json")
    source_hashes = {str(path): r.sha(path.read_bytes()) for path in sources}
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                              for case in (ScopeControls, ManifestControls, FixtureControls, EnvelopeControls))
    with patch("subprocess.Popen", side_effect=AssertionError("native launch forbidden in pure controls")):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    source_drift = [str(path) for path in sources if r.sha(path.read_bytes()) != source_hashes[str(path)]]
    value = dict(Status="PASS" if result.wasSuccessful() and not source_drift else "FAIL", Tests=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped), ToolInvocations=0,
        CpuExecution=False, BoardExecution=False, SourceHashes=source_hashes, SourceDrift=source_drift,
        FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(json.dumps(value, sort_keys=True))
    return 0 if value["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
