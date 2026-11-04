"""Pure controls for the final-image pilot's command envelope and claim scope."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("classic_final_pilot_controls", HERE / "run.py")
r = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = r
SPEC.loader.exec_module(r)


class CommandControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="classic-final-command-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pilot = r.Pilot.__new__(r.Pilot)
        self.pilot.output = self.root
        self.pilot.inputs = {}
        self.pilot.environment = {"PILOT_TEST": "bounded"}
        self.pilot.commands = []
        self.tool = self.root / "tool.exe"
        self.tool.write_bytes(b"not executed by these pure controls")
        self.pilot.inputs[str(self.tool.resolve())] = {"Sha256": r.sha(self.tool.read_bytes())}
        self.result = SimpleNamespace(returncode=0, timed_out=False, elapsed=0.1,
                                      stdout=b"out\x00\xff", stderr=b"err\xfe")
        self.events = []
        self.pilot.process = SimpleNamespace(run=self.invoke)

    def invoke(self, argv, **kwargs):
        self.events.append((argv, kwargs))
        record = json.loads((self.root / "command-0000.json").read_text())
        self.assertEqual(record["Status"], "ATTEMPT")
        self.assertIsNone(record["Exit"])
        self.assertIsNone(record["TimedOut"])
        self.assertEqual(record["Argv"], argv)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result

    def record(self):
        record = json.loads((self.root / "command-0000.json").read_text())
        self.assertEqual(json.loads((self.root / "commands.json").read_text()), [record])
        self.assertEqual(self.pilot.commands, [record])
        return record

    def test_attempt_precedes_launch_and_binary_output_is_preserved(self):
        result = self.pilot.command([self.tool, "argument with spaces", "--literal=1"], "control", timeout=2)
        self.assertIs(result, self.result)
        argv, kwargs = self.events[0]
        self.assertEqual(argv, [str(self.tool), "argument with spaces", "--literal=1"])
        self.assertEqual(kwargs, {"cwd": str(self.root), "env": self.pilot.environment, "timeout": 2})
        self.assertEqual(self.record()["Status"], "PASS")
        self.assertEqual((self.root / "command-0000.stdout").read_bytes(), b"out\x00\xff")
        self.assertEqual((self.root / "command-0000.stderr").read_bytes(), b"err\xfe")

    def test_timeout_is_failure_even_with_zero_root_exit(self):
        self.result.timed_out = True
        with self.assertRaisesRegex(RuntimeError, "tool failed/timeout"):
            self.pilot.command([self.tool], "timeout")
        record = self.record()
        self.assertEqual(record["Status"], "FAIL")
        self.assertEqual(record["Exit"], 0)
        self.assertIs(record["TimedOut"], True)
        self.assertEqual((self.root / "command-0000.stdout").read_bytes(), self.result.stdout)

    def test_nonzero_and_runner_failure_are_not_success(self):
        for code in (1, -1, 125):
            with self.subTest(code=code):
                self.pilot.commands.clear()
                self.result.returncode = code
                with self.assertRaises(RuntimeError):
                    self.pilot.command([self.tool], "failure")
                self.assertEqual(self.record()["Status"], "FAIL")

    def test_boolean_exit_and_timeout_fields_are_rejected(self):
        for code, timeout in ((False, False), (0, 0), (True, False), (0, None)):
            with self.subTest(code=code, timeout=timeout):
                self.pilot.commands.clear()
                self.result.returncode, self.result.timed_out = code, timeout
                with self.assertRaises(RuntimeError):
                    self.pilot.command([self.tool], "malformed-result")
                self.assertEqual(self.record()["Status"], "FAIL")

    def test_launch_exception_keeps_failure_record(self):
        self.result = OSError("blocked launch")
        with self.assertRaisesRegex(OSError, "blocked launch"):
            self.pilot.command([self.tool], "launch exception")
        record = self.record()
        self.assertEqual(record["Status"], "FAIL")
        self.assertIn("blocked launch", record["Error"])
        self.assertIsNone(record["Exit"])

    def test_tool_change_fails_before_launch(self):
        self.tool.write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "tool drift before launch"):
            self.pilot.command([self.tool], "drift")
        self.assertEqual(self.events, [])
        self.assertEqual(self.record()["Status"], "FAIL")

    def test_untracked_and_missing_executable_fail_before_launch(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                self.pilot.commands.clear()
                self.pilot.inputs.clear()
                if missing:
                    self.tool.unlink()
                with self.assertRaises((RuntimeError, FileNotFoundError)):
                    self.pilot.command([self.tool], "untracked")
                self.assertEqual(self.events, [])
                self.assertEqual(self.record()["Status"], "FAIL")

    def test_interrupt_is_recorded_before_propagation(self):
        self.result = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.pilot.command([self.tool], "interrupt")
        self.assertEqual(self.record()["Status"], "FAIL")


class ScopeControls(unittest.TestCase):
    def test_no_required_global_or_execution_claim(self):
        report = r.scope_report()
        self.assertEqual(report["Verdict"], "FAIL")
        self.assertEqual(report["Cohort"], r.PROFILES["CM4"][0])
        self.assertEqual(report["Profile"], "CM4")
        self.assertEqual(report["Mode"], "O2")
        self.assertEqual(report["Linkage"], "direct")
        self.assertIs(type(report["RequiredCellsSatisfied"]), int)
        self.assertEqual(report["RequiredCellsSatisfied"], 0)
        for key in ("ReferenceBuilt", "LTO", "RequiredCellSatisfied", "FinalElfProof",
                    "FinalRootRelocationProof", "CompleteObjectProof", "PolicyEquivalence",
                    "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
            self.assertIs(report[key], False)

    def test_scope_reports_do_not_share_mutable_state(self):
        first, second = r.scope_report(), r.scope_report()
        first["Commands"].append("mutated")
        first["Sources"].append("mutated")
        first["InputDrift"].append("mutated")
        self.assertEqual(second["Commands"], [])
        self.assertEqual(second["Sources"], [])
        self.assertEqual(second["InputDrift"], [])

    def test_source_groups_are_exactly_context_plus_concrete_profile(self):
        self.assertEqual(r.COMMON_SOURCES,
                         ("context/context_core.c", "context/context_runtime_state.c", "context/context_panic.c"))
        expected = {
            "CM4": ("cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default", "ARM_CM4", "arm_cm4"),
            "CM7": ("cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default", "ARM_CM7/r0p1", "arm_cm7_r0p1"),
            "CM0": ("cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default", "ARM_CM0", "arm_cm0"),
            "CM0PLUS": ("cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default", "ARM_CM0", "arm_cm0"),
            "CM0PLUSVTOR": ("cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default", "ARM_CM0", "arm_cm0"),
            "CM3": ("cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default", "ARM_CM3", "arm_cm3"),
        }
        self.assertEqual(r.PROFILES, expected)
        self.assertEqual(r.MODES, ("O0", "Og", "O2", "Os", "O3"))
        for profile, (cohort, directory, storage) in expected.items():
            for mode in r.MODES:
                with self.subTest(profile=profile, mode=mode):
                    self.assertEqual(r.selection(profile, mode), (cohort, directory, storage,
                        tuple("fiber/port/" + directory + "/" + name for name in
                              ("fiber_port.c", "fiber_port_boot.c", "fiber_port_exception.c"))))
                    report = r.scope_report(profile, mode)
                    self.assertEqual((report["Profile"], report["Cohort"], report["Mode"]), (profile, cohort, mode))
                    self.assertIs(report["LTO"], False)
                    self.assertIs(report["ReferenceBuilt"], False)
                    self.assertEqual(report["RequiredCellsSatisfied"], 0)
                    for key in ("RequiredCellSatisfied", "FinalElfProof", "FinalRootRelocationProof",
                                "CompleteObjectProof", "PolicyEquivalence", "CpuExecution",
                                "BoardExecution", "GlobalFreezeQualified"):
                        self.assertIs(report[key], False)

    def test_unsupported_selection_is_rejected_without_output(self):
        for profile, mode in (("CM3MPU", "O2"), ("cm4", "O2"), ("CM7", "O2-LTO"),
                              ("CM4", "Ofast"), (None, "O2"), ("CM7", True),
                              ("CM0+", "O2"), ("CM0PLUS", "O2-LTO"), ("CM0", "O1"),
                              ("cm3", "O2"), ("CM3", "O2-LTO")):
            with self.subTest(profile=profile, mode=mode):
                with patch.object(Path, "mkdir", side_effect=AssertionError("must reject before mkdir")):
                    with self.assertRaisesRegex(RuntimeError, "unsupported native"):
                        r.Pilot(SimpleNamespace(output_dir="uncreated", profile=profile, mode=mode))

    def test_startup_uses_the_recorded_compiler_target(self):
        source = (HERE / "startup.S").read_text(encoding="ascii")
        self.assertNotRegex(source, r"(?m)^\s*\.(?:cpu|fpu|arch)\s")
        self.assertIn(".thumb", source)

    def test_origin_negative_control_has_owned_fixture_padding(self):
        source = (HERE / "startup.S").read_text(encoding="ascii")
        script = (HERE / "link.ld").read_text(encoding="ascii")
        self.assertRegex(source, r'[.]section [.]text[.]pilot_origin_padding,"ax",%progbits\s+[.]balign 2\s+nop\s+nop')
        self.assertIn("KEEP(*(.text.pilot_origin_padding))", script)
        self.assertNotRegex(source, r'(?m)^[.]type\s+pilot_origin_padding')

    def test_fresh_output_admission_is_before_creation(self):
        with tempfile.TemporaryDirectory(prefix="classic-final-admission-") as directory:
            path = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "fresh external output"):
                r.Pilot(SimpleNamespace(output_dir=str(path)))
            self.assertEqual(list(path.iterdir()), [])
        repo = HERE.parents[2]
        candidate = repo / "pilot-control-must-not-create"
        self.assertFalse(candidate.exists())
        with self.assertRaisesRegex(RuntimeError, "fresh external output"):
            r.Pilot(SimpleNamespace(output_dir=str(candidate)))
        self.assertFalse(candidate.exists())

    def test_import_does_not_launch_process_or_create_output(self):
        spec = importlib.util.spec_from_file_location("classic_final_import_control", HERE / "run.py")
        module = importlib.util.module_from_spec(spec)
        with patch("subprocess.Popen", side_effect=AssertionError("must not spawn")), \
                patch.object(Path, "mkdir", side_effect=AssertionError("must not create")), \
                patch.object(Path, "write_bytes", side_effect=AssertionError("must not write")):
            spec.loader.exec_module(module)

    def test_parent_path_alias_cannot_bypass_repo_output_guard(self):
        repo = HERE.parents[2]
        candidate = repo.parent / "uncreated-parent" / ".." / repo.name / "must-not-create-pilot"
        with patch.object(Path, "mkdir", side_effect=AssertionError("admission reached mkdir")):
            with self.assertRaisesRegex(RuntimeError, "fresh external output"):
                r.Pilot(SimpleNamespace(output_dir=str(candidate)))

    def test_finish_cannot_promote_an_unbuilt_pilot(self):
        with tempfile.TemporaryDirectory(prefix="classic-final-unbuilt-") as directory:
            pilot = r.Pilot.__new__(r.Pilot)
            pilot.output = Path(directory)
            pilot.inputs, pilot.generated, pilot.commands = {}, {}, []
            pilot.report = r.scope_report()
            self.assertFalse(pilot.finish(None))
            self.assertEqual(pilot.report["Verdict"], "FAIL")

    def test_process_environment_does_not_capture_credentials(self):
        source = {"Path": "toolchain", "SystemRoot": "windows", "TEMP": "temporary",
                  "GH_TOKEN": "secret-one", "AWS_SECRET_ACCESS_KEY": "secret-two",
                  "PRIVATE_SETTING": "secret-three", "PYTHONPATH": "not-inherited"}
        self.assertEqual(r.process_environment(source),
                         {"Path": "toolchain", "SystemRoot": "windows", "TEMP": "temporary"})
        self.assertEqual(source["GH_TOKEN"], "secret-one")

    def test_compiler_overrides_are_rejected_before_filtering(self):
        for key in ("GCC_EXEC_PREFIX", "COMPILER_PATH", "LIBRARY_PATH", "CPATH",
                    "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
                    "DEPENDENCIES_OUTPUT", "SUNPRO_DEPENDENCIES", "GCC_SPECS", "LD_PRELOAD"):
            for spelling in (key, key.lower()):
                with self.subTest(key=spelling):
                    with self.assertRaisesRegex(RuntimeError, "ambient compiler override"):
                        r.process_environment({"PATH": "toolchain", spelling: "injected"})
        self.assertEqual(r.process_environment({"PATH": "toolchain", "CPATH": ""}), {"PATH": "toolchain"})


class CM0Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo = HERE.parents[2]
        cls.admission = r.load("classic_final_cm0_controls", repo / r.CM0_HELPERS[0])
        cls.checker = r.load("classic_final_cm0_protocol_controls", repo / r.CM0_HELPERS[1])
        cls.recipe = r.load("classic_final_recipe_controls", repo / r.HELPERS[5])

    def manifest(self, profile):
        identity, _, _, sources = r.selection(profile, "O2")
        cpu, vtor = self.admission.COHORTS[identity]
        target = dict(cpu=cpu, architecture="ARMV6M", float_abi="soft", fpu_present=False,
            fpu_used=False, fpu_unit="", fp_stacking="none", vtor=vtor, mpu_regions=0,
            security_role="classic", psplim_slot=False, psplim_register=False, mve="none",
            pac=False, bti=False, errata_policy="none", r9_abi="aapcs",
            nvic_priority_bits=2, scheduler_basepri=0)
        artifact = dict(role="runtime", source_group_id="CM0", abi_contract="forward8", target=target,
            compile_flags=["-mcpu=" + cpu, "-mthumb", "-mfloat-abi=soft"],
            defines=dict(FIBER_PORT_BUILD_SELECTED="1", FIBER_PORT_ARMV6M="1"))
        return dict(cohorts=[dict(id=identity, artifacts=[artifact])],
                    source_groups=[dict(id="CM0", sources=list(sources))])

    def test_exact_three_authoritative_cohorts(self):
        self.assertEqual(r.CM0_PROFILES, {"CM0", "CM0PLUS", "CM0PLUSVTOR"})
        self.assertEqual({r.PROFILES[p][0] for p in r.CM0_PROFILES}, set(self.admission.COHORTS))
        self.assertEqual(r.CM0_HELPERS, ("tools/freeze_cm0_mechanisms.py",
                                        "tools/fixtures/cm0_freeze_parity/closed_roots.py"))

    def test_all_fifteen_manifest_recipes_are_exact(self):
        for profile in sorted(r.CM0_PROFILES):
            for mode in r.MODES:
                with self.subTest(profile=profile, mode=mode):
                    manifest = self.manifest(profile)
                    artifact = r.require_manifest_selection(manifest, profile, mode, self.admission)
                    self.assertIs(artifact, manifest["cohorts"][0]["artifacts"][0])
                    flags = self.recipe.native_flags(artifact, mode, "generated", "ARM_CM0", "repo", "cmsis")
                    self.assertEqual(flags[:4], [*artifact["compile_flags"], "-" + mode])
                    self.assertEqual([f for f in flags if f.startswith("-D")],
                        ["-DFIBER_PORT_ARMV6M=1", "-DFIBER_PORT_BUILD_SELECTED=1"])
                    main = self.recipe.cmsis_main(artifact["target"])
                    self.assertIn('#include "core_cm0%s.h"' % ("plus" if profile != "CM0" else ""), main)
                    self.assertIn("#define __NVIC_PRIO_BITS 2U", main)
                    self.assertIn("#define __FPU_PRESENT 0U", main)
                    self.assertIn("#define __VTOR_PRESENT %dU" % int(profile == "CM0PLUSVTOR"), main)

    def test_cohort_count_and_artifact_count_are_strict(self):
        for kind in ("no-cohort", "duplicate-cohort", "no-artifact", "duplicate-artifact"):
            manifest = self.manifest("CM0")
            rows = manifest["cohorts"]
            if kind == "no-cohort":
                rows.clear()
            elif kind == "duplicate-cohort":
                rows.append(copy.deepcopy(rows[0]))
            elif kind == "no-artifact":
                rows[0]["artifacts"].clear()
            else:
                rows[0]["artifacts"].append(copy.deepcopy(rows[0]["artifacts"][0]))
            with self.subTest(kind=kind), self.assertRaisesRegex(RuntimeError, "unique cohort"):
                r.require_manifest_selection(manifest, "CM0", "O2", self.admission)

    def test_source_group_is_cm0_not_cli_profile_alias(self):
        for profile in ("CM0PLUS", "CM0PLUSVTOR"):
            for side in ("artifact", "source-group"):
                manifest = self.manifest(profile)
                if side == "artifact":
                    manifest["cohorts"][0]["artifacts"][0]["source_group_id"] = profile
                else:
                    manifest["source_groups"][0]["id"] = profile
                with self.subTest(profile=profile, side=side), self.assertRaises(RuntimeError):
                    r.require_manifest_selection(manifest, profile, "O2", self.admission)

    def test_source_group_membership_order_and_ownership_are_strict(self):
        original = self.manifest("CM0")["source_groups"][0]
        sources = original["sources"]
        mutants = [[], [original, copy.deepcopy(original)],
            [dict(original, sources=sources[:-1])], [dict(original, sources=list(reversed(sources)))],
            [dict(original, sources=[*sources, sources[0]])],
            [dict(original, sources=[s.replace("ARM_CM0", "ARM_CM4") for s in sources])]]
        for groups in mutants:
            manifest = self.manifest("CM0")
            manifest["source_groups"] = groups
            with self.subTest(groups=groups), self.assertRaisesRegex(RuntimeError, "exact source group"):
                r.require_manifest_selection(manifest, "CM0", "O2", self.admission)

    def test_foreign_target_flags_and_defines_are_rejected(self):
        target_mutants = dict(cpu="cortex-m0plus", vtor=True, float_abi="hard", fpu_present=True,
            fpu_used=True, fpu_unit="fpv4-sp-d16", nvic_priority_bits=4, scheduler_basepri=16,
            mpu_regions=8, architecture="ARMV7EM", r9_abi="fixed-r9")
        for field, value in target_mutants.items():
            manifest = self.manifest("CM0")
            manifest["cohorts"][0]["artifacts"][0]["target"][field] = value
            with self.subTest(target=field), self.assertRaises(RuntimeError):
                r.require_manifest_selection(manifest, "CM0", "O2", self.admission)
        for flags in (["-mcpu=cortex-m0", "-mthumb"],
                      ["-mcpu=cortex-m0", "-mthumb", "-mfloat-abi=soft", "-O2"],
                      ["-mthumb", "-mcpu=cortex-m0", "-mfloat-abi=soft"]):
            manifest = self.manifest("CM0")
            manifest["cohorts"][0]["artifacts"][0]["compile_flags"] = flags
            with self.subTest(flags=flags), self.assertRaises(RuntimeError):
                r.require_manifest_selection(manifest, "CM0", "O2", self.admission)
        for key in ("FIBER_FPU_LAZY", "FIBER_SCHEDULER_BASEPRI", "FIBER_PORT_ARMV7EM"):
            manifest = self.manifest("CM0")
            manifest["cohorts"][0]["artifacts"][0]["defines"][key] = "0"
            with self.subTest(define=key), self.assertRaisesRegex(RuntimeError, "exact defines"):
                r.require_manifest_selection(manifest, "CM0", "O2", self.admission)

    def test_startup_flags_derive_only_literal_vtor_without_c_header(self):
        for profile in r.CM0_PROFILES:
            artifact = self.manifest(profile)["cohorts"][0]["artifacts"][0]
            for mode in r.MODES:
                with self.subTest(profile=profile, mode=mode):
                    self.assertEqual(r.startup_flags(artifact, mode), [*artifact["compile_flags"],
                        "-" + mode, "-g0", "-DPILOT_HAS_VTOR=" + str(int(profile == "CM0PLUSVTOR"))])
            for malformed in (0, 1, "0", "1", None):
                changed = copy.deepcopy(artifact)
                changed["target"]["vtor"] = malformed
                with self.subTest(malformed=malformed), self.assertRaisesRegex(RuntimeError, "literal startup VTOR"):
                    r.startup_flags(changed, "O2")

    def test_startup_thumb1_copy_zero_and_conditional_vtor(self):
        source = (HERE / "startup.S").read_text(encoding="ascii")
        self.assertNotRegex(source, r"\[r[01]\],\s*#4")
        self.assertIn("ldr r3, [r0]\n    str r3, [r1]\n    adds r0, #4\n    adds r1, #4", source)
        self.assertIn("str r3, [r1]\n    adds r1, #4", source)
        self.assertRegex(source, r"#if PILOT_HAS_VTOR\s+ldr r0, =pilot_vectors\s+ldr r1, =0xE000ED08\s+str r0, \[r1\]\s+dsb\s+isb\s+#endif")
        self.assertIn('#error "PILOT_HAS_VTOR must be the literal manifest fixture trait"', source)
        script = (HERE / "link.ld").read_text(encoding="ascii")
        for token in ("__data_load__", "__data_start__", "__data_end__", "__bss_start__", "__bss_end__"):
            self.assertIn(token, source)
            self.assertIn(token, script)
        self.assertIn("ENTRY(Reset_Handler)", script)
        self.assertIn("KEEP(*(.isr_vector))", script)

    def test_actual_startup_literal_guard_vtor_zero_and_one(self):
        for vtor in (False, True):
            body = b"\x00\x00" + (struct.pack("<I", 0xE000ED08) if vtor else bytes(4)) + bytes(4)
            image = SimpleNamespace(symbol=unittest.mock.Mock(return_value=dict(value=3, section=7, size=len(body))),
                                    section_read=unittest.mock.Mock(return_value=body))
            evidence = r.startup_literal_guard(image, vtor)
            image.symbol.assert_called_once_with("Reset_Handler", "STT_FUNC", root=True)
            image.section_read.assert_called_once_with(7, 2, len(body))
            self.assertEqual(evidence["BodySha256"], r.sha(body))
            self.assertIs(type(evidence["ExpectedLiteralCount"]), int)
            self.assertEqual(evidence["ExpectedLiteralCount"], int(vtor))
            self.assertEqual(evidence["ObservedLiteralCount"], int(vtor))
            self.assertEqual(evidence["LiteralOffsets"], [2] if vtor else [])
            self.assertIs(evidence["LiteralPredicateSatisfied"], True)
            self.assertIs(evidence["FullMMIOProof"], False)

    def test_actual_startup_literal_guard_rejects_wrong_count_and_nonbool(self):
        literal = struct.pack("<I", 0xE000ED08)
        for vtor, body in ((False, literal), (True, bytes(8)), (True, literal * 2)):
            image = SimpleNamespace(symbol=lambda *args, **kwargs: dict(value=1, section=2, size=len(body)),
                                    section_read=lambda *args: body)
            with self.subTest(vtor=vtor, body=body), self.assertRaisesRegex(RuntimeError, "aligned-literal count"):
                r.startup_literal_guard(image, vtor)
        for malformed in (0, 1, "0", "1", None):
            with self.subTest(vtor=malformed), self.assertRaisesRegex(RuntimeError, "literal startup VTOR trait"):
                r.startup_literal_guard(None, malformed)

    def test_exact_soft_vs_hard_final_flags(self):
        for profile in r.PROFILES:
            expected = 0x05000200 if profile in r.CM0_PROFILES or profile == "CM3" else 0x05000400
            r.require_final_float_flags(expected, profile)
            for flags in (0x05000000, 0x05000600, expected ^ 0x600, True, False):
                with self.subTest(profile=profile, flags=flags), self.assertRaises(RuntimeError):
                    r.require_final_float_flags(flags, profile)

    def test_all_fifteen_complete_native_protocols(self):
        for profile in r.CM0_PROFILES:
            for mode in r.MODES:
                protocols = self.checker._protocols(mode)["Native"]
                calls = []
                def function(name, **kwargs):
                    calls.append((name, kwargs))
                    return copy.deepcopy(protocols[name])
                evidence = r.match_native_protocols(SimpleNamespace(function=function), profile, mode, self.checker)
                self.assertEqual([row["Name"] for row in evidence], list(protocols))
                self.assertEqual(calls, [(name, dict(literal_islands=True, thumb1_tail_nop=True)) for name in protocols])
                self.assertEqual([row["TailNops"] for row in evidence], [int(mode == "O0")] * 3)

    def test_complete_protocol_rejects_added_missing_or_changed_token(self):
        for mode in r.MODES:
            protocols = self.checker._protocols(mode)["Native"]
            for root in protocols:
                for mutation in ("extra", "missing", "changed"):
                    bodies = copy.deepcopy(protocols)
                    if mutation == "extra":
                        bodies[root].append(("nop", "@ (mov r8, r8)"))
                    elif mutation == "missing":
                        bodies[root].pop()
                    else:
                        bodies[root][0] = ("nop", "@ (mov r8, r8)")
                    image = SimpleNamespace(function=lambda name, **kwargs: bodies[name])
                    with self.subTest(mode=mode, root=root, mutation=mutation), self.assertRaisesRegex(RuntimeError, "complete protocol mismatch"):
                        r.match_native_protocols(image, "CM0", mode, self.checker)

    def test_protocol_tail_counter_does_not_accept_boolean_or_wrong_mode(self):
        protocols = self.checker._protocols("O2")["Native"]
        for tail in (True, False, 1, -1, None):
            checker = SimpleNamespace(_protocols=lambda mode: dict(Native=protocols),
                _match=lambda *args: dict(TailNops=tail))
            with self.subTest(tail=tail), self.assertRaisesRegex(RuntimeError, "tail layout"):
                r.match_native_protocols(None, "CM0", "O2", checker)

    def test_cm0_attribute_gate_rejects_thumb2_and_fp(self):
        attributes = ('Tag_CPU_name: "6S-M"\nTag_CPU_arch: v6S-M\n'
                      'Tag_CPU_arch_profile: Microcontroller\nTag_THUMB_ISA_use: Thumb-1\n')
        self.admission.require_attributes(attributes)
        for changed in (attributes.replace("Thumb-1", "Thumb-2"), attributes + "Tag_FP_arch: VFPv4-D16\n",
                        attributes + "Tag_ABI_VFP_args: VFP registers\n", attributes + 'Tag_CPU_name: "6S-M"\n'):
            with self.subTest(attributes=changed), self.assertRaises(RuntimeError):
                self.admission.require_attributes(changed)


class CM3Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo = HERE.parents[2]
        cls.admission = r.load("classic_final_cm3_controls", repo / r.CM3_HELPERS[0])
        cls.checker = r.load("classic_final_cm3_protocol_controls", repo / r.CM3_HELPERS[1])
        cls.recipe = r.load("classic_final_cm3_recipe_controls", repo / r.HELPERS[5])

    def manifest(self):
        identity, _, _, sources = r.selection("CM3", "O2")
        target = dict(cpu="cortex-m3", architecture="ARMV7M", float_abi="soft", fpu_present=False,
            fpu_used=False, fpu_unit="", fp_stacking="none", vtor=True, mpu_regions=0,
            security_role="classic", psplim_slot=False, psplim_register=False, mve="none",
            pac=False, bti=False, errata_policy="none", r9_abi="aapcs", nvic_priority_bits=4,
            scheduler_basepri=16)
        artifact = dict(role="runtime", source_group_id="CM3", abi_contract="forward8", target=target,
            compile_flags=["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft"],
            defines=dict(FIBER_PORT_BUILD_SELECTED="1", FIBER_PORT_ARMV7M="1", FIBER_SCHEDULER_BASEPRI="16"),
            upstream_sources=["portable/GCC/ARM_CM3/port.c"],
            upstream_defines=dict(FIBER_FREERTOS_PARITY_ENABLE_MPU="0", FIBER_FREERTOS_PARITY_ENABLE_FPU="0",
                                  FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE="0"))
        return dict(cohorts=[dict(id=identity, artifacts=[artifact])],
                    source_groups=[dict(id="CM3", sources=list(sources))])

    def test_closed_helper_routes_and_base_helper_order(self):
        self.assertEqual(r.HELPERS, (
            "tools/freeze_classic_fp_mechanisms.py", "tools/freeze_cm3_mechanisms.py",
            "tools/freeze_cohorts.py", "tools/runtime_sources.py", "tools/runtime_sources.ps1",
            "tools/fixtures/freeze_cohorts/build_recipe.py", "tools/fixtures/freeze_cohorts/process_runner.py",
            "tools/fixtures/cm55_tfm_parity/elf.py", "tools/fixtures/cm4_cm7_freeze_parity/check.py"))
        self.assertEqual(r.CM3_HELPERS, ("tools/fixtures/cm3_final_image/admission.py",
                                       "tools/fixtures/cm3_freeze_parity/check.py"))
        expected = {"CM4": (r.HELPERS[0], r.HELPERS[8]), "CM7": (r.HELPERS[0], r.HELPERS[8]),
                    "CM0": r.CM0_HELPERS, "CM0PLUS": r.CM0_HELPERS, "CM0PLUSVTOR": r.CM0_HELPERS,
                    "CM3": r.CM3_HELPERS}
        self.assertEqual({profile: r.select_helpers(profile) for profile in r.PROFILES}, expected)
        for profile in ("CM3MPU", "cm3", "CM33", None, True):
            with self.subTest(profile=profile), self.assertRaisesRegex(RuntimeError, "unsupported native helper"):
                r.select_helpers(profile)

    def test_all_five_cm3_recipes_use_generic_cmsis_generator(self):
        for mode in r.MODES:
            with self.subTest(mode=mode):
                manifest = self.manifest()
                artifact = r.require_manifest_selection(manifest, "CM3", mode, self.admission)
                self.assertIs(artifact, manifest["cohorts"][0]["artifacts"][0])
                flags = self.recipe.native_flags(artifact, mode, "generated", "ARM_CM3", "repo", "cmsis")
                self.assertEqual(flags[:4], ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-" + mode])
                self.assertEqual([flag for flag in flags if flag.startswith("-D")],
                    ["-DFIBER_PORT_ARMV7M=1", "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_SCHEDULER_BASEPRI=16"])
                self.assertEqual(flags[-2:], ["-include", str(Path("generated") / "main.h")])
                self.assertFalse(any(flag.startswith("-mfpu=") for flag in flags))
                main = self.recipe.cmsis_main(artifact["target"])
                self.assertIn('#include "core_cm3.h"', main)
                for name, value in (("__NVIC_PRIO_BITS", 4), ("__VTOR_PRESENT", 1), ("__FPU_PRESENT", 0),
                                    ("__FPU_USED", 0), ("__DSP_PRESENT", 0), ("__MPU_PRESENT", 0)):
                    self.assertIn("#define %s %dU" % (name, value), main)
                self.assertEqual(r.startup_flags(artifact, mode),
                                 [*artifact["compile_flags"], "-" + mode, "-g0", "-DPILOT_HAS_VTOR=1"])

    def test_cm3_admission_receives_exact_cohort_identity(self):
        manifest = self.manifest()
        admission = SimpleNamespace(require_cohort=unittest.mock.Mock())
        artifact = r.require_manifest_selection(manifest, "CM3", "O2", admission)
        admission.require_cohort.assert_called_once_with(artifact,
            "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default")
        for name in ("FIBER_FPU_LAZY", "FIBER_PORT_ARMV6M", "FIBER_PORT_ARMV7EM"):
            changed = self.manifest()
            changed["cohorts"][0]["artifacts"][0]["defines"][name] = "0"
            with self.subTest(define=name), self.assertRaisesRegex(RuntimeError, "exact defines"):
                r.require_manifest_selection(changed, "CM3", "O2", admission)

    def test_cm3_source_group_remains_exact_and_ordered(self):
        original = self.manifest()["source_groups"][0]
        sources = original["sources"]
        for groups in ([], [original, copy.deepcopy(original)], [dict(original, id="CM4")],
                       [dict(original, sources=list(reversed(sources)))],
                       [dict(original, sources=sources[:-1])],
                       [dict(original, sources=[source.replace("ARM_CM3", "ARM_CM4") for source in sources])]):
            manifest = self.manifest()
            manifest["source_groups"] = groups
            with self.subTest(groups=groups), self.assertRaisesRegex(RuntimeError, "exact source group"):
                r.require_manifest_selection(manifest, "CM3", "O2", self.admission)

    def test_profile_admission_loads_only_captured_selected_helper(self):
        root = Path("captured-source")
        classic, selected = object(), object()
        for profile in r.PROFILES:
            pilot = SimpleNamespace(profile=profile, root=root, classic=classic)
            with self.subTest(profile=profile), patch.object(r, "load", return_value=selected) as load:
                actual = r.Pilot.profile_admission(pilot)
                if profile in ("CM4", "CM7"):
                    self.assertIs(actual, classic)
                    load.assert_not_called()
                else:
                    self.assertIs(actual, selected)
                    family = "cm3" if profile == "CM3" else "cm0"
                    load.assert_called_once_with("classic_final_" + family + "_admission",
                                                 root / r.select_helpers(profile)[0])

    def test_prepare_captures_cm3_admission_and_checker_before_loading(self):
        pilot = r.Pilot.__new__(r.Pilot)
        pilot.profile, pilot.repo, pilot.root, pilot.fixture = "CM3", HERE.parents[2], Path("captured-source"), HERE
        captured = {}
        pilot.capture = lambda original, target: captured.setdefault(target, original)

        def load(name, path):
            self.assertIn(path, captured)
            if path == pilot.root / r.CM3_HELPERS[0]:
                for relative in r.CM3_HELPERS:
                    self.assertEqual(captured[pilot.root / relative], pilot.repo / relative)
                raise LookupError("selected helpers captured")
            return SimpleNamespace()

        with patch.object(r, "load", side_effect=load), self.assertRaisesRegex(LookupError, "selected helpers captured"):
            pilot.prepare()

    def test_prelink_loads_cm3_checker_from_captured_root(self):
        root, fixture = Path("captured-source"), Path("captured-fixture")
        sources = [Path("source-%d.c" % index) for index in range(8)] + [fixture / "startup.S"]
        objects = [Path("object-%d.o" % index) for index in range(9)]
        pilot = SimpleNamespace(root=root, fixture_copy=fixture, profile="CM3", sources=sources, objects=objects,
            artifact=dict(target=dict(vtor=True)), object_hashes=[(str(path), "A" * 64) for path in objects],
            report=dict(Sources=[dict(SourceSha256="B" * 64) for _ in sources]),
            final_reader=SimpleNamespace(_ELF=unittest.mock.Mock()))
        with patch.object(r, "startup_literal_guard", return_value={}), \
                patch.object(r, "load", side_effect=[SimpleNamespace(), LookupError("captured checker")]) as load:
            with self.assertRaisesRegex(LookupError, "captured checker"):
                r.Pilot.prelink(pilot)
        self.assertEqual(load.call_args_list, [
            unittest.mock.call("classic_final_prelink_decoder", root / r.HELPERS[7]),
            unittest.mock.call("classic_final_prelink_protocol", root / r.CM3_HELPERS[1])])

    def test_attribute_dispatch_keeps_old_signatures_and_adds_cm3(self):
        with tempfile.TemporaryDirectory(prefix="cm3-attribute-dispatch-") as directory:
            path = Path(directory) / "port.o"
            path.with_suffix(".attributes").write_text("synthetic attribute text", encoding="ascii")
            for profile in r.PROFILES:
                admission = SimpleNamespace(require_attributes=unittest.mock.Mock())
                with self.subTest(profile=profile):
                    r.Pilot.require_attributes(SimpleNamespace(profile=profile, admission=admission), path)
                    expected = ("synthetic attribute text", profile) if profile in ("CM4", "CM7") else ("synthetic attribute text",)
                    admission.require_attributes.assert_called_once_with(*expected)

    def test_all_five_flat_cm3_native_protocols_and_mode_tails(self):
        for mode in r.MODES:
            calls = []
            def function(name, **kwargs):
                calls.append((name, kwargs))
                return copy.deepcopy(self.checker._NATIVE[name]) + [("nop", "")] * int(mode == "O0")
            evidence = r.match_native_protocols(SimpleNamespace(function=function), "CM3", mode, self.checker)
            self.assertEqual([row["Name"] for row in evidence], list(self.checker._NATIVE))
            self.assertEqual(calls, [(name, dict(literal_islands=True)) for name in self.checker._NATIVE])
            self.assertEqual([row["TailNops"] for row in evidence], [int(mode == "O0")] * 3)

    def test_cm3_complete_body_and_literal_descriptor_mutations_reject(self):
        for mutation in ("missing", "extra", "literal"):
            bodies = copy.deepcopy(self.checker._NATIVE)
            root = "SVC_Handler"
            if mutation == "missing":
                bodies[root].pop(0)
            elif mutation == "extra":
                bodies[root].insert(0, ("nop", ""))
            else:
                descriptor = json.loads(bodies[root][-1][1])
                descriptor["Relocations"][0]["Target"] = "unadmitted_slot"
                bodies[root][-1] = ("@literal-island", json.dumps(descriptor, sort_keys=True, separators=(",", ":")))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(RuntimeError, "complete protocol mismatch"):
                r.match_native_protocols(SimpleNamespace(function=lambda name, **kwargs: bodies[name]), "CM3", "O2", self.checker)

    def test_cm3_wrong_mode_and_boolean_tail_counters_reject(self):
        for mode in r.MODES:
            image = SimpleNamespace(function=lambda name, **kwargs:
                copy.deepcopy(self.checker._NATIVE[name]) + [("nop", "")] * int(mode != "O0"))
            with self.subTest(mode=mode), self.assertRaisesRegex(RuntimeError, "tail layout"):
                r.match_native_protocols(image, "CM3", mode, self.checker)
        for tail in (True, False, 1, None):
            checker = SimpleNamespace(_NATIVE=self.checker._NATIVE, _match=lambda *args: dict(TailNops=tail))
            with self.subTest(tail=tail), self.assertRaisesRegex(RuntimeError, "tail layout"):
                r.match_native_protocols(None, "CM3", "O2", checker)

    def test_cm3_scope_is_not_the_fp_scope(self):
        for mode in r.MODES:
            report = r.scope_report("CM3", mode)
            self.assertEqual(report["ProofScope"], "NATIVE_CM3_DIRECT_TWIN_BUILD_ONLY")
            self.assertIs(type(report["RequiredCellsSatisfied"]), int)
            self.assertEqual(report["RequiredCellsSatisfied"], 0)
            for name in ("ReferenceBuilt", "LTO", "RequiredCellSatisfied", "FinalElfProof", "FinalRootRelocationProof",
                         "CompleteObjectProof", "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
                self.assertIs(report[name], False)
        for profile in ("CM4", "CM7"):
            self.assertEqual(r.scope_report(profile)["ProofScope"], "NATIVE_CLASSIC_FP_DIRECT_TWIN_BUILD_ONLY")
        for profile in r.CM0_PROFILES:
            self.assertEqual(r.scope_report(profile)["ProofScope"], "NATIVE_CM0_DIRECT_TWIN_BUILD_ONLY")


class ArtifactSealControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="classic-final-artifact-seal-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pilot = r.Pilot.__new__(r.Pilot)
        self.pilot.output = self.root
        self.pilot.inputs, self.pilot.generated = {}, {}
        self.pilot.memberships, self.pilot.copy_memberships = [], []
        self.pilot.commands = [dict(Status="PASS")]
        self.pilot.report = r.scope_report()
        self.pilot._prepared = self.pilot._built = True
        self.pilot._prelink_verified = self.pilot._twins_verified = True
        self.pilot.objects = []
        for index in range(9):
            path = self.root / ("object-%d.o" % index)
            path.write_bytes(bytes([index]))
            self.pilot.objects.append(path)
            self.pilot.report["Sources"].append(dict(Object=str(path), ObjectSha256=r.sha(path.read_bytes()),
                                                     CompileDependenciesVerified=True))
        self.pilot.freeze_objects()
        self.pilot.report["Links"] = [dict(Kind=name) for name in ("ordinary", "emit-relocs")]
        self.pilot.report["PrelinkNativeRoots"] = [dict(Name=name) for name in
            ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler")]
        self.pilot.report["PrelinkStartupLiteralGuard"] = dict(LiteralPredicateSatisfied=True)
        self.pilot.report["ObjectChecks"] = [dict(Stage=stage, Status="PASS", Error=None) for stage in
            ("before-prelink", "after-prelink", "before-link-ordinary", "after-link-ordinary",
             "before-link-emit-relocs", "after-link-emit-relocs")]
        self.payload = self.root / "payload.bin"
        self.payload.write_bytes(b"retained artifact")

    def assert_closed_report(self, verdict):
        self.assertEqual(self.pilot.report["Verdict"], verdict)
        self.assertEqual(json.loads((self.root / "results.json").read_bytes()), self.pilot.report)
        recorded = json.loads((self.root / "artifacts.json").read_bytes())["Artifacts"]
        actual = {path.relative_to(self.root).as_posix(): r.sha(path.read_bytes())
                  for path in self.root.rglob("*") if path.is_file() and path.name != "artifacts.json"}
        self.assertEqual(recorded, actual)
        self.assertEqual(self.pilot.report["RequiredCellsSatisfied"], 0)
        for key in ("RequiredCellSatisfied", "FinalElfProof", "FinalRootRelocationProof", "PolicyEquivalence",
                    "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
            self.assertIs(self.pilot.report[key], False)

    def injected_failure(self, fault):
        save = r.save
        fired = []

        def intercept(path, value):
            if path == self.root / "artifacts.json" and not fired:
                fired.append(fault)
                if fault == "manifest-write":
                    raise OSError("injected manifest write error")
                save(path, value)
                if fault == "addition":
                    (self.root / "late.bin").write_bytes(b"late artifact")
                elif fault == "modification":
                    self.payload.write_bytes(b"late changed artifact")
                elif fault == "deletion":
                    self.payload.unlink()
                else:
                    raise AssertionError("unknown seal fault")
            else:
                save(path, value)

        with patch.object(r, "save", side_effect=intercept):
            self.assertFalse(self.pilot.finish(None))
        self.assertEqual(fired, [fault])
        self.assertIn("artifact sealing failed", self.pilot.report["Error"])
        self.assertNotIn("ArtifactSealRecoveryError", self.pilot.report)
        self.assert_closed_report("FAIL")

    def test_unchanged_artifacts_close_successfully(self):
        self.assertTrue(self.pilot.finish(None))
        self.assert_closed_report("NATIVE-FINAL-TWIN-BUILD-PASS")
        self.assertIsNone(self.pilot.report["Error"])

    def test_late_artifact_addition_persists_failure(self):
        self.injected_failure("addition")

    def test_late_artifact_modification_persists_failure(self):
        self.injected_failure("modification")

    def test_late_artifact_deletion_persists_failure(self):
        self.injected_failure("deletion")

    def test_manifest_write_error_persists_failure(self):
        self.injected_failure("manifest-write")


class ObjectControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="classic-final-object-controls-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pilot = r.Pilot.__new__(r.Pilot)
        self.pilot.output = self.root
        self.pilot.report = r.scope_report()
        self.pilot.objects = []
        for index in range(9):
            path = self.root / ("object-%d.o" % index)
            path.write_bytes(bytes([index]) * 16)
            self.pilot.objects.append(path)
            self.pilot.report["Sources"].append(dict(Object=str(path), ObjectSha256=r.sha(path.read_bytes()),
                                                       CompileDependenciesVerified=True))

    def freeze(self):
        self.pilot.freeze_objects()
        self.pilot.verify_objects("test-initial")

    def test_exact_object_freeze_and_recheck(self):
        self.freeze()
        self.assertEqual(len(self.pilot.object_hashes), 9)
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Status"], "PASS")
        with self.assertRaisesRegex(RuntimeError, "already frozen"):
            self.pilot.freeze_objects()

    def test_incomplete_or_duplicate_inventory_rejected(self):
        self.pilot.objects.pop()
        with self.assertRaisesRegex(RuntimeError, "nine-object"):
            self.pilot.freeze_objects()
        self.pilot.objects.append(self.pilot.objects[0])
        with self.assertRaisesRegex(RuntimeError, "nine-object"):
            self.pilot.freeze_objects()

    def test_unverified_compile_dependencies_rejected(self):
        self.pilot.report["Sources"][0]["CompileDependenciesVerified"] = False
        with self.assertRaisesRegex(RuntimeError, "actual compilation dependencies"):
            self.pilot.freeze_objects()

    def test_object_identity_cannot_change_at_freeze(self):
        self.pilot.report["Sources"][0]["Object"] = str(self.root / "unrelated.o")
        with self.assertRaisesRegex(RuntimeError, "object/source identity"):
            self.pilot.freeze_objects()

    def test_changed_object_is_failure_with_terminal_record(self):
        self.freeze()
        self.pilot.objects[3].write_bytes(b"different object")
        with self.assertRaisesRegex(RuntimeError, "frozen object drift"):
            self.pilot.verify_objects("changed")
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Status"], "FAIL")
        self.assertEqual(json.loads((self.root / "object-checks.json").read_text()),
                         self.pilot.report["ObjectChecks"])

    def test_membership_change_is_failure(self):
        self.freeze()
        self.pilot.objects.reverse()
        with self.assertRaisesRegex(RuntimeError, "membership"):
            self.pilot.verify_objects("reordered")

    def test_missing_object_is_failure(self):
        self.freeze()
        self.pilot.objects[2].unlink()
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            self.pilot.verify_objects("missing")
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Status"], "FAIL")

    def test_drift_prevents_link_invocation(self):
        self.freeze()
        self.pilot.objects[0].write_bytes(b"changed before link")
        self.pilot.command = unittest.mock.Mock(side_effect=AssertionError("must not launch"))
        with self.assertRaisesRegex(RuntimeError, "frozen object drift"):
            self.pilot.link_twin("ordinary", ["not executed"])
        self.pilot.command.assert_not_called()

    def test_link_time_object_change_is_detected(self):
        self.freeze()
        def command(*args):
            self.pilot.objects[0].write_bytes(b"changed during link")
            return "apparent success"
        self.pilot.command = command
        with self.assertRaisesRegex(RuntimeError, "frozen object drift"):
            self.pilot.link_twin("emit-relocs", ["not executed"])
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Stage"], "after-link-emit-relocs")
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Status"], "FAIL")

    def test_failed_link_still_rechecks_objects(self):
        self.freeze()
        self.pilot.command = unittest.mock.Mock(side_effect=RuntimeError("link failed"))
        with self.assertRaisesRegex(RuntimeError, "link failed"):
            self.pilot.link_twin("ordinary", ["not executed"])
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Stage"], "after-link-ordinary")
        self.assertEqual(self.pilot.report["ObjectChecks"][-1]["Status"], "PASS")

    def test_exact_actual_dependency_inventory(self):
        expected = [dict(Path="source.c", Sha256="A" * 64), dict(Path="header.h", Sha256="B" * 64)]
        r.require_compile_dependencies(expected, [dict(item) for item in expected])
        mutants = (expected[:1], [*expected, dict(Path="extra.h", Sha256="C" * 64)],
                   [dict(expected[0]), dict(expected[1], Sha256="D" * 64)], list(reversed(expected)))
        for actual in mutants:
            with self.subTest(actual=actual):
                with self.assertRaisesRegex(RuntimeError, "actual compilation dependencies differ"):
                    r.require_compile_dependencies(expected, actual)
        for discovered, actual in (([], []), (expected, []), (None, expected), (tuple(expected), expected)):
            with self.subTest(discovered=discovered, actual=actual):
                with self.assertRaisesRegex(RuntimeError, "empty actual/discovery"):
                    r.require_compile_dependencies(discovered, actual)

    def test_dependency_parser_retains_escaped_space_and_hash(self):
        paths = [self.root / "source with space.c", self.root / "header#one.h"]
        for path in paths:
            path.write_bytes(b"bound input")
        dep = self.root / "source.d"
        escaped = [str(path).replace("\\", "/").replace(" ", "\\ ").replace("#", "\\#") for path in paths]
        dep.write_text("pilot-source-0: " + escaped[0] + " \\\n " + escaped[1] + "\n", encoding="utf-8")
        self.assertEqual(r.read_dependencies(dep), tuple(sorted(path.resolve() for path in paths)))
        dep.write_text("pilot-source-0: " + escaped[0] + " " + escaped[0] + "\n", encoding="utf-8")
        self.assertEqual(r.read_dependencies(dep), (paths[0].resolve(),))
        dep.write_text("pilot-source-0: \n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "empty dependency"):
            r.read_dependencies(dep)

    def test_distinct_include_spellings_bind_one_physical_dependency(self):
        header = self.root / "header.h"
        header.write_bytes(b"one physical header")
        alias_directory = self.root / "include-alias"
        alias_directory.mkdir()
        alias = str(alias_directory) + "/../header.h"
        dep = self.root / "alias.d"
        dep.write_text("pilot-source-1: " + header.as_posix() + " " + alias.replace("\\", "/") + "\n",
                       encoding="utf-8")
        self.assertEqual(r.read_dependencies(dep), (header.resolve(),))


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    path = Path(args.report).resolve()
    if path.exists() or not path.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        raise SystemExit("requires a fresh report inside TEMP")
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                              for case in (CommandControls, ScopeControls, CM0Controls, CM3Controls, ArtifactSealControls,
                                           ObjectControls))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = dict(Status="PASS" if result.wasSuccessful() else "FAIL", Tests=result.testsRun,
                  Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
                  ToolInvocations=0, CpuExecution=False, BoardExecution=False,
                  FailureDetails=[dict(Test=str(case), Detail=detail)
                                  for case, detail in result.failures + result.errors])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    print(json.dumps(report, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
