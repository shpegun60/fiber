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
        for profile, mode in (("CM3", "O2"), ("cm4", "O2"), ("CM7", "O2-LTO"),
                              ("CM4", "Ofast"), (None, "O2"), ("CM7", True),
                              ("CM0+", "O2"), ("CM0PLUS", "O2-LTO"), ("CM0", "O1")):
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
            expected = 0x05000200 if profile in r.CM0_PROFILES else 0x05000400
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
                              for case in (CommandControls, ScopeControls, CM0Controls, ObjectControls))
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
