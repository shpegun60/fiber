"""Pure CM3 LTO capture-probe controls; never tools, targets or transport proof."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
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
PROBE = HERE / "probe.py"
p = None
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
NATIVE_SOURCES = (
    "context/context_core.c", "context/context_runtime_state.c", "context/context_panic.c",
    "fiber/port/ARM_CM3/fiber_port.c", "fiber/port/ARM_CM3/fiber_port_boot.c",
    "fiber/port/ARM_CM3/fiber_port_exception.c", "fiber/port/fiber_port_context_cohort_expectation.c",
    "tools/fixtures/classic_final_image/application.c", "tools/fixtures/classic_final_image/startup.S",
)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def artifact():
    return dict(role="runtime", source_group_id="CM3", abi_contract="forward8",
        target=dict(cpu="cortex-m3", architecture="ARMV7M", float_abi="soft", fpu_present=False, fpu_used=False,
            fpu_unit="", fp_stacking="none", vtor=True, mpu_regions=0, security_role="classic",
            psplim_slot=False, psplim_register=False, mve="none", pac=False, bti=False,
            errata_policy="none", r9_abi="aapcs", nvic_priority_bits=4, scheduler_basepri=16),
        compile_flags=["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft"],
        defines=dict(FIBER_PORT_ARMV7M="1", FIBER_PORT_BUILD_SELECTED="1", FIBER_SCHEDULER_BASEPRI="16"),
        upstream_defines=dict(FIBER_FREERTOS_PARITY_ENABLE_MPU="0", FIBER_FREERTOS_PARITY_ENABLE_FPU="0",
                             FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE="0"),
        upstream_sources=["portable/GCC/ARM_CM3/port.c"])


def baseline_flags():
    return ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-std=gnu11", "-g0",
            "-ffreestanding", "-ffunction-sections", "-fdata-sections"]


def synthetic_root():
    return Path(tempfile.gettempdir()).resolve() / "cm3-lto-probe-pure-not-created"


class RecipeTests(unittest.TestCase):
    def test_fixed_nine_source_order_is_eight_c_and_one_startup(self):
        self.assertEqual(p.COHORT, COHORT)
        self.assertEqual(tuple(p.SOURCES), NATIVE_SOURCES)
        self.assertEqual(sum(name.endswith(".c") for name in p.SOURCES), 8)
        self.assertEqual([name for name in p.SOURCES if name.endswith(".S")], [NATIVE_SOURCES[-1]])

    def test_slim_o2_flags_preserve_baseline_and_do_not_mutate_it(self):
        base = baseline_flags()
        before = base[:]
        actual = p.mode_flags(base)
        self.assertEqual(actual, [*before, "-flto", "-fno-fat-lto-objects"])
        self.assertEqual(base, before)
        self.assertIsNot(actual, base)

    def test_wrong_or_multiple_optimization_modes_reject(self):
        for flags in ([], ["-Og"], ["-O0"], ["-Os"], ["-O3"], ["-Ofast"],
                      ["-O2", "-O2"], ["-O2", "-O0"], ["-O2", "-Og"]):
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "exact O2"):
                p.mode_flags(flags)

    def test_lto_or_fat_counterflags_in_baseline_reject(self):
        for flag in ("-flto", "-flto=1", "-flto=auto", "-flto-partition=one", "-fno-lto",
                     "-ffat-lto-objects", "-fno-fat-lto-objects"):
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, "override LTO"):
                p.mode_flags([*baseline_flags(), flag])

    def test_compile_flag_container_and_elements_are_literal(self):
        for flags in (tuple(baseline_flags()), "-O2", None, ["-O2", True], ["-O2", 2]):
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "literal compile flags"):
                p.mode_flags(flags)

    def link(self, emit=False, selected=None, objects=None):
        root = synthetic_root()
        if objects is None:
            objects = [root / ("source-%d.o" % index) for index in range(9)]
        return p.link_flags(artifact() if selected is None else selected, objects,
                            root / "link.ld", root / "image.elf", root / "image.map", emit)

    def test_exact_single_partition_link_and_ordered_providers(self):
        root = synthetic_root()
        expected = ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-flto",
            "-flto-partition=one", "-save-temps=obj", "-v", "-nostdlib", "-Wl,-plugin-opt=-save-temps",
            "-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack",
            "-T", str(root / "link.ld"), *(str(root / ("source-%d.o" % i)) for i in range(9)),
            "-Wl,-Map=" + str(root / "image.map"), "-o", str(root / "image.elf")]
        self.assertEqual(self.link(), expected)
        self.assertNotIn("-flto=1", expected)

    def test_plugin_retention_is_mandatory_not_driver_save_temps_alone(self):
        flags = self.link()
        self.assertEqual(flags.count("-Wl,-plugin-opt=-save-temps"), 1)
        self.assertEqual(flags.count("-save-temps=obj"), 1)
        self.assertEqual(flags.count("-flto-partition=one"), 1)
        # These independent predicates fail if the recipe loses plugin retention.
        for removed in ("-Wl,-plugin-opt=-save-temps", "-flto-partition=one"):
            changed = flags[:]
            changed.remove(removed)
            with self.subTest(removed=removed), self.assertRaisesRegex(ValueError, "link recipe binding"):
                p.same(changed, flags, "link recipe binding")

    def test_twins_differ_only_by_emit_relocs_in_own_recipe(self):
        ordinary, emitted = self.link(False), self.link(True)
        self.assertNotIn("-Wl,--emit-relocs", ordinary)
        self.assertEqual(emitted.count("-Wl,--emit-relocs"), 1)
        self.assertEqual([value for value in emitted if value != "-Wl,--emit-relocs"], ordinary)
        self.assertEqual(emitted[-3:], ordinary[-3:])

    def test_foreign_reordered_or_extra_target_flags_reject(self):
        for flags in (["-mcpu=cortex-m4", "-mthumb", "-mfloat-abi=soft"],
                      ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=hard"],
                      ["-mthumb", "-mcpu=cortex-m3", "-mfloat-abi=soft"],
                      [*artifact()["compile_flags"], "-mfpu=fpv4-sp-d16"], []):
            selected = artifact()
            selected["compile_flags"] = flags
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "exact CM3 target flags"):
                self.link(selected=selected)

    def test_emit_bool_aliases_reject(self):
        for value in (0, 1, "true", None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "literal emit"):
                self.link(emit=value)

    def test_empty_or_duplicate_link_providers_reject(self):
        root = synthetic_root()
        for objects in ([], (), [root / "same.o", str(root / "same.o")], "one.o", None):
            with self.subTest(objects=objects), self.assertRaisesRegex(ValueError, "ordered unique"):
                p.link_flags(artifact(), objects, root / "link.ld", root / "image.elf", root / "image.map", False)


class MachineNameTests(unittest.TestCase):
    def test_actual_single_partition_machine_suffix_is_bound_to_output(self):
        output = synthetic_root() / "ordinary" / "image.elf"
        machine = output.with_name("image.elf.ltrans0.ltrans.o")
        self.assertEqual(p.require_saved_machine_name(machine, output), machine.absolute())

    def test_ir_assembly_foreign_partition_or_foreign_output_cannot_substitute(self):
        output = synthetic_root() / "ordinary" / "image.elf"
        for name in ("image.elf.ltrans0.o", "image.elf.ltrans0.ltrans.s", "image.elf.ltrans1.ltrans.o",
                     "other.elf.ltrans0.ltrans.o", "image.ltrans0.ltrans.o", "ordinary.o", "image.elf"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "WPA IR is not machine authority"):
                p.require_saved_machine_name(output.with_name(name), output)

    def test_other_link_directory_machine_is_not_own_machine(self):
        root = synthetic_root()
        with self.assertRaisesRegex(ValueError, "exact single-partition"):
            p.require_saved_machine_name(root / "emit-relocs/image.elf.ltrans0.ltrans.o", root / "ordinary/image.elf")


class ScopeAndDataTests(unittest.TestCase):
    def test_scope_defaults_cannot_promote_capture_to_abi_or_execution(self):
        row = p.scope_report()
        self.assertEqual((row["Status"], row["Scope"], row["Profile"], row["Mode"], row["Cohort"], row["Linkage"]),
            ("FAIL", "NATIVE_CM3_O2_LTO_CAPTURE_FEASIBILITY_ONLY", "CM3", "O2-lto", COHORT, "direct"))
        self.assertIs(row["LTO"], True)
        for name in ("FinalRootRelocationProof", "FinalReferenceParity", "CompleteObjectProof",
                     "SourceToMachineSemanticProof", "OrdinaryOwnerContractSatisfied", "PolicyEquivalence",
                     "ReferenceBuilt", "ArchiveExtraction", "CpuExecution", "BoardExecution",
                     "RequiredCellSatisfied", "GlobalFreezeQualified"):
            with self.subTest(name=name):
                self.assertIs(row[name], False)
        for name in ("TranslationUnits", "SlimIRObjects", "FinalExecutableLinks", "SavedMachineObjects", "RequiredCellsSatisfied"):
            self.assertIs(type(row[name]), int)
            self.assertEqual(row[name], 0)

    def test_scope_mutable_records_are_not_shared(self):
        first, second = p.scope_report(), p.scope_report()
        for name in ("Commands", "Sources", "Links"):
            first[name].append({"synthetic": True})
            self.assertEqual(second[name], [])

    def test_sha256_is_exact_uppercase_not_truthy_or_truncated(self):
        value = sha(b"synthetic captured buffer")
        self.assertEqual(p.digest_text(value), value)
        for wrong in (value.lower(), value[:-1], value + "0", "G" * 64, True, 1, None):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(ValueError, "exact SHA256"):
                p.digest_text(wrong)

    def test_duplicate_json_keys_reject_including_nested(self):
        for text in ('{"value":1,"value":1}', '{"outer":{"value":1,"value":2}}'):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                json.loads(text, object_pairs_hook=p.unique_object)
        self.assertEqual(json.loads('{"x":1,"y":[2]}', object_pairs_hook=p.unique_object), {"x": 1, "y": [2]})

    def test_typed_binding_rejects_bool_int_alias_and_order_changes(self):
        p.same({"x": 1, "y": False}, {"y": False, "x": 1}, "binding")
        for actual, expected in ((True, 1), (False, 0), ([1, 2], [2, 1]), ({"x": False}, {"x": 0})):
            with self.subTest(actual=actual), self.assertRaisesRegex(ValueError, "binding"):
                p.same(actual, expected, "binding")
        with self.assertRaises(ValueError):
            p.same(float("nan"), float("nan"), "binding")

    def test_portable_membership_paths_reject_traversal_and_noncanonical_names(self):
        self.assertEqual(p.portable_name("source/context/context_core.c"), Path("source/context/context_core.c"))
        for name in ("", "/absolute", "../outside", "x/../outside", "x/./file", "x//file", "x\\file", True):
            with self.subTest(name=name), self.assertRaises(ValueError):
                p.portable_name(name)


def synthetic_seed():
    """Metadata-only fixture: mocked authenticated I/O, never a producer receipt."""
    seed = p.Seed.__new__(p.Seed)
    seed.root = synthetic_root() / "seed"
    gcc = synthetic_root() / "tools/bin/arm-none-eabi-gcc.exe"
    worker_root = synthetic_root() / "tools/libexec/gcc/arm-none-eabi/14.3.1"
    workers = {name: worker_root / (name + ".exe") for name in p.WORKERS}
    plugin = worker_root / "liblto_plugin.dll"
    interpreter = synthetic_root() / "python/python.exe"
    seed.originals = {path: {} for path in (gcc, plugin, interpreter, *workers.values())}
    seed.captures, seed.inputs = {}, {"Generated": {}}
    fixture = seed.root / "source/tools/fixtures/classic_final_image"
    header = fixture / "main.h"
    seed.captures[fixture / "link.ld"] = {}
    base, startup = baseline_flags(), ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2"]
    payloads, records, commands = {header: b"/* synthetic main */\n"}, {}, []

    def add_command(label, argv, stdout=None):
        index = len(commands)
        row = dict(Status="PASS", Exit=0, TimedOut=False, Error=None, Cwd=str(seed.root), Label=label, Argv=argv)
        commands.append(row)
        records[seed.root / ("command-%04d.json" % index)] = row
        if stdout is not None:
            payloads[seed.root / ("command-%04d.stdout" % index)] = stdout
        return row

    for name, path in workers.items():
        add_command("resolve " + name, [str(gcc), "-print-prog-name=" + name], (str(path) + "\n").encode("utf-8"))
    sources = []
    for index, name in enumerate(NATIVE_SOURCES):
        source, obj = seed.root / "source" / name, seed.root / ("source-%d.o" % index)
        seed.captures[source] = {}
        flags = startup[:] if index == 8 else [*base, "-I" + str(source.parent)]
        payloads[source] = ("synthetic dependency " + str(index)).encode("ascii")
        payloads[obj] = ("synthetic prelink object " + str(index)).encode("ascii")
        deps = [{"Path": str(source), "Sha256": sha(payloads[source])}]
        row = dict(Source=str(source), SourceSha256=sha(payloads[source]), Object=str(obj), ObjectSha256=sha(payloads[obj]),
                   CompileFlags=flags, CompileDependenciesVerified=True,
                   Dependencies=deps, ActualCompileDependencies=copy.deepcopy(deps), CompileDependencyFile=str(obj) + ".d")
        sources.append(row)
        add_command("compile " + source.name, [str(gcc), *flags, "-MD", "-MF", row["CompileDependencyFile"],
                    "-MT", "pilot-source-" + str(index), "-c", str(source), "-o", str(obj)])
    links = []
    for kind in ("ordinary", "emit-relocs"):
        image, link_map = seed.root / (kind + ".elf"), seed.root / (kind + ".map")
        payloads[image], payloads[link_map] = b"synthetic final", b"synthetic link map"
        links.append(dict(Kind=kind, Path=str(image), Sha256=sha(payloads[image]),
                          Map=str(link_map), MapSha256=sha(payloads[link_map])))
        flags = [str(gcc), "-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-nostdlib",
            "-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack",
            "-T", str(fixture / "link.ld"), *[row["Object"] for row in sources]]
        if kind == "emit-relocs":
            flags.append("-Wl,--emit-relocs")
        add_command("link " + kind, [*flags, "-Wl,-Map=" + str(link_map), "-o", str(image)])
    parser_file = seed.root / "python/elftools/__init__.py"
    seed.artifacts = {"python/elftools/__init__.py": sha(b"synthetic parser")}
    seed.captures[parser_file] = {}
    row = dict(Verdict="NATIVE-FINAL-TWIN-BUILD-PASS", Profile="CM3", Mode="O2", Cohort=COHORT,
        ProofScope="NATIVE_CM3_DIRECT_TWIN_BUILD_ONLY", RequiredCellsSatisfied=0, TranslationUnits=9,
        FinalExecutableLinks=2, InputDrift=[], TwinLoadImageIdentical=True, TwinAllocatedSectionsIdentical=True,
        CohortArtifact=artifact(), CompileFlags=base[:], Sources=sources, Links=links, Commands=commands,
        ObjectChecks=[dict(Stage=stage, Status="PASS", Error=None) for stage in (
            "before-prelink", "after-prelink", "before-link-ordinary", "after-link-ordinary",
            "before-link-emit-relocs", "after-link-emit-relocs", "closing")], Interpreter={"ModulePath": str(interpreter)})
    for name in ("LTO", "ReferenceBuilt", "RequiredCellSatisfied", "FinalElfProof", "FinalRootRelocationProof",
                 "CompleteObjectProof", "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
        row[name] = False
    seed.result = row
    seed.closure = SimpleNamespace(read=Mock(side_effect=lambda path, expected=None: payloads[Path(path)]),
                                   structured=Mock(side_effect=lambda path: records[Path(path)]))

    def require_model(value, identity):
        p.same(identity, COHORT, "synthetic fixed cohort")
        p.same(value, artifact(), "synthetic fixed artifact")

    modules = {p.CLASSIC + "run.py": SimpleNamespace(startup_flags=Mock(return_value=startup)),
        p.RECIPE: SimpleNamespace(native_flags=Mock(return_value=base), cmsis_main=Mock(return_value="/* synthetic main */\n")),
        p.MODEL: SimpleNamespace(require_cohort=Mock(side_effect=require_model)), p.PROCESS: SimpleNamespace()}
    seed.module = Mock(side_effect=lambda name: modules[name])
    seed._test_records, seed._test_payloads, seed._test_add_command = records, payloads, add_command
    return seed


class SeedMetadataTests(unittest.TestCase):
    def validate(self, seed):
        with patch.object(p, "regular", side_effect=lambda path: Path(path)), patch.object(Path, "glob", return_value=()):
            return seed.validate()

    def test_complete_synthetic_metadata_reaches_actual_recipe_and_command_checks(self):
        seed = synthetic_seed()
        self.assertIsNone(self.validate(seed))
        self.assertEqual(seed.module.call_count, 4)
        seed.model.require_cohort.assert_called_once_with(seed.result["CohortArtifact"], COHORT)
        seed.recipe.native_flags.assert_called_once()
        seed.native.startup_flags.assert_called_once_with(seed.result["CohortArtifact"], "O2")

    def test_foreign_identity_mode_scope_or_verdict_rejects_before_helper_load(self):
        for key, value in (("Verdict", "PASS"), ("Profile", "CM4"), ("Mode", "Og"), ("Mode", "O2-lto"),
                           ("Cohort", COHORT + "-foreign"), ("ProofScope", "NATIVE_CM4_DIRECT_TWIN_BUILD_ONLY")):
            seed = synthetic_seed()
            seed.result[key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "exact qualified native CM3 O2 seed"):
                self.validate(seed)
            seed.module.assert_not_called()

    def test_scope_promotions_and_false_integer_aliases_reject(self):
        keys = ("LTO", "ReferenceBuilt", "RequiredCellSatisfied", "FinalElfProof", "FinalRootRelocationProof",
                "CompleteObjectProof", "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified")
        for key in keys:
            for value in (True, 0, None):
                seed = synthetic_seed()
                seed.result[key] = value
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "literal false seed scope"):
                    self.validate(seed)

    def test_required_count_and_producer_closure_counters_are_typed(self):
        for key, value in (("RequiredCellsSatisfied", False), ("RequiredCellsSatisfied", 1),
                           ("TranslationUnits", 8), ("TranslationUnits", 9.0),
                           ("FinalExecutableLinks", True), ("InputDrift", ["changed"])):
            seed = synthetic_seed()
            seed.result[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.validate(seed)

    def test_seven_ordered_successful_checkpoints_required(self):
        for change in ("missing", "reordered", "duplicate", "failed", "error"):
            seed = synthetic_seed()
            rows = seed.result["ObjectChecks"]
            if change == "missing":
                rows.pop()
            elif change == "reordered":
                rows[0], rows[1] = rows[1], rows[0]
            elif change == "duplicate":
                rows.append(copy.deepcopy(rows[-1]))
            elif change == "failed":
                rows[-1]["Status"] = "FAIL"
            else:
                rows[-1]["Error"] = "late failure"
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "seed object check"):
                self.validate(seed)

    def test_twin_comparisons_are_true_booleans_not_truthy_aliases(self):
        for key in ("TwinLoadImageIdentical", "TwinAllocatedSectionsIdentical"):
            for value in (False, 1, None):
                seed = synthetic_seed()
                seed.result[key] = value
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "seed twin comparison"):
                    self.validate(seed)

    def test_model_is_called_on_actual_artifact_not_only_target_flags(self):
        for change in ("priority", "float", "defines", "upstream", "bool-alias"):
            seed = synthetic_seed()
            selected = seed.result["CohortArtifact"]
            if change == "priority":
                selected["target"]["scheduler_basepri"] = 32
            elif change == "float":
                selected["target"]["float_abi"] = "hard"
            elif change == "defines":
                selected["defines"]["FIBER_SCHEDULER_BASEPRI"] = "32"
            elif change == "upstream":
                selected["upstream_sources"] = ["portable/GCC/ARM_CM4F/port.c"]
            else:
                selected["target"]["fpu_used"] = 0
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "synthetic fixed artifact"):
                self.validate(seed)

    def test_source_count_order_and_exact_paths_are_bound(self):
        for change in ("missing", "reordered", "foreign"):
            seed = synthetic_seed()
            rows = seed.result["Sources"]
            if change == "missing":
                rows.pop()
            elif change == "reordered":
                rows[0], rows[1] = rows[1], rows[0]
            else:
                rows[3]["Source"] = str(seed.root / "source/fiber/port/ARM_CM4F/fiber_port.c")
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "exact ordered nine"):
                self.validate(seed)

    def test_flags_and_complete_compile_command_cannot_diverge(self):
        for change in ("receipt-flags", "source-flags", "startup-flags", "command-flags", "command-source", "command-object"):
            seed = synthetic_seed()
            row = seed.result["Sources"][0]
            command = next(cmd for cmd in seed.result["Commands"] if cmd["Label"] == "compile context_core.c")
            if change == "receipt-flags":
                seed.result["CompileFlags"].append("-flto")
            elif change == "source-flags":
                row["CompileFlags"].append("-flto")
            elif change == "startup-flags":
                seed.result["Sources"][-1]["CompileFlags"].append("-flto")
            elif change == "command-flags":
                command["Argv"].insert(1, "-ffat-lto-objects")
            else:
                option = "-c" if change == "command-source" else "-o"
                command["Argv"][command["Argv"].index(option) + 1] += ".foreign"
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "recipe|compile command"):
                self.validate(seed)

    def test_dependency_verification_and_actual_discovery_equality_are_required(self):
        for change in ("false", "integer", "different", "uncovered"):
            seed = synthetic_seed()
            row = seed.result["Sources"][0]
            if change in ("false", "integer"):
                row["CompileDependenciesVerified"] = False if change == "false" else 1
            elif change == "different":
                row["ActualCompileDependencies"][0]["Sha256"] = "0" * 64
            else:
                dependency = {"Path": str(seed.root / "uncovered.h"), "Sha256": "0" * 64}
                row["Dependencies"].append(dependency)
                row["ActualCompileDependencies"].append(copy.deepcopy(dependency))
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "dependencies|dependency"):
                self.validate(seed)

    def test_command_terminal_state_and_exact_record_are_mandatory(self):
        for key, value in (("Exit", False), ("Exit", 1), ("TimedOut", True), ("TimedOut", 0),
                           ("Error", "failure"), ("Status", "PENDING"), ("Cwd", "foreign")):
            seed = synthetic_seed()
            seed.result["Commands"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "successful bound seed command"):
                self.validate(seed)
        seed = synthetic_seed()
        seed._test_records[seed.root / "command-0000.json"] = dict(seed.result["Commands"][0], Exit=2)
        with self.assertRaisesRegex(ValueError, "seed command record"):
            self.validate(seed)

    def test_all_workers_and_one_source_bound_compiler_required(self):
        seed = synthetic_seed()
        seed.result["Commands"][0]["Label"] = "not a resolution"
        with self.assertRaisesRegex(ValueError, "all six captured workers"):
            self.validate(seed)
        seed = synthetic_seed()
        command = next(cmd for cmd in seed.result["Commands"] if cmd["Label"] == "compile context_core.c")
        other = synthetic_root() / "tools/bin/foreign-gcc.exe"
        seed.originals[other] = {}
        command["Argv"][0] = str(other)
        with self.assertRaisesRegex(ValueError, "one seed source-bound compiler"):
            self.validate(seed)

    def test_git_lowercase_c_config_is_not_a_compiler_invocation(self):
        seed = synthetic_seed()
        git = synthetic_root() / "tools/bin/git.exe"
        seed.originals[git] = {}
        seed._test_add_command("synthetic git metadata", [str(git), "-c", "core.autocrlf=false", "-C", "pinned", "status"])
        self.assertIsNone(self.validate(seed))

    def test_seed_links_require_both_ordered_full_commands_not_just_success_flags(self):
        for change in ("missing", "reordered", "lto", "provider", "map", "duplicate-command"):
            seed = synthetic_seed()
            rows = seed.result["Links"]
            command = next(cmd for cmd in seed.result["Commands"] if cmd["Label"] == "link ordinary")
            if change == "missing":
                rows.pop()
            elif change == "reordered":
                rows.reverse()
            elif change == "lto":
                command["Argv"].insert(1, "-flto")
            elif change == "provider":
                index = command["Argv"].index(seed.result["Sources"][0]["Object"])
                command["Argv"][index] = "foreign.o"
            elif change == "map":
                rows[0]["Map"] += ".foreign"
            else:
                seed._test_add_command(command["Label"], command["Argv"][:])
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "seed links|seed link recipe"):
                self.validate(seed)

    def test_parser_capture_membership_cannot_be_empty_or_uncovered(self):
        for uncovered in (False, True):
            seed = synthetic_seed()
            if uncovered:
                seed.captures.pop(seed.root / "python/elftools/__init__.py")
            else:
                seed.artifacts.clear()
            with self.subTest(uncovered=uncovered), self.assertRaisesRegex(ValueError, "complete seed parser capture"):
                self.validate(seed)


def section_text(*, ir=False, executable=0, machine="ARM", kind="REL"):
    lines = ["ELF Header:", "  Class: ELF32", "  Data: 2's complement, little endian",
             "  Type: " + kind + " (synthetic inspection record)", "  Machine: " + machine,
             "  Number of section headers: " + str(3 if ir else 2), "Section Headers:",
             "  [Nr] Name Type Addr Off Size ES Flg Lk Inf Al",
             "  [ 0]                   NULL 00000000 000000 000000 00      0 0 0",
             "  [ 1] .text PROGBITS 00000000 000034 %06x 00 AX 0 0 4" % executable]
    if ir:
        lines.append("  [ 2] .gnu.lto_.synthetic PROGBITS 00000000 000040 000010 00 E 0 0 1")
    lines.append("Key to Flags:")
    return "\n".join(lines) + "\n"


def elf_header_fixture(*, kind=1, machine=40, sections=2):
    """Header and section-table bounds only, not a complete executable fixture."""
    ident = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    return ident + struct.pack("<HHIIIIIHHHHHH", kind, machine, 1, 0, 0, 52, 0x05000000,
                               52, 0, 0, 40, sections, 0) + b"\0" * (40 * sections)


class MockCompileTests(unittest.TestCase):
    def make_probe(self):
        seed = synthetic_seed()
        seed.output, seed.artifact = synthetic_root() / "probe-output", artifact()
        seed.sources = seed.result["Sources"]
        seed.tool_root = synthetic_root() / "tools"
        seed.native = SimpleNamespace(read_dependencies=Mock())
        seed.closure.hashes = {}
        by_depfile = {}
        for row in seed.sources:
            source = Path(row["Source"])
            row["SourceSha256"] = sha(seed._test_payloads[source])
            seed.closure.hashes[source] = row["SourceSha256"]
            by_depfile["%02d-%s.d" % (len(by_depfile), source.stem)] = [source]
        seed.native.read_dependencies.side_effect = lambda path: by_depfile[Path(path).name]
        probe = p.Probe(seed, SimpleNamespace())
        probe.tool_root, probe.tools = seed.output / "toolchain", {"gcc": synthetic_root() / "gcc.exe"}
        probe.command = Mock()
        probe.inspect = Mock(side_effect=lambda path: section_text(ir=not Path(path).name.startswith("08-"),
                                                                   executable=4 if Path(path).name.startswith("08-") else 0))
        return probe

    def compile(self, probe, *, c_sections=3, startup_sections=2):
        def read(path):
            path = Path(path)
            if path.suffix == ".o":
                return elf_header_fixture(sections=startup_sections if path.name.startswith("08-") else c_sections)
            return probe.seed._test_payloads[path]
        with patch.object(p, "regular", side_effect=lambda path: Path(path)), \
                patch.object(Path, "mkdir"), patch.object(Path, "read_bytes", read):
            probe.compile()

    def test_eight_slim_c_compiles_and_one_native_startup_keep_exact_flags(self):
        probe = self.make_probe()
        self.compile(probe)
        self.assertEqual(probe.command.call_count, 9)
        self.assertEqual((probe.report["TranslationUnits"], probe.report["SlimIRObjects"]), (9, 8))
        self.assertEqual(len(probe.objects), 9)
        for index, call in enumerate(probe.command.call_args_list):
            source = probe.seed.sources[index]
            flags = source["CompileFlags"] if index == 8 else [*source["CompileFlags"], "-flto", "-fno-fat-lto-objects"]
            result = probe.report["Sources"][index]
            expected = [probe.tools["gcc"], *flags, "-MD", "-MF", Path(result["DependencyFile"]),
                        "-MT", "pilot-source-" + str(index), "-c", Path(source["Source"]), "-o", Path(result["Object"])]
            self.assertEqual(call.args, (expected, "compile " + Path(source["Source"]).name))
            self.assertIs(result["SlimIR"], index != 8)
            self.assertIs(result["CompileDependenciesVerified"], True)
        self.assertEqual(probe.report["ObjectChecks"], [{"Stage": "after-compile", "Status": "PASS"}])

    def test_fat_object_executable_fallback_rejects_even_with_ir(self):
        probe = self.make_probe()
        probe.inspect = Mock(return_value=section_text(ir=True, executable=4))
        with self.assertRaisesRegex(ValueError, "no fat machine fallback"):
            self.compile(probe)

    def test_native_only_object_cannot_replace_slim_c_ir(self):
        probe = self.make_probe()
        probe.inspect = Mock(return_value=section_text(executable=4))
        with self.assertRaisesRegex(ValueError, "genuine slim GIMPLE"):
            self.compile(probe, c_sections=2)

    def test_startup_must_not_be_ir(self):
        probe = self.make_probe()
        probe.inspect = Mock(return_value=section_text(ir=True))
        with self.assertRaisesRegex(ValueError, "startup must remain non-LTO"):
            self.compile(probe, startup_sections=3)

    def test_foreign_machine_and_nonrelocatable_inspection_reject(self):
        for text in (section_text(ir=True, machine="AArch64"), section_text(ir=True, kind="EXEC")):
            probe = self.make_probe()
            probe.inspect = Mock(return_value=text)
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "actual ARM ET_REL input"):
                self.compile(probe)

    def test_new_compile_dependencies_must_match_admitted_seed(self):
        probe = self.make_probe()
        probe.seed.native.read_dependencies.side_effect = None
        probe.seed.native.read_dependencies.return_value = [synthetic_root() / "foreign.h"]
        with self.assertRaisesRegex(ValueError, "dependency set changed"):
            self.compile(probe)


class MachineClassificationTests(unittest.TestCase):
    class ReachedFinalInspection(Exception):
        pass

    def first_machine(self, text, data=None):
        seed = SimpleNamespace(output=synthetic_root() / "machine-probe", artifact=artifact(),
                               script=synthetic_root() / "link.ld", closure=SimpleNamespace(close=Mock()))
        probe = p.Probe(seed, SimpleNamespace())
        probe.tools = {"gcc": synthetic_root() / "gcc.exe"}
        probe.prepare, probe.compile, probe.verify_objects = Mock(), Mock(), Mock()
        probe.command = Mock(return_value=SimpleNamespace(stderr=b"synthetic trace"))
        probe.objects = [synthetic_root() / ("ir-%d.o" % index) for index in range(9)]
        # Raw symbol metadata only; this boundary makes no ABI/placement claim.
        facts = "\n".join((
            "1: 00000001 4 FUNC GLOBAL DEFAULT 1 fiber_port_start_first_context",
            "2: 00000005 4 FUNC GLOBAL DEFAULT 1 SVC_Handler",
            "3: 00000009 4 FUNC GLOBAL DEFAULT 1 PendSV_Handler",
            "4: 0000000d 4 FUNC GLOBAL DEFAULT 1 fiber_panic",
            "5: 00000011 4 FUNC GLOBAL DEFAULT 1 fiber_port_context_validate_restore",
            "6: 00000015 4 FUNC GLOBAL DEFAULT 1 fiber_port_context_validate_save_current",
            "7: 00000019 4 FUNC GLOBAL DEFAULT 1 fiber_port_scheduler_pick_next_from_pendsv",
            "8: 00000000 4 OBJECT LOCAL DEFAULT 1 fiber_internal_runtime_current_context_slot"))
        probe.inspect = Mock(side_effect=[text + facts + "\n", self.ReachedFinalInspection()])
        if data is None:
            data = elf_header_fixture(sections=3 if ".gnu.lto_" in text else 2)
        with patch.object(Path, "mkdir"), patch.object(Path, "is_file", return_value=True), \
                patch.object(p, "regular", side_effect=lambda path: Path(path)), patch.object(Path, "read_bytes", return_value=data):
            probe.build()

    def test_machine_body_admission_reaches_next_boundary_without_claiming_build_pass(self):
        with self.assertRaises(self.ReachedFinalInspection):
            self.first_machine(section_text(executable=4))

    def test_correct_machine_filename_does_not_admit_ir_or_empty_code(self):
        for text in (section_text(ir=True), section_text(ir=True, executable=4), section_text()):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "GIMPLE or lacks executable machine bytes"):
                self.first_machine(text)

    def test_machine_owner_must_still_be_arm_etrel(self):
        for text in (section_text(executable=4, kind="EXEC"), section_text(executable=4, machine="AArch64")):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "saved machine must be actual ARM ET_REL"):
                self.first_machine(text)


    def test_saved_machine_rejects_elf64_and_big_endian_even_if_arm_rel(self):
        for index, value in ((4, 2), (5, 2)):
            data = bytearray(elf_header_fixture())
            data[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.first_machine(section_text(executable=4), bytes(data))


class SectionParsingTests(unittest.TestCase):
    def test_complete_numbered_rows_are_retained_including_empty_null_name(self):
        rows = p.section_records(section_text(ir=True))
        self.assertEqual([row["Index"] for row in rows], [0, 1, 2])
        self.assertEqual(rows[0]["Type"], "NULL")
        self.assertEqual(rows[1]["Name"], ".text")
        self.assertEqual(rows[2]["Name"], ".gnu.lto_.synthetic")

    def test_unmatched_numbered_section_row_cannot_be_silently_dropped(self):
        original = section_text(ir=True)
        valid = "  [ 2] .gnu.lto_.synthetic PROGBITS 00000000 000040 000010 00 E 0 0 1"
        for malformed in ("  [ 2] .gnu.lto_.synthetic PROGBITS 00000000 000040 NOTHEX 00 E 0 0 1",
                          "  [ 2] .hidden_machine PROGBITS 00000000 000040 000010 00 AX? 0 0 1",
                          "  [ 2] .gnu.lto_.synthetic PROGBITS truncated"):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                p.section_records(original.replace(valid, malformed))


class ElfHeaderTests(unittest.TestCase):
    def test_actual_header_gate_accepts_bounded_elf32_little_endian_arm_rel(self):
        row = p.require_elf32le(elf_header_fixture())
        self.assertEqual(row, dict(Class="ELF32", Data="little-endian", Type="REL", Machine="ARM", Version=1,
                                  HeaderSize=52, SectionOffset=52, SectionEntrySize=40, SectionCount=2))

    def test_elf64_big_endian_or_wrong_ident_version_are_not_arm32_machine_authority(self):
        for index, value in ((4, 2), (5, 2), (6, 0)):
            data = bytearray(elf_header_fixture())
            data[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                p.require_elf32le(bytes(data))

    def test_truncated_or_unbounded_header_section_table_rejects(self):
        original = elf_header_fixture()
        malformed = [original[:51], original[:-1], bytearray(original), bytearray(original), bytearray(original)]
        struct.pack_into("<I", malformed[2], 32, len(original) + 40)
        struct.pack_into("<H", malformed[3], 46, 0)
        struct.pack_into("<H", malformed[4], 48, 0)
        for data in malformed:
            with self.subTest(data=bytes(data)), self.assertRaises(ValueError):
                p.require_elf32le(bytes(data))

    def test_foreign_machine_or_wrong_elf_type_rejects(self):
        for data in (elf_header_fixture(machine=183), elf_header_fixture(kind=2)):
            with self.subTest(data=data), self.assertRaises(ValueError):
                p.require_elf32le(data)
        self.assertEqual(p.require_elf32le(elf_header_fixture(kind=2), "EXEC")["Type"], "EXEC")


class ClosureTests(unittest.TestCase):
    def test_caller_hash_checked_against_same_parsed_bytes(self):
        path = synthetic_root() / "results.json"
        data = b'{"Status":"PASS","Count":9}'
        with patch.object(p, "regular", side_effect=lambda value: Path(value)), patch.object(Path, "read_bytes", return_value=data):
            closure = p.Closure()
            self.assertEqual(closure.structured(path, sha(data)), {"Status": "PASS", "Count": 9})
            with self.assertRaisesRegex(ValueError, "input hash mismatch"):
                closure.structured(path, "0" * 64)

    def test_closing_detects_late_content_change(self):
        path = synthetic_root() / "captured.c"
        with patch.object(p, "regular", side_effect=lambda value: Path(value)), \
                patch.object(Path, "read_bytes", side_effect=[b"original", b"changed"]):
            closure = p.Closure()
            closure.read(path)
            with self.assertRaisesRegex(ValueError, "input hash mismatch"):
                closure.close()

    def test_tree_rejects_extra_or_missing_artifact_membership(self):
        root = synthetic_root() / "closure"
        for actual in ({}, {"one": root / "one", "extra": root / "extra"}):
            with self.subTest(actual=actual), patch.object(p, "checked_path", side_effect=lambda value: Path(value)), \
                    patch.object(p, "files_under", return_value=actual), self.assertRaisesRegex(ValueError, "complete artifact membership"):
                p.Closure().tree(root, {"one": sha(b"one")})

    def test_closing_rejects_late_membership_addition(self):
        root = synthetic_root() / "closure"
        with patch.object(p, "files_under", return_value={"extra": root / "extra"}):
            closure = p.Closure()
            closure.memberships[root] = set()
            with self.assertRaisesRegex(ValueError, "input membership changed"):
                closure.close()


def memory_admission():
    """In-memory seed envelope only; validation and helper execution are mocked."""
    base = synthetic_root() / "admission"
    root, inventory, source = base / "seed", base / "inventory", base / "owned/source.h"
    buffers = {source: b"synthetic owned header", inventory / "results.json": b'{"Inventory":true}'}
    encode = lambda value: (json.dumps(value, sort_keys=True) + "\n").encode("ascii")
    buffers[inventory / "artifacts.json"] = encode({"Artifacts": {"results.json": sha(buffers[inventory / "results.json"])}})
    rows = []
    for index, original in enumerate((source, inventory / "artifacts.json", inventory / "results.json")):
        captured = root / "source" / ("capture-%d.dat" % index)
        buffers[captured] = buffers[original]
        rows.append(dict(Original=str(original), Captured=str(captured), Sha256=sha(buffers[original])))
    sources = []
    for index, name in enumerate(NATIVE_SOURCES):
        original, captured = base / "owned" / name, root / "source" / name
        obj = root / "objects" / ("source-%02d.o" % index)
        buffers[original] = ("synthetic source bytes %d\n" % index).encode("ascii")
        buffers[captured] = buffers[original]
        buffers[obj] = ("synthetic owning object bytes %d; not ELF\n" % index).encode("ascii")
        value = sha(buffers[captured])
        rows.append(dict(Original=str(original), Captured=str(captured), Sha256=value))
        sources.append(dict(Source=str(captured), SourceSha256=value, Object=str(obj), ObjectSha256=sha(buffers[obj])))
    generated = root / "source/generated/main.h"
    buffers[generated] = b"/* synthetic generated header */\n"
    buffers[root / "results.json"] = encode({"SourceInventoryReceipt": str(inventory), "Sources": sources})
    buffers[root / "inputs.json"] = encode({"Files": rows, "Generated": {str(generated): sha(buffers[generated])}})
    artifacts = {path.relative_to(root).as_posix(): sha(data) for path, data in buffers.items() if path.is_relative_to(root)}
    buffers[root / "artifacts.json"] = encode({"Artifacts": artifacts})
    buffers[p.REPO / p.FROZEN] = b"# loader execution replaced by mock\n"
    buffers[PROBE] = b"# source closure replaced by in-memory buffer\n"
    buffers[base / "interpreter/python.exe"] = b"synthetic interpreter input"
    args = SimpleNamespace(native_build=str(root), native_receipt_sha256=sha(buffers[root / "results.json"]),
        native_artifacts_sha256=sha(buffers[root / "artifacts.json"]), output_dir=str(base / "fresh-output"))
    return args, buffers


class AdmissionEnvelopeTests(unittest.TestCase):
    def admit(self, args, buffers):
        def files(root):
            return {path.relative_to(root).as_posix(): path for path in buffers if path.is_relative_to(root)}

        def samefile(path, other):
            path, other = Path(path), Path(other)
            if path not in buffers or other not in buffers:
                raise FileNotFoundError("samefile requires two declared in-memory files")
            return path == other

        loader = SimpleNamespace(FrozenSources=Mock(return_value=SimpleNamespace()))

        def metadata(seed):
            interpreter = Path(args.native_build).parent / "interpreter/python.exe"
            seed.native = SimpleNamespace(interpreter_path=Mock(return_value=interpreter))
            seed.tool_root = Path(args.native_build).parent / "tools"

        with patch.object(p, "checked_path", side_effect=lambda path, must_exist=True: Path(path)), \
                patch.object(p, "regular", side_effect=lambda path: Path(path)), \
                patch.object(p, "files_under", side_effect=files), \
                patch.object(Path, "read_bytes", lambda path: buffers[Path(path)]), \
                patch.object(Path, "samefile", samefile), \
                patch.object(Path, "exists", return_value=False), \
                patch.object(Path, "mkdir", side_effect=AssertionError("admission must not create output")), \
                patch.object(p, "load_buffer", return_value=loader) as load, \
                patch.object(p.Seed, "validate", autospec=True, side_effect=metadata) as validate:
            self.last_loader = load
            seed = p.Seed(args)
            validate.assert_called_once_with(seed)
            load.assert_called_once()
            return seed

    def test_authenticated_envelope_reaches_metadata_validation_without_output_creation(self):
        args, buffers = memory_admission()
        seed = self.admit(args, buffers)
        self.assertEqual(seed.output, Path(args.output_dir))
        self.assertEqual(len(seed.originals), 12)
        self.assertEqual([row["Source"] for row in seed.result["Sources"]],
                         [str(seed.root / "source" / name) for name in NATIVE_SOURCES])
        for row in seed.result["Sources"]:
            self.assertEqual(row["SourceSha256"], sha(buffers[Path(row["Source"])]))
            self.assertEqual(row["ObjectSha256"], sha(buffers[Path(row["Object"])]))

    def test_both_caller_hashes_reject_before_helper_loading(self):
        for key in ("native_receipt_sha256", "native_artifacts_sha256"):
            args, buffers = memory_admission()
            setattr(args, key, "0" * 64)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "input hash mismatch"):
                self.admit(args, buffers)
            self.last_loader.assert_not_called()

    def test_tampered_capture_or_original_cannot_be_admitted(self):
        for captured in (False, True):
            args, buffers = memory_admission()
            root = Path(args.native_build)
            selected = root / "source/capture-0.dat" if captured else root.parent / "owned/source.h"
            buffers[selected] += b"changed"
            with self.subTest(captured=captured), self.assertRaisesRegex(ValueError, "input hash mismatch"):
                self.admit(args, buffers)

    def test_authenticated_denial_roots_reject_output_overlap_in_both_directions(self):
        args, _ = memory_admission()
        base, root = Path(args.native_build).parent, Path(args.native_build)
        for output in (p.REPO, p.REPO / "would-create", root, root / "new-output", base,
                       base / "inventory/new-output", base / "owned/new-output"):
            args, buffers = memory_admission()
            args.output_dir = str(output)
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, "fresh output must not overlap"):
                self.admit(args, buffers)


    def test_late_compiler_and_interpreter_roots_are_also_denied(self):
        for name in ("tools", "interpreter"):
            args, buffers = memory_admission()
            args.output_dir = str(Path(args.native_build).parent / name / "new-output")
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "compiler/interpreter root"):
                self.admit(args, buffers)
            self.last_loader.assert_called_once()


class CommandEnvelopeTests(unittest.TestCase):
    def command_probe(self):
        root = synthetic_root() / "commands"
        runner = Mock()
        probe = p.Probe(SimpleNamespace(output=root, process=SimpleNamespace(run=runner)), SimpleNamespace())
        gcc = root / "toolchain/bin/gcc.exe"
        probe.tool_hashes, probe.environment = {gcc: sha(b"synthetic compiler identity")}, {"TEMP": str(root / "tmp")}
        probe.verify_tools = Mock()
        return probe, gcc, runner

    def invoke(self, probe, gcc, saved):
        def save(path, value):
            saved.append((Path(path), copy.deepcopy(value)))
        with patch.object(p, "save", side_effect=save), \
                patch.object(p, "checked_path", side_effect=lambda path: Path(path)), \
                patch.object(p, "regular", side_effect=lambda path: Path(path)), patch.object(Path, "write_bytes"):
            return probe.command([gcc, "--synthetic-not-executed"], "synthetic command")

    def test_attempt_is_recorded_before_mock_process_and_success_is_terminal(self):
        probe, gcc, runner = self.command_probe()
        saved = []

        def result(*args, **kwargs):
            self.assertEqual(saved[0][1]["Status"], "ATTEMPT")
            self.assertIsNone(saved[0][1]["Exit"])
            self.assertEqual(args[0], [str(gcc), "--synthetic-not-executed"])
            self.assertEqual(kwargs, dict(cwd=str(probe.output), env=probe.environment, timeout=120))
            return SimpleNamespace(returncode=0, stdout=b"captured stdout", stderr=b"captured stderr", timed_out=False, elapsed=0.01)

        runner.side_effect = result
        self.invoke(probe, gcc, saved)
        runner.assert_called_once()
        self.assertEqual(probe.report["Commands"][0]["Status"], "PASS")
        self.assertEqual(saved[-1][0], probe.output / "commands.json")
        self.assertEqual(saved[-1][1], probe.report["Commands"])

    def test_timeout_even_with_zero_exit_and_bool_exit_cannot_pass(self):
        for result in (SimpleNamespace(returncode=0, timed_out=True, elapsed=0.01, stdout=b"partial", stderr=b"partial"),
                       SimpleNamespace(returncode=False, timed_out=False, elapsed=0.01, stdout=b"", stderr=b"")):
            probe, gcc, runner = self.command_probe()
            saved = []
            runner.return_value = result
            with self.subTest(result=result), self.assertRaisesRegex(ValueError, "command failed/timeout"):
                self.invoke(probe, gcc, saved)
            self.assertEqual(probe.report["Commands"][0]["Status"], "FAIL")
            self.assertEqual(saved[-1][1][0]["Status"], "FAIL")

    def test_baseexception_is_retained_and_reraised_not_converted_to_pass(self):
        probe, gcc, runner = self.command_probe()
        saved = []
        runner.side_effect = KeyboardInterrupt("synthetic interruption")
        with self.assertRaises(KeyboardInterrupt):
            self.invoke(probe, gcc, saved)
        self.assertEqual(probe.report["Commands"][0]["Status"], "FAIL")
        self.assertIn("KeyboardInterrupt", probe.report["Commands"][0]["Error"])
        self.assertEqual(saved[-1][1][0]["Status"], "FAIL")


def synthetic_finish():
    """Complete metadata envelope for real finish/seal methods, not ELF evidence."""
    root = synthetic_root() / "finish-output"
    seed = SimpleNamespace(output=root, closure=p.Closure())
    probe = p.Probe(seed, SimpleNamespace())
    buffers = {}
    for index, name in enumerate(NATIVE_SOURCES):
        original = synthetic_root() / "finish-seed/source" / name
        captured = root / "input-bytes" / ("source-%02d.dat" % index)
        obj = root / "objects" / ("source-%02d.o" % index)
        buffers[original] = ("synthetic source %d\n" % index).encode("ascii")
        buffers[captured] = buffers[original]
        buffers[obj] = ("synthetic object %d; not an ELF\n" % index).encode("ascii")
        value = sha(buffers[original])
        seed.closure.hashes[original] = value
        probe.inputs.append(dict(Original=str(original), Captured=str(captured), Sha256=value))
        probe.objects.append(obj)
        probe.object_hashes[obj] = sha(buffers[obj])
        probe.report["Sources"].append(dict(Source=str(original), SourceSha256=value,
            Object=str(obj), ObjectSha256=sha(buffers[obj]), SlimIR=index != 8,
            CompileFlags=baseline_flags() + ([] if index == 8 else ["-flto", "-fno-fat-lto-objects"]),
            ActualCompileDependencies=[dict(Path=str(original), Sha256=value)], CompileDependenciesVerified=True))
    probe.tool_root = root / "toolchain"
    tool = probe.tool_root / "bin/arm-none-eabi-gcc.exe"
    buffers[tool] = b"synthetic tool identity, never an executable"
    probe.tools["gcc"], probe.tool_hashes[tool] = tool, sha(buffers[tool])
    probe.report["Commands"] = [dict(Label="synthetic completed command", Argv=[str(tool), "--not-executed"],
        Cwd=str(root), Status="PASS", Exit=0, TimedOut=False, Error=None)]
    for kind in ("ordinary", "emit-relocs"):
        directory = root / kind
        image, link_map, machine = directory / "image.elf", directory / "image.map", directory / "image.elf.ltrans0.ltrans.o"
        buffers[image], buffers[link_map], buffers[machine] = b"synthetic final bytes", b"synthetic map", b"synthetic machine bytes"
        probe.report["Links"].append(dict(Kind=kind, Path=str(image), Sha256=sha(buffers[image]),
            Map=str(link_map), MapSha256=sha(buffers[link_map]), Machine=str(machine), MachineSha256=sha(buffers[machine])))
    vector = struct.pack("<16I", 0x20001000, 0x08000081, *([0] * 14))
    load = vector + b"synthetic load payload"
    twins = dict(Identical=True, Entry=0x08000081, VectorAddress=0x08000000, VectorBytes=vector.hex(),
        Segments=[dict(Vaddr=0x08000000, Paddr=0x08000000, FileSize=len(load), MemSize=len(load),
                       Flags=5, Align=4, BytesSha256=sha(load))])
    buffers[root / "load-image.json"] = (json.dumps(twins, indent=2, sort_keys=True) + "\n").encode("ascii")
    probe.report.update(TranslationUnits=9, SlimIRObjects=8, FinalExecutableLinks=2, SavedMachineObjects=2,
        TwinLoadImageCompared=True, TwinLoadImages=twins,
        TwinLoadImagesPath=str(root / "load-image.json"),
        TwinLoadImagesSha256=sha(buffers[root / "load-image.json"]))
    probe.complete = probe.twins_verified = True
    return probe, buffers


class FinishSealingTests(unittest.TestCase):
    def finish(self, probe, buffers, *, error=None, on_save=None, on_close=None):
        attempts, statuses = {}, []

        def regular(path):
            path = Path(path)
            if path not in buffers:
                raise FileNotFoundError(str(path))
            return path

        def files(root):
            return {path.relative_to(root).as_posix(): path for path in buffers if path.is_relative_to(root)}

        def save(path, value):
            path = Path(path)
            attempts[path] = attempts.get(path, 0) + 1
            if path == probe.output / "results.json":
                statuses.append(value["Status"])
            if on_save:
                on_save("before", path, attempts[path], buffers)
            buffers[path] = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("ascii")
            if on_save:
                on_save("after", path, attempts[path], buffers)

        real_close, close_count = probe.seed.closure.close, 0

        def close():
            nonlocal close_count
            close_count += 1
            if on_close:
                on_close(close_count, buffers)
            real_close()

        self.saved_statuses = statuses
        with patch.object(p, "regular", side_effect=regular), patch.object(p, "files_under", side_effect=files), \
                patch.object(p, "save", side_effect=save), patch.object(Path, "read_bytes", lambda path: buffers[regular(path)]), \
                patch.object(probe.seed.closure, "close", side_effect=close), \
                patch("subprocess.Popen", side_effect=AssertionError("sealing controls cannot execute processes")):
            return probe.finish(error)

    def receipt(self, probe, buffers, status, *, sealed=True):
        row = json.loads(buffers[probe.output / "results.json"])
        self.assertEqual(row["Status"], status)
        self.assertIs(row["OutputSealVerified"], sealed)
        for name in ("FinalRootRelocationProof", "FinalReferenceParity", "CompleteObjectProof", "PolicyEquivalence",
                     "SourceToMachineSemanticProof", "OrdinaryOwnerContractSatisfied", "ReferenceBuilt", "ArchiveExtraction",
                     "CpuExecution", "BoardExecution", "RequiredCellSatisfied", "GlobalFreezeQualified"):
            self.assertIs(row[name], False)
        self.assertIs(type(row["RequiredCellsSatisfied"]), int)
        self.assertEqual(row["RequiredCellsSatisfied"], 0)
        if sealed:
            manifest = json.loads(buffers[probe.output / "artifacts.json"])
            actual = {path.relative_to(probe.output).as_posix(): sha(data) for path, data in buffers.items()
                      if path.is_relative_to(probe.output) and path != probe.output / "artifacts.json"}
            self.assertEqual(manifest, {"Artifacts": actual})
        return row

    def test_complete_envelope_seals_exact_membership_without_promoting_proof(self):
        probe, buffers = synthetic_finish()
        self.assertIs(self.finish(probe, buffers), True)
        row = self.receipt(probe, buffers, "PASS")
        self.assertIs(row["InputClosureVerified"], True)
        self.assertEqual(row["ClosingFilesVerified"], 10)
        self.assertEqual(json.loads(buffers[probe.output / "inputs.json"])["Files"], probe.inputs)

    def test_changed_or_missing_twin_file_rejects_before_first_seal(self):
        for change in ("change", "delete"):
            probe, buffers = synthetic_finish()
            path = probe.output / "load-image.json"
            if change == "change":
                buffers[path] += b" \n"
            else:
                del buffers[path]
            with self.subTest(change=change):
                self.assertIs(self.finish(probe, buffers), False)
                row = self.receipt(probe, buffers, "FAIL")
                self.assertIs(row["InputClosureVerified"], False)
                self.assertNotIn("PASS", self.saved_statuses)

    def test_saved_twin_path_hash_and_receipt_value_are_bound_before_seal(self):
        for change in ("path", "hash", "value"):
            probe, buffers = synthetic_finish()
            if change == "path":
                probe.report["TwinLoadImagesPath"] = str(probe.output / "other-twins.json")
            elif change == "hash":
                probe.report["TwinLoadImagesSha256"] = "0" * 64
            else:
                probe.report["TwinLoadImages"]["Entry"] += 4
            with self.subTest(change=change):
                self.assertIs(self.finish(probe, buffers), False)
                self.receipt(probe, buffers, "FAIL")
                self.assertNotIn("PASS", self.saved_statuses)

    def test_explicit_build_error_remains_failure_even_with_all_completion_counts(self):
        probe, buffers = synthetic_finish()
        self.assertIs(self.finish(probe, buffers, error=RuntimeError("original build failed")), False)
        row = self.receipt(probe, buffers, "FAIL")
        self.assertIn("original build failed", row["Error"])
        self.assertNotIn("PASS", self.saved_statuses)

    def test_incomplete_or_failed_build_cannot_finalize_pass(self):
        for change in ("incomplete", "sources", "links", "slim-count", "machine-count", "final-count", "command"):
            probe, buffers = synthetic_finish()
            if change == "incomplete":
                probe.complete = False
            elif change == "sources":
                probe.report["Sources"].pop()
            elif change == "links":
                probe.report["Links"].pop()
            elif change == "slim-count":
                probe.report["SlimIRObjects"] = 7
            elif change == "machine-count":
                probe.report["SavedMachineObjects"] = 1
            elif change == "final-count":
                probe.report["FinalExecutableLinks"] = 1
            else:
                probe.report["Commands"][0]["Status"] = "FAIL"
            with self.subTest(change=change):
                self.assertIs(self.finish(probe, buffers), False)
                self.receipt(probe, buffers, "FAIL")
                self.assertNotIn("PASS", self.saved_statuses)

    def test_finish_requires_private_twin_marker_and_literal_comparison_flag(self):
        for change in ("unverified", "not-compared", "integer-alias", "missing-flag"):
            probe, buffers = synthetic_finish()
            if change == "unverified":
                probe.twins_verified = False
            elif change == "not-compared":
                probe.report["TwinLoadImageCompared"] = False
            elif change == "integer-alias":
                probe.report["TwinLoadImageCompared"] = 1
            else:
                del probe.report["TwinLoadImageCompared"]
            with self.subTest(change=change):
                self.assertIs(self.finish(probe, buffers), False)
                self.receipt(probe, buffers, "FAIL")
                self.assertNotIn("PASS", self.saved_statuses)

    def test_finish_requires_identical_twin_result_not_empty_or_truthy_alias(self):
        for evidence in ({}, {"Identical": False}, {"Identical": 1}):
            probe, buffers = synthetic_finish()
            probe.report["TwinLoadImages"] = evidence
            with self.subTest(evidence=evidence):
                self.assertIs(self.finish(probe, buffers), False)
                self.receipt(probe, buffers, "FAIL")
                self.assertNotIn("PASS", self.saved_statuses)

    def test_preexisting_input_drift_persists_failure_not_pass(self):
        probe, buffers = synthetic_finish()
        buffers[Path(probe.inputs[0]["Original"])] += b"changed"
        self.assertIs(self.finish(probe, buffers), False)
        row = self.receipt(probe, buffers, "FAIL")
        self.assertIs(row["InputClosureVerified"], False)
        self.assertIn("input hash mismatch", row["Error"])

    def test_manifest_write_add_change_or_delete_recomputes_consistent_fail_manifest(self):
        for change in ("add", "change", "delete"):
            probe, buffers = synthetic_finish()

            def mutate(phase, path, attempt, data):
                if phase == "after" and path == probe.output / "artifacts.json" and attempt == 1:
                    if change == "add":
                        data[probe.output / "late.extra"] = b"late artifact"
                    elif change == "change":
                        data[probe.objects[0]] += b"late mutation"
                    else:
                        del data[probe.objects[0]]

            with self.subTest(change=change):
                self.assertIs(self.finish(probe, buffers, on_save=mutate), False)
                row = self.receipt(probe, buffers, "FAIL")
                self.assertIn("PASS", self.saved_statuses)
                self.assertIn("sealing:", row["Error"])
                self.assertIs(row["InputClosureVerified"], False)

    def test_manifest_write_receipt_mutation_cannot_leave_stale_pass(self):
        probe, buffers = synthetic_finish()

        def mutate(phase, path, attempt, data):
            if phase == "after" and path == probe.output / "artifacts.json" and attempt == 1:
                data[probe.output / "results.json"] = b'{"Status":"PASS","Foreign":true}'

        self.assertIs(self.finish(probe, buffers, on_save=mutate), False)
        self.receipt(probe, buffers, "FAIL")

    def test_one_time_manifest_write_error_after_pass_recovers_as_failure(self):
        probe, buffers = synthetic_finish()

        def fail(phase, path, attempt, data):
            if phase == "before" and path == probe.output / "artifacts.json" and attempt == 1:
                raise OSError("synthetic manifest write failure")

        self.assertIs(self.finish(probe, buffers, on_save=fail), False)
        row = self.receipt(probe, buffers, "FAIL")
        self.assertIn("PASS", self.saved_statuses)
        self.assertIn("synthetic manifest write failure", row["Error"])

    def test_late_after_seal_add_change_or_delete_downgrades_saved_pass(self):
        for change in ("add", "change", "delete"):
            probe, buffers = synthetic_finish()
            target = Path(probe.report["Links"][0]["Map"])

            def mutate(count, data):
                if count == 2:
                    if change == "add":
                        data[probe.output / "late.extra"] = b"late artifact"
                    elif change == "change":
                        data[target] += b"changed after seal"
                    else:
                        del data[target]

            with self.subTest(change=change):
                self.assertIs(self.finish(probe, buffers, on_close=mutate), False)
                row = self.receipt(probe, buffers, "FAIL")
                self.assertIn("late artifact membership/hash drift", row["Error"])
                self.assertIn("PASS", self.saved_statuses)

    def test_late_manifest_raw_byte_change_is_not_hidden_by_equal_json(self):
        probe, buffers = synthetic_finish()

        def mutate(count, data):
            if count == 2:
                data[probe.output / "artifacts.json"] += b" \n"

        self.assertIs(self.finish(probe, buffers, on_close=mutate), False)
        row = self.receipt(probe, buffers, "FAIL")
        self.assertIn("late artifact manifest drift", row["Error"])

    def test_late_input_rehash_failure_downgrades_persisted_pass(self):
        probe, buffers = synthetic_finish()

        def mutate(count, data):
            if count == 2:
                data[Path(probe.inputs[0]["Original"])] += b"late input change"

        self.assertIs(self.finish(probe, buffers, on_close=mutate), False)
        row = self.receipt(probe, buffers, "FAIL")
        self.assertIs(row["InputClosureVerified"], False)
        self.assertIn("input hash mismatch", row["Error"])
        self.assertIn("PASS", self.saved_statuses)

    def test_baseexception_during_sealing_is_retained_as_failure(self):
        probe, buffers = synthetic_finish()

        def fail(phase, path, attempt, data):
            if phase == "before" and path == probe.output / "artifacts.json" and attempt == 1:
                raise KeyboardInterrupt("synthetic seal interruption")

        self.assertIs(self.finish(probe, buffers, on_save=fail), False)
        row = self.receipt(probe, buffers, "FAIL")
        self.assertIn("KeyboardInterrupt", row["Error"])

    def test_permanent_manifest_write_failure_does_not_leave_qualified_pass(self):
        probe, buffers = synthetic_finish()

        def fail(phase, path, attempt, data):
            if phase == "before" and path == probe.output / "artifacts.json":
                raise OSError("persistent manifest storage failure")

        self.assertIs(self.finish(probe, buffers, on_save=fail), False)
        row = self.receipt(probe, buffers, "FAIL", sealed=False)
        self.assertIn("persistent manifest storage failure", row["SealError"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    target = args.report.resolve()
    if target.exists() or not target.is_relative_to(Path(tempfile.gettempdir()).resolve()) or target.is_relative_to(REPO):
        parser.error("fresh TEMP report outside repository required")
    report = dict(Status="FAIL", Tests=0, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        Scope="PURE_CM3_O2_LTO_CAPTURE_PROBE_CONTRACTS_ONLY", ToolInvocations=0, NativeCommandsExecuted=0,
        ActualLTOTested=False, MachineOwnerTransportProven=False, SourceOwnershipProven=False,
        RequiredCellsSatisfied=0, FinalElfProof=False, FinalReferenceParity=False, PolicyEquivalence=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, Error=None)
    paths = [Path(__file__).resolve(), PROBE]
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized Python unsupported")
        buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        global p
        spec = importlib.util.spec_from_file_location("cm3_lto_probe_pure_controls", PROBE)
        p = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = p
        with patch("subprocess.Popen", side_effect=AssertionError("process execution forbidden in pure controls")):
            exec(compile(buffers[PROBE], str(PROBE), "exec"), p.__dict__)
            suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
            count = suite.countTestCases()
            if count == 0:
                raise ValueError("nonempty pure probe controls required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        report["SourceDrift"] = [str(path) for path in paths if not path.is_file() or sha(path.read_bytes()) != report["SourceHashes"][str(path)]]
        if result.wasSuccessful() and result.testsRun == count > 0 and not result.skipped and not report["SourceDrift"]:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Errors=report["Errors"] + 1, Error=traceback.format_exc())
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="ascii") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
