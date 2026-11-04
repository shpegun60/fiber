"""Pure fixed-CM3 controls using actual authenticated inventory bytes, never builds.

The default inventory hash is the manifest byte hash recorded by closed e8,
not a learned machine-code oracle. A different independently authenticated
manifest can be supplied explicitly. Only metadata/attribute checks run.
"""
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import traceback
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location("cm3_final_native_admission_controls", HERE / "admission.py")
admission = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = admission
ADMISSION_BYTES = (HERE / "admission.py").read_bytes()
exec(compile(ADMISSION_BYTES, str(HERE / "admission.py"), "exec"), admission.__dict__)
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
MANIFEST_SHA256 = "A988CD5D7A2BFA197E43950AB42A1E09CAD6BF5AE2A585165E676F76C904B689"
MANIFEST_PATH = Path("C:/fzin-20261104-e8/inputs/tools/freeze_cohorts.json")
SOURCES = ["fiber/port/ARM_CM3/fiber_port.c", "fiber/port/ARM_CM3/fiber_port_boot.c",
           "fiber/port/ARM_CM3/fiber_port_exception.c"]
INVENTORY_BYTES = None
EXPECTED_MANIFEST_SHA256 = MANIFEST_SHA256
ATTRIBUTES = '\n'.join(("Attribute Section: aeabi", "File Attributes", '  Tag_CPU_name: "7-M"',
    "  Tag_CPU_arch: v7", "  Tag_CPU_arch_profile: Microcontroller", "  Tag_THUMB_ISA_use: Thumb-2",
    "  Tag_ABI_PCS_wchar_t: 4", "  Tag_ABI_align_needed: 8-byte",
    "  Tag_ABI_FP_number_model: IEEE 754", "  Tag_ABI_FP_rounding: Needed", ""))


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def strict_json(data):
    def pairs(items):
        result, seen = {}, set()
        for key, value in items:
            if key.casefold() in seen:
                raise ValueError("duplicate/case-aliased JSON key")
            seen.add(key.casefold())
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError("non-finite JSON constant: " + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)


def authenticated_inventory(data, expected_sha256):
    if type(data) is not bytes or type(expected_sha256) is not str or not re.fullmatch(r"[A-Fa-f0-9]{64}", expected_sha256):
        raise ValueError("inventory bytes and independently supplied SHA256 required")
    if sha(data) != expected_sha256.upper():
        raise ValueError("inventory byte hash mismatch")
    manifest = strict_json(data)
    if type(manifest) is not dict or type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        raise ValueError("inventory schema")
    if manifest.get("reference_commit") != "a50edad08b29052631aa469d4df6e6ec7ff68878" or manifest.get("compiler_baseline") != "GNU Arm GCC 14.3.1":
        raise ValueError("inventory pin/compiler baseline")
    if manifest.get("required_object_modes") != ["O0", "Og", "O2", "Os", "O3"]:
        raise ValueError("inventory ordinary modes")
    cohorts, groups = manifest.get("cohorts"), manifest.get("source_groups")
    if type(cohorts) is not list or type(groups) is not list:
        raise ValueError("inventory row lists")
    selected = [row for row in cohorts if type(row) is dict and row.get("id") == COHORT]
    source_groups = [row for row in groups if type(row) is dict and row.get("id") == "CM3"]
    if len(selected) != 1 or len(source_groups) != 1:
        raise ValueError("unique CM3 cohort/source group required")
    expected_group = dict(id="CM3", registry_id="CM3", role="runtime", sources=SOURCES)
    if source_groups[0] != expected_group:
        raise ValueError("exact CM3 source group required")
    cohort = selected[0]
    if cohort.get("scope") != "Claimed" or cohort.get("compiler_admission") != "Admitted" or cohort.get("runtime_selectable") is not True:
        raise ValueError("CM3 inventory admission fields")
    artifacts = cohort.get("artifacts")
    if type(artifacts) is not list or len(artifacts) != 1:
        raise ValueError("single CM3 runtime artifact required")
    admission.require_cohort(artifacts[0], cohort["id"])
    return manifest, artifacts[0]


def selected_cohort(manifest):
    return next(row for row in manifest["cohorts"] if row["id"] == COHORT)


class CohortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.artifact = authenticated_inventory(INVENTORY_BYTES, EXPECTED_MANIFEST_SHA256)

    def reject(self, change, reason="cm3-final-admission"):
        value = copy.deepcopy(self.artifact)
        change(value)
        with self.assertRaisesRegex(admission.Rejected, reason):
            admission.require_cohort(value, COHORT)

    def test_actual_inventory_artifact_default_and_explicit_identity(self):
        value = copy.deepcopy(self.artifact)
        before = copy.deepcopy(value)
        self.assertIsNone(admission.require_cohort(value))
        self.assertIsNone(admission.require_cohort(value, COHORT))
        self.assertEqual(value, before)
        self.assertEqual(admission.COHORT, COHORT)
        self.assertEqual(admission.SOURCE_GROUP, "CM3")
        self.assertEqual(list(admission.SOURCES), SOURCES)

    def test_foreign_identity_and_container_types(self):
        for identity in ("CM3", "CM0", "CM3MPU", True, None,
                "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p8-b2-aapcs-default"):
            with self.subTest(identity=identity), self.assertRaises(admission.Rejected):
                admission.require_cohort(self.artifact, identity)
        for value in (None, [], True, (self.artifact,)):
            with self.assertRaises(admission.Rejected):
                admission.require_cohort(value)

    def test_real_foreign_inventory_artifacts_reject(self):
        foreign = ("cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p8-b2-aapcs-default",
                   "cm4-cortex-m4-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default",
                   "cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p4-b0-aapcs-default")
        for identity in foreign:
            row = next(row for row in self.manifest["cohorts"] if row["id"] == identity)
            with self.subTest(cohort=identity), self.assertRaises(admission.Rejected):
                admission.require_cohort(row["artifacts"][0], COHORT)

    def test_complete_artifact_key_set(self):
        for key in self.artifact:
            with self.subTest(missing=key):
                self.reject(lambda a, k=key: a.pop(k))
        for key in ("Cohort", "source_group", "policy", "extra"):
            self.reject(lambda a, k=key: a.update({k: "unadmitted"}))

    def test_role_source_group_and_abi_binding(self):
        for key, value in (("role", "secure_companion"), ("source_group_id", "CM3MPU"),
                           ("source_group_id", "CM4"), ("abi_contract", "reverse8"), ("abi_contract", True)):
            self.reject(lambda a, k=key, v=value: a.__setitem__(k, v))

    def test_every_target_field_is_mandatory_and_typed(self):
        for key, good in self.artifact["target"].items():
            self.reject(lambda a, k=key: a["target"].pop(k))
            if type(good) is bool:
                wrong = int(good)
            elif type(good) is int:
                wrong = float(good)
            else:
                wrong = None
            with self.subTest(key=key, wrong=wrong):
                self.reject(lambda a, k=key, v=wrong: a["target"].__setitem__(k, v))
        self.reject(lambda a: a["target"].update(extra=False))
        self.reject(lambda a: a["target"].update(VTOR=True))

    def test_foreign_target_facts_reject(self):
        changes = dict(cpu="cortex-m4", architecture="ARMV7EM", float_abi="softfp", fpu_present=True,
            fpu_used=True, fpu_unit="fpv4-sp-d16", fp_stacking="lazy", vtor=False, mpu_regions=8,
            security_role="secure", psplim_slot=True, psplim_register=True, mve="integer", pac=True,
            bti=True, errata_policy="cm7-r0p1", r9_abi="fixed-r9", nvic_priority_bits=8, scheduler_basepri=2)
        for key, value in changes.items():
            with self.subTest(key=key):
                self.reject(lambda a, k=key, v=value: a["target"].__setitem__(k, v))

    def test_exact_flag_order_and_no_additions(self):
        self.reject(lambda a: a["compile_flags"].reverse())
        self.reject(lambda a: a.update(compile_flags=tuple(a["compile_flags"])))
        for flag in ("-O2", "-flto", "-ffixed-r9", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard", "-mcpu=cortex-m3"):
            self.reject(lambda a, f=flag: a["compile_flags"].append(f))

    def test_exact_literal_defines(self):
        for key in self.artifact["defines"]:
            self.reject(lambda a, k=key: a["defines"].pop(k))
            self.reject(lambda a, k=key: a["defines"].__setitem__(k, int(a["defines"][k])))
        for value in ("2", "0x10", "016", True):
            self.reject(lambda a, v=value: a["defines"].update(FIBER_SCHEDULER_BASEPRI=v))
        self.reject(lambda a: a["defines"].update(FIBER_PORT_ARMV7EM="1"))

    def test_exact_upstream_provider_and_defines(self):
        for paths in ([], ["portable/GCC/ARM_CM4F/port.c"],
                      ["portable/GCC/ARM_CM3/port.c", "portable/GCC/ARM_CM0/portasm.c"],
                      ("portable/GCC/ARM_CM3/port.c",)):
            self.reject(lambda a, p=paths: a.update(upstream_sources=p))
        for key in self.artifact["upstream_defines"]:
            self.reject(lambda a, k=key: a["upstream_defines"].pop(k))
            for value in (0, False, "1"):
                self.reject(lambda a, k=key, v=value: a["upstream_defines"].__setitem__(k, v))
        self.reject(lambda a: a["upstream_defines"].update(configENABLE_ERRATA_837070_WORKAROUND="1"))

    def test_mapping_order_is_not_semantic(self):
        value = dict(reversed(list(self.artifact.items())))
        value["target"] = dict(reversed(list(value["target"].items())))
        value["defines"] = dict(reversed(list(value["defines"].items())))
        self.assertIsNone(admission.require_cohort(value))

    def test_helper_has_no_ambient_repository_import_or_io(self):
        tree = ast.parse(ADMISSION_BYTES)
        modules = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
        self.assertEqual(modules, ["re"])
        self.assertFalse(any(isinstance(node, ast.ImportFrom) for node in ast.walk(tree)))
        captured = {"__name__": "captured_cm3_admission", "__file__": "not-a-repository/captured/admission.py"}
        with patch("builtins.open", side_effect=AssertionError("I/O")), \
             patch.object(Path, "read_bytes", side_effect=AssertionError("I/O")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            exec(compile(ADMISSION_BYTES, captured["__file__"], "exec"), captured)
            self.assertIsNone(captured["require_cohort"](copy.deepcopy(self.artifact), COHORT))
            self.assertIsNone(captured["require_attributes"](ATTRIBUTES))


class AttributeTests(unittest.TestCase):
    def test_exact_required_fields_with_unrelated_abi_tags(self):
        self.assertIsNone(admission.require_attributes(ATTRIBUTES))
        self.assertIsNone(admission.require_attributes(ATTRIBUTES.replace("\n", "\r\n")))

    def test_required_attribute_missing_or_foreign(self):
        replacements = {'Tag_CPU_name: "7-M"': 'Tag_CPU_name: "7E-M"', "Tag_CPU_arch: v7": "Tag_CPU_arch: v6S-M",
            "Tag_CPU_arch_profile: Microcontroller": "Tag_CPU_arch_profile: Application",
            "Tag_THUMB_ISA_use: Thumb-2": "Tag_THUMB_ISA_use: Thumb-1"}
        for old, new in replacements.items():
            for text in (ATTRIBUTES.replace(old, new), "\n".join(line for line in ATTRIBUTES.splitlines() if old not in line)):
                with self.subTest(field=old), self.assertRaises(admission.Rejected):
                    admission.require_attributes(text)

    def test_forbidden_feature_tags_even_when_empty_or_case_aliased(self):
        for tag in ("Tag_FP_arch", "Tag_ABI_HardFP_use", "Tag_ABI_VFP_args", "Tag_MVE_arch", "Tag_Advanced_SIMD_arch", "Tag_PAC_extension", "Tag_BTI_extension"):
            for name in (tag, tag.swapcase()):
                for value in ("", "VFPv4"):
                    with self.subTest(tag=name, value=value), self.assertRaises(admission.Rejected):
                        admission.require_attributes(ATTRIBUTES + name + ": " + value + "\n")

    def test_duplicate_or_malformed_tag_records(self):
        for line in ('Tag_CPU_name: "7-M"', 'Tag_cpu_name: "7-M"', "Tag_FP_arch VFPv4",
                     "Tag_CPU_arch : v7", "Tag_FP_arch", "tag_FP_arch: VFPv4"):
            with self.subTest(line=line), self.assertRaises(admission.Rejected):
                admission.require_attributes(ATTRIBUTES + line + "\n")

    def test_attribute_input_types_and_empty_text(self):
        for value in (None, True, 0, [], {}, b"Tag_CPU_arch: v7", "", ATTRIBUTES + "\0"):
            with self.subTest(value=value), self.assertRaises(admission.Rejected):
                admission.require_attributes(value)


class InventoryAuthorityTests(unittest.TestCase):
    def test_raw_buffer_hash_precedes_parse_and_selection(self):
        for data in (INVENTORY_BYTES + b"\n", b"not-json"):
            with patch("json.loads", side_effect=AssertionError("unverified parse")):
                with self.assertRaisesRegex(ValueError, "byte hash mismatch"):
                    authenticated_inventory(data, EXPECTED_MANIFEST_SHA256)

    def test_invalid_hash_types_duplicate_keys_and_nonfinite_json(self):
        for value in (None, True, "A" * 63, "G" * 64):
            with self.assertRaises(ValueError):
                authenticated_inventory(INVENTORY_BYTES, value)
        for data in (b'{"cohorts":[],"COHORTS":[]}', b'{"extra":NaN}'):
            with self.assertRaises(ValueError):
                authenticated_inventory(data, sha(data))

    def test_missing_duplicate_or_foreign_inventory_selection(self):
        baseline, _ = authenticated_inventory(INVENTORY_BYTES, EXPECTED_MANIFEST_SHA256)
        changes = (
            lambda m: m.update(schema_version=True), lambda m: m.update(reference_commit="0" * 40),
            lambda m: m.update(compiler_baseline="Clang14.3.1"),
            lambda m: m["cohorts"].remove(selected_cohort(m)),
            lambda m: m["cohorts"].append(copy.deepcopy(selected_cohort(m))),
            lambda m: selected_cohort(m).update(runtime_selectable=1),
            lambda m: selected_cohort(m).update(artifacts=[]),
            lambda m: selected_cohort(m)["artifacts"].append(copy.deepcopy(selected_cohort(m)["artifacts"][0])),
            lambda m: selected_cohort(m)["artifacts"][0]["target"].update(scheduler_basepri=2),
            lambda m: next(g for g in m["source_groups"] if g["id"] == "CM3")["sources"].reverse(),
            lambda m: m["source_groups"].append(copy.deepcopy(next(g for g in m["source_groups"] if g["id"] == "CM3"))),
        )
        for change in changes:
            manifest = copy.deepcopy(baseline)
            change(manifest)
            data = json.dumps(manifest).encode("ascii")
            with self.subTest(change=change), self.assertRaises(ValueError):
                authenticated_inventory(data, sha(data))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--inventory-manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--inventory-sha256", default=MANIFEST_SHA256)
    args = parser.parse_args(argv)
    report_path = args.report.resolve()
    if report_path.exists() or not report_path.is_relative_to(Path(tempfile.gettempdir()).resolve()) or report_path.is_relative_to(REPO):
        parser.error("fresh TEMP report outside repository required")
    sources = [Path(__file__).resolve(), HERE / "admission.py"]
    report = dict(Status="FAIL", Tests=0, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        Scope="PURE_FIXED_CM3_NATIVE_ADMISSION_AND_ATTRIBUTE_CONTROLS_ONLY", ExpectedManifestSha256=args.inventory_sha256,
        ManifestSha256=None, ActualInventoryArtifactUsed=False, ToolInvocations=0, NativeCommandsExecuted=0,
        RequiredCellsSatisfied=0, FinalElfProof=False, FinalReferenceParity=False, PolicyEquivalence=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, Error=None)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized Python unsupported")
        report["SourceHashes"] = {str(path): sha(path.read_bytes()) for path in sources}
        if report["SourceHashes"][str(HERE / "admission.py")] != sha(ADMISSION_BYTES):
            raise ValueError("loaded admission source drift")
        global INVENTORY_BYTES, EXPECTED_MANIFEST_SHA256
        manifest_path = args.inventory_manifest.resolve(strict=True)
        INVENTORY_BYTES = manifest_path.read_bytes()
        EXPECTED_MANIFEST_SHA256 = args.inventory_sha256
        authenticated_inventory(INVENTORY_BYTES, EXPECTED_MANIFEST_SHA256)
        sources.append(manifest_path)
        report["SourceHashes"][str(manifest_path)] = sha(INVENTORY_BYTES)
        report.update(ManifestSha256=sha(INVENTORY_BYTES), ActualInventoryArtifactUsed=True)
        suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
        count = suite.countTestCases()
        with patch("subprocess.Popen", side_effect=AssertionError("process execution forbidden")):
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        report["SourceDrift"] = [str(path) for path in sources if not path.is_file() or sha(path.read_bytes()) != report["SourceHashes"][str(path)]]
        if result.wasSuccessful() and result.testsRun == count > 0 and not result.skipped and not report["SourceDrift"]:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Errors=report["Errors"] + 1, Error=traceback.format_exc())
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("x", encoding="ascii") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("Receipt:", report_path, sha(report_path.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
