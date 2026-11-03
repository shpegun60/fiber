"""Synthetic inventory/accounting controls; no compiler, ELF or CPU evidence."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path

PATH = Path(__file__).resolve().parents[2] / "freeze_cohorts.py"
SPEC = importlib.util.spec_from_file_location("freeze_inventory_under_test", PATH)
f = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(f)


def sample():
    registry = {"CM4": dict(directory="ARM_CM4", kind="classic", cpu="cortex-m4", core=4,
                            architecture="ARMV7EM", mpu=0, sources=["fiber_port.c"], defines=[])}
    target = dict(cpu="cortex-m4", architecture="ARMV7EM", float_abi="hard", fpu_present=True,
        fpu_used=True, fpu_unit="fpv4-sp-d16", fp_stacking="eager", vtor=True, mpu_regions=0,
        security_role="classic", psplim_slot=False, psplim_register=False, mve="none", pac=False,
        bti=False, errata_policy="none", r9_abi="aapcs", nvic_priority_bits=4, scheduler_basepri=16)
    artifact = dict(role="runtime", source_group_id="CM4", abi_contract="forward8", target=target,
        compile_flags=["-mcpu=cortex-m4", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard"],
        defines={"FIBER_FPU_LAZY": "0"}, upstream_sources=["portable/GCC/ARM_CM4F/port.c"], upstream_defines={})
    value = dict(schema_version=1, reference_commit=f.PIN, compiler_baseline="GNU Arm GCC 14.3.1",
        required_object_modes=list(f.OBJECT_MODES), required_final_modes=list(f.FINAL_MODES),
        source_groups=[dict(id="CM4", registry_id="CM4", role="runtime", sources=["fiber/port/ARM_CM4/fiber_port.c"])],
        cohorts=[dict(id="cm4-hard-eager", scope="Claimed", compiler_admission="Admitted", runtime_selectable=True,
            artifacts=[artifact], policy={}, claim_refs=[dict(path="tools/compile_matrix.ps1",
            selector="synthetic-control", proof_scope="synthetic")])], scope_backlog=[])
    return value, registry


def main():
    records = []
    value, registry = sample()

    def test(name, action, expected, reason=None):
        rejected = None
        try:
            action()
            accepted = True
        except (RuntimeError, TypeError, KeyError, ValueError) as failure:
            accepted, rejected = False, str(failure)
        f.need(accepted is expected and (reason is None or rejected == "freeze-inventory: " + reason),
               "synthetic-control-" + name + ": " + str(rejected))
        records.append(dict(Name=name, Accepted=accepted, Rejection=rejected))

    test("valid-structure", lambda: f.validate_manifest(value, registry), True)
    required = f.plan(value)
    f.need(required["RequiredCellCount"] == 19 and not required["GlobalFreezeQualified"], "synthetic-plan-count")

    def planned_requirements():
        f.need(required["PlannedProofRequirements"] == {
            "runtime": ["forward-eight", "reverse-v1", "current-slot-isolation", "strong-handlers",
                        "exact-profile-context-cohort", "generated-assembly-reference-parity",
                        "final-elf-vectors", "negative-link-controls"],
            "secure_companion": ["companion-gateway-abi", "paired-image-contract",
                                 "generated-assembly-reference-parity", "negative-link-controls"],
            "common": ["cpu-neutral-engine", "reverse-v1-ownership", "source-provider-identity"],
        }, "synthetic-proof-requirements")
        f.need(required["InventoryManifestSha256"] == f.sha(f.encoded(value)),
               "synthetic-plan-manifest-binding")
        f.need(required["ExpectedOnly"] is True and required["Execution"] == "NOT_RUN" and
               required["GlobalFreezeQualified"] is False and all(
                   row["Execution"] == "NOT_RUN" and row["Adapter"] == "NOT_SELECTED"
                   for row in required["RequiredCells"]), "synthetic-plan-is-not-execution")

    test("declared-proof-requirements-not-cpu-proof", planned_requirements, True)
    actions = (
        ("missing-final-mode", lambda v: v["required_final_modes"].pop(), "exact-seven-final-modes"),
        ("wrong-mode-order", lambda v: v["required_object_modes"].reverse(), "exact-five-object-modes"),
        ("bool-schema", lambda v: v.update(schema_version=True), "schema-version"),
        ("wrong-reference", lambda v: v.update(reference_commit="0" * 40), "reference-pin"),
        ("clang-containing-gcc-version", lambda v: v.update(compiler_baseline="Clang 14.3.1"), "compiler-baseline-version"),
        ("missing-group", lambda v: v["source_groups"].clear(), "source-groups"),
        ("missing-source", lambda v: v["source_groups"][0]["sources"].append("fiber/port/ARM_CM4/foreign.c"), "canonical-source-group"),
        ("duplicate-cohort", lambda v: v["cohorts"].append(deepcopy(v["cohorts"][0])), "duplicate-cohort-id"),
        ("renamed-same-cohort", lambda v: v["cohorts"].append(dict(deepcopy(v["cohorts"][0]), id="alias")), "duplicate-exact-cohort"),
        ("selectable-pending", lambda v: v["cohorts"][0].update(compiler_admission="Pending"), "selectable-needs-admission"),
        ("fake-bool", lambda v: v["cohorts"][0].update(runtime_selectable=1), "runtime-selectable-bool"),
        ("optimization-counterflag", lambda v: v["cohorts"][0]["artifacts"][0]["compile_flags"].append("-O0"), "non-target-compile-flag"),
        ("numeric-define", lambda v: v["cohorts"][0]["artifacts"][0]["defines"].update(FIBER_FPU_LAZY=0), "define-string-value"),
        ("target-abi-mismatch", lambda v: v["cohorts"][0]["artifacts"][0]["target"].update(float_abi="softfp"), "compile-target-binding"),
        ("cpu-arch-mismatch", lambda v: v["cohorts"][0]["artifacts"][0]["target"].update(cpu="cortex-m33"), "cpu-architecture"),
        ("bool-region-count", lambda v: v["cohorts"][0]["artifacts"][0]["target"].update(mpu_regions=False), "mpu-regions"),
        ("psplim-missing-register", lambda v: v["cohorts"][0]["artifacts"][0]["target"].update(psplim_slot=True), "psplim-slot-requires-register"),
        ("missing-fp-policy", lambda v: v["cohorts"][0]["artifacts"][0]["defines"].pop("FIBER_FPU_LAZY"), "fp-policy-define-binding"),
        ("wrong-fp-policy", lambda v: v["cohorts"][0]["artifacts"][0]["defines"].update(FIBER_FPU_LAZY="1"), "fp-policy-define-binding"),
        ("lazy-target-eager-define", lambda v: v["cohorts"][0]["artifacts"][0]["target"].update(fp_stacking="lazy"), "fp-policy-define-binding"),
        ("fixed-r9-missing-flag", lambda v: v["cohorts"][0]["artifacts"][0]["target"].update(r9_abi="fixed-r9"), "compile-r9-binding"),
        ("fixed-r9-undeclared-flag", lambda v: v["cohorts"][0]["artifacts"][0]["compile_flags"].append("-ffixed-r9"), "compile-r9-binding"),
        ("unknown-policy", lambda v: v["cohorts"][0]["policy"].update(unknown_policy="1"), "unknown-cohort-policy"),
        ("upstream-traversal", lambda v: v["cohorts"][0]["artifacts"][0].update(upstream_sources=["../foreign.c"]), "unsafe-relative-path"),
        ("protected-claim", lambda v: v["cohorts"][0]["claim_refs"][0].update(path="tools/test_m55_secure_closed_parity.ps1"), "protected-input"),
    )
    for name, mutate, reason in actions:
        bad = deepcopy(value)
        mutate(bad)
        test(name, lambda: f.validate_manifest(bad, registry), False, reason)

    lazy = deepcopy(value)
    lazy["cohorts"][0]["artifacts"][0]["target"]["fp_stacking"] = "lazy"
    lazy["cohorts"][0]["artifacts"][0]["defines"]["FIBER_FPU_LAZY"] = "1"
    test("matching-lazy-fp-policy", lambda: f.validate_manifest(lazy, registry), True)
    fixed_r9 = deepcopy(value)
    fixed_r9["cohorts"][0]["artifacts"][0]["target"]["r9_abi"] = "fixed-r9"
    fixed_r9["cohorts"][0]["artifacts"][0]["compile_flags"].append("-ffixed-r9")
    test("matching-fixed-r9", lambda: f.validate_manifest(fixed_r9, registry), True)

    # Keep the synthetic canonical row fixed to isolate the staged registry-ID gate.
    for staged_id in ("C55S", "C3SO", "C5SO", "CM33FTFM"):
        staged = deepcopy(value)
        staged["source_groups"][0]["registry_id"] = staged_id
        staged_registry = {staged_id: deepcopy(registry["CM4"])}
        staged["cohorts"][0]["runtime_selectable"] = False
        test(staged_id + "-staged-not-selectable", lambda: f.validate_manifest(staged, staged_registry), True)
        staged["cohorts"][0]["runtime_selectable"] = True
        test(staged_id + "-staged-selectable-denied", lambda: f.validate_manifest(staged, staged_registry),
             False, "staged-runtime-admission")

    for literal, declared in ((b"0", False), (b"1", True)):
        header = b"#define FIBER_PORT_RUNTIME_SELECTABLE " + literal + b"\n"
        test("source-runtime-literal-" + literal.decode("ascii"),
             lambda: f.source_runtime_admission(header, declared), True)
        test("source-runtime-mismatch-" + literal.decode("ascii"),
             lambda: f.source_runtime_admission(header, not declared), False, "source-runtime-admission")
    test("source-runtime-no-macro-no-new-claim",
         lambda: f.need(f.source_runtime_admission(b"/* no selectable declaration */\n", False) is None,
                        "synthetic-source-no-new-claim"), True)
    for suffix, header in (
        ("expression", b"#define FIBER_PORT_RUNTIME_SELECTABLE (0)\n"),
        ("unknown-literal", b"#define FIBER_PORT_RUNTIME_SELECTABLE 2\n"),
        ("duplicate", b"#define FIBER_PORT_RUNTIME_SELECTABLE 0\n#define FIBER_PORT_RUNTIME_SELECTABLE 0\n"),
    ):
        test("source-runtime-unparsed-" + suffix,
             lambda: f.source_runtime_admission(header, False), False, "source-runtime-admission")

    for spelling in ("16", "0x10u"):
        bound_basepri = deepcopy(value)
        bound_basepri["cohorts"][0]["artifacts"][0]["defines"]["FIBER_SCHEDULER_BASEPRI"] = spelling
        test("basepri-define-bound-" + spelling, lambda: f.validate_manifest(bound_basepri, registry), True)
    for spelling in ("32", "0x20u"):
        bad_basepri = deepcopy(value)
        bad_basepri["cohorts"][0]["artifacts"][0]["defines"]["FIBER_SCHEDULER_BASEPRI"] = spelling
        test("basepri-define-mismatch-" + spelling, lambda: f.validate_manifest(bad_basepri, registry),
             False, "basepri-define-binding")
    test("zero-unsigned-literal", lambda: f.need(f.integer_define("0u") == 0, "synthetic-zero-literal"), True)
    for spelling in ("00", "016u", "08u"):
        test("leading-zero-unsigned-denied-" + spelling,
             lambda: f.integer_define(spelling), False, "integer-define-spelling")

    region_key = "FIBER_TEST_MPU_TOTAL_REGIONS"
    mpu_registry = deepcopy(registry)
    mpu_registry["CM4"].update(kind="mpu", mpu=8, defines=[region_key + "=8"])
    mpu = deepcopy(value)
    mpu["cohorts"][0]["artifacts"][0]["target"]["mpu_regions"] = 8
    mpu["cohorts"][0]["artifacts"][0]["defines"][region_key] = "8"
    for regions, spelling in ((8, "8"), (16, "0x10u")):
        bound_mpu = deepcopy(mpu)
        bound_mpu["cohorts"][0]["artifacts"][0]["target"]["mpu_regions"] = regions
        bound_mpu["cohorts"][0]["artifacts"][0]["defines"][region_key] = spelling
        test("mpu-region-define-bound-" + spelling, lambda: f.validate_manifest(bound_mpu, mpu_registry), True)
    for name, mutate, reason in (
        ("mpu-region-missing-key", lambda v: v["cohorts"][0]["artifacts"][0]["defines"].pop(region_key), "mpu-region-define-name"),
        ("mpu-region-extra-key", lambda v: v["cohorts"][0]["artifacts"][0]["defines"].update(OTHER_MPU_TOTAL_REGIONS="8"), "mpu-region-define-name"),
        ("mpu-region-value-mismatch", lambda v: v["cohorts"][0]["artifacts"][0]["defines"].update({region_key: "16"}), "mpu-region-define-binding"),
    ):
        bad_mpu = deepcopy(mpu)
        mutate(bad_mpu)
        test(name, lambda: f.validate_manifest(bad_mpu, mpu_registry), False, reason)

    for group_id, cpu, architecture, core, basepri in (
        ("CM0MPU", "cortex-m0", "ARMV6M", 0, 0),
        ("CM3MPU", "cortex-m3", "ARMV7M", 3, 16),
    ):
        fixed_registry = {group_id: dict(registry["CM4"], kind="mpu", mpu=8,
                                       cpu=cpu, architecture=architecture, core=core)}
        fixed_mpu = deepcopy(value)
        fixed_mpu["source_groups"][0]["registry_id"] = group_id
        fixed_artifact = fixed_mpu["cohorts"][0]["artifacts"][0]
        fixed_artifact["target"].update(cpu=cpu, architecture=architecture, float_abi="soft",
            fpu_present=False, fpu_used=False, fpu_unit="", fp_stacking="none",
            mpu_regions=8, scheduler_basepri=basepri)
        fixed_artifact["compile_flags"] = ["-mcpu=" + cpu, "-mfloat-abi=soft"]
        fixed_artifact["defines"] = {}
        test(group_id + "-fixed-eight-regions", lambda: f.validate_manifest(fixed_mpu, fixed_registry), True)
        fixed_artifact["target"]["mpu_regions"] = 16
        test(group_id + "-sixteen-regions-denied", lambda: f.validate_manifest(fixed_mpu, fixed_registry),
             False, "fixed-mpu-region-binding")

    for field in ("compile_flags", "upstream_sources"):
        original = deepcopy(value)
        if field == "upstream_sources":
            original["cohorts"][0]["artifacts"][0][field].append("portable/GCC/ARM_CM4F/portASM.S")
        reordered = deepcopy(original)
        reordered["cohorts"][0]["artifacts"][0][field].reverse()

        def same_fingerprint():
            f.validate_manifest(reordered, registry)
            f.need([row["CohortSha256"] for row in f.plan(original)["RequiredCells"]] ==
                   [row["CohortSha256"] for row in f.plan(reordered)["RequiredCells"]],
                   "synthetic-order-normalized-fingerprint")

        test("normalized-" + field + "-fingerprint", same_fingerprint, True)
        alias = deepcopy(reordered["cohorts"][0])
        alias["id"] = "alias-" + field
        original["cohorts"].append(alias)
        test("renamed-reordered-" + field + "-alias", lambda: f.validate_manifest(original, registry),
             False, "duplicate-exact-cohort")

    provider_alias = deepcopy(value)
    alias = dict(deepcopy(provider_alias["cohorts"][0]), id="alias-provider", policy={"provider": "typed-fixture"})
    provider_alias["cohorts"].append(alias)
    test("renamed-provider-policy-alias", lambda: f.validate_manifest(provider_alias, registry),
         False, "duplicate-exact-cohort")

    for policy, define in (
        ("hash_on_switch", "FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH"),
        ("address_map_on_switch", "FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH"),
        ("rewind_msp", "FIBER_REWIND_MSP"),
    ):
        for setting in ("0", "1"):
            bound = deepcopy(value)
            bound["cohorts"][0]["policy"][policy] = setting
            bound["cohorts"][0]["artifacts"][0]["defines"][define] = setting
            test(policy + "-bound-" + setting, lambda: f.validate_manifest(bound, registry), True)
        for suffix, replacement in (("missing-define", None), ("mismatched-define", "0")):
            bad = deepcopy(bound)
            if replacement is None:
                bad["cohorts"][0]["artifacts"][0]["defines"].pop(define)
            else:
                bad["cohorts"][0]["artifacts"][0]["defines"][define] = replacement
            test(policy + "-" + suffix, lambda: f.validate_manifest(bad, registry),
                 False, "cohort-policy-define-binding")
        bad = deepcopy(bound)
        bad["cohorts"][0]["policy"][policy] = 1
        test(policy + "-numeric-not-string", lambda: f.validate_manifest(bad, registry),
             False, "cohort-policy-define-binding")
        asserted_alias = deepcopy(bound)
        asserted_alias["cohorts"][0]["policy"].clear()
        asserted_alias["cohorts"].append(dict(deepcopy(bound["cohorts"][0]), id="alias-" + policy))
        test("renamed-matching-" + policy + "-assertion-alias",
             lambda: f.validate_manifest(asserted_alias, registry), False, "duplicate-exact-cohort")

    artifact = value["cohorts"][0]["artifacts"][0]
    m23 = dict(artifact["target"], cpu="cortex-m23", architecture="ARMV8M_BASELINE", float_abi="soft",
               fpu_present=False, fpu_used=False, fpu_unit="", fp_stacking="none", security_role="ntz",
               psplim_slot=True, psplim_register=False, scheduler_basepri=0)
    test("m23-baseline-reserved-psplim-slot", lambda: f.target(m23, ["-mcpu=cortex-m23", "-mfloat-abi=soft"]), True)
    for cpu, architecture, basepri in (
        ("cortex-m0", "ARMV6M", 0),
        ("cortex-m33", "ARMV8M_MAINLINE", 16),
        ("cortex-m55", "ARMV81M_MAINLINE", 16),
    ):
        bad_target = dict(m23, cpu=cpu, architecture=architecture, scheduler_basepri=basepri)
        flags = ["-mcpu=" + cpu, "-mfloat-abi=soft"]
        test(cpu + "-reserved-psplim-slot-denied", lambda: f.target(bad_target, flags),
             False, "psplim-slot-requires-register")
    companion = dict(m23, cpu="cortex-m33", architecture="ARMV8M_MAINLINE",
                     security_role="secure_companion", psplim_slot=False)
    flags = ["-mcpu=cortex-m33", "-mfloat-abi=soft", "-mcmse"]
    test("companion-basepri-zero-not-applicable", lambda: f.target(companion, flags, role="secure_companion"), True)
    test("runtime-basepri-zero-mainline-denied", lambda: f.target(companion, flags), False, "basepri-architecture")
    test("companion-nonzero-basepri-denied",
         lambda: f.target(dict(companion, scheduler_basepri=16), flags, role="secure_companion"),
         False, "basepri-architecture")
    test("companion-mainline-missing-psplim-register",
         lambda: f.target(dict(companion, psplim_slot=True), flags, role="secure_companion"),
         False, "psplim-slot-requires-register")

    blob = b"first line\nsecond line\n"

    def reference_match(actual, expected):
        f.need(f.reference_bytes_match(actual, blob) == expected, "synthetic-reference-byte-classification")

    test("reference-exact-bytes", lambda: reference_match(blob, "exact"), True)
    test("reference-git-lf-worktree-crlf",
         lambda: reference_match(blob.replace(b"\n", b"\r\n"), "git-lf-worktree-crlf"), True)
    for name, actual in (
        ("reference-semantic-edit", b"first line\nsecond EDIT\n"),
        ("reference-crlf-semantic-edit", b"first line\r\nsecond EDIT\r\n"),
        ("reference-mixed-line-endings", b"first line\r\nsecond line\n"),
        ("reference-lone-carriage-returns", b"first line\rsecond line\r"),
    ):
        test(name, lambda: f.reference_bytes_match(actual, blob), False, "reference-source-bytes")
    test("reference-blob-cr-not-normalizable",
         lambda: f.reference_bytes_match(b"first line\r\r\nsecond line\r\r\n",
                                        b"first line\r\nsecond line\r\n"),
         False, "reference-source-bytes")

    test("duplicate-json-key", lambda: f.read_json(b'{"a":1,"a":2}'), False, "duplicate/case-aliased-json-key")
    test("case-alias-json-key", lambda: f.read_json(b'{"a":1,"A":2}'), False, "duplicate/case-aliased-json-key")
    identity = ("Cohort", "ArtifactRole", "Representation", "Mode", "Linkage", "SourceGroup", "CohortSha256")
    observed = [dict({k: row[k] for k in identity}, SourceInventorySha256="A" * 64,
                     Status="PASS", ProofManifestSha256="B" * 64) for row in required["RequiredCells"]]
    test("accounting-only-positive", lambda: f.validate_coverage_keys(value, required, observed, "A" * 64), True)
    for name, length, repair_count in (
        ("empty-required-and-observed", 0, False),
        ("empty-self-consistent-required-and-observed", 0, True),
        ("truncated-required-and-observed", len(observed) - 1, False),
        ("truncated-self-consistent-required-and-observed", len(observed) - 1, True),
    ):
        bad_required = deepcopy(required)
        bad_required["RequiredCells"] = bad_required["RequiredCells"][:length]
        if repair_count:
            bad_required["RequiredCellCount"] = length
        test(name, lambda: f.validate_coverage_keys(value, bad_required, observed[:length], "A" * 64),
             False, "coverage-plan-binding")
    for name, mutate in (
        ("forged-required-count", lambda v: v.update(RequiredCellCount=20)),
        ("duplicate-required-cell", lambda v: v["RequiredCells"].__setitem__(1, deepcopy(v["RequiredCells"][0]))),
        ("reordered-required-cells", lambda v: v["RequiredCells"].reverse()),
        ("forged-required-cohort-hash", lambda v: v["RequiredCells"][0].update(CohortSha256="C" * 64)),
        ("forged-required-provider", lambda v: v["RequiredCells"][0].update(SourceGroup="CM7")),
        ("forged-required-manifest-hash", lambda v: v.update(InventoryManifestSha256="C" * 64)),
        ("missing-proof-requirements", lambda v: v.pop("PlannedProofRequirements")),
        ("missing-reverse-v1-requirement", lambda v: v["PlannedProofRequirements"]["runtime"].remove("reverse-v1")),
        ("missing-provider-identity-requirement", lambda v: v["PlannedProofRequirements"]["common"].remove("source-provider-identity")),
        ("forged-plan-global-proof", lambda v: v.update(GlobalFreezeQualified=True)),
        ("forged-plan-execution", lambda v: v.update(Execution="RUN")),
        ("unexpected-plan-field", lambda v: v.update(UntrustedExtra=True)),
    ):
        bad_required = deepcopy(required)
        mutate(bad_required)
        test(name, lambda: f.validate_coverage_keys(value, bad_required, observed, "A" * 64),
             False, "coverage-plan-binding")
    other_manifest = deepcopy(value)
    other_manifest["cohorts"][0]["claim_refs"][0]["selector"] = "different-snapshot-selector"
    test("plan-bound-to-entire-manifest",
         lambda: f.validate_coverage_keys(other_manifest, required, observed, "A" * 64),
         False, "coverage-plan-binding")
    for name, mutate, reason in (
        ("missing-cell", lambda v: v.pop(), "coverage-cell-count"),
        ("duplicate-cell", lambda v: v.__setitem__(1, deepcopy(v[0])), "duplicate-or-foreign-coverage-cell"),
        ("foreign-mode", lambda v: v[0].update(Mode="O1"), "duplicate-or-foreign-coverage-cell"),
        ("cross-snapshot", lambda v: v[0].update(SourceInventorySha256="C" * 64), "cross-snapshot-coverage"),
        ("wrong-cohort-hash", lambda v: v[0].update(CohortSha256="C" * 64), "coverage-cohort-binding"),
        ("wrong-provider", lambda v: v[0].update(SourceGroup="CM7"), "coverage-cohort-binding"),
        ("not-run-cell", lambda v: v[0].update(Status="NOT_RUN"), "coverage-status"),
        ("missing-proof-hash", lambda v: v[0].update(ProofManifestSha256=""), "coverage-proof-hash")):
        bad = deepcopy(observed)
        mutate(bad)
        test(name, lambda: f.validate_coverage_keys(value, required, bad, "A" * 64), False, reason)
    facts = f.validate_coverage_keys(value, required, observed, "A" * 64)
    f.need(facts["GlobalFreezeQualified"] is False and facts["ProofScope"] == "KEY_ACCOUNTING_NOT_CPU_PROOF",
           "synthetic-must-not-qualify-cpu")
    print(json.dumps(dict(Verdict="SYNTHETIC-CONTROLS-PASS", Controls=records, TargetExecutions=0,
                         CompilerInvocations=0, GlobalFreezeQualified=False), indent=2))


if __name__ == "__main__":
    main()
