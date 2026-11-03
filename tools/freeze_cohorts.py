"""Exact freeze inventory/planning only; never executes a compiler or firmware."""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess

PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
OBJECT_MODES = ("O0", "Og", "O2", "Os", "O3")
FINAL_MODES = (*OBJECT_MODES, "O2-lto", "Os-lto")
REGISTRY_IDS = frozenset(("C5TF", "C3FP", "CM7", "CM0", "CM3", "CM4", "CM0MPU", "CM3MPU",
    "CM4MPU", "CM23NTZ", "CM33NTZ", "CM33FNTZ", "CM55NTZ", "CM55FNTZ", "CM55MVEFNTZ",
    "CM33TFM", "CM33FTFM", "CM33MPU", "CM55MPU", "CM55FMPU", "CM55MVEFMPU", "C33S",
    "C55S", "C3SO", "C5SO", "C33S_GATEWAY", "C55S_GATEWAY"))
TOP = {"schema_version", "reference_commit", "compiler_baseline", "required_object_modes",
       "required_final_modes", "source_groups", "cohorts", "scope_backlog"}
GROUP = {"id", "registry_id", "role", "sources"}
COHORT = {"id", "scope", "compiler_admission", "runtime_selectable", "artifacts", "policy", "claim_refs"}
ARTIFACT = {"role", "source_group_id", "abi_contract", "target", "compile_flags", "defines",
            "upstream_sources", "upstream_defines"}
TARGET = {"cpu", "architecture", "float_abi", "fpu_present", "fpu_used", "fpu_unit", "fp_stacking",
          "vtor", "mpu_regions", "security_role", "psplim_slot", "psplim_register", "mve", "pac", "bti",
          "errata_policy", "r9_abi", "nvic_priority_bits", "scheduler_basepri"}
ARCH_CPUS = {"ARMV6M": {"cortex-m0", "cortex-m0plus"}, "ARMV7M": {"cortex-m3"},
             "ARMV7EM": {"cortex-m4", "cortex-m7"}, "ARMV8M_BASELINE": {"cortex-m23"},
             "ARMV8M_MAINLINE": {"cortex-m33"}, "ARMV81M_MAINLINE": {"cortex-m55", "cortex-m85"}}
STOPPED = {"cm33f_secure_transfer_reference", "m55_secure_closed_parity",
           "test_cm33f_secure_transfer_reference.ps1", "test_m55_secure_closed_parity.ps1"}
RUNTIME_ROLES = ("engine", "state", "panic", "optional_configuration", "legacy_compat", "facade_bridge")
STAGED_RUNTIME_GROUPS = frozenset(("C55S", "C3SO", "C5SO", "CM33FTFM"))
POLICY_DEFINES = {"hash_on_switch": "FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH",
                 "address_map_on_switch": "FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH",
                 "rewind_msp": "FIBER_REWIND_MSP"}


def need(ok, reason):
    if not ok:
        raise RuntimeError("freeze-inventory: " + reason)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def reference_bytes_match(actual, blob):
    if actual == blob:
        return "exact"
    need(b"\r" not in blob and actual == blob.replace(b"\n", b"\r\n"), "reference-source-bytes")
    return "git-lf-worktree-crlf"


def read_json(data):
    def pairs(items):
        result, seen = {}, set()
        for key, value in items:
            need(key.casefold() not in seen, "duplicate/case-aliased-json-key")
            seen.add(key.casefold())
            result[key] = value
        return result
    return json.loads(data.decode("utf-8-sig"), object_pairs_hook=pairs)


def keys(value, expected, reason):
    need(type(value) is dict and set(value) == expected, reason + "-fields")


def text(value, reason, empty=False):
    need(type(value) is str and (empty or bool(value)) and len(value) <= 2048 and
         all(32 <= ord(c) < 127 for c in value), reason)
    return value


def identifier(value, reason):
    need(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value), reason)
    return value


def relative(value):
    text(value, "relative-path")
    path = PurePosixPath(value)
    need(not path.is_absolute() and path.parts and ".." not in path.parts and
         "\\" not in value and ":" not in value and path.as_posix() == value,
         "unsafe-relative-path")
    need(not {p.casefold() for p in path.parts} & STOPPED, "protected-input")
    return value


def strings(values, reason, nonempty=True):
    need(type(values) is list and (not nonempty or values), reason + "-list")
    for value in values:
        text(value, reason + "-item")
    need(len(set(values)) == len(values), reason + "-duplicate")
    return values


def definitions(value):
    need(type(value) is dict, "defines-object")
    for key, item in value.items():
        need(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key), "define-name")
        text(item, "define-string-value", empty=True)


def integer_define(value):
    need(type(value) is str and re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)[uU]?", value),
         "integer-define-spelling")
    value = value.rstrip("uU")
    return int(value, 16 if value.lower().startswith("0x") else 10)


def source_runtime_admission(header, declared):
    values = re.findall(rb"(?m)^[ \t]*#[ \t]*define[ \t]+FIBER_PORT_RUNTIME_SELECTABLE([^\r\n]*)", header)
    if values:
        need(len(values) == 1 and values[0].strip() in (b"0", b"1") and
             declared is (values[0].strip() == b"1"), "source-runtime-admission")


def target(value, flags, role="runtime"):
    keys(value, TARGET, "target")
    for name in ("fpu_present", "fpu_used", "vtor", "psplim_slot", "psplim_register", "pac", "bti"):
        need(type(value[name]) is bool, "target-bool-" + name)
    for name in ("cpu", "architecture", "float_abi", "fpu_unit", "fp_stacking", "security_role", "mve",
                 "errata_policy", "r9_abi"):
        text(value[name], "target-string-" + name, empty=name == "fpu_unit")
    cpu = value["cpu"].split("+", 1)[0]
    need(value["architecture"] in ARCH_CPUS and cpu in ARCH_CPUS[value["architecture"]], "cpu-architecture")
    need(value["float_abi"] in ("soft", "softfp", "hard"), "float-abi")
    need(value["fp_stacking"] in ("none", "eager", "lazy"), "fp-stacking")
    need(value["mve"] in ("none", "integer", "fp"), "mve-kind")
    need(not value["fpu_used"] or value["fpu_present"], "used-fpu-requires-present")
    need((value["float_abi"] != "soft") is value["fpu_used"], "float-abi-fpu-use")
    need((value["fp_stacking"] != "none") is value["fpu_used"], "fp-stacking-fpu-use")
    need(value["fpu_present"] or value["fpu_unit"] == "", "absent-fpu-unit")
    need(value["mve"] != "fp" or value["fpu_used"], "mve-fp-requires-fpu")
    need(value["mve"] == "none" or value["architecture"] == "ARMV81M_MAINLINE", "mve-architecture")
    need("+nomve" not in value["cpu"] or value["mve"] == "none", "nomve-target")
    reserved_baseline_slot = cpu == "cortex-m23" and value["architecture"] == "ARMV8M_BASELINE"
    need(not value["psplim_slot"] or value["psplim_register"] or reserved_baseline_slot,
         "psplim-slot-requires-register")
    need(not (value["pac"] or value["bti"]) or value["architecture"] == "ARMV81M_MAINLINE", "pac-bti-architecture")
    need(value["errata_policy"] == "none" or cpu == "cortex-m7", "errata-cpu")
    need(value["errata_policy"] in ("none", "837070-primask-preserving"), "errata-policy")
    need(value["r9_abi"] in ("aapcs", "fixed-r9"), "r9-abi")
    regions, bits, basepri = (value[k] for k in ("mpu_regions", "nvic_priority_bits", "scheduler_basepri"))
    need(type(regions) is int and regions in (0, 8, 16), "mpu-regions")
    need(type(bits) is int and 2 <= bits <= 8, "nvic-priority-bits")
    need(type(basepri) is int and 0 <= basepri <= 255 and basepri % (1 << (8 - bits)) == 0,
         "scheduler-basepri")
    baseline = value["architecture"] in ("ARMV6M", "ARMV8M_BASELINE")
    need((basepri == 0) is (baseline or role == "secure_companion"), "basepri-architecture")
    need(value["vtor"] or cpu in ("cortex-m0", "cortex-m0plus"), "missing-required-vtor")
    strings(flags, "compile-flags")
    for flag in flags:
        need(re.fullmatch(r"-m(?:cpu=[A-Za-z0-9_+.-]+|fpu=[A-Za-z0-9_+.-]+|float-abi=(?:soft|softfp|hard)|thumb|cmse|single-pic-base|pic-register=r9)", flag)
             or flag in ("-ffixed-r9", "-fpic"), "non-target-compile-flag")
    need(flags.count("-mcpu=" + value["cpu"]) == 1 and
         flags.count("-mfloat-abi=" + value["float_abi"]) == 1, "compile-target-binding")
    need([f for f in flags if f.startswith("-mcpu=")] == ["-mcpu=" + value["cpu"]] and
         [f for f in flags if f.startswith("-mfloat-abi=")] == ["-mfloat-abi=" + value["float_abi"]],
         "conflicting-compile-target")
    need([f for f in flags if f.startswith("-mfpu=")] ==
         (["-mfpu=" + value["fpu_unit"]] if value["fpu_unit"] else []), "compile-fpu-binding")
    need(("-ffixed-r9" in flags) is (value["r9_abi"] == "fixed-r9"), "compile-r9-binding")


def cohort_artifacts(cohort):
    # These option categories cannot have competing values; their order is immaterial.
    artifacts = []
    for artifact in cohort["artifacts"]:
        artifacts.append(dict(artifact, compile_flags=sorted(artifact["compile_flags"]),
                              upstream_sources=sorted(artifact["upstream_sources"])))
    return artifacts


def cohort_fingerprint(cohort):
    return sha(encoded(dict(artifacts=cohort_artifacts(cohort), policy=cohort["policy"])))


def read_registry(data):
    """Extract only the existing pure inventory function, not the audit runner."""
    tree = ast.parse(data)
    found = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "profiles"]
    need(len(found) == 1, "canonical-registry-function")
    for node in ast.walk(found[0]):
        need(not isinstance(node, (ast.Import, ast.ImportFrom, ast.With, ast.AsyncFunctionDef,
                                   ast.Global, ast.Nonlocal, ast.While, ast.Try, ast.Lambda)), "nonliteral-registry-operation")
        if isinstance(node, ast.Call):
            need((isinstance(node.func, ast.Name) and node.func.id in ("dict", "sorted")) or
                 (isinstance(node.func, ast.Attribute) and node.func.attr in ("append", "get")),
                 "nonliteral-registry-call")
    namespace = {"__builtins__": {"dict": dict, "sorted": sorted}}
    exec(compile(ast.Module(body=found, type_ignores=[]), "<captured-source-group-inventory>", "exec"), namespace)
    rows = namespace["profiles"]()
    need(type(rows) is list and len(rows) == len(REGISTRY_IDS) and
         {row["name"] for row in rows} == REGISTRY_IDS, "canonical-27-source-groups")
    return {row["name"]: row for row in rows}


def validate_manifest(value, registry):
    keys(value, TOP, "manifest")
    need(type(value["schema_version"]) is int and value["schema_version"] == 1, "schema-version")
    need(value["reference_commit"] == PIN, "reference-pin")
    need(value["compiler_baseline"] == "GNU Arm GCC 14.3.1", "compiler-baseline-version")
    need(value["required_object_modes"] == list(OBJECT_MODES), "exact-five-object-modes")
    need(value["required_final_modes"] == list(FINAL_MODES), "exact-seven-final-modes")
    need(type(value["source_groups"]) is list and value["source_groups"], "source-groups")
    groups, represented = {}, set()
    for group in value["source_groups"]:
        keys(group, GROUP, "source-group")
        name = identifier(group["id"], "group-id")
        need(name.casefold() not in {n.casefold() for n in groups}, "duplicate-group-id")
        need(group["role"] in ("runtime", "secure_companion"), "group-role")
        strings(group["sources"], "group-sources")
        for path in group["sources"]:
            need(relative(path).startswith("fiber/port/") and PurePosixPath(path).suffix.lower() in (".c", ".s"),
                 "port-source-path")
        ref = group["registry_id"]
        if ref is not None:
            need(type(ref) is str and ref in registry and ref not in represented, "registry-group-identity")
            canonical = registry[ref]
            expected = sorted("fiber/port/" + canonical["directory"] + "/" + f for f in canonical["sources"])
            need(sorted(group["sources"]) == expected and
                 group["role"] == ("secure_companion" if canonical["kind"] == "companion" else "runtime"),
                 "canonical-source-group")
            represented.add(ref)
        groups[name] = group
    need(represented == set(registry), "missing-registry-group")
    need(type(value["cohorts"]) is list and value["cohorts"], "cohort-list")
    ids, fingerprints, used = set(), set(), set()
    for cohort in value["cohorts"]:
        keys(cohort, COHORT, "cohort")
        name = identifier(cohort["id"], "cohort-id")
        need(name.casefold() not in ids, "duplicate-cohort-id")
        ids.add(name.casefold())
        need(cohort["scope"] in ("Claimed", "Pending", "ReferenceOnly"), "cohort-scope")
        need(cohort["compiler_admission"] in ("Admitted", "Pending", "ReferenceOnly"), "compiler-admission")
        need(type(cohort["runtime_selectable"]) is bool, "runtime-selectable-bool")
        need(not cohort["runtime_selectable"] or cohort["compiler_admission"] == "Admitted", "selectable-needs-admission")
        need(type(cohort["policy"]) is dict and all(type(v) in (str, int, bool) for v in cohort["policy"].values()),
             "cohort-policy")
        need(set(cohort["policy"]) <= set(POLICY_DEFINES) | {"provider"}, "unknown-cohort-policy")
        need(type(cohort["artifacts"]) is list and 1 <= len(cohort["artifacts"]) <= 2, "cohort-artifacts")
        roles = []
        for artifact in cohort["artifacts"]:
            keys(artifact, ARTIFACT, "artifact")
            role, group_id = artifact["role"], artifact["source_group_id"]
            need(role in ("runtime", "secure_companion") and group_id in groups and
                 groups[group_id]["role"] == role, "artifact-group-role")
            roles.append(role)
            used.add(group_id)
            need(artifact["abi_contract"] == ("forward8" if role == "runtime" else "secure_companion"), "artifact-abi")
            need(groups[group_id]["registry_id"] is not None or cohort["compiler_admission"] == "Pending",
                 "unregistered-admitted-group")
            target(artifact["target"], artifact["compile_flags"], role)
            group_ref = groups[group_id]["registry_id"]
            if group_ref is not None:
                need(not cohort["runtime_selectable"] or group_ref not in STAGED_RUNTIME_GROUPS,
                     "staged-runtime-admission")
                canonical = registry[group_ref]
                target_cpu = artifact["target"]["cpu"].split("+", 1)[0]
                allowed_cpus = {canonical["cpu"].split("+", 1)[0]}
                if group_ref == "CM0":
                    allowed_cpus.add("cortex-m0plus")
                elif group_ref == "CM4MPU":
                    allowed_cpus.add("cortex-m7")
                need(target_cpu in allowed_cpus and artifact["target"]["architecture"] == canonical["architecture"],
                     "source-group-target-binding")
                need(bool(artifact["target"]["mpu_regions"]) == bool(canonical["mpu"]), "source-group-mpu-binding")
                security = {"classic": "classic", "mpu": "classic", "fpmpu": "ntz", "fpsvc": "ntz",
                    "ntz": "ntz", "tfm": "tfm", "paired": "non_secure", "paired-staged": "non_secure",
                    "secure-only": "secure_only", "companion": "secure_companion"}[canonical["kind"]]
                if canonical["core"] >= 23 and canonical["kind"] == "mpu":
                    security = "ntz"
                need(artifact["target"]["security_role"] == security, "source-group-security-binding")
                need(("-mcmse" in artifact["compile_flags"]) is
                     (canonical["kind"] in ("secure-only", "companion")), "cmse-image-role")
            definitions(artifact["defines"])
            definitions(artifact["upstream_defines"])
            if "FIBER_SCHEDULER_BASEPRI" in artifact["defines"]:
                need(integer_define(artifact["defines"]["FIBER_SCHEDULER_BASEPRI"]) ==
                     artifact["target"]["scheduler_basepri"], "basepri-define-binding")
            if group_ref is not None:
                region_keys = {d.split("=", 1)[0] for d in canonical["defines"]
                               if "_MPU_TOTAL_REGIONS=" in d}
                actual_keys = {k for k in artifact["defines"] if k.endswith("_MPU_TOTAL_REGIONS")}
                need(region_keys == actual_keys, "mpu-region-define-name")
                if region_keys:
                    need(all(integer_define(artifact["defines"][k]) == artifact["target"]["mpu_regions"]
                             for k in region_keys), "mpu-region-define-binding")
                elif canonical["mpu"]:
                    need(artifact["target"]["mpu_regions"] == 8, "fixed-mpu-region-binding")
            if artifact["target"]["fpu_used"]:
                need(artifact["defines"].get("FIBER_FPU_LAZY") ==
                     ("1" if artifact["target"]["fp_stacking"] == "lazy" else "0"), "fp-policy-define-binding")
            strings(artifact["upstream_sources"], "upstream-sources")
            for path in artifact["upstream_sources"]:
                need(relative(path).startswith("portable/"), "upstream-port-source")
        for policy, define in POLICY_DEFINES.items():
            if policy in cohort["policy"]:
                need(cohort["policy"][policy] in ("0", "1") and
                     cohort["artifacts"][0]["defines"].get(define) == cohort["policy"][policy],
                     "cohort-policy-define-binding")
        if "provider" in cohort["policy"]:
            need(cohort["policy"]["provider"] == "typed-fixture", "cohort-provider-policy")
        need(roles == ["runtime"] or roles == ["runtime", "secure_companion"], "paired-companion-not-standalone")
        runtime_group = groups[cohort["artifacts"][0]["source_group_id"]]
        if runtime_group["registry_id"] is not None:
            paired = registry[runtime_group["registry_id"]]["kind"] in ("paired", "paired-staged")
            need((len(roles) == 2) is paired, "exact-companion-pairing")
        if len(roles) == 2:
            left, right = (artifact["target"] for artifact in cohort["artifacts"])
            need(left["cpu"].split("+", 1)[0] == right["cpu"].split("+", 1)[0] and
                 left["architecture"] == right["architecture"], "cross-cpu-companion")
        fingerprint = sha(encoded(cohort_artifacts(cohort)))
        need(fingerprint not in fingerprints, "duplicate-exact-cohort")
        fingerprints.add(fingerprint)
        need(type(cohort["claim_refs"]) is list and cohort["claim_refs"], "cohort-claim-refs")
        for ref in cohort["claim_refs"]:
            keys(ref, {"path", "selector", "proof_scope"}, "claim-ref")
            relative(ref["path"])
            text(ref["selector"], "claim-selector")
            text(ref["proof_scope"], "claim-proof-scope")
    need(used == set(groups), "unrepresented-source-group")
    need(type(value["scope_backlog"]) is list, "scope-backlog")
    backlog = set()
    for row in value["scope_backlog"]:
        keys(row, {"id", "status", "description", "refs"}, "backlog")
        identifier(row["id"], "backlog-id")
        need(row["id"].casefold() not in ids | backlog, "duplicate-backlog-id")
        backlog.add(row["id"].casefold())
        need(row["status"] in ("Pending", "ReferenceOnly"), "backlog-status")
        text(row["description"], "backlog-description")
        for path in strings(row["refs"], "backlog-refs"):
            relative(path)
    return groups


def plan(value):
    cells = []
    for cohort in value["cohorts"]:
        fingerprint = cohort_fingerprint(cohort)
        for artifact in cohort["artifacts"]:
            for representation, modes, linkages in (("object", OBJECT_MODES, ("none",)),
                                                     ("final", FINAL_MODES, ("direct", "archive"))):
                for mode in modes:
                    for linkage in linkages:
                        cells.append(dict(Cohort=cohort["id"], CohortSha256=fingerprint,
                            ArtifactRole=artifact["role"], SourceGroup=artifact["source_group_id"],
                            Representation=representation, Mode=mode, Linkage=linkage,
                            CompilerAdmission=cohort["compiler_admission"], Scope=cohort["scope"],
                            Execution="NOT_RUN", Adapter="NOT_SELECTED"))
    keys_seen = {(r["Cohort"], r["ArtifactRole"], r["Representation"], r["Mode"], r["Linkage"]) for r in cells}
    need(len(keys_seen) == len(cells), "duplicate-required-cell")
    return dict(SchemaVersion=1, RequiredCells=cells, RequiredCellCount=len(cells),
                InventoryManifestSha256=sha(encoded(value)),
                ObjectModes=list(OBJECT_MODES), FinalModes=list(FINAL_MODES),
                PlannedProofRequirements={
                    "runtime": ["forward-eight", "reverse-v1", "current-slot-isolation", "strong-handlers",
                                "exact-profile-context-cohort", "generated-assembly-reference-parity",
                                "final-elf-vectors", "negative-link-controls"],
                    "secure_companion": ["companion-gateway-abi", "paired-image-contract",
                                         "generated-assembly-reference-parity", "negative-link-controls"],
                    "common": ["cpu-neutral-engine", "reverse-v1-ownership", "source-provider-identity"],
                },
                ExpectedOnly=True, Execution="NOT_RUN", GlobalFreezeQualified=False)


def validate_coverage_keys(manifest, required, observed, source_inventory_sha256):
    """Identity accounting only: this does not validate any CPU proof artifact."""
    need(type(source_inventory_sha256) is str and re.fullmatch(r"[0-9A-F]{64}", source_inventory_sha256),
         "accounting-source-hash")
    need(required == plan(manifest), "coverage-plan-binding")
    expected = required["RequiredCells"]
    need(bool(expected), "empty-coverage-plan")
    need(type(observed) is list and len(observed) == len(expected), "coverage-cell-count")
    identity = ("Cohort", "ArtifactRole", "Representation", "Mode", "Linkage")
    lookup = {tuple(row[k] for k in identity): row for row in expected}
    seen = set()
    for row in observed:
        keys(row, set(identity) | {"SourceGroup", "CohortSha256", "SourceInventorySha256", "Status",
                                  "ProofManifestSha256"}, "coverage-cell")
        key = tuple(row[k] for k in identity)
        need(key in lookup and key not in seen, "duplicate-or-foreign-coverage-cell")
        seen.add(key)
        need(row["CohortSha256"] == lookup[key]["CohortSha256"] and
             row["SourceGroup"] == lookup[key]["SourceGroup"], "coverage-cohort-binding")
        need(row["SourceInventorySha256"] == source_inventory_sha256, "cross-snapshot-coverage")
        need(type(row["Status"]) is str and row["Status"] == "PASS", "coverage-status")
        need(type(row["ProofManifestSha256"]) is str and re.fullmatch(r"[0-9A-F]{64}", row["ProofManifestSha256"]),
             "coverage-proof-hash")
    need(seen == set(lookup), "missing-coverage-cell")
    return dict(AccountingComplete=True, Cells=len(seen), GlobalFreezeQualified=False,
                ProofScope="KEY_ACCOUNTING_NOT_CPU_PROOF")


def regular(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and not
         getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400, "missing/reparse-input")
    return path.resolve(strict=True)


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="ascii")


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--freertos", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    repo = Path(args.repo).resolve(strict=True)
    out = Path(args.output_dir).resolve()
    need(not out.exists() and not out.is_relative_to(repo), "fresh-external-output-required")
    out.mkdir(parents=True)
    result = dict(Verdict="FAIL", Error=None, GlobalFreezeQualified=False, CompilerInvocations=0,
                  TargetExecutions=0, ProofScope="DECLARED_INVENTORY_AND_PLAN_ONLY",
                  CompilerDependenciesCaptured=False)
    save(out / "results.json", result)
    records, commands = {}, []

    def capture(path, base=repo, prefix=""):
        path = regular(path)
        name = prefix + path.relative_to(base).as_posix()
        relative(name)
        data = path.read_bytes()
        if name in records:
            need(records[name]["Sha256"] == sha(data), "opening-input-drift")
        else:
            target = out / "inputs" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            records[name] = dict(Original=str(path), Captured=str(target), Sha256=sha(data))
        return data

    def git(root, *arguments):
        executable = regular(shutil.which("git"))
        capture(executable, executable.parent, "host-git/")
        argv = [str(executable), "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(root), *arguments]
        process = subprocess.run(argv, capture_output=True, timeout=30)
        commands.append(dict(Arguments=argv, Exit=process.returncode, StdoutSha256=sha(process.stdout),
                             Stderr=process.stderr.decode("utf-8", "replace")))
        need(process.returncode == 0, "reference-git-identity")
        return process.stdout

    try:
        capture(Path(__file__))
        manifest_path = regular(args.manifest)
        manifest = read_json(capture(manifest_path))
        registry = read_registry(capture(repo / "tools/fixtures/sensitive_port_closure/run.py"))
        groups = validate_manifest(manifest, registry)
        reader_path = regular(repo / "tools/runtime_sources.py")
        reader_bytes = capture(reader_path)
        runtime_manifest_path = regular(repo / "tools/runtime_sources.json")
        capture(runtime_manifest_path)
        spec = importlib.util.spec_from_file_location("captured_runtime_source_reader", reader_path)
        reader = importlib.util.module_from_spec(spec)
        exec(compile(reader_bytes, str(reader_path), "exec"), reader.__dict__)
        for path in reader.get_runtime_source_inputs(repo, RUNTIME_ROLES):
            capture(path)
        runtime_providers = {}
        for role in RUNTIME_ROLES:
            runtime_providers[role] = [path.relative_to(repo).as_posix()
                                      for path in reader.get_runtime_source_paths(repo, (role,))]
            capture(runtime_manifest_path)
        for group in groups.values():
            for path in group["sources"]:
                capture(repo / path)
            for directory in {str(PurePosixPath(p).parent) for p in group["sources"]}:
                for path in sorted((repo / directory).glob("*.h")):
                    capture(path)
        for directory in (repo / "context", repo / "fiber", repo / "fiber/port"):
            for path in sorted(directory.glob("*.h")):
                capture(path)
        for cohort in manifest["cohorts"]:
            runtime = cohort["artifacts"][0]
            directory = PurePosixPath(groups[runtime["source_group_id"]]["sources"][0]).parent
            source_runtime_admission(capture(repo / directory / "fiber_portmacro.h"), cohort["runtime_selectable"])
            for ref in cohort["claim_refs"]:
                capture(repo / ref["path"])
        for row in manifest["scope_backlog"]:
            for path in row["refs"]:
                capture(repo / path)
        reference = Path(args.freertos).resolve(strict=True)
        need(reference.is_dir() and git(reference, "rev-parse", "HEAD").decode("ascii").strip() == PIN,
             "actual-reference-pin")
        need(not git(reference, "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"),
             "reference-worktree-drift")
        upstream = sorted({path for cohort in manifest["cohorts"] for artifact in cohort["artifacts"]
                           for path in artifact["upstream_sources"]})
        reference_bindings = []
        for path in upstream:
            data = capture(reference / path, reference, "pinned-reference/")
            blob = git(reference, "show", PIN + ":" + path)
            normalization = reference_bytes_match(data, blob)
            blob_path = out / "reference-blobs" / path
            blob_path.parent.mkdir(parents=True, exist_ok=True)
            blob_path.write_bytes(blob)
            reference_bindings.append(dict(Path=path, WorktreeSha256=sha(data), GitBlobSha256=sha(blob),
                                            ByteComparison=normalization))
        required = plan(manifest)
        save(out / "required-cells.json", required)
        source_hash = sha(encoded({k: v["Sha256"] for k, v in sorted(records.items())}))
        result.update(Verdict="INVENTORY-PLAN-PASS", SourceInventorySha256=source_hash,
            ManifestSha256=sha(manifest_path.read_bytes()), SourceGroups=len(groups),
            Cohorts=len(manifest["cohorts"]), PairedCohorts=sum(len(c["artifacts"]) == 2 for c in manifest["cohorts"]),
            CohortsByScope=dict(Counter(c["scope"] for c in manifest["cohorts"])),
            PendingBacklog=sum(row["status"] == "Pending" for row in manifest["scope_backlog"]),
            ReferenceIdentityVerified=True, ReferenceFiles=len(upstream), ReferenceCommit=PIN,
            ReferenceFileBindings=reference_bindings,
            RuntimeProviders=runtime_providers,
            RequiredCellCount=required["RequiredCellCount"],
            RequiredCellsSha256=sha((out / "required-cells.json").read_bytes()))
        drift = [name for name, row in records.items() if sha(regular(row["Original"]).read_bytes()) != row["Sha256"]
                 or sha(regular(row["Captured"]).read_bytes()) != row["Sha256"]]
        need(not drift, "closing-input-drift")
        result["InputDrift"] = drift
    except Exception as failure:
        result.update(Verdict="FAIL", Error=type(failure).__name__ + ": " + str(failure))
    try:
        save(out / "capture.json", dict(Files=list(records.values())))
        save(out / "commands.json", commands)
        save(out / "results.json", result)
        artifacts = {p.relative_to(out).as_posix(): sha(regular(p).read_bytes())
                     for p in sorted(out.rglob("*")) if p.is_file() and p.name != "artifacts.json"}
        save(out / "artifacts.json", dict(Artifacts=artifacts))
        measured = {p.relative_to(out).as_posix(): sha(regular(p).read_bytes())
                    for p in sorted(out.rglob("*")) if p.is_file() and p.name != "artifacts.json"}
        need(measured == artifacts, "closing-artifact-drift")
    except Exception as failure:
        result.update(Verdict="FAIL", Error=type(failure).__name__ + ": " + str(failure))
        save(out / "results.json", result)
        save(out / "artifacts.json", dict(Artifacts={p.relative_to(out).as_posix(): sha(regular(p).read_bytes())
             for p in sorted(out.rglob("*")) if p.is_file() and p.name != "artifacts.json"}))
    print(result["Verdict"] + " " + str(out), flush=True)
    return 0 if result["Verdict"] == "INVENTORY-PLAN-PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
