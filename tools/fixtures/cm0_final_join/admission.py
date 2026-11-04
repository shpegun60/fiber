"""Pure CM0 producer admission; physical closure and reader replay are caller-owned."""
import json
from pathlib import PurePosixPath, PureWindowsPath
import re


PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
PROFILES = {
    "CM0": ("cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default", "cortex-m0", False),
    "CM0PLUS": ("cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default", "cortex-m0plus", False),
    "CM0PLUSVTOR": ("cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default", "cortex-m0plus", True),
}
MODES = ("O0", "Og", "O2", "Os", "O3")
CHECKPOINTS = ("before-prelink", "after-prelink", "before-link-ordinary", "after-link-ordinary",
               "before-link-emit-relocs", "after-link-emit-relocs", "closing")
VERDICTS = {"Native": "NATIVE-FINAL-TWIN-BUILD-PASS", "Reference": "REFERENCE-CM0-FINAL-TWIN-BUILD-PASS"}
FALSE_FIELDS = ("LTO", "RequiredCellSatisfied", "FinalElfProof", "FinalRootRelocationProof",
                "CompleteObjectProof", "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified")
REFERENCE_FALSE = ("NativeBuilt", "FinalReferenceParity", "SchedulerSemanticsProven", "CSourceSemanticProof",
                   "ReferenceKernelAvailable", "HandlerRoutingProven", "UnreachabilityProven")
PORT = "portable/GCC/ARM_CM0/"
NATIVE_DEFINES = dict(FIBER_PORT_ARMV6M="1", FIBER_PORT_BUILD_SELECTED="1")
UPSTREAM_DEFINES = dict(FIBER_FREERTOS_PARITY_ENABLE_MPU="0", FIBER_FREERTOS_PARITY_ENABLE_FPU="0",
                        FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE="0")


def _need(ok, message):
    if not ok:
        raise ValueError("cm0-final-admission: " + message)


def _sha(value, label):
    _need(type(value) is str and re.fullmatch(r"[0-9A-Fa-f]{64}", value) is not None, label)


def _path(value, label):
    _need(type(value) is str and value and "\0" not in value, label)
    windows, posix = PureWindowsPath(value), PurePosixPath(value)
    path = windows if windows.is_absolute() else posix
    _need(path.is_absolute() and ".." not in path.parts, label)
    return path.as_posix().casefold() if path is windows else path.as_posix()


def _json(value):
    def check(item):
        if type(item) is dict:
            _need(all(type(key) is str for key in item), "artifact JSON keys")
            for child in item.values():
                check(child)
        elif type(item) is list:
            for child in item:
                check(child)
        else:
            _need(item is None or type(item) in (str, int, float, bool), "artifact JSON type")
    check(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("cm0-final-admission: artifact JSON") from error


def _dependencies(value, label):
    _need(type(value) is list and value, label)
    paths = set()
    for dependency in value:
        _need(type(dependency) is dict and set(dependency) == {"Path", "Sha256"}, label)
        path = _path(dependency["Path"], label + " path")
        _need(path not in paths, label + " duplicate")
        paths.add(path)
        _sha(dependency["Sha256"], label + " hash")
    return paths


def _artifact(artifact, profile):
    _, cpu, vtor = PROFILES[profile]
    target = dict(cpu=cpu, architecture="ARMV6M", float_abi="soft", fpu_present=False,
        fpu_used=False, fpu_unit="", fp_stacking="none", vtor=vtor, mpu_regions=0, security_role="classic",
        psplim_slot=False, psplim_register=False, mve="none", pac=False, bti=False, errata_policy="none",
        r9_abi="aapcs", nvic_priority_bits=2, scheduler_basepri=0)
    _need(_json(artifact.get("target")) == _json(target), "exact CM0 p2/b0 soft target")
    _need(artifact.get("role") == "runtime" and artifact.get("source_group_id") == "CM0"
          and artifact.get("abi_contract") == "forward8", "CM0 runtime artifact")
    _need(_json(artifact.get("compile_flags")) == _json(["-mcpu=" + cpu, "-mthumb", "-mfloat-abi=soft"]), "artifact flags")
    _need(_json(artifact.get("defines")) == _json(NATIVE_DEFINES)
          and _json(artifact.get("upstream_defines")) == _json(UPSTREAM_DEFINES), "artifact defines")
    _need(artifact.get("upstream_sources") == [PORT + "port.c", PORT + "portasm.c"], "artifact upstream sources")


def _flags(flags, source, artifact, side, mode):
    _need(type(flags) is list and flags and all(type(flag) is str and flag and "\0" not in flag for flag in flags),
          "compile flag types")
    prefix = [*artifact["compile_flags"], "-" + mode]
    _need(flags[:len(prefix)] == prefix, "exact target/mode flag prefix")
    _need([flag for flag in flags if flag.startswith("-O")] == ["-" + mode], "single optimization mode")
    _need(not any(flag.startswith(("-flto", "-fno-", "-march=", "-mabi=")) or flag.startswith("@") for flag in flags)
          and not any(flag.startswith(("-mcpu=", "-mfpu=", "-mfloat-abi=", "-mthumb", "-marm"))
                      for flag in flags[len(prefix):]), "unadmitted codegen override")
    assembly = source.endswith(".S")
    defines = ({"PILOT_HAS_VTOR": str(int(artifact["target"]["vtor"]))} if side == "Native" else {}) if assembly else (
        NATIVE_DEFINES if side == "Native" else UPSTREAM_DEFINES)
    expected = sorted("-D" + key + "=" + value for key, value in defines.items())
    _need(sorted(flag for flag in flags if flag.startswith("-D")) == expected, "exact compile defines")


def validate_receipt(row, *, side, profile, mode, expected_cohort, expected_artifact, expected_sources) -> None:
    """Admit metadata against caller-authenticated selections, never open files.

    Source paths and the full artifact are independent caller inputs. This is
    not source-pin proof, physical alias detection, closure or ELF validation.
    """
    _need(type(side) is str and side in VERDICTS, "side")
    _need(type(profile) is str and profile in PROFILES, "profile selection")
    _need(type(mode) is str and mode in MODES, "mode selection")
    _need(type(expected_cohort) is str and expected_cohort == PROFILES[profile][0], "expected cohort")
    _need(type(expected_artifact) is dict and expected_artifact, "expected artifact")
    _artifact(expected_artifact, profile)
    count = 9 if side == "Native" else 5
    _need(type(expected_sources) in (list, tuple) and len(expected_sources) == count, "expected source count")
    expected_keys = [_path(path, "expected source path") for path in expected_sources]
    _need(len(set(expected_keys)) == count, "duplicate expected source")
    _need(type(row) is dict, "receipt object")
    for key, expected in (("Verdict", VERDICTS[side]), ("Profile", profile), ("Mode", mode),
                          ("Cohort", expected_cohort), ("Linkage", "direct")):
        _need(type(row.get(key)) is str and row[key] == expected, key)
    _need(row.get("Error", "missing") is None, "receipt error")
    for key in FALSE_FIELDS:
        _need(row.get(key) is False, key)
    _need(row.get("ReferenceBuilt") is (side == "Reference"), "ReferenceBuilt")
    for key in REFERENCE_FALSE:
        if side == "Reference" or key in row:
            _need(row.get(key) is False, key)
    _need(type(row.get("RequiredCellsSatisfied")) is int and row["RequiredCellsSatisfied"] == 0, "required counter")
    _need(type(row.get("InputDrift")) is list and row["InputDrift"] == [], "input drift")
    _sha(row.get("SourceInventorySha256"), "inventory hash")
    _need(type(row.get("CohortArtifact")) is dict and _json(row["CohortArtifact"]) == _json(expected_artifact), "artifact binding")
    if side == "Reference":
        _need(row.get("ReferenceCommit") == PIN and row.get("SourceGroup") == "CM0", "reference pin/source group")
        for key in ("ReferenceClosingIdentityVerified", "ArtifactSealVerified"):
            _need(row.get(key) is True, key)
        _need(row.get("ProofScope") == "PINNED_REFERENCE_CM0_FIVE_OWNING_PRELINK_ROOTS_AND_DIRECT_TWINS_ONLY",
              "reference producer scope")
        _need(row.get("SchedulerThreshold") == "BASEPRI-NOT-APPLICABLE;PRIMASK-ENVELOPE"
              and row.get("FPPolicy") == "NOT-APPLICABLE-NO-FPU", "reference no-FP/threshold policy")
        _need(type(row.get("DeclaredVTOR")) is bool and row["DeclaredVTOR"] is PROFILES[profile][2], "reference VTOR")
        _need(type(row.get("FixtureHandlerInstallationCheck")) is int
              and row["FixtureHandlerInstallationCheck"] == int(PROFILES[profile][2]), "handler-check recipe")
    _need(type(row.get("TranslationUnits")) is int and row["TranslationUnits"] == count, "translation units")
    _need(type(row.get("FinalExecutableLinks")) is int and row["FinalExecutableLinks"] == 2, "link count")
    for key in ("TwinLoadImageIdentical", "TwinAllocatedSectionsIdentical"):
        _need(row.get(key) is True, key)
    sources = row.get("Sources")
    _need(type(sources) is list and len(sources) == count, "source count")
    objects, role_paths = set(), set(expected_keys)
    for index, source in enumerate(sources):
        _need(type(source) is dict, "source row")
        _path(source.get("Source"), "source path")
        _need(source["Source"] == expected_sources[index], "ordered source binding")
        _sha(source.get("SourceSha256"), "source hash")
        obj = _path(source.get("Object"), "object path")
        _need(obj not in objects and obj not in role_paths, "object role alias")
        objects.add(obj)
        _sha(source.get("ObjectSha256"), "object hash")
        _flags(source.get("CompileFlags"), source["Source"], expected_artifact, side, mode)
        _need(source.get("CompileDependenciesVerified") is True, "actual dependencies verified")
        declared, actual = source.get("Dependencies"), source.get("ActualCompileDependencies")
        dependency_paths = _dependencies(declared, "declared dependencies")
        _dependencies(actual, "actual dependencies")
        _need(_json(declared) == _json(actual), "actual/declaration dependency binding")
        _need(expected_keys[index] in dependency_paths, "source dependency missing")
    role_paths.update(objects)
    links = row.get("Links")
    _need(type(links) is list and len(links) == 2, "two links")
    for link, kind in zip(links, ("ordinary", "emit-relocs")):
        _need(type(link) is dict and type(link.get("Kind")) is str and link["Kind"] == kind, "ordered twin links")
        for key, digest_key in (("Path", "Sha256"), ("Map", "MapSha256")):
            path = _path(link.get(key), "link " + key)
            _need(path not in role_paths, "link role alias")
            role_paths.add(path)
            _sha(link.get(digest_key), "link " + digest_key)
    checks = row.get("ObjectChecks")
    _need(type(checks) is list and len(checks) == len(CHECKPOINTS), "object checkpoint count")
    for check, stage in zip(checks, CHECKPOINTS):
        _need(type(check) is dict and type(check.get("Stage")) is str and check["Stage"] == stage
              and type(check.get("Status")) is str and check["Status"] == "PASS"
              and check.get("Error", "missing") is None, "ordered successful object checkpoints")
    commands = row.get("Commands")
    _need(type(commands) is list and commands, "nonempty command records")
    for command in commands:
        _need(type(command) is dict and type(command.get("Status")) is str and command["Status"] == "PASS", "terminal command status")
        _need(type(command.get("Exit")) is int and command["Exit"] == 0 and command.get("TimedOut") is False
              and command.get("Error", "missing") is None, "terminal command result")
        _need(type(command.get("Label")) is str and command["Label"], "command label")
        argv = command.get("Argv")
        _need(type(argv) is list and argv and all(type(arg) is str and arg and "\0" not in arg for arg in argv), "command argv")
        _path(argv[0], "command executable")
        _path(command.get("Cwd"), "command cwd")
        seconds = command.get("Seconds")
        _need(type(seconds) in (int, float) and 0 <= seconds < float("inf"), "command elapsed")
    bound_compiles = []
    for index, source in enumerate(sources):
        compiles = [command["Argv"] for command in commands
                    if command["Argv"].count("-c") == 1
                    and command["Argv"][command["Argv"].index("-c") + 1:command["Argv"].index("-c") + 2] == [source["Source"]]]
        _need(len(compiles) == 1, "one actual compile command per source")
        argv, flags = compiles[0], source["CompileFlags"]
        dependency = source.get("CompileDependencyFile")
        _path(dependency, "compile dependency file")
        _need(argv == [argv[0], *flags, "-MD", "-MF", dependency, "-MT", "pilot-source-" + str(index),
                       "-c", source["Source"], "-o", source["Object"]], "actual compile binding")
        bound_compiles.append(argv)
    compilers = {argv[0] for argv in bound_compiles}
    _need(len(compilers) == 1, "single compiler executable required")
    compiler = next(iter(compilers))
    _need(sum(command["Argv"][0] == compiler and "-c" in command["Argv"] for command in commands) == count,
          "actual compile count")
