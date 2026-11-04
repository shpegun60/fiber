"""Pure metadata admission; artifact bytes and physical identities are caller-owned."""
import json
from pathlib import PurePosixPath, PureWindowsPath
import re


MODES = ("O0", "Og", "O2", "Os", "O3")
CHECKPOINTS = ("before-prelink", "after-prelink", "before-link-ordinary",
               "after-link-ordinary", "before-link-emit-relocs", "after-link-emit-relocs", "closing")
VERDICTS = {"Native": "NATIVE-FINAL-TWIN-BUILD-PASS",
            "Reference": "REFERENCE-CLASSIC-FP-FINAL-TWIN-BUILD-PASS"}
FALSE_FIELDS = ("LTO", "ReferenceBuilt", "RequiredCellSatisfied", "FinalElfProof",
                "FinalRootRelocationProof", "CompleteObjectProof", "PolicyEquivalence",
                "CpuExecution", "BoardExecution", "GlobalFreezeQualified")


def _need(condition, message):
    if not condition:
        raise ValueError("classic-final-admission: " + message)


def _sha(value, label):
    _need(type(value) is str and re.fullmatch(r"[0-9A-Fa-f]{64}", value) is not None, label)


def _path(value, label):
    _need(type(value) is str and value and "\0" not in value, label)
    windows, posix = PureWindowsPath(value), PurePosixPath(value)
    path = windows if windows.is_absolute() else posix
    _need(path.is_absolute() and ".." not in path.parts, label)
    # Lexical only: filesystem alias and physical-identity checks belong to the caller.
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
        raise ValueError("classic-final-admission: artifact JSON") from error


def _dependencies(value, label):
    _need(type(value) is list and bool(value), label)
    paths = set()
    for dependency in value:
        _need(type(dependency) is dict and set(dependency) == {"Path", "Sha256"}, label)
        path = _path(dependency["Path"], label + " path")
        _need(path not in paths, label + " duplicate")
        paths.add(path)
        _sha(dependency["Sha256"], label + " hash")
    return paths


def validate_receipt(row, *, side, profile, mode, expected_cohort, expected_artifact, expected_sources) -> None:
    """Validate one completed producer's metadata, never files or proof semantics.

    side is exactly 'Native' or 'Reference'. Expected selections and source paths
    come from the caller's independently admitted inventory, not this receipt.
    """
    _need(type(side) is str and side in VERDICTS, "side")
    _need(type(profile) is str and profile in ("CM4", "CM7"), "profile selection")
    _need(type(mode) is str and mode in MODES, "mode selection")
    _need(type(expected_cohort) is str and bool(expected_cohort), "expected cohort")
    _need(type(expected_artifact) is dict and bool(expected_artifact), "expected artifact")
    count = 9 if side == "Native" else 4
    _need(type(expected_sources) in (list, tuple) and len(expected_sources) == count, "expected source count")
    expected_keys = [_path(path, "expected source path") for path in expected_sources]
    _need(len(set(expected_keys)) == count, "duplicate expected source")
    _need(type(row) is dict, "receipt object")
    _need(row.get("Verdict") == VERDICTS[side] and type(row.get("Verdict")) is str, "verdict")
    _need(row.get("Error", "missing") is None, "receipt error")
    _need(type(row.get("Profile")) is str and row["Profile"] == profile, "profile")
    _need(type(row.get("Mode")) is str and row["Mode"] == mode, "mode")
    _need(type(row.get("Cohort")) is str and row["Cohort"] == expected_cohort, "cohort")
    _need(type(row.get("Linkage")) is str and row["Linkage"] == "direct", "direct linkage")
    for key in FALSE_FIELDS:
        if key == "ReferenceBuilt" and side == "Reference":
            _need(row.get(key) is True, key)
        else:
            _need(row.get(key) is False, key)
    for key in ("NativeBuilt", "FinalReferenceParity", "SchedulerSemanticsProven", "ReferenceKernelAvailable"):
        if key in row:
            _need(row[key] is False, key)
    # Current native receipts have no NativeBuilt field; do not invent a true requirement.
    _need(type(row.get("RequiredCellsSatisfied")) is int and row["RequiredCellsSatisfied"] == 0, "required counter")
    _need(type(row.get("InputDrift")) is list and row["InputDrift"] == [], "input drift")
    _sha(row.get("SourceInventorySha256"), "inventory hash")
    _need(type(row.get("CohortArtifact")) is dict and _json(row["CohortArtifact"]) == _json(expected_artifact), "artifact binding")
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
        _need(source.get("Source") == expected_sources[index], "ordered source binding")
        _sha(source.get("SourceSha256"), "source hash")
        obj = _path(source.get("Object"), "object path")
        _need(obj not in objects and obj not in role_paths, "object role alias")
        objects.add(obj)
        _sha(source.get("ObjectSha256"), "object hash")
        _need(source.get("CompileDependenciesVerified") is True, "actual dependencies verified")
        declared = source.get("Dependencies")
        actual = source.get("ActualCompileDependencies")
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
              and check.get("Status") == "PASS" and type(check.get("Status")) is str
              and check.get("Error", "missing") is None, "ordered successful object checkpoints")

    commands = row.get("Commands")
    _need(type(commands) is list and bool(commands), "nonempty command records")
    for command in commands:
        _need(type(command) is dict and type(command.get("Status")) is str and command["Status"] == "PASS",
              "terminal command status")
        _need(type(command.get("Exit")) is int and command["Exit"] == 0
              and command.get("TimedOut") is False and command.get("Error", "missing") is None, "terminal command result")
        _need(type(command.get("Label")) is str and bool(command["Label"]), "command label")
        argv = command.get("Argv")
        _need(type(argv) is list and bool(argv) and all(type(arg) is str and arg and "\0" not in arg for arg in argv),
              "command argv")
        _path(argv[0], "command executable")
        _path(command.get("Cwd"), "command cwd")
        seconds = command.get("Seconds")
        _need(type(seconds) in (int, float) and 0 <= seconds < float("inf"), "command elapsed")
