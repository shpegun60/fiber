"""Declaration/provider admission for native current CM3 O2-lto/direct only.

The unchanged ordinary helper supplies a source-pinned independent type oracle
and bounded CPP declaration scanner. Its ordinary-mode receipt inspector is
never called, and none of its globals are changed. Public calls consume bytes
only; importing this module authenticates the frozen helper before execution.

Real LTO source rows contain ActualCompileDependencies, not the ordinary
Dependencies field. Here their paths/hashes bind to the capture InputHashes
declarations and, for project files, supplied source bytes. The original Seed
discovery-set comparison, compiler commands, object/external bytes, producer
1191CDC/E9 authentication and all closing seals remain outer obligations.
Neither slim-IR declarations nor C type compatibility prove LTO semantics.
"""

import copy
import hashlib
import json
from pathlib import Path
import types


ORDINARY_SHA256 = "43F2E49D638D0E586A24AD2B32D0B8D86C58CC9A63E134EF6AF064437278CAE5"
EXPECTED_PRODUCER_SHA256 = "1191CDCDA9FC9312B09858D6439674DBCA19ABFCE5B0108F3575AEF3C65C0852"
MODE = "O2-lto"
ADAPTER_SCOPE = "NATIVE_CURRENT_CM3_O2_LTO_DIRECT_DECLARATION_PROVIDER_ADMISSION_ONLY"


def _load_ordinary():
    path = Path(__file__).resolve().parents[1] / "ordinary_final_cell" / "abi.py"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest().upper() != ORDINARY_SHA256:
        raise ValueError("cm3-lto-abi: frozen ordinary helper source identity")
    value = types.ModuleType("_cm3_lto_abi_frozen_ordinary")
    value.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), value.__dict__)
    return value


_ordinary = _load_ordinary()
Rejected = _ordinary.Rejected
SLOT = _ordinary.SLOT
FORWARD = _ordinary.FORWARD
REVERSE = _ordinary.REVERSE
ATTRIBUTE_QUERIES = _ordinary.ATTRIBUTE_QUERIES
UNPROVEN_ATTRIBUTES = _ordinary.UNPROVEN_ATTRIBUTES


def _need(condition, message):
    if not condition:
        raise Rejected("cm3-lto-abi: " + message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def profile_contract():
    facts = _ordinary.profile_contract("CM3")
    facts.update(Mode=MODE, AllowedModes=[MODE], LTO=True,
                 ExpectedProducerSha256=EXPECTED_PRODUCER_SHA256)
    return facts


def source_order():
    return _ordinary.source_order("CM3")


def source_hashes():
    return _ordinary.source_hashes("CM3")


def _metadata():
    facts = profile_contract()
    return dict(Profile="CM3", Cohort=facts["Cohort"], Mode=MODE, Linkage="direct",
                LTO=True, AllowedModes=[MODE], TargetContract=facts, AdapterScope=ADAPTER_SCOPE)


def _decorate(record):
    result = copy.deepcopy(record)
    result.update(_metadata())
    return result


def emit_probes():
    """Emit unchanged CM3 source bytes: two accepts and three absent-slot probes.

    Noreturn pointer types and supported attribute queries retain the independent
    frozen oracle. no_sanitize reflection remains unsupported (GCC14 query ICE):
    accepted compilation and the same-attempt CPP declaration scan are required,
    not attribute-effect or full semantic ABI proof. Legacy cm0_abi C names are
    deliberately unchanged, not an assertion about the admitted target or mode.
    """
    return {name: _decorate(row) for name, row in _ordinary.emit_probes("CM3").items()}


def inspect_sources(sources):
    """Check the unchanged eighteen CM3/E9 raw source identities."""
    return _decorate(_ordinary.inspect_sources("CM3", sources))


def inspect_preprocessed_attributes(raw):
    """Inspect twelve canonical declarations; outer code authenticates origins."""
    return _decorate(_ordinary.inspect_preprocessed_attributes("CM3", raw))


def _parse(raw):
    _need(type(raw) is bytes, "receipt must be authenticated bytes")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=_ordinary._core._object,
                            parse_constant=lambda value: _need(False, "nonfinite JSON: " + value))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejected("cm3-lto-abi: invalid receipt JSON") from error
    _need(type(result) is dict, "receipt must be an object")
    return result


def _input_hashes(value):
    _need(type(value) is dict and value, "capture InputHashes declarations required")
    result, folded = {}, set()
    for path, digest in value.items():
        path = _ordinary._core._path(path)
        _need(path.casefold() not in folded, "duplicate/aliased declared input")
        folded.add(path.casefold())
        result[path] = _ordinary._core._hash(digest)
    return result


def _flags(value):
    _need(type(value) is list and value and all(type(flag) is str for flag in value),
          "literal compile flags required")
    result, include_path = [], False
    for flag in value:
        if include_path:
            result.append(_ordinary._core._path(flag))
            include_path = False
        elif flag == "-include":
            result.append(flag)
            include_path = True
        elif flag.startswith("-I"):
            result.append("-I" + _ordinary._core._path(flag[2:]))
        else:
            result.append(flag)
    _need(not include_path, "missing forced-include path")
    return result


def _expected_flags(root, index, relative):
    if index == 8:
        return ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-g0", "-DPILOT_HAS_VTOR=1"]
    include = ("tools/fixtures/classic_final_image", "fiber/port/ARM_CM3", "fiber/port",
               "fiber", "context", "")
    return (["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-std=gnu11", "-g0",
             "-ffreestanding", "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra",
             "-Werror=implicit-function-declaration", "-Werror=attributes", "-Werror=ignored-attributes",
             "-DFIBER_PORT_ARMV7M=1", "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_SCHEDULER_BASEPRI=16"]
            + ["-I" + root + ("/" + item if item else "") for item in include]
            + ["-I" + root[:-7] + "/cmsis", "-include", root + "/tools/fixtures/classic_final_image/main.h",
               "-I" + root + "/" + relative.rsplit("/", 1)[0], "-flto", "-fno-fat-lto-objects"])


def inspect_provider_dependencies(sources, receipt_bytes, *, source_root, capture_root):
    """Bind the real nine-TU LTO source/dependency/object declaration schema.

    Output hashes and paths are declarations, not object-byte qualification.
    InputHashes is the declared dependency authority, not an invented ordinary
    Dependencies array. Seed discovery-set equality is not recomputed here.
    """
    inspection = inspect_sources(sources)
    receipt = _parse(receipt_bytes)
    facts = profile_contract()
    for key, expected in (("Profile", "CM3"), ("Mode", MODE), ("Cohort", facts["Cohort"]),
                          ("Linkage", "direct"), ("SourceInventorySha256", facts["SourceInventorySha256"])):
        _need(type(receipt.get(key)) is str and receipt[key] == expected, "wrong " + key)
    _need(receipt.get("LTO") is True, "LTO must be literal true")
    for key, expected in (("TranslationUnits", 9), ("SlimIRObjects", 8)):
        _need(type(receipt.get(key)) is int and receipt[key] == expected, "literal " + key)
    rows = receipt.get("Sources")
    _need(type(rows) is list and len(rows) == 9, "exact ordered nine source records required")
    path = _ordinary._core._path
    root, capture = path(source_root), path(capture_root)
    _need(root.endswith("/source"), "source_root must end in /source")
    _need(not root.casefold().startswith(capture.casefold() + "/")
          and not capture.casefold().startswith(root.casefold() + "/")
          and root.casefold() != capture.casefold(), "source/capture roots overlap")
    declared = _input_hashes(receipt.get("InputHashes"))
    bound, external = [], {}
    for index, (relative, row) in enumerate(zip(source_order(), rows)):
        _need(type(row) is dict, "source row must be an object")
        source = root + "/" + relative
        digest = _sha(sources[relative])
        _need(path(row.get("Source")) == source, "source order/path mismatch")
        _need(_ordinary._core._hash(row.get("SourceSha256")) == digest, "source hash mismatch")
        stem = relative.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        obj = capture + "/objects/" + format(index, "02d") + "-" + stem + ".o"
        dep = obj[:-2] + ".d"
        _need(path(row.get("Object")) == obj and path(row.get("DependencyFile")) == dep,
              "capture object/dependency index/path mismatch")
        object_hash = _ordinary._core._hash(row.get("ObjectSha256"))
        _need(row.get("SlimIR") is (index != 8), "eight declared slim C inputs and native startup required")
        flags = _flags(row.get("CompileFlags"))
        _need(flags == _expected_flags(root, index, relative), "fixed CM3/O2-lto compile flag recipe")
        _need(row.get("CompileDependenciesVerified") is True, "dependencies not declared verified")
        actual = _ordinary._core._dependencies(row.get("ActualCompileDependencies"))
        if "Dependencies" in row:
            _need(_ordinary._core._dependencies(row["Dependencies"]) == actual,
                  "optional declared/actual dependency records differ")
        _need(actual.get(source) == digest, "own source actual dependency missing/different")
        captured = []
        for name, dependency_hash in actual.items():
            _need(declared.get(name) == dependency_hash, "actual dependency not equal to declared capture input")
            if name.casefold().startswith(root.casefold() + "/"):
                _need(name.startswith(root + "/"), "case-aliased project dependency root")
                relative_name = name[len(root) + 1:]
                _need(relative_name in sources and _sha(sources[relative_name]) == dependency_hash,
                      "captured project dependency bytes missing/different: " + relative_name)
                captured.append(relative_name)
            else:
                _need(name not in external or external[name] == dependency_hash, "external dependency hash conflict")
                external[name] = dependency_hash
        mandatory = {relative}
        if index <= 4:
            mandatory.update(("context/context_port_abi.h", "context/context_api_attributes.h",
                              "context/context_api_types.h", "fiber/fiber_api_attributes.h"))
        if index in (0, 1, 3, 4):
            mandatory.add("context/context_runtime_port_abi.h")
        _need(mandatory <= set(captured), "canonical provider header dependency missing")
        bound.append(dict(ObjectIndex=index, Source=relative, Object=obj, DependencyFile=dep,
                          DeclaredObjectSha256=object_hash, DeclaredSlimIR=index != 8,
                          CompileFlags=flags, Dependencies=sorted(captured)))
    return dict(_metadata(), ReceiptSha256=_sha(receipt_bytes), SourceInspection=inspection,
                DeclaredProviderDependenciesBound=True, DeclaredDependencyAuthority="CAPTURE_INPUT_HASHES",
                SeedDiscoveryDependencySetCompared=False, SourceRoot=root, CaptureRoot=capture,
                Providers=bound, UnverifiedExternalDependencies=[dict(Path=name, Sha256=digest)
                    for name, digest in sorted(external.items())], Scope=_ordinary._core._scope())
