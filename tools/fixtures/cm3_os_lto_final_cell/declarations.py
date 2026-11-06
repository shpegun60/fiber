"""Pure CM3 Os-lto/direct declaration and provider-record predicates.

The caller supplies the authenticated ordinary ABI helper and source buffers.
Only its mode-neutral CM3 type oracle, source pins, CPP scanner and structural
validators are reused. Neither ordinary nor O2-lto receipt admission is called.
No helper is loaded here, no globals are changed, and no function performs I/O.

Provider flags are compared with a fixed recipe, not inferred from a receipt:
the ordinary O2 seed changes its sole optimization to Os, and the eight C inputs
add the two slim-LTO flags. Startup remains a native input. Dependency hashes
bind declarations and supplied project bytes only. Authenticated capture/seed,
compiler attempts, external bytes, actual objects and closing seals are caller
obligations. No declaration check proves attribute effects or earns cell credit.
"""

import copy
import hashlib
import json


ORDINARY_SHA256 = "43F2E49D638D0E586A24AD2B32D0B8D86C58CC9A63E134EF6AF064437278CAE5"
MODE = "Os-lto"
ADAPTER_SCOPE = "NATIVE_CURRENT_CM3_OS_LTO_DIRECT_DECLARATION_PROVIDER_ADMISSION_ONLY"


class Rejected(ValueError):
    pass


def _need(condition, message):
    if not condition:
        raise Rejected("cm3-os-lto-declarations: " + message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def profile_contract(*, ordinary):
    """Compose fresh Os facts from the mode-neutral, fixed CM3 target facts."""
    facts = copy.deepcopy(ordinary.profile_contract("CM3"))
    facts.update(Mode=MODE, AllowedModes=[MODE], LTO=True)
    return facts


def source_order(*, ordinary):
    return tuple(ordinary.source_order("CM3"))


def source_hashes(*, ordinary):
    return tuple(ordinary.source_hashes("CM3"))


def _metadata(ordinary):
    facts = profile_contract(ordinary=ordinary)
    return dict(Profile="CM3", Cohort=facts["Cohort"], Mode=MODE, Linkage="direct",
                LTO=True, AllowedModes=[MODE], TargetContract=facts, AdapterScope=ADAPTER_SCOPE)


def _decorate(record, ordinary):
    result = copy.deepcopy(record)
    result.update(_metadata(ordinary))
    return result


def emit_probes(*, ordinary):
    """Return unchanged CM3 oracle bytes: two accepts, three absent-slot probes.

    Their declarations are mode-neutral. GCC14 no_sanitize reflection remains
    unsupported; the same-attempt CPP scanner and accepted compile are required.
    The inherited probe C names are intentionally unchanged.
    """
    return {name: _decorate(row, ordinary) for name, row in ordinary.emit_probes("CM3").items()}


def inspect_sources(sources, *, ordinary):
    """Check the independent eighteen raw E9 CM3 source/header identities."""
    return _decorate(ordinary.inspect_sources("CM3", sources), ordinary)


def inspect_preprocessed_attributes(raw, *, ordinary):
    """Scan the twelve canonical declarations, without inferring CPP authority."""
    return _decorate(ordinary.inspect_preprocessed_attributes("CM3", raw), ordinary)


def _parse(raw, ordinary):
    _need(type(raw) is bytes, "receipt must be authenticated bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=ordinary._core._object,
                           parse_constant=lambda item: _need(False, "nonfinite JSON: " + item))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejected("cm3-os-lto-declarations: invalid receipt JSON") from error
    _need(type(value) is dict, "receipt must be an object")
    return value


def _input_hashes(value, core):
    _need(type(value) is dict and value, "capture InputHashes declarations required")
    result, aliases = {}, set()
    for name, digest in value.items():
        name = core._path(name)
        _need(name.casefold() not in aliases, "duplicate/aliased declared input")
        aliases.add(name.casefold())
        result[name] = core._hash(digest)
    return result


def _flags(value, core):
    _need(type(value) is list and value and all(type(flag) is str for flag in value),
          "literal compile flags required")
    result, forced = [], False
    for flag in value:
        if forced:
            result.append(core._path(flag))
            forced = False
        elif flag == "-include":
            result.append(flag)
            forced = True
        elif flag.startswith("-I"):
            result.append("-I" + core._path(flag[2:]))
        else:
            result.append(flag)
    _need(not forced, "missing forced-include path")
    return result


def _seed_flags(root, index, relative):
    if index == 8:
        return ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-g0", "-DPILOT_HAS_VTOR=1"]
    includes = ("tools/fixtures/classic_final_image", "fiber/port/ARM_CM3", "fiber/port",
                "fiber", "context", "")
    return (["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2", "-std=gnu11", "-g0",
             "-ffreestanding", "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra",
             "-Werror=implicit-function-declaration", "-Werror=attributes", "-Werror=ignored-attributes",
             "-DFIBER_PORT_ARMV7M=1", "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_SCHEDULER_BASEPRI=16"]
            + ["-I" + root + ("/" + suffix if suffix else "") for suffix in includes]
            + ["-I" + root[:-7] + "/cmsis", "-include", root + "/tools/fixtures/classic_final_image/main.h",
               "-I" + root + "/" + relative.rsplit("/", 1)[0]])


def inspect_provider_dependencies(sources, receipt_bytes, *, source_root, capture_root, ordinary):
    """Bind the genuine Os nine-provider metadata, never qualify capture bytes.

    CompileFlags are not inferred from unvalidated seed flags. Both the seed
    recipe and actual compile recipe are independently checked. Actual compiler
    dependencies use the LTO schema and must equal capture InputHashes entries;
    project entries additionally bind supplied, pinned source bytes. The caller
    must still compare the seed discovery sets and authenticate external bytes.
    """
    inspection = inspect_sources(sources, ordinary=ordinary)
    receipt, core = _parse(receipt_bytes, ordinary), ordinary._core
    facts = profile_contract(ordinary=ordinary)
    for key, expected in (("Profile", "CM3"), ("Mode", MODE), ("SeedMode", "O2"),
                          ("Cohort", facts["Cohort"]), ("Linkage", "direct"),
                          ("SourceInventorySha256", facts["SourceInventorySha256"])):
        _need(type(receipt.get(key)) is str and receipt[key] == expected, "wrong " + key)
    _need(receipt.get("LTO") is True, "LTO must be literal true")
    for key, expected in (("TranslationUnits", 9), ("SlimIRObjects", 8)):
        _need(type(receipt.get(key)) is int and receipt[key] == expected, "literal " + key)
    rows = receipt.get("Sources")
    _need(type(rows) is list and len(rows) == 9, "exact ordered nine source records required")
    root, capture = core._path(source_root), core._path(capture_root)
    _need(root.endswith("/source"), "source_root must end in /source")
    _need(core._path(receipt.get("SeedBuild")) == root[:-7], "source root must belong to declared seed")
    _need(root.casefold() != capture.casefold()
          and not root.casefold().startswith(capture.casefold() + "/")
          and not capture.casefold().startswith(root.casefold() + "/"), "source/capture roots overlap")
    declared = _input_hashes(receipt.get("InputHashes"), core)
    bound, external = [], {}
    for index, (relative, row) in enumerate(zip(source_order(ordinary=ordinary), rows)):
        _need(type(row) is dict, "source row must be an object")
        source, digest = root + "/" + relative, _sha(sources[relative])
        _need(core._path(row.get("Source")) == source, "source order/path mismatch")
        _need(core._hash(row.get("SourceSha256")) == digest, "source hash mismatch")
        stem = relative.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        obj = capture + "/objects/" + format(index, "02d") + "-" + stem + ".o"
        dep = obj[:-2] + ".d"
        _need(core._path(row.get("Object")) == obj and core._path(row.get("DependencyFile")) == dep,
              "capture object/dependency index/path mismatch")
        object_hash = core._hash(row.get("ObjectSha256"))
        _need(row.get("SlimIR") is (index != 8), "eight declared slim C inputs and native startup required")
        seed_flags = _flags(row.get("SeedCompileFlags"), core)
        _need(seed_flags == _seed_flags(root, index, relative), "fixed ordinary O2 seed flag recipe")
        expected = ["-Os" if flag == "-O2" else flag for flag in seed_flags]
        if index != 8:
            expected += ["-flto", "-fno-fat-lto-objects"]
        flags = _flags(row.get("CompileFlags"), core)
        _need(flags == expected, "fixed CM3/Os-lto compile flag transform")
        _need(row.get("CompileDependenciesVerified") is True, "dependencies not declared verified")
        actual = core._dependencies(row.get("ActualCompileDependencies"))
        if "Dependencies" in row:
            _need(core._dependencies(row["Dependencies"]) == actual,
                  "optional declared/actual dependency records differ")
        _need(actual.get(source) == digest, "own source actual dependency missing/different")
        captured = []
        for name, dependency_hash in actual.items():
            _need(declared.get(name) == dependency_hash, "actual dependency differs from capture InputHashes")
            if name.casefold().startswith(root.casefold() + "/"):
                _need(name.startswith(root + "/"), "case-aliased project dependency root")
                suffix = name[len(root) + 1:]
                _need(suffix in sources and _sha(sources[suffix]) == dependency_hash,
                      "captured project dependency bytes missing/different: " + suffix)
                captured.append(suffix)
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
                          SeedCompileFlags=seed_flags, CompileFlags=flags, Dependencies=sorted(captured)))
    return dict(_metadata(ordinary), ReceiptSha256=_sha(receipt_bytes), SourceInspection=inspection,
                DeclaredProviderDependenciesBound=True, DeclaredDependencyAuthority="CAPTURE_INPUT_HASHES",
                SeedFlagsTransformVerified=True, SeedDiscoveryDependencySetCompared=False,
                SourceRoot=root, CaptureRoot=capture, Providers=bound,
                UnverifiedExternalDependencies=[dict(Path=name, Sha256=digest)
                    for name, digest in sorted(external.items())], Scope=ordinary._core._scope())
