"""Pure declaration probes for six fixed native ordinary profile contracts.

The pinned CM0 helper supplies the independent C type oracle and bounded CPP
scanner, not receipt authority. Its globals and qualified files are unchanged.
Project source expectations below come from the E9 captured source inventory,
not a receipt being inspected. Public functions consume caller-admitted bytes
and perform no I/O. Loading this module authenticates one frozen helper buffer.

Profiles are exact uppercase strings. ABI declarations do not depend on an
optimization mode; receipt inspection admits only the five ordinary modes.
Exact CPU/FPU-unit flags, accepted compiler attempts, actual object definitions,
dependencies and closing seals remain outer obligations. Macro guards do not
prove an exact microcontroller or attribute effects. No function grants credit.
"""

import copy
import hashlib
import json
from pathlib import Path
import types


CORE_SHA256 = "F5AA5CE6BD21130249D571D0AA03BD72C735DA04832C2B6DBF13EFD548CB4F4B"
INVENTORY_SHA256 = "69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313"
INVENTORY_MANIFEST_SHA256 = "BC6B8EADABCAA6637FDD121D03B5CA341EEE31848D7E007D1D027AEE63EC8CBE"
MODES = ("O0", "Og", "O2", "Os", "O3")
PROFILES = ("CM0", "CM0PLUS", "CM0PLUSVTOR", "CM3", "CM4", "CM7")


def _load_core():
    path = Path(__file__).resolve().parents[1] / "cm0_final_cell" / "abi.py"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest().upper() != CORE_SHA256:
        raise ValueError("ordinary-cell-abi: frozen CM0 helper source identity")
    module = types.ModuleType("_ordinary_cell_frozen_cm0_abi")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


_core = _load_core()
Rejected = _core.Rejected
SLOT = _core.SLOT
FORWARD = _core.FORWARD
REVERSE = _core.REVERSE
ATTRIBUTE_QUERIES = _core.ATTRIBUTE_QUERIES
UNPROVEN_ATTRIBUTES = _core.UNPROVEN_ATTRIBUTES

# Profile, cohort, group, architecture, float ABI, FPU unit, VTOR, priority bits,
# BASEPRI. These exact tuples occur in the pinned E9 manifest.
_PROFILE_ROWS = (
    ("CM0", "cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default",
     "CM0", "ARMV6M", "soft", "", False, 2, 0),
    ("CM0PLUS", "cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default",
     "CM0", "ARMV6M", "soft", "", False, 2, 0),
    ("CM0PLUSVTOR", "cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default",
     "CM0", "ARMV6M", "soft", "", True, 2, 0),
    ("CM3", "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default",
     "CM3", "ARMV7M", "soft", "", True, 4, 16),
    ("CM4", "cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default",
     "CM4", "ARMV7EM", "hard", "fpv4-sp-d16", True, 4, 16),
    ("CM7", "cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default",
     "CM7", "ARMV7EM", "hard", "fpv5-d16", True, 4, 16),
)

# Raw hashes are copied from E9 capture.json source bindings. The common nine
# headers and six non-port sources are already fixed by the frozen CM0 helper.
_PORT_PINS = (
    ("CM0", "ARM_CM0", (
        "DEEFD31BB1A26A3BB94D8B36B47AC983BD52168B630885E89A01E2821E287FB3",
        "22275EFF60D0C2D424EF4648132EDD1EC996CCD079181C566F579C1BF86E9C42",
        "4A4443A36151988EA2DC0EF0E19BAE5B9F360054C41FEBF5A2A1C9EEB11EEBCC")),
    ("CM3", "ARM_CM3", (
        "5A505807BE048B7EE84BC16DC644A90473B41D29296811C6E5494CE9793E9D45",
        "7D1D115F507F6267C2A50F2E4C4BA3327DC9BF943034B648A0B399609486F265",
        "048F134C09D27CBBF5FE1539E483481B1F364F42D372CC9962E1B2E3B37BA284")),
    ("CM4", "ARM_CM4", (
        "FBEC06226D2D3D3B683B3C6B69F937C5FB3CE2D6311F915116F5B9290E4DBA6C",
        "F8B22118D7E134A62FC526C294DFAB8C73C82699C3C42B19478A59A30A265030",
        "92C98D141F7FD4BDE77EAAC9E2B9A17A1E437F9A6439965C7B5CD8B9411B126F")),
    ("CM7", "ARM_CM7/r0p1", (
        "B21EE4327D9B7132ECD8B76964968C0E43E73EBDB12DDBC2AB3FB55FCB7EFC38",
        "5855ACD3CE1457E8DA912039C37F2381B2DADEE3DABC71F89C3DC709306EFD71",
        "FB6F72886BF5AF34AB30F405783ED01377498C5AA690950D84B10F5A86DCF959")),
)


def _need(condition, message):
    if not condition:
        raise Rejected("ordinary-cell-abi: " + message)


def _sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def profile_contract(profile):
    """Return fresh fixed facts, never accept caller-supplied target contracts."""
    _need(type(profile) is str and profile in PROFILES, "unknown/ill-typed profile")
    row = next(row for row in _PROFILE_ROWS if row[0] == profile)
    _, cohort, group, arch, abi, fpu, vtor, priorities, basepri = row
    return {"Profile": profile, "Cohort": cohort, "SourceGroup": group,
            "Architecture": arch, "FloatABI": abi, "FpuUnit": fpu,
            "FPStacking": "eager" if fpu else "none", "VTOR": vtor,
            "NVICPriorityBits": priorities, "SchedulerBASEPRI": basepri,
            "Linkage": "direct", "AllowedModes": list(MODES),
            "SourceInventorySha256": INVENTORY_SHA256,
            "InventoryManifestSha256": INVENTORY_MANIFEST_SHA256}


def source_order(profile):
    facts = profile_contract(profile)
    directory = next(row[1] for row in _PORT_PINS if row[0] == facts["SourceGroup"])
    selected = tuple("fiber/port/" + directory + "/" + name for name in (
        "fiber_port.c", "fiber_port_boot.c", "fiber_port_exception.c"))
    return _core.SOURCE_ORDER[:3] + selected + _core.SOURCE_ORDER[6:]


def source_hashes(profile):
    """Fixed raw expectations, not hashes learned from supplied source bytes."""
    facts = profile_contract(profile)
    order = source_order(profile)
    port_hashes = next(row[2] for row in _PORT_PINS if row[0] == facts["SourceGroup"])
    common = tuple((path, digest) for path, digest in _core.SOURCE_HASHES
                   if path not in _core.SOURCE_ORDER[3:6])
    return common + tuple(zip(order[3:6], port_hashes))


def _metadata(profile):
    facts = profile_contract(profile)
    return {"Profile": profile, "Cohort": facts["Cohort"], "Linkage": "direct",
            "AllowedModes": list(MODES), "TargetContract": facts}


def _target_guard(profile):
    facts = profile_contract(profile)
    arch = {"ARMV6M": "6M", "ARMV7M": "7M", "ARMV7EM": "7EM"}[facts["Architecture"]]
    other = [name for name in ("6M", "7M", "7EM") if name != arch]
    condition = ["!defined(__ARM_ARCH_" + arch + "__)", "!defined(__thumb__)"]
    condition.extend("defined(__ARM_ARCH_" + name + "__)" for name in other)
    if facts["FloatABI"] == "soft":
        condition.extend(("defined(__ARM_PCS_VFP)", "defined(__ARM_FP)"))
    else:
        condition.extend(("!defined(__ARM_PCS_VFP)", "defined(__SOFTFP__)",
                          "!defined(__ARM_FP)", "((__ARM_FP & 4) != 4)"))
        # Single-only versus single+double is observable; exact unit selection
        # additionally needs the outer fixed -mfpu flag and ELF attributes.
        condition.append("((__ARM_FP & 8) != " + ("8" if profile == "CM7" else "0") + ")")
    return ("#if !defined(__GNUC__) || defined(__clang__) || __GNUC__ != 14\n"
            "#error ORDINARY_ABI_requires_GCC_14\n#endif\n#if "
            + " || ".join(condition)
            + "\n#error ORDINARY_ABI_requires_" + profile + "_target_contract\n#endif\n"
            '_Static_assert(sizeof(void *) == 4, "ORDINARY_ABI_pointer_width");\n'
            '_Static_assert(FIBER_RUNTIME_PORT_ABI_VERSION == 1u, "ORDINARY_ABI_reverse_version");\n')


def emit_probes(profile):
    """Emit the same five independent typed/attribute/absent-slot C probes.

    No type is inferred from an observed header. Noreturn-qualified expected
    pointers and the ten supported GCC reflection forms are unchanged. GCC14's
    no_sanitize query ICE is not bypassed into bundle proof: accepted compile,
    the exact CPP declaration scan and same-attempt bindings remain required.
    Legacy cm0_abi C identifiers intentionally name the shared frozen oracle.
    """
    metadata = _metadata(profile)
    probes = _core.emit_probes()
    for name, record in probes.items():
        if name in ("types.c", "attributes.c"):
            _need(record["Source"].count(_core._TARGET) == 1, "frozen oracle guard boundary")
            record["Source"] = record["Source"].replace(_core._TARGET, _target_guard(profile), 1)
            record["SourceSha256"] = _sha(record["Source"].encode("ascii"))
        record.update(copy.deepcopy(metadata))
        record["Scope"] = _core._scope()
    return probes


def inspect_sources(profile, sources):
    """Check eighteen E9/common source identities; extra captured files allowed."""
    metadata = _metadata(profile)
    _core._sources(sources)
    records = []
    for path, expected in source_hashes(profile):
        _need(path in sources, "missing source: " + path)
        actual = _sha(sources[path])
        _need(actual == expected, "raw source identity mismatch: " + path)
        records.append({"Path": path, "Sha256": actual})
    order = source_order(profile)
    owners = [{"Name": name, "Direction": direction, "ObjectIndex": index,
               "Source": order[index], "NoReturn": noreturn}
              for direction, rows in (("forward", FORWARD), ("reverse", REVERSE))
              for name, _, index, noreturn in rows]
    return dict(metadata, RawSourceIdentitiesChecked=True, Sources=records,
                ExpectedOwners=owners, Scope=_core._scope())


def inspect_preprocessed_attributes(profile, preprocessed_bytes):
    """Scan unchanged common declarations, retaining full claimed header origins.

    A marker is not authentication. Original header bytes, accepted compile,
    discovery/actual dependencies and reflection checks must be bound outside.
    No mode is inferred from CPP text, and no CM0 receipt result is reused.
    """
    metadata = _metadata(profile)
    record = _core.inspect_preprocessed_attributes(preprocessed_bytes)
    del record["Mode"]
    record.update(metadata)
    return record


def inspect_provider_dependencies(profile, sources, receipt_bytes, *, source_root):
    """Bind one exact ordinary native declaration-provider dependency receipt.

    Supplied source bytes are checked against fixed E9 pins, not receipt status.
    Object/external dependency bytes are absent here and are explicitly unproved.
    Outer admission must bind the returned Mode to its requested cell, as well
    as commands, ELF origins, external bytes, immutable input and closing seals.
    """
    inspection = inspect_sources(profile, sources)
    facts = profile_contract(profile)
    _need(type(receipt_bytes) is bytes, "receipt must be authenticated bytes")
    try:
        receipt = json.loads(receipt_bytes.decode("utf-8"), object_pairs_hook=_core._object,
                             parse_constant=lambda value: _need(False, "nonfinite JSON: " + value))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejected("ordinary-cell-abi: invalid receipt JSON") from error
    _need(type(receipt) is dict, "receipt must be an object")
    for key, expected in (("Profile", profile), ("Cohort", facts["Cohort"]),
                          ("Linkage", "direct"), ("SourceInventorySha256", INVENTORY_SHA256)):
        _need(type(receipt.get(key)) is str and receipt[key] == expected, "wrong " + key)
    mode = receipt.get("Mode")
    _need(type(mode) is str and mode in MODES, "wrong ordinary mode")
    _need(receipt.get("LTO") is False, "LTO must be false")
    _need(type(receipt.get("TranslationUnits")) is int and receipt["TranslationUnits"] == 9,
          "translation unit count must be integer nine")
    records = receipt.get("Sources")
    _need(type(records) is list and len(records) == 9, "exact ordered nine sources required")
    root = _core._path(source_root)
    _need(root.endswith("/source"), "source_root must end in /source")
    native_root = root[:-7]
    bound, external = [], {}
    for index, (relative, row) in enumerate(zip(source_order(profile), records)):
        _need(type(row) is dict, "source record must be an object")
        source = root + "/" + relative
        _need(_core._path(row.get("Source")) == source, "source order/path mismatch")
        _need(_core._hash(row.get("SourceSha256")) == _sha(sources[relative]), "source hash mismatch")
        stem = relative.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        obj = native_root + "/objects/" + format(index, "02d") + "-" + stem + ".o"
        _need(_core._path(row.get("Object")) == obj, "object index/path mismatch")
        object_hash = _core._hash(row.get("ObjectSha256"))
        _need(row.get("CompileDependenciesVerified") is True, "dependencies not declared verified")
        declared = _core._dependencies(row.get("Dependencies"))
        actual = _core._dependencies(row.get("ActualCompileDependencies"))
        _need(declared == actual, "declared/actual dependency records differ")
        _need(actual.get(source) == _sha(sources[relative]), "own source dependency missing")
        captured = []
        for path, digest in actual.items():
            if path.casefold().startswith(root.casefold() + "/"):
                _need(path.startswith(root + "/"), "case-aliased dependency root")
                name = path[len(root) + 1:]
                _need(name in sources and _sha(sources[name]) == digest,
                      "captured dependency bytes missing/different: " + name)
                captured.append(name)
            else:
                _need(path not in external or external[path] == digest, "external hash conflict")
                external[path] = digest
        mandatory = {relative}
        if index in (0, 1, 2, 3, 4):
            mandatory.update(("context/context_port_abi.h", "context/context_api_attributes.h",
                              "context/context_api_types.h", "fiber/fiber_api_attributes.h"))
        if index in (0, 1, 3, 4):
            mandatory.add("context/context_runtime_port_abi.h")
        _need(mandatory <= set(captured), "canonical provider header dependency missing")
        bound.append({"ObjectIndex": index, "Source": relative, "Object": obj,
                      "DeclaredObjectSha256": object_hash, "Dependencies": sorted(captured)})
    return dict(_metadata(profile), Mode=mode, ReceiptSha256=_sha(receipt_bytes),
                SourceInspection=inspection, DeclaredProviderDependenciesBound=True,
                Providers=bound, UnverifiedExternalDependencies=[
                    {"Path": path, "Sha256": digest} for path, digest in sorted(external.items())],
                Scope=_core._scope())
