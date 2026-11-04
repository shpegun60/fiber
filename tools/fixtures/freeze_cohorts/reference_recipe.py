"""Pure pinned-FreeRTOS native-object recipes; no I/O or process execution.

The caller validates the authoritative manifest and captures/pin-checks all
sources, headers, and the copied freeze_base_FreeRTOSConfig.h. Relative output
paths are kernel-relative. ExtraIncludes contains kernel paths only; an external
TF-M include root appears in Flags, never disguised as a kernel provider.
ExactTargetRecipe means unchanged target compiler flags, not policy, assembly,
runtime, ABI-layout, or global-freeze equivalence.
"""
from pathlib import Path
import re


OBJECT_MODES = ("O0", "Og", "O2", "Os", "O3")
_PORTS = {
    "CM0": "ARM_CM0", "CM0MPU": "ARM_CM0",
    "CM3": "ARM_CM3", "CM3MPU": "ARM_CM3_MPU",
    "CM4": "ARM_CM4F", "CM7": "ARM_CM7/r0p1", "CM4MPU": "ARM_CM4_MPU",
    "CM23NTZ": "ARM_CM23_NTZ/non_secure",
    "C3FP": "ARM_CM33_NTZ/non_secure", "C3SO": "ARM_CM33_NTZ/non_secure",
    "CM33NTZ": "ARM_CM33_NTZ/non_secure", "CM33FNTZ": "ARM_CM33_NTZ/non_secure",
    "CM33TFM": "ARM_CM33_NTZ/non_secure", "CM33FTFM": "ARM_CM33_NTZ/non_secure",
    "CM33MPU": "ARM_CM33_NTZ/non_secure",
    "CM55NTZ": "ARM_CM55_NTZ/non_secure", "CM55FNTZ": "ARM_CM55_NTZ/non_secure",
    "CM55MVEFNTZ": "ARM_CM55_NTZ/non_secure", "CM55MPU": "ARM_CM55_NTZ/non_secure",
    "CM55FMPU": "ARM_CM55_NTZ/non_secure", "CM55MVEFMPU": "ARM_CM55_NTZ/non_secure",
    "C5SO": "ARM_CM55_NTZ/non_secure", "C5TF": "ARM_CM55_NTZ/non_secure",
    "C33S": "ARM_CM33/non_secure", "C55S": "ARM_CM55/non_secure",
    "C33S_GATEWAY": "ARM_CM33/secure", "C55S_GATEWAY": "ARM_CM55/secure",
}
_GATEWAYS = {"C33S_GATEWAY", "C55S_GATEWAY"}
_TFM = {"C5TF", "CM33TFM", "CM33FTFM"}
_SECURE_EXTRAS = {
    "C33S": "portable/GCC/ARM_CM33/secure",
    "C55S": "portable/GCC/ARM_CM55/secure",
}
_TFM_SOURCE = "portable/ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c"
_TARGET_FLAG = re.compile(
    r"-m(?:cpu=[A-Za-z0-9_+.-]+|fpu=[A-Za-z0-9_+.-]+|float-abi=(?:soft|softfp|hard)|"
    r"thumb|cmse|single-pic-base|pic-register=r9)\Z"
)
_C_FLAGS = (
    "-std=gnu11", "-g0", "-ffreestanding", "-ffunction-sections", "-fdata-sections",
    "-Wall", "-Wextra", "-Werror=implicit-function-declaration", "-Werror=attributes",
    "-Werror=ignored-attributes",
)
_PRIORITIES = ("configMAX_SYSCALL_INTERRUPT_PRIORITY", "configMAX_API_CALL_INTERRUPT_PRIORITY")


def _need(condition, reason):
    if not condition:
        raise RuntimeError("freeze-reference-recipe: " + reason)


def _path(value):
    _need(isinstance(value, (str, Path)) and bool(str(value)) and
          not any(c in str(value) for c in "\r\n\0"), "include-path")
    return Path(value)


def _sources(group):
    directory = "portable/GCC/" + _PORTS[group]
    if group in _GATEWAYS:
        names = ("secure_context.c", "secure_context_port.c", "secure_init.c", "secure_heap.c")
    elif _PORTS[group] in ("ARM_CM3", "ARM_CM3_MPU", "ARM_CM4F", "ARM_CM4_MPU", "ARM_CM7/r0p1"):
        names = ("port.c",)
    else:
        names = ("port.c", "portasm.c")
    result = [directory + "/" + name for name in names]
    if group in _TFM:
        result.append(_TFM_SOURCE)
    return result


def _target_flags(artifact):
    target, flags = artifact["target"], artifact["compile_flags"]
    _need(type(target) is dict and {
        "cpu", "architecture", "float_abi", "fpu_unit", "fpu_present", "fpu_used",
        "fp_stacking", "r9_abi", "nvic_priority_bits", "scheduler_basepri",
    } <= set(target), "missing-target-facts")
    _need(type(target["cpu"]) is str and target["float_abi"] in ("soft", "softfp", "hard") and
          type(target["fpu_unit"]) is str, "target-flags")
    _need(type(flags) is list and flags and all(type(f) is str for f in flags), "compile-flags")
    _need(len(flags) == len(set(flags)), "duplicate-compile-flag")
    _need(all(_TARGET_FLAG.fullmatch(f) or f in ("-ffixed-r9", "-fpic") for f in flags),
          "non-target-compile-flag")
    for prefix, expected in (("-mcpu=", target["cpu"]), ("-mfloat-abi=", target["float_abi"])):
        _need([f for f in flags if f.startswith(prefix)] == [prefix + expected], "compile-target-binding")
    _need("-mthumb" in flags, "thumb-required")
    _need([f for f in flags if f.startswith("-mfpu=")] ==
          (["-mfpu=" + target["fpu_unit"]] if target["fpu_unit"] else []), "compile-fpu-binding")
    _need(target["r9_abi"] in ("aapcs", "fixed-r9") and
          ("-ffixed-r9" in flags) == (target["r9_abi"] == "fixed-r9"), "compile-r9-binding")
    _need(type(target["fpu_present"]) is bool and type(target["fpu_used"]) is bool and
          (not target["fpu_used"] or target["fpu_present"]), "target-fpu-facts")
    _need(target["fp_stacking"] in ("none", "eager", "lazy") and
          (target["fp_stacking"] != "none") == target["fpu_used"], "target-fp-stacking")
    _need((target["float_abi"] != "soft") == target["fpu_used"], "target-float-use")
    return list(flags)


def _threshold(artifact):
    target = artifact["target"]
    value, bits = target["scheduler_basepri"], target["nvic_priority_bits"]
    _need(type(value) is int and 0 <= value <= 255 and type(bits) is int and 2 <= bits <= 8,
          "target-threshold")
    if artifact["role"] == "secure_companion":
        _need(value == 0, "companion-threshold-not-applicable")
        return 0, "secure-companion-no-scheduler"
    if target["architecture"] in ("ARMV6M", "ARMV8M_BASELINE"):
        _need(value == 0, "baseline-threshold-not-applicable")
        return 0, "baseline-primask"
    _need(target["architecture"] in ("ARMV7M", "ARMV7EM", "ARMV8M_MAINLINE", "ARMV81M_MAINLINE"),
          "target-architecture")
    _need(value != 0 and value % (1 << (8 - bits)) == 0, "basepri-alignment")
    return value, None


def _companion_count(artifact):
    group = artifact["source_group_id"]
    if group not in _GATEWAYS:
        return None
    name = "FIBER_ARM_CM%s_SECURE_CONTEXT_MAX_COUNT" % ("33" if group == "C33S_GATEWAY" else "55")
    defines = artifact.get("defines", {})
    _need(type(defines) is dict, "fiber-defines-object")
    value = defines.get(name)
    _need(type(value) is str and re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)[uU]?", value),
          "companion-count-binding")
    number = value.rstrip("uU")
    _need(int(number, 16 if number.lower().startswith("0x") else 10) == 3, "companion-count-binding")
    return 3


def reference_recipe(artifact, mode, fixture_dir, freertos, tfm_include=None) -> dict:
    """Return exactly Flags, ConfigText, PortmacroProvider, ExtraIncludes,
    Differences, WitnessKind, ExactTargetRecipe, without touching the filesystem.

    The caller copies the pinned base config to fixture_dir/
    freeze_base_FreeRTOSConfig.h and writes ConfigText as FreeRTOSConfig.h.
    tfm_include is an already pinned/captured TF-M interface include root, accepted
    only for C5TF/CM33TFM/CM33FTFM. Missing providers are errors, not stub requests.
    Soft CM4/CM7 use their same declared FP port with softfp plus a physical FPU
    witness; this never satisfies the original exact soft ABI/FPU-target cell.
    """
    _need(type(mode) is str and mode in OBJECT_MODES, "native-object-mode")
    _need(type(artifact) is dict and {
        "source_group_id", "role", "target", "compile_flags", "upstream_sources", "upstream_defines",
    } <= set(artifact), "missing-artifact-fields")
    group = artifact["source_group_id"]
    _need(type(group) is str and group in _PORTS, "unknown-source-group")
    role = artifact["role"]
    _need(role == ("secure_companion" if group in _GATEWAYS else "runtime"), "profile-role-binding")
    sources = artifact["upstream_sources"]
    _need(type(sources) is list and all(type(s) is str for s in sources) and
          len(sources) == len(set(sources)) and set(sources) == set(_sources(group)),
          "upstream-source-binding")
    flags = _target_flags(artifact)
    threshold, not_applicable = _threshold(artifact)
    count = _companion_count(artifact)
    definitions = artifact["upstream_defines"]
    _need(type(definitions) is dict, "upstream-defines-object")
    for name, value in definitions.items():
        _need(type(name) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name), "define-name")
        _need(type(value) is str and all(32 <= ord(c) < 127 for c in value), "define-string-value")
        _need(name not in (*_PRIORITIES, "secureconfigMAX_SECURE_CONTEXTS"), "reserved-config-define")
    fixture, kernel = _path(fixture_dir), _path(freertos)
    _need((tfm_include is not None) == (group in _TFM),
          "missing-pinned-tfm-include" if group in _TFM else "unexpected-tfm-include")
    external = _path(tfm_include) if tfm_include is not None else None
    directory = "portable/GCC/" + _PORTS[group]
    provider = None if group in _GATEWAYS else directory + "/portmacro.h"
    extras = [directory] if group in _GATEWAYS else ([_SECURE_EXTRAS[group]] if group in _SECURE_EXTRAS else [])
    includes = [fixture, kernel / "include"]
    if provider is not None:
        includes.append(kernel / directory)
    includes.extend(kernel / path for path in extras)
    if external is not None:
        includes.append(external)

    differences = []
    witness = "none"
    target = artifact["target"]
    if group in ("CM4", "CM7") and target["float_abi"] == "soft":
        _need(target["cpu"] == ("cortex-m4" if group == "CM4" else "cortex-m7"), "soft-witness-cpu")
        unit = "fpv4-sp-d16" if group == "CM4" else "fpv5-d16"
        flags = [item for flag in flags for item in
                 (["-mfpu=" + unit, "-mfloat-abi=softfp"] if flag == "-mfloat-abi=soft" else [flag])]
        witness = "soft-abi-fp-port-softfp"
        differences.append({
            "Kind": "soft-abi-fp-port-witness", "Scope": "witness-only-native-object",
            "DeclaredFloatAbi": "soft", "ReferenceFloatAbi": "softfp", "ReferenceFpu": unit,
            "DeclaredFpuPresent": target["fpu_present"], "DeclaredFpuUsed": False,
            "ReferenceUsesFpu": True, "ReferenceFPCCR": {"ASPEN": 1, "LSPEN": 1},
            "ExcludedClaims": ["exact-abi", "exact-fpu-target", "fp-policy-equivalence", "assembly-parity", "runtime-parity"],
        })
    if target["fp_stacking"] == "eager":
        differences.append({
            "Kind": "fpccr-eager-vs-lazy", "Scope": "native-object-only-no-policy-equivalence",
            "FiberPolicy": "eager", "ReferenceFPCCR": {"ASPEN": 1, "LSPEN": 1},
        })
    if not_applicable is not None:
        differences.append({"Kind": "threshold-not-applicable", "Reason": not_applicable, "ConfigLiteral": 0})
    elif threshold != 128:
        differences.append({"Kind": "threshold-config-binding", "FixtureDefault": 128, "Reference": threshold})
    if count is not None:
        differences.append({"Kind": "secure-context-count-binding", "UpstreamDefault": 8, "Fiber": count, "Reference": count})
    lines = ["#ifndef FIBER_FREEZE_REFERENCE_CONFIG_H", "#define FIBER_FREEZE_REFERENCE_CONFIG_H",
             '#include "freeze_base_FreeRTOSConfig.h"']
    for name in _PRIORITIES:
        lines.extend(("#undef " + name, "#define %s %dU" % (name, threshold)))
    if count is not None:
        lines.extend(("#undef secureconfigMAX_SECURE_CONTEXTS", "#define secureconfigMAX_SECURE_CONTEXTS 3U"))
    lines.extend(("#endif", ""))
    return {
        "Flags": [*flags, "-" + mode, *_C_FLAGS,
                  *("-D" + name + "=" + definitions[name] for name in sorted(definitions)),
                  *("-I" + str(path) for path in includes)],
        "ConfigText": "\n".join(lines), "PortmacroProvider": provider, "ExtraIncludes": extras,
        "Differences": differences, "WitnessKind": witness, "ExactTargetRecipe": witness == "none",
    }
