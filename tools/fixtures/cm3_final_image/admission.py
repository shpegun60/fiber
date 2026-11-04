"""Fixed CM3 native cohort/attribute checks; no files, tools or target execution.

The caller authenticates inventory bytes and selects the unique cohort and
source-group rows. This helper checks the complete artifact, not inventory
provenance, compiler identity, final ELF semantics or runtime equivalence.
"""
import re


COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
SOURCE_GROUP = "CM3"
SOURCES = ("fiber/port/ARM_CM3/fiber_port.c", "fiber/port/ARM_CM3/fiber_port_boot.c",
           "fiber/port/ARM_CM3/fiber_port_exception.c")
_ARTIFACT = dict(
    role="runtime", source_group_id="CM3", abi_contract="forward8",
    target=dict(cpu="cortex-m3", architecture="ARMV7M", float_abi="soft", fpu_present=False,
        fpu_used=False, fpu_unit="", fp_stacking="none", vtor=True, mpu_regions=0, security_role="classic",
        psplim_slot=False, psplim_register=False, mve="none", pac=False, bti=False, errata_policy="none",
        r9_abi="aapcs", nvic_priority_bits=4, scheduler_basepri=16),
    compile_flags=["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft"],
    defines=dict(FIBER_PORT_ARMV7M="1", FIBER_PORT_BUILD_SELECTED="1", FIBER_SCHEDULER_BASEPRI="16"),
    upstream_sources=["portable/GCC/ARM_CM3/port.c"],
    upstream_defines=dict(FIBER_FREERTOS_PARITY_ENABLE_MPU="0", FIBER_FREERTOS_PARITY_ENABLE_FPU="0",
                          FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE="0"))
_ATTRIBUTES = {"Tag_CPU_name": '"7-M"', "Tag_CPU_arch": "v7",
               "Tag_CPU_arch_profile": "Microcontroller", "Tag_THUMB_ISA_use": "Thumb-2"}
_FORBIDDEN = frozenset(name.casefold() for name in (
    "Tag_FP_arch", "Tag_ABI_HardFP_use", "Tag_MVE_arch", "Tag_Advanced_SIMD_arch", "Tag_ABI_VFP_args",
    "Tag_PAC_extension", "Tag_BTI_extension"))


class Rejected(ValueError):
    pass


def _need(condition, detail):
    if not condition:
        raise Rejected("cm3-final-admission: " + detail)


def _same(actual, expected):
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return all(type(key) is str for key in actual) and set(actual) == set(expected) and all(
            _same(actual[key], value) for key, value in expected.items())
    if type(expected) is list:
        return len(actual) == len(expected) and all(_same(left, right) for left, right in zip(actual, expected))
    return actual == expected


def require_cohort(artifact, identity=COHORT) -> None:
    """Require the single p4/b16 soft/no-FP/VTOR1 ordinary-AAPCS artifact."""
    _need(type(identity) is str and identity == COHORT, "exact cohort identity required")
    _need(type(artifact) is dict and all(type(key) is str for key in artifact)
          and set(artifact) == set(_ARTIFACT), "exact artifact fields required")
    for field, expected in _ARTIFACT.items():
        _need(_same(artifact[field], expected), "exact artifact " + field + " required")


def require_attributes(text) -> None:
    """Apply freeze_cm3_mechanisms.require_cm3_attributes' fixed CM3 contract.

    Ordinary unrelated ABI tags remain allowed. Malformed, duplicate or
    case-aliased Tag records fail closed; FP/MVE/SIMD/PAC/BTI tags are forbidden.
    Attributes alone do not establish the source, CPU execution or mode.
    """
    _need(type(text) is str and "\0" not in text, "attribute text required")
    fields, names = {}, set()
    for line in text.splitlines():
        if not line.lstrip().casefold().startswith("tag_"):
            continue
        match = re.fullmatch(r"\s*(Tag_[A-Za-z0-9_]+):[^\S\r\n]*(.*?)\s*", line)
        _need(match is not None, "malformed attribute record")
        name, value = match.groups()
        key = name.casefold()
        _need(key not in names, "duplicate/case-aliased attribute")
        names.add(key)
        _need(key not in _FORBIDDEN, "forbidden FP/MVE/SIMD/PAC/BTI attribute")
        fields[name] = value
    _need(all(fields.get(name) == value for name, value in _ATTRIBUTES.items()), "exact CM3 codegen attributes required")
