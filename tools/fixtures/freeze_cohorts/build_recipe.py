"""Pure native-object recipes for already validated freeze-manifest artifacts.

No files are read or written and no compiler or other process is executed.
The generated CMSIS device header describes fixture hardware, not a board.
"""
from pathlib import Path
import re

OBJECT_MODES = ("O0", "Og", "O2", "Os", "O3")
_CORES = {
    "cortex-m0": ("core_cm0.h", "ARMV6M", 0),
    "cortex-m0plus": ("core_cm0plus.h", "ARMV6M", 0),
    "cortex-m3": ("core_cm3.h", "ARMV7M", 0),
    "cortex-m4": ("core_cm4.h", "ARMV7EM", 1),
    "cortex-m7": ("core_cm7.h", "ARMV7EM", 1),
    "cortex-m23": ("core_cm23.h", "ARMV8M_BASELINE", 0),
    "cortex-m33": ("core_cm33.h", "ARMV8M_MAINLINE", 1),
    "cortex-m55": ("core_cm55.h", "ARMV81M_MAINLINE", 1),
    "cortex-m85": ("core_cm85.h", "ARMV81M_MAINLINE", 1),
}
_TARGET_FLAG = re.compile(
    r"-m(?:cpu=[A-Za-z0-9_+.-]+|fpu=[A-Za-z0-9_+.-]+|float-abi=(?:soft|softfp|hard)|"
    r"thumb|cmse|single-pic-base|pic-register=r9)\Z"
)
_NATIVE_FLAGS = (
    "-std=gnu11", "-g0", "-ffreestanding", "-ffunction-sections", "-fdata-sections",
    "-Wall", "-Wextra", "-Werror=implicit-function-declaration", "-Werror=attributes",
    "-Werror=ignored-attributes",
)


def _need(condition, reason):
    if not condition:
        raise RuntimeError("freeze-recipe: " + reason)


def _facts(target):
    _need(type(target) is dict and {
        "cpu", "architecture", "nvic_priority_bits", "vtor", "fpu_present", "fpu_used",
        "mpu_regions", "mve",
    } <= set(target), "missing-target-facts")
    _need(type(target["cpu"]) is str, "cpu")
    cpu = target["cpu"].split("+", 1)[0]
    _need(cpu in _CORES, "unsupported-cpu")
    header, architecture, dsp = _CORES[cpu]
    _need(target["architecture"] == architecture, "cpu-architecture")
    for name in ("vtor", "fpu_present", "fpu_used"):
        _need(type(target[name]) is bool, "target-bool-" + name)
    _need(not target["fpu_used"] or target["fpu_present"], "used-fpu-requires-present")
    _need(type(target["nvic_priority_bits"]) is int and 2 <= target["nvic_priority_bits"] <= 8,
          "nvic-priority-bits")
    _need(type(target["mpu_regions"]) is int and target["mpu_regions"] in (0, 8, 16), "mpu-regions")
    _need(target["mve"] in ("none", "integer", "fp"), "mve-kind")
    _need(target["mve"] == "none" or architecture == "ARMV81M_MAINLINE", "mve-architecture")
    _need("+nomve" not in target["cpu"] or target["mve"] == "none", "nomve-target")
    _need(target["mve"] != "fp" or target["fpu_used"], "mve-fp-requires-fpu")
    return header, dsp, int(architecture.startswith("ARMV8"))


def cmsis_main(target: dict) -> str:
    """Return ASCII main.h text from explicit manifest hardware facts."""
    core_header, dsp, sau = _facts(target)
    macros = (
        ("__NVIC_PRIO_BITS", target["nvic_priority_bits"]),
        ("__VTOR_PRESENT", int(target["vtor"])),
        ("__FPU_PRESENT", int(target["fpu_present"])),
        ("__FPU_USED", int(target["fpu_used"])),
        ("__MPU_PRESENT", int(target["mpu_regions"] != 0)),
        ("__MVE_PRESENT", int(target["mve"] != "none")),
        ("__DSP_PRESENT", dsp),
        ("__ICACHE_PRESENT", 0), ("__DCACHE_PRESENT", 0),
        ("__ITCM_PRESENT", 0), ("__DTCM_PRESENT", 0),
        ("__SAUREGION_PRESENT", sau), ("__Vendor_SysTickConfig", 0),
    )
    lines = ["#ifndef FIBER_FREEZE_COHORT_MAIN_H", "#define FIBER_FREEZE_COHORT_MAIN_H",
             "/* Manifest fixture hardware facts; not a board configuration. */"]
    lines.extend("#define %s %dU" % item for item in macros)
    lines.extend((
        "", "typedef enum IRQn {",
        "    NonMaskableInt_IRQn = -14, HardFault_IRQn = -13,",
        "    MemoryManagement_IRQn = -12, BusFault_IRQn = -11,",
        "    UsageFault_IRQn = -10, SecureFault_IRQn = -9,",
        "    SVCall_IRQn = -5, DebugMonitor_IRQn = -4,",
        "    PendSV_IRQn = -2, SysTick_IRQn = -1, Device_IRQn = 0",
        "} IRQn_Type;", "", '#include "' + core_header + '"',
        "#if __FPU_USED != %dU" % int(target["fpu_used"]),
        '#error "CMSIS FPU use disagrees with the manifest fixture"',
        "#endif", "#endif", "",
    ))
    return "\n".join(lines)


def native_flags(artifact: dict, mode: str, fixture_dir, port_dir, repo, cmsis) -> list[str]:
    """Return argv flags, without executable, source/output operands or filesystem I/O.

    mode is exactly O0/Og/O2/Os/O3. Preserve artifact target-flag order, then
    append mode, native C flags, sorted literal -Dname=value arguments, seven
    include paths and the forced fixture/main.h. port_dir is this artifact's
    private directory, including for secure companions. No ABI/provider,
    architecture, BASEPRI or counterflag definitions are synthesized.
    """
    _need(type(mode) is str and mode in OBJECT_MODES, "native-object-mode")
    _need(type(artifact) is dict and {"target", "compile_flags", "defines", "role"} <= set(artifact),
          "missing-artifact-fields")
    _need(artifact["role"] in ("runtime", "secure_companion"), "artifact-role")
    target = artifact["target"]
    _facts(target)
    _need({"float_abi", "fpu_unit", "r9_abi", "scheduler_basepri"} <= set(target), "missing-target-flags")
    _need(target["float_abi"] in ("soft", "softfp", "hard"), "float-abi")
    _need(type(target["fpu_unit"]) is str and target["r9_abi"] in ("aapcs", "fixed-r9"), "target-flags")
    _need(type(target["scheduler_basepri"]) is int and 0 <= target["scheduler_basepri"] <= 255,
          "scheduler-basepri")
    flags = artifact["compile_flags"]
    _need(type(flags) is list and flags and all(type(flag) is str for flag in flags), "compile-flags")
    _need(len(flags) == len(set(flags)), "duplicate-compile-flag")
    _need(all(_TARGET_FLAG.fullmatch(flag) or flag in ("-ffixed-r9", "-fpic") for flag in flags),
          "non-target-compile-flag")
    _need([flag for flag in flags if flag.startswith("-mcpu=")] == ["-mcpu=" + target["cpu"]] and
          [flag for flag in flags if flag.startswith("-mfloat-abi=")] == ["-mfloat-abi=" + target["float_abi"]],
          "compile-target-binding")
    _need([flag for flag in flags if flag.startswith("-mfpu=")] ==
          (["-mfpu=" + target["fpu_unit"]] if target["fpu_unit"] else []), "compile-fpu-binding")
    _need(("-ffixed-r9" in flags) is (target["r9_abi"] == "fixed-r9"), "compile-r9-binding")
    defines = artifact["defines"]
    _need(type(defines) is dict, "defines-object")
    for name, value in defines.items():
        _need(type(name) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name), "define-name")
        _need(type(value) is str and all(32 <= ord(char) < 127 for char in value), "define-string-value")
    directories = (fixture_dir, port_dir, Path(repo) / "fiber/port", Path(repo) / "fiber",
                   Path(repo) / "context", repo, cmsis)
    paths = []
    for path in directories:
        _need(isinstance(path, (str, Path)) and str(path) and not any(c in str(path) for c in "\r\n\0"),
              "include-path")
        paths.append(Path(path))
    return [*flags, "-" + mode, *_NATIVE_FLAGS,
            *("-D" + name + "=" + defines[name] for name in sorted(defines)),
            *("-I" + str(path) for path in paths), "-include", str(paths[0] / "main.h")]
