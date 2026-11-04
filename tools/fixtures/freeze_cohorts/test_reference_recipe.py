"""Synthetic pure recipe controls; no native compiler, process, Git, or board I/O."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "freeze_reference_recipe_under_test", Path(__file__).with_name("reference_recipe.py"))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)

PROFILES = {
    "CM0": ("ARM_CM0", "cortex-m0", "ARMV6M", 0, False),
    "CM0MPU": ("ARM_CM0", "cortex-m0plus", "ARMV6M", 8, False),
    "CM3": ("ARM_CM3", "cortex-m3", "ARMV7M", 0, False),
    "CM3MPU": ("ARM_CM3_MPU", "cortex-m3", "ARMV7M", 8, False),
    "CM4": ("ARM_CM4F", "cortex-m4", "ARMV7EM", 0, True),
    "CM7": ("ARM_CM7/r0p1", "cortex-m7", "ARMV7EM", 0, True),
    "CM4MPU": ("ARM_CM4_MPU", "cortex-m4", "ARMV7EM", 8, True),
    "CM23NTZ": ("ARM_CM23_NTZ/non_secure", "cortex-m23", "ARMV8M_BASELINE", 0, False),
    "C3FP": ("ARM_CM33_NTZ/non_secure", "cortex-m33", "ARMV8M_MAINLINE", 16, True),
    "CM33NTZ": ("ARM_CM33_NTZ/non_secure", "cortex-m33", "ARMV8M_MAINLINE", 0, False),
    "CM33FNTZ": ("ARM_CM33_NTZ/non_secure", "cortex-m33", "ARMV8M_MAINLINE", 0, True),
    "CM33MPU": ("ARM_CM33_NTZ/non_secure", "cortex-m33", "ARMV8M_MAINLINE", 8, False),
    "CM33TFM": ("ARM_CM33_NTZ/non_secure", "cortex-m33", "ARMV8M_MAINLINE", 0, False),
    "CM33FTFM": ("ARM_CM33_NTZ/non_secure", "cortex-m33", "ARMV8M_MAINLINE", 0, True),
    "C3SO": ("ARM_CM33_NTZ/non_secure", "cortex-m33", "ARMV8M_MAINLINE", 0, False),
    "CM55NTZ": ("ARM_CM55_NTZ/non_secure", "cortex-m55", "ARMV81M_MAINLINE", 0, False),
    "CM55FNTZ": ("ARM_CM55_NTZ/non_secure", "cortex-m55+nomve", "ARMV81M_MAINLINE", 0, True),
    "CM55MVEFNTZ": ("ARM_CM55_NTZ/non_secure", "cortex-m55", "ARMV81M_MAINLINE", 0, True),
    "CM55MPU": ("ARM_CM55_NTZ/non_secure", "cortex-m55", "ARMV81M_MAINLINE", 8, False),
    "CM55FMPU": ("ARM_CM55_NTZ/non_secure", "cortex-m55+nomve", "ARMV81M_MAINLINE", 16, True),
    "CM55MVEFMPU": ("ARM_CM55_NTZ/non_secure", "cortex-m55", "ARMV81M_MAINLINE", 16, True),
    "C5SO": ("ARM_CM55_NTZ/non_secure", "cortex-m55", "ARMV81M_MAINLINE", 0, False),
    "C5TF": ("ARM_CM55_NTZ/non_secure", "cortex-m55", "ARMV81M_MAINLINE", 0, False),
    "C33S": ("ARM_CM33/non_secure", "cortex-m33", "ARMV8M_MAINLINE", 0, False),
    "C55S": ("ARM_CM55/non_secure", "cortex-m55", "ARMV81M_MAINLINE", 0, False),
    "C33S_GATEWAY": ("ARM_CM33/secure", "cortex-m33", "ARMV8M_MAINLINE", 0, False),
    "C55S_GATEWAY": ("ARM_CM55/secure", "cortex-m55", "ARMV81M_MAINLINE", 0, False),
}
TFM = {"C5TF", "CM33TFM", "CM33FTFM"}
GATEWAYS = {"C33S_GATEWAY", "C55S_GATEWAY"}


def sample(group="CM4"):
    directory, cpu, architecture, mpu, fp = PROFILES[group]
    baseline = architecture in ("ARMV6M", "ARMV8M_BASELINE")
    gateway = group in GATEWAYS
    unit = "fpv4-sp-d16" if cpu == "cortex-m4" else ("fpv5-d16" if cpu == "cortex-m7" else "fpv5-sp-d16")
    if "MVE" in group:
        unit = ""
    target = dict(cpu=cpu, architecture=architecture, float_abi="hard" if fp else "soft",
        fpu_present=fp, fpu_used=fp, fpu_unit=unit if fp else "", fp_stacking="eager" if fp else "none",
        r9_abi="aapcs", nvic_priority_bits=4, scheduler_basepri=0 if baseline or gateway else 16)
    flags = ["-mcpu=" + cpu, "-mthumb"] + (["-mfpu=" + unit] if fp and unit else []) + ["-mfloat-abi=" + target["float_abi"]]
    if gateway or group in ("C3SO", "C5SO"):
        flags.append("-mcmse")
    if gateway:
        names = ("secure_context.c", "secure_context_port.c", "secure_init.c", "secure_heap.c")
    elif group in ("CM3", "CM3MPU", "CM4", "CM7", "CM4MPU"):
        names = ("port.c",)
    else:
        names = ("port.c", "portasm.c")
    sources = ["portable/GCC/" + directory + "/" + name for name in names]
    if group in TFM:
        sources.append("portable/ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c")
    defines = dict(FIBER_FREERTOS_PARITY_ENABLE_MPU=str(int(mpu != 0)),
        FIBER_FREERTOS_PARITY_ENABLE_FPU=str(int(fp)),
        FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE=str(int(gateway or group in ("C33S", "C55S"))))
    if mpu:
        defines["FIBER_FREERTOS_PARITY_MPU_REGIONS"] = str(mpu)
    if group in ("C3SO", "C5SO"):
        defines["FIBER_FREERTOS_PARITY_SECURE_ONLY"] = "1"
    if "MVE" in group:
        defines["FIBER_FREERTOS_PARITY_ENABLE_MVE"] = "1"
    fiber_defines = {"FIBER_ONLY_SENTINEL": "1"}
    if gateway:
        name = "FIBER_ARM_CM%s_SECURE_CONTEXT_MAX_COUNT" % ("33" if group == "C33S_GATEWAY" else "55")
        fiber_defines[name] = "3"
    return dict(source_group_id=group, role="secure_companion" if gateway else "runtime",
        target=target, compile_flags=flags, upstream_sources=sources, upstream_defines=defines,
        defines=fiber_defines)


def main():
    records = []
    generated, kernel, tfm = (Path(p) for p in ("synthetic/generated fixture", "synthetic/kernel", "synthetic/tfm/interface/include"))

    def need(condition, reason):
        if not condition:
            raise RuntimeError("reference-control: " + reason)

    def test(name, action, reason=None):
        try:
            action()
        except RuntimeError as error:
            need(reason is not None and str(error) == "freeze-reference-recipe: " + reason,
                 name + ": " + str(error))
            records.append({"Name": name, "ExpectedRejection": reason})
        else:
            need(reason is None, name + ": expected rejection " + str(reason))
            records.append({"Name": name, "Accepted": True})

    def recipe(artifact, mode="O2", external="auto"):
        include = tfm if artifact["source_group_id"] in TFM else None
        return r.reference_recipe(artifact, mode, generated, kernel, include if external == "auto" else external)

    expected_keys = {"Flags", "ConfigText", "PortmacroProvider", "ExtraIncludes", "Differences", "WitnessKind", "ExactTargetRecipe"}
    for group, (directory, *_) in PROFILES.items():
        for mode in ("O0", "Og", "O2", "Os", "O3"):
            def exact_profile(group=group, directory=directory, mode=mode):
                artifact = sample(group)
                before = deepcopy(artifact)
                actual = recipe(artifact, mode)
                need(set(actual) == expected_keys, "stable result schema")
                need(artifact == before, "input mutation")
                need(actual["ExactTargetRecipe"] is True and actual["WitnessKind"] == "none", "ordinary target flags exact")
                need(actual["Flags"][:len(artifact["compile_flags"])] == artifact["compile_flags"], "target order")
                need([f for f in actual["Flags"] if f.startswith("-O")] == ["-" + mode], "one mode")
                need(not any(f.startswith(("-flto", "-fno-")) for f in actual["Flags"]), "no LTO/counterflags")
                need("-include" not in actual["Flags"] and not any("CMSIS" in f or "FIBER_ONLY_SENTINEL" in f for f in actual["Flags"]), "no CMSIS/Fiber defines")
                provider = None if group in GATEWAYS else "portable/GCC/" + directory + "/portmacro.h"
                extras = ["portable/GCC/" + directory] if group in GATEWAYS else (
                    ["portable/GCC/ARM_CM33/secure"] if group == "C33S" else
                    ["portable/GCC/ARM_CM55/secure"] if group == "C55S" else [])
                need(actual["PortmacroProvider"] == provider and actual["ExtraIncludes"] == extras, "exact provider map")
                includes = [generated, kernel / "include"]
                if provider:
                    includes.append(kernel / "portable/GCC" / directory)
                includes.extend(kernel / p for p in extras)
                if group in TFM:
                    includes.append(tfm)
                need([f for f in actual["Flags"] if f.startswith("-I")] == ["-I" + str(p) for p in includes], "no include union")
                definitions = ["-D" + k + "=" + artifact["upstream_defines"][k] for k in sorted(artifact["upstream_defines"])]
                need([f for f in actual["Flags"] if f.startswith("-D")] == definitions, "exact sorted upstream definitions")
                text = actual["ConfigText"]
                need(text.count('#include "freeze_base_FreeRTOSConfig.h"') == 1, "copied base include")
                value = artifact["target"]["scheduler_basepri"]
                for key in ("configMAX_SYSCALL_INTERRUPT_PRIORITY", "configMAX_API_CALL_INTERRUPT_PRIORITY"):
                    need("#undef " + key + "\n#define %s %dU" % (key, value) in text, "raw threshold")
                if group in GATEWAYS:
                    need("#define secureconfigMAX_SECURE_CONTEXTS 3U" in text, "companion count three")
            test(group + "-" + mode, exact_profile)

    for group, bits, threshold, present, fixed in (
        ("CM4", 4, 16, False, False), ("CM4", 3, 32, False, False),
        ("CM4", 3, 32, True, False), ("CM4", 3, 32, True, True),
        ("CM7", 4, 16, False, False), ("CM7", 3, 32, True, False), ("CM7", 3, 32, True, True),
    ):
        def witness(group=group, bits=bits, threshold=threshold, present=present, fixed=fixed):
            artifact = sample(group)
            target = artifact["target"]
            target.update(float_abi="soft", fpu_present=present, fpu_used=False, fpu_unit="", fp_stacking="none",
                          nvic_priority_bits=bits, scheduler_basepri=threshold, r9_abi="fixed-r9" if fixed else "aapcs")
            artifact["compile_flags"] = ["-mcpu=" + target["cpu"], "-mthumb", "-mfloat-abi=soft"] + (["-ffixed-r9"] if fixed else [])
            artifact["upstream_defines"]["FIBER_FREERTOS_PARITY_ENABLE_FPU"] = "0"
            before = deepcopy(artifact)
            actual = recipe(artifact)
            unit = "fpv4-sp-d16" if group == "CM4" else "fpv5-d16"
            need(actual["Flags"][:4] == ["-mcpu=" + target["cpu"], "-mthumb", "-mfpu=" + unit, "-mfloat-abi=softfp"], "same FP port softfp witness")
            need(("-ffixed-r9" in actual["Flags"]) == fixed, "witness R9")
            need(actual["ExactTargetRecipe"] is False and actual["WitnessKind"] == "soft-abi-fp-port-softfp", "witness exclusion")
            difference = actual["Differences"][0]
            need(difference["Scope"] == "witness-only-native-object" and "exact-abi" in difference["ExcludedClaims"], "witness scope")
            need(difference["DeclaredFpuPresent"] == present and difference["ReferenceUsesFpu"] is True, "physical FPU mismatch explicit")
            need(artifact == before, "witness mutation")
        test("soft-witness-%s-%s-%s-%s-%s" % (group, bits, threshold, present, fixed), witness)

    for value, bits in ((2, 7), (16, 4), (32, 3), (64, 2), (128, 4)):
        def raw_priority(value=value, bits=bits):
            artifact = sample("CM3")
            artifact["target"].update(scheduler_basepri=value, nvic_priority_bits=bits)
            need("#define configMAX_SYSCALL_INTERRUPT_PRIORITY %dU" % value in recipe(artifact)["ConfigText"], "no second shift")
        test("raw-priority-" + str(value), raw_priority)

    def fp_limits():
        artifact = sample("CM33FNTZ")
        eager = recipe(artifact)
        difference = next(d for d in eager["Differences"] if d["Kind"] == "fpccr-eager-vs-lazy")
        need(difference["ReferenceFPCCR"] == {"ASPEN": 1, "LSPEN": 1}, "pinned lazy bits")
        need(difference["Scope"] == "native-object-only-no-policy-equivalence", "eager limitation")
        artifact["target"]["fp_stacking"] = "lazy"
        lazy = recipe(artifact)
        need(not any(d["Kind"] == "fpccr-eager-vs-lazy" for d in lazy["Differences"]), "no eager mismatch for lazy")
        need(eager["Flags"] == lazy["Flags"] and eager["ConfigText"] == lazy["ConfigText"], "no fake FP policy override")
    test("eager-lazy-limits", fp_limits)

    for group in ("CM55MVEFNTZ", "CM55MVEFMPU"):
        def isa_default_fpu(group=group):
            artifact = sample(group)
            actual = recipe(artifact)
            need(artifact["target"]["fpu_used"] is True and artifact["target"]["fpu_unit"] == "", "ISA-default fixture")
            need(not any(f.startswith("-mfpu=") for f in actual["Flags"]), "no invented FPU flag")
            need(actual["ExactTargetRecipe"] is True, "ISA-default target remains exact")
        test(group + "-isa-default-fpu", isa_default_fpu)
        artifact = sample(group)
        artifact["compile_flags"].append("-mfpu=fpv5-sp-d16")
        test(group + "-reject-invented-mfpu", lambda a=artifact: recipe(a), "compile-fpu-binding")

    for group in GATEWAYS:
        for literal in ("3", "3u", "0x03U"):
            def companion_binding(group=group, literal=literal):
                artifact = sample(group)
                name = "FIBER_ARM_CM%s_SECURE_CONTEXT_MAX_COUNT" % ("33" if group == "C33S_GATEWAY" else "55")
                artifact["defines"][name] = literal
                need(any(d["Kind"] == "secure-context-count-binding" and d["Reference"] == 3 for d in recipe(artifact)["Differences"]), "count binding")
            test(group + "-count-" + literal, companion_binding)

    for group in PROFILES:
        artifact = sample(group)
        artifact["upstream_sources"].append("portable/GCC/ARM_CM3/foreign.c")
        test(group + "-reject-foreign-source", lambda a=artifact: recipe(a), "upstream-source-binding")
    for mode in ("O1", "Ofast", "O2-lto", "-O2", "O2 -flto", ""):
        test("reject-mode-" + repr(mode), lambda m=mode: recipe(sample(), m), "native-object-mode")
    for flag in ("-flto", "-flto=auto", "-fno-lto", "-O3", "-fno-builtin", "-Iforeign", "-D__ARM_FP=4", "@foreign.rsp"):
        artifact = sample()
        artifact["compile_flags"].append(flag)
        test("reject-flag-" + flag, lambda a=artifact: recipe(a), "non-target-compile-flag")
    for group in TFM:
        test(group + "-missing-provider", lambda g=group: recipe(sample(g), external=None), "missing-pinned-tfm-include")
    test("non-tfm-extra-provider", lambda: recipe(sample(), external=tfm), "unexpected-tfm-include")
    for group in ("CM0", "CM23NTZ", "C33S_GATEWAY", "C55S_GATEWAY"):
        artifact = sample(group)
        artifact["target"]["scheduler_basepri"] = 16
        reason = "companion-threshold-not-applicable" if group in GATEWAYS else "baseline-threshold-not-applicable"
        test(group + "-nonzero-na-threshold", lambda a=artifact: recipe(a), reason)
    for value in (0, 1, 17, 256, True):
        artifact = sample("CM3")
        artifact["target"]["scheduler_basepri"] = value
        test("reject-mainline-basepri-" + str(value), lambda a=artifact: recipe(a),
             "target-threshold" if value == 256 or value is True else "basepri-alignment")
    for group in GATEWAYS:
        artifact = sample(group)
        name = "FIBER_ARM_CM%s_SECURE_CONTEXT_MAX_COUNT" % ("33" if group == "C33S_GATEWAY" else "55")
        del artifact["defines"][name]
        test(group + "-reject-missing-count", lambda a=artifact: recipe(a), "companion-count-binding")
        for value in ("4", "", 3, "03", "003", "03u", "0x03UL", "3UL", " 3", "3 "):
            artifact = sample(group)
            name = "FIBER_ARM_CM%s_SECURE_CONTEXT_MAX_COUNT" % ("33" if group == "C33S_GATEWAY" else "55")
            artifact["defines"][name] = value
            test(group + "-reject-count-" + repr(value), lambda a=artifact: recipe(a), "companion-count-binding")
    for name in ("configMAX_SYSCALL_INTERRUPT_PRIORITY", "configMAX_API_CALL_INTERRUPT_PRIORITY", "secureconfigMAX_SECURE_CONTEXTS"):
        artifact = sample()
        artifact["upstream_defines"][name] = "128"
        test("reject-reserved-" + name, lambda a=artifact: recipe(a), "reserved-config-define")
    for key, value, reason in (("role", "secure_companion", "profile-role-binding"),
                               ("source_group_id", "UNKNOWN", "unknown-source-group")):
        artifact = sample()
        artifact[key] = value
        test("reject-" + key, lambda a=artifact: recipe(a), reason)
    for key, value, reason in (("cpu", "cortex-m7", "compile-target-binding"),
                              ("fpu_unit", "fpv5-d16", "compile-fpu-binding"),
                              ("r9_abi", "fixed-r9", "compile-r9-binding")):
        artifact = sample()
        artifact["target"][key] = value
        test("reject-binding-" + key, lambda a=artifact: recipe(a), reason)
    for source_change in ("missing", "duplicate", "cross-family"):
        artifact = sample("CM33FNTZ")
        if source_change == "missing":
            artifact["upstream_sources"].pop()
        elif source_change == "duplicate":
            artifact["upstream_sources"].append(artifact["upstream_sources"][0])
        else:
            artifact["upstream_sources"] = ["portable/GCC/ARM_CM55_NTZ/non_secure/port.c", "portable/GCC/ARM_CM55_NTZ/non_secure/portasm.c"]
        test("reject-sources-" + source_change, lambda a=artifact: recipe(a), "upstream-source-binding")
    for bad_path in ("", "bad\npath", "bad\0path"):
        test("reject-path-" + repr(bad_path), lambda p=bad_path: r.reference_recipe(sample(), "O2", p, kernel), "include-path")
    need(len(PROFILES) == 27, "all groups represented")
    print(json.dumps({"Status": "PURE-CONTROLS-PASS", "Controls": len(records),
        "PositiveControls": sum(x.get("Accepted", False) for x in records),
        "ExpectedRejections": sum("ExpectedRejection" in x for x in records),
        "SourceGroups": len(PROFILES), "CompilerExecutions": 0, "CpuExecutions": 0,
        "AssemblyParityClaimed": False, "GlobalFreezeQualified": False}, sort_keys=True))


if __name__ == "__main__":
    main()
