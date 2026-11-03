"""Pure build-recipe controls: no native compilation, process launch or board I/O."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import re

PATH = Path(__file__).with_name("build_recipe.py")
SPEC = importlib.util.spec_from_file_location("freeze_build_recipe_under_test", PATH)
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


def sample():
    target = dict(cpu="cortex-m4", architecture="ARMV7EM", float_abi="hard", fpu_present=True,
        fpu_used=True, fpu_unit="fpv4-sp-d16", fp_stacking="eager", vtor=True, mpu_regions=8,
        security_role="classic", psplim_slot=False, psplim_register=False, mve="none", pac=False,
        bti=False, errata_policy="none", r9_abi="aapcs", nvic_priority_bits=4, scheduler_basepri=16)
    return dict(role="runtime", abi_contract="forward8", target=target,
                compile_flags=["-mcpu=cortex-m4", "-mthumb", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard"],
                defines={"FIBER_SCHEDULER_BASEPRI": "16", "FIBER_PORT_ARMV7EM": "1", "FIBER_FPU_LAZY": "0"})


def main():
    records = []
    artifact = sample()
    directories = tuple(Path(p) for p in ("synthetic/generated", "synthetic/private", "synthetic/repo", "synthetic/CMSIS"))

    def need(ok, reason):
        if not ok:
            raise RuntimeError("recipe-control: " + reason)

    def test(name, action, expected=True, reason=None):
        rejection = None
        try:
            action()
            accepted = True
        except (RuntimeError, KeyError, TypeError, ValueError) as failure:
            accepted, rejection = False, str(failure)
        need(accepted is expected and (reason is None or rejection == "freeze-recipe: " + reason),
             name + ": " + str(rejection))
        records.append(dict(Name=name, Accepted=accepted, Rejection=rejection))

    def flags(value=artifact, mode="O2", paths=directories):
        return r.native_flags(value, mode, *paths)

    def macros(target):
        header = r.cmsis_main(target)
        return {name: int(value) for name, value in re.findall(r"^#define (__\w+) ([0-9]+)U$", header, re.M)}

    for mode in ("O0", "Og", "O2", "Os", "O3"):
        def exact_recipe():
            actual = flags(mode=mode)
            fixture, private, repo, cmsis = directories
            expected = [*artifact["compile_flags"], "-" + mode, "-std=gnu11", "-g0", "-ffreestanding",
                "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra",
                "-Werror=implicit-function-declaration", "-Werror=attributes", "-Werror=ignored-attributes",
                "-DFIBER_FPU_LAZY=0", "-DFIBER_PORT_ARMV7EM=1", "-DFIBER_SCHEDULER_BASEPRI=16",
                *("-I" + str(p) for p in (fixture, private, repo / "fiber/port", repo / "fiber", repo / "context", repo, cmsis)),
                "-include", str(fixture / "main.h")]
            need(actual == expected, "exact ordered native recipe")
            need([f for f in actual if f.startswith("-O")] == ["-" + mode], "one native optimization")
            need(not any(f.startswith(("-flto", "-fno-")) for f in actual), "no LTO/counterflags")
        test("exact-native-" + mode, exact_recipe)

    for mode in ("O2-lto", "Os-lto", "O1", "Ofast", "-O2", "O2 -flto", ""):
        test("reject-mode-" + repr(mode), lambda: flags(mode=mode), False, "native-object-mode")
    for flag in ("-O0", "-flto", "-flto=auto", "-fno-lto", "-fno-stack-protector", "-fno-function-sections",
                 "-finstrument-functions", "--coverage", "-g", "@foreign.rsp", "-Iforeign", "-DOVERRIDE=1"):
        bad = deepcopy(artifact)
        bad["compile_flags"].append(flag)
        test("reject-artifact-flag-" + flag, lambda: flags(bad), False, "non-target-compile-flag")
    bad = deepcopy(artifact)
    bad["compile_flags"].append("-mcpu=cortex-m7")
    test("conflicting-cpu-flag", lambda: flags(bad), False, "compile-target-binding")
    bad = deepcopy(artifact)
    bad["compile_flags"].append("-mthumb")
    test("duplicate-target-flag", lambda: flags(bad), False, "duplicate-compile-flag")

    def preserve_order_and_inputs():
        reordered = deepcopy(artifact)
        reordered["compile_flags"].reverse()
        before = deepcopy(reordered)
        actual = flags(reordered)
        need(actual[:len(reordered["compile_flags"])] == reordered["compile_flags"], "target flag order")
        need(reordered == before, "recipe mutated artifact")
        r.cmsis_main(reordered["target"])
        need(reordered == before, "header mutated target")
    test("preserve-target-order-and-inputs", preserve_order_and_inputs)

    fixed = deepcopy(artifact)
    fixed["target"]["r9_abi"] = "fixed-r9"
    fixed["compile_flags"].extend(("-ffixed-r9", "-fpic", "-msingle-pic-base", "-mpic-register=r9"))
    test("preserve-fixed-r9-flags", lambda: need(flags(fixed)[:len(fixed["compile_flags"])] == fixed["compile_flags"], "r9 flags"))
    bad = deepcopy(artifact)
    bad["target"]["r9_abi"] = "fixed-r9"
    test("fixed-r9-missing-flag", lambda: flags(bad), False, "compile-r9-binding")
    bad = deepcopy(artifact)
    bad["compile_flags"].append("-ffixed-r9")
    test("fixed-r9-undeclared-flag", lambda: flags(bad), False, "compile-r9-binding")

    def exact_definitions():
        value = deepcopy(artifact)
        value["defines"] = {"Z_EMPTY": "", "FIBER_PORT_ARMV7EM": "0", "A_EXPR": "(1U << 3)"}
        actual = flags(value)
        need([f for f in actual if f.startswith("-D")] ==
             ["-DA_EXPR=(1U << 3)", "-DFIBER_PORT_ARMV7EM=0", "-DZ_EMPTY="], "literal sorted defines")
        need(not any("FIBER_SCHEDULER_BASEPRI" in f or "FIBER_PORT_BUILD_SELECTED" in f for f in actual),
             "synthesized provider/basepri definition")
    test("literal-defines-no-architecture-or-basepri-overrides", exact_definitions)
    for value in (16, True, "line\nbreak"):
        bad = deepcopy(artifact)
        bad["defines"]["BAD"] = value
        test("reject-nonliteral-define-" + repr(value), lambda: flags(bad), False, "define-string-value")

    def exact_header():
        header = r.cmsis_main(artifact["target"])
        need(macros(artifact["target"]) == {
            "__NVIC_PRIO_BITS": 4, "__VTOR_PRESENT": 1, "__FPU_PRESENT": 1, "__FPU_USED": 1,
            "__MPU_PRESENT": 1, "__MVE_PRESENT": 0, "__DSP_PRESENT": 1,
            "__ICACHE_PRESENT": 0, "__DCACHE_PRESENT": 0, "__ITCM_PRESENT": 0, "__DTCM_PRESENT": 0,
            "__SAUREGION_PRESENT": 0, "__Vendor_SysTickConfig": 0,
        }, "exact hardware facts")
        need(header.index("} IRQn_Type;") < header.index('#include "core_cm4.h"'), "IRQn before CMSIS")
        need("FIBER_SCHEDULER_BASEPRI" not in header and "FIBER_FPU_LAZY" not in header and
             "FIBER_PORT_ARMV7EM" not in header, "policy leaked into hardware facts")
        header.encode("ascii")
    test("exact-cmsis-fixture-header", exact_header)

    for cpu, architecture, core in (("cortex-m0", "ARMV6M", "cm0"), ("cortex-m0plus", "ARMV6M", "cm0plus"),
                                   ("cortex-m3", "ARMV7M", "cm3"), ("cortex-m23", "ARMV8M_BASELINE", "cm23"),
                                   ("cortex-m33", "ARMV8M_MAINLINE", "cm33"), ("cortex-m85", "ARMV81M_MAINLINE", "cm85")):
        target = dict(artifact["target"], cpu=cpu, architecture=architecture, fpu_present=False, fpu_used=False,
                      vtor=cpu not in ("cortex-m0", "cortex-m0plus"), mpu_regions=0)
        def core_selection():
            header = r.cmsis_main(target)
            need('#include "core_' + core + '.h"' in header, "explicit core header")
            need(macros(target)["__VTOR_PRESENT"] == int(target["vtor"]), "exact VTOR")
            need(macros(target)["__SAUREGION_PRESENT"] == int(architecture.startswith("ARMV8")), "SAU architecture")
            need(macros(target)["__DSP_PRESENT"] == int(cpu in ("cortex-m33", "cortex-m85")), "classic DSP facts")
        test("explicit-header-" + cpu, core_selection)
    soft_m7 = dict(artifact["target"], cpu="cortex-m7", fpu_used=False, float_abi="soft", fpu_unit="", fp_stacking="none")
    test("cm7-soft-physical-fpu-present-unused", lambda: need(
        macros(soft_m7)["__FPU_PRESENT"] == 1 and macros(soft_m7)["__FPU_USED"] == 0 and
        '#include "core_cm7.h"' in r.cmsis_main(soft_m7), "physical FPU is not ABI use"))
    for cpu, mve, expected in (("cortex-m55+nomve", "none", 0), ("cortex-m55", "integer", 1), ("cortex-m55", "fp", 1)):
        target = dict(artifact["target"], cpu=cpu, architecture="ARMV81M_MAINLINE", mve=mve)
        test("m55-fixture-" + mve, lambda: need(macros(target)["__MVE_PRESENT"] == expected and
             macros(target)["__SAUREGION_PRESENT"] == 1 and '#include "core_cm55.h"' in r.cmsis_main(target), "MVE fixture facts"))
    bad_target = dict(artifact["target"], cpu="cortex-m55+nomve", architecture="ARMV81M_MAINLINE", mve="fp")
    test("nomve-cannot-claim-mve", lambda: r.cmsis_main(bad_target), False, "nomve-target")
    for key in ("cpu", "fpu_present", "fpu_used", "nvic_priority_bits", "vtor"):
        bad_target = deepcopy(artifact["target"])
        bad_target.pop(key)
        test("no-default-header-" + key, lambda: r.cmsis_main(bad_target), False, "missing-target-facts")
    bad = deepcopy(artifact)
    bad["target"].pop("scheduler_basepri")
    test("no-default-basepri", lambda: flags(bad), False, "missing-target-flags")

    def companion_recipe():
        companion = deepcopy(artifact)
        companion.update(role="secure_companion", abi_contract="secure_companion")
        companion["target"].update(cpu="cortex-m33", architecture="ARMV8M_MAINLINE", float_abi="soft",
            fpu_present=False, fpu_used=False, fpu_unit="", fp_stacking="none", mpu_regions=0,
            security_role="secure_companion", scheduler_basepri=0)
        companion["compile_flags"] = ["-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft", "-mcmse"]
        companion["defines"] = {"FIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT": "3"}
        secure_private = Path("synthetic/own-secure-port")
        actual = flags(companion, paths=(directories[0], secure_private, directories[2], directories[3]))
        need("-I" + str(secure_private) in actual and "-I" + str(directories[1]) not in actual, "own companion private directory")
        need([f for f in actual if f.startswith("-D")] == ["-DFIBER_ARM_CM33_SECURE_CONTEXT_MAX_COUNT=3"],
             "companion inherited runtime/forward ABI definitions")
        need("-mcmse" in actual and macros(companion["target"])["__MPU_PRESENT"] == 0, "companion own image facts")
    test("companion-own-directory-and-definitions-not-forward-abi", companion_recipe)
    print(json.dumps(dict(Verdict="PURE-BUILD-RECIPE-PASS", Controls=records,
                         CompilerInvocations=0, TargetExecutions=0, GlobalFreezeQualified=False), indent=2))


if __name__ == "__main__":
    main()
