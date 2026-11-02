"""Actual selected-header Thumb-1 vector loads; no exception/board claim."""
import argparse
import hashlib
import importlib.metadata
import json
import os
import pathlib
import re
import subprocess
import traceback

import elftools
import unicorn

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_MCLASS, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_R5,
    UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
    UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_SP, UC_ARM_REG_LR,
    UC_ARM_REG_XPSR,
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, required=True)
    parser.add_argument("--arm-gcc", type=pathlib.Path, required=True)
    parser.add_argument("--cmsis-core", type=pathlib.Path, required=True)
    parser.add_argument("--build", type=pathlib.Path, required=True)
    args = parser.parse_args()
    repo, out = args.repo.resolve(), args.build.resolve()
    fixture = pathlib.Path(__file__).resolve().parent
    out.mkdir(parents=True, exist_ok=False)
    tool_queries = []
    programs = []
    for name in ("as", "ld", "cc1", "collect2", "lto1", "lto-wrapper"):
        command = [str(args.arm_gcc), "-print-prog-name=" + name]
        result = subprocess.run(command, capture_output=True, text=True)
        require(result.returncode == 0, "Cannot resolve compiler subprogram " + name)
        path = pathlib.Path(result.stdout.strip()).resolve()
        require(path.is_file(), "Compiler subprogram not found: " + str(path))
        programs.append(path)
        tool_queries.append({"Arguments": command, "Path": str(path), "Hash": sha(path)})
    dependencies = {name: importlib.metadata.version(name) for name in ("unicorn", "pyelftools")}
    require(dependencies == {"unicorn": "2.1.4", "pyelftools": "0.33"},
            "Use the pinned classic-audit Python requirements")
    commands, cases, controls, failure = [], [], [], ""

    def run(command, stem, allow_failure=False):
        result = subprocess.run([str(p) for p in command], capture_output=True, text=True)
        row = {"Arguments": [str(p) for p in command], "ExitCode": result.returncode,
               "Stdout": result.stdout, "Stderr": result.stderr}
        path = out / (stem + ".command.json")
        path.write_text(json.dumps(row, indent=2), encoding="ascii")
        commands.append(str(path))
        if not allow_failure:
            require(result.returncode == 0, "Command failed: " + str(path) + "\n" + result.stderr)
        return result

    def compiler_flags(mpu, vtor):
        profile = "ARM_CM0_MPU" if mpu else "ARM_CM0"
        cpu = "cortex-m0plus" if mpu or vtor else "cortex-m0"
        return ["-mcpu=" + cpu, "-mthumb", "-mfloat-abi=soft", "-std=gnu11",
                "-ffreestanding", "-fno-builtin", "-fno-common",
                "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra", "-Wundef",
                "-Werror=implicit-function-declaration", "-DFIBER_PORT_BUILD_SELECTED=1",
                "-DFIBER_PORT_ARMV6M=1", "-DTHUMB1_MPU=" + str(mpu),
                "-DTHUMB1_VTOR=" + str(vtor), "-I" + str(fixture),
                "-I" + str(repo / "fiber/port" / profile),
                "-I" + str(repo), "-I" + str(args.cmsis_core),
                "-include", str(fixture / "main.h")]

    def line_dependencies(path):
        paths = set()
        for match in re.finditer(r'^#\s+\d+\s+("(?:[^"\\]|\\.)*")', path.read_text(), re.M):
            value = json.loads(match[1])
            if value.startswith("<"):
                continue
            dependency = pathlib.Path(value).resolve()
            require(dependency.is_file(), "Missing preprocessed dependency: " + str(dependency))
            paths.add(dependency)
        return paths

    # Derive the real include closure, including compiler system headers. Other
    # agents editing unrelated profiles must not invalidate this focused gate.
    dependency_paths = set()
    for mpu in (0, 1):
        for vtor in (0, 1):
            for opt in ("O0", "Og", "O2", "Os", "O3"):
                name = f"dependencies-mpu{mpu}-vtor{vtor}-{opt}"
                pre = out / (name + ".i")
                run([args.arm_gcc, *compiler_flags(mpu, vtor), "-" + opt, "-E",
                     fixture / "probe.c", "-o", pre], name)
                dependency_paths.update(line_dependencies(pre))
    inputs = sorted(set([*fixture.glob("*"), args.arm_gcc, *programs,
                         pathlib.Path(unicorn.__file__), pathlib.Path(elftools.__file__),
                         repo / "tools/test_thumb1_vector_constraints.ps1", *dependency_paths]))
    inputs = [p for p in inputs if p.is_file()]
    before = [{"Path": str(p), "Hash": sha(p)} for p in inputs]
    (out / "inputs-before.json").write_text(json.dumps(before, indent=2), encoding="ascii")

    try:
        run([args.arm_gcc, "--version"], "compiler")
        for mpu in (0, 1):
            profile = "ARM_CM0_MPU" if mpu else "ARM_CM0"
            for vtor in (0, 1):
                cpu = "cortex-m0plus" if mpu or vtor else "cortex-m0"
                base_flags = compiler_flags(mpu, vtor)
                for opt in ("O0", "Og", "O2", "Os", "O3"):
                    for reserved in (False, True):
                        for lto in (False, True):
                            name = f"{profile}-vtor{vtor}-{opt}-reserved{int(reserved)}-lto{int(lto)}"
                            flags = base_flags + ["-" + opt]
                            if reserved:
                                flags += ["-ffixed-r9"]
                            if lto:
                                flags += ["-flto", "-fno-fat-lto-objects", "-flto-partition=one"]
                            obj, elf = out / (name + ".o"), out / (name + ".elf")
                            run([args.arm_gcc, *flags, "-save-temps=obj", "-c", fixture / "probe.c", "-o", obj], name + "-compile")
                            require(line_dependencies(obj.with_suffix(".i")) <= dependency_paths,
                                    "Compiled source acquired an unrecorded include dependency")
                            run([args.arm_gcc, *flags, "-nostdlib", "-Wl,--gc-sections", "-T", fixture / "image.ld",
                                 obj, "-o", elf], name + "-link")
                            with elf.open("rb") as stream:
                                image = ELFFile(stream)
                                symbol = image.get_section_by_name(".symtab").get_symbol_by_name("thumb1_vector_probe")
                                require(symbol and len(symbol) == 1, "Missing unique actual-header probe")
                                entry = symbol[0]["st_value"]
                                segments = [(seg["p_vaddr"], seg.data()) for seg in image.iter_segments()
                                            if seg["p_type"] == "PT_LOAD"]
                            checks = 0
                            for vector_base in (0, 0x08010000):
                                for index in (0, 1, 17):
                                    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
                                    for start, size in ((0, 0x1000), (0x08000000, 0x20000),
                                                        (0x20000000, 0x10000), (0xE000E000, 0x1000)):
                                        uc.mem_map(start, size)
                                    for address, content in segments:
                                        uc.mem_write(address, content)
                                    uc.mem_write(0xE000ED08, vector_base.to_bytes(4, "little"))
                                    selected_base = vector_base if (mpu or vtor) else 0
                                    selected_index = index if mpu else 0
                                    expected = 0x20001230 + index * 4
                                    uc.mem_write(selected_base + selected_index * 4, expected.to_bytes(4, "little"))
                                    uc.reg_write(UC_ARM_REG_R0, vector_base)
                                    uc.reg_write(UC_ARM_REG_R1, index)
                                    saved = (UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                                             UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11)
                                    for n, register in enumerate(saved):
                                        uc.reg_write(register, 0x12340000 + n)
                                    sp, stop = 0x2000FFF8, 0x0801F000
                                    uc.reg_write(UC_ARM_REG_SP, sp)
                                    uc.reg_write(UC_ARM_REG_LR, stop | 1)
                                    uc.reg_write(UC_ARM_REG_XPSR, 1 << 24)
                                    reached = []

                                    def on_code(machine, address, size, user):
                                        if address == stop:
                                            reached.append(True)
                                            machine.emu_stop()

                                    uc.hook_add(UC_HOOK_CODE, on_code)
                                    uc.emu_start(entry | 1, stop + 2, count=10000)
                                    require(reached and uc.reg_read(UC_ARM_REG_R0) == expected, name + ": wrong vector read")
                                    require(uc.reg_read(UC_ARM_REG_SP) == sp, name + ": SP not preserved")
                                    for n, register in enumerate(saved):
                                        require(uc.reg_read(register) == 0x12340000 + n, name + ": callee register changed")
                                    checks += 10
                            cases.append({"Name": name, "Elf": str(elf), "Hash": sha(elf), "Checks": checks})

                # Restore only the bad constraints in real preprocessed source.
                # The forced-r8 caller must make this old instruction unencodable.
                name = f"{profile}-vtor{vtor}-bad-constraint"
                pre = out / (name + ".i")
                run([args.arm_gcc, *base_flags, "-O2", "-E", fixture / "probe.c", "-o", pre], name + "-preprocess")
                text = pre.read_text()
                pattern = r'("ldr %0, \[%1\]"\s*:\s*)"=l"(\(value\)\s*:\s*)"l"'
                bad, count = re.subn(pattern, r'\1"=r"\2"r"', text)
                require(count == 1, "Control must change exactly one actual-header LDR constraint pair")
                mutant = out / (name + "-mutant.i")
                mutant.write_text(bad, encoding="ascii")
                result = run([args.arm_gcc, "-mcpu=" + cpu, "-mthumb", "-mfloat-abi=soft", "-O2",
                              "-x", "cpp-output", "-c", mutant, "-o", out / (name + ".o")], name, True)
                diagnostics = re.findall(r"^.*?: (?:fatal )?(?:error|Error): (.+)$", result.stderr, re.M)
                require(result.returncode == 1 and diagnostics and
                        all(re.fullmatch(r"lo register required -- `ldr .+'", line) for line in diagnostics),
                        "Bad-constraint control must fail specifically on Thumb-1 low-register encoding")
                controls.append({"Name": name, "Source": str(mutant), "Hash": sha(mutant),
                                 "Diagnostics": diagnostics})
        require(len(cases) == 80 and len(controls) == 4, "Incomplete qualification inventory")
    except Exception:
        failure = traceback.format_exc()
    after = [{"Path": str(p), "Hash": sha(p)} for p in inputs]
    drift = [new for old, new in zip(before, after) if old != new]
    report = {"Verdict": "PASS" if not failure and not drift else "FAIL",
              "Boundary": "Actual selected-header vector-load codegen and Unicorn execution; not exception/runtime/board or whole-port attributes qualification",
              "Cases": cases, "Controls": controls, "Error": failure, "InputDrift": drift,
              "Commands": commands, "InputCount": len(before), "ToolchainQueries": tool_queries,
              "Dependencies": dependencies,
              "CompilerEnvironment": {key: os.environ.get(key) for key in
                                      ("GCC_EXEC_PREFIX", "COMPILER_PATH", "LIBRARY_PATH")}}
    (out / "inputs-after.json").write_text(json.dumps(after, indent=2), encoding="ascii")
    (out / "results.json").write_text(json.dumps(report, indent=2), encoding="ascii")
    artifacts = [{"Path": str(p), "Hash": sha(p)} for p in sorted(out.rglob("*")) if p.is_file()]
    (out / "artifacts.json").write_text(json.dumps(artifacts, indent=2), encoding="ascii")
    print(f"{report['Verdict']}: {len(cases)} ELF cases, {len(controls)} controls; {out}")
    if failure:
        print(failure)
    return 0 if report["Verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
