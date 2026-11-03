"""CM0/CM0+ non-MPU five-option and final-LTO paired mechanism evidence only."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import sys
import traceback

sys.dont_write_bytecode = True
OPT_ERROR = "Disable PYTHONOPTIMIZE and do not use -O/-OO for CM0 freeze parity"
if not __debug__ or sys.flags.optimize:
    raise SystemExit(OPT_ERROR)

HERE = Path(__file__).resolve().parent
COMMON_PATH = HERE.parent / "classic_context_runtime/run.py"
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

common = load("cm0_freeze_evidence", COMMON_PATH)
check = load("cm0_freeze_checks", HERE / "check.py")
need, digest, save = common.need, common.digest, common.save
PROFILES = (("CM0", "cortex-m0", 0), ("CM0PLUS", "cortex-m0plus", 1))
MODES = (("O0", False), ("Og", False), ("O2", False), ("Os", False), ("O3", False),
         ("O2", True), ("Os", True))
MUTANTS = {"save-stride": "FIBER.PENDSV.SAVE_STRIDE", "restore-r9": "FIBER.PENDSV.RESTORE_R9",
           "mask-restore": "FIBER.PENDSV.MASK_RESTORE"}
EXPLICIT = ("tools/test_cm0_freeze_parity.ps1", "tools/fixtures/classic_context_runtime/run.py")
COMPILE = ("-mthumb", "-mfloat-abi=soft", "-std=gnu11", "-g0", "-ffreestanding", "-fno-builtin",
           "-fno-common", "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra",
           "-Wundef", "-Werror=undef", "-Werror=implicit-function-declaration", "-Werror=return-type")


def exact_rejection(result, diagnostic):
    return (result.get("TimedOut") is False and type(result.get("Exit")) is int and result["Exit"] == 1 and
            result["Stdout"] == "" and result["Stderr"].replace("\r\n", "\n") == diagnostic + "\n")


class Suite(common.Suite):
    def __init__(self, args):
        args.development_smoke = False
        super().__init__(args)
        need(HERE == self.repo / "tools/fixtures/cm0_freeze_parity", "Runner must belong to selected export")
        self.fixture = HERE
        self.controls = []
        self.normal_pairs = []
        self.legacy_pairs = []
        self.report.update(Scope=__doc__, CompleteSuite=False, CpuExecution=False, BoardExecution=False,
                           GlobalParity=False, Controls=self.controls, OrdinaryPairs=self.normal_pairs,
                           LegacyFocusedPairs=self.legacy_pairs,
                           Profiles=[dict(Name=n, Cpu=c, Vtor=v) for n, c, v in PROFILES])

    def inspect_qemu(self, name):
        # The inherited helper collects tools/inputs; this new gate has no CPU-execution phase.
        return dict(Status="NOT_REQUESTED", Scope="Link/code-generation gate; no QEMU invocation")

    def repo_inventory(self):
        super().repo_inventory()
        for name in EXPLICIT:
            self.enroll(self.repo / name, "ExplicitEvidenceHelper")
        relative = {Path(k).relative_to(self.repo).as_posix(): v["Sha256"] for k, v in self.inputs.items()
                    if Path(k).is_relative_to(self.repo)}
        self.repo_paths_before = set(relative)
        self.report["RepositoryIdentity"]["TreeSha256"] = hashlib.sha256(
            json.dumps(relative, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest().upper()

    def check_repository_inventory(self):
        if self.exact_git:
            names = self.git(self.repo, "ls-files", "-z")["Stdout"].split("\0")
            paths = {self.repo / n for n in names if n and "__pycache__" not in Path(n).parts}
        else:
            paths = set(common.directory_files(self.repo))
        paths.update(common.directory_files(self.fixture))
        paths.update(self.repo / n for n in (*EXPLICIT, "tools/test_classic_context_runtime.ps1",
            "tools/freertos_asm_parity.ps1", "tools/runtime_sources.py", "tools/runtime_sources.ps1", "tools/runtime_sources.json"))
        drift = {p.relative_to(self.repo).as_posix() for p in paths} ^ self.repo_paths_before
        self.report["RepositoryInventoryDrift"] = sorted(drift)
        need(not drift, "Repository/export inventory changed")

    def preflight(self):
        super().preflight()
        driver = (self.repo / "tools/freertos_asm_parity.ps1").read_text()
        need("Cm0NonMpuOnly" in driver, "Required bounded parity-driver integration is absent")
        wrapper = self.command([self.tools["gcc"], "-print-prog-name=lto-wrapper"], "identify LTO wrapper")["Stdout"].strip()
        self.enroll(wrapper, "CompilerSubprocess")
        self.plugin = Path(self.command([self.tools["gcc"], "-print-file-name=liblto_plugin.dll"],
                                       "query actual LTO plugin")["Stdout"].strip()).resolve(strict=True)
        self.report["ParserControls"] = check.parser_controls()
        guards = []
        for filename in ("run.py", "check.py"):
            for level in ("-O", "-OO"):
                for mode in ("direct", "import"):
                    target = HERE / filename
                    arguments = [sys.executable, level, str(target), "--help"] if mode == "direct" else [
                        sys.executable, level, "-c", "import runpy;runpy.run_path(" + repr(str(target)) + ",run_name='guard_import')"]
                    result = self.command(arguments, "optimized Python " + filename + " " + level + " " + mode, expected=None)
                    need(exact_rejection(result, OPT_ERROR), "Optimized invocation did not fail exactly")
                    guards.append(dict(File=filename, Level=level, Mode=mode, Command=result["Record"]))
        fake = dict(TimedOut=False, Exit=1, Stdout="", Stderr="RuntimeError: " + OPT_ERROR + "\n")
        need(not exact_rejection(fake, OPT_ERROR), "Counterfeit traceback accepted")
        fake.update(Exit=True, Stderr=OPT_ERROR + "\n")
        need(not exact_rejection(fake, OPT_ERROR), "Boolean exit accepted")
        self.report["OptimizedInvocationControls"] = guards
        self.report["DiagnosticCounterfeitControls"] = 2
        self.driver_policy_controls()
        mirror = []
        for index, record in enumerate(self.inputs.values()):
            source = Path(record["Path"])
            if source.suffix.lower() not in (".c", ".h", ".s", ".ld", ".py", ".ps1", ".json", ".md", ".txt"):
                continue
            target = self.build / "input-bytes" / ("%05d-" % index + source.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            need(digest(target) == record["Sha256"], "Input-byte capture drift")
            mirror.append(dict(Path=str(source), Copy=str(target), Sha256=record["Sha256"]))
        save(self.build / "input-mirror.json", mirror)
        save(self.build / "inputs.before.json", list(self.inputs.values()))

    def driver_policy_controls(self):
        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"
        diagnostic = "O0/Og/O3 parity is admitted only by the bounded -Cm0NonMpuOnly mode"
        controls = []
        for opt, mode in itertools.product(("-O0", "-Og", "-O3"), ("", "-Cm0Only", "-Cm3Only")):
            output = self.build / ("forbidden-" + opt[1:] + (mode or "default"))
            command = ("try { & " + quote(self.repo / "tools/freertos_asm_parity.ps1") +
                " -Optimization " + quote(opt) + " " + mode + " -ArmGcc " +
                quote(self.build / "forbidden-compiler.exe") + " -BuildRoot " + quote(output) +
                "; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 23 }")
            result = self.command([self.tools["powershell"], "-NoProfile", "-Command", command],
                                  "actual driver rejects expanded optimization outside new selector", expected=None)
            need(result["Exit"] == 23 and not result["TimedOut"] and result["Stdout"] == "" and
                 result["Stderr"].replace("\r\n", "\n") == diagnostic + "\n" and not output.exists(),
                 "Driver optimization admission changed or reached discovery/output")
            controls.append(dict(Optimization=opt, Mode=mode or "default", Command=result["Record"]))
        need(len(controls) == 9, "Literal nine driver admission controls")
        self.report["DriverAdmissionControls"] = controls

    def stage(self):
        for (name, cpu, vtor), (opt, lto), archive in itertools.product(PROFILES, MODES, (False, True)):
            label = "-".join((name, opt, "lto" if lto else "normal", "archive" if archive else "direct"))
            self.rows.append(dict(Name=label, Profile=name, Cpu=cpu, Vtor=vtor, Optimization=opt,
                                  LTO=lto, Archive=archive, Consumer="context", Kind="Positive", Status="STAGED"))
        need(len(self.rows) == len({r["Name"] for r in self.rows}) == 28, "Literal 28 final-ELF pairs")
        self.report["ExpectedPairs"] = 28
        self.report["ExpectedElfs"] = 56
        self.report["ExpectedCompiledControls"] = 84
        save(self.build / "staged.json", self.rows)

    def ordinary_parity(self):
        for opt in ("O0", "Og", "O2", "Os", "O3"):
            directory = self.build / ("paired-objects-" + opt)
            row = dict(Optimization=opt, Status="STAGED")
            self.normal_pairs.append(row)
            result = self.command([self.tools["powershell"], "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                self.repo / "tools/freertos_asm_parity.ps1", "-ArmGcc", self.a.gcc, "-CmsisCore", self.a.cmsis,
                "-FreeRtosKernel", self.a.freertos, "-Optimization", "-" + opt, "-BuildRoot", directory,
                "-Cm0NonMpuOnly", "-KeepBuild"], "existing bounded paired objects " + opt, timeout=300)
            need("CM0_NONMPU_FOCUSED_PARITY_PASS" in result["Stdout"], "Missing bounded paired-object PASS")
            receipt = directory / "CM0-NONMPU-FOCUSED/result.json"
            data = json.loads(receipt.read_text(encoding="utf-8-sig"))
            need(data["Status"] == "PASS" and data["Configurations"] == 2 and data["CompiledObjects"] == 4 and
                 len(data["Mechanisms"]) == 6 and data["SourceDrift"] == 0, "Exact bounded paired-object coverage")
            row.update(Status="PASS", Receipt=str(receipt), Sha256=digest(receipt), Command=result["Record"])
        for opt in ("O2", "Os"):
            directory = self.build / ("legacy-cm0-" + opt)
            result = self.command([self.tools["powershell"], "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                self.repo / "tools/freertos_asm_parity.ps1", "-ArmGcc", self.a.gcc, "-CmsisCore", self.a.cmsis,
                "-FreeRtosKernel", self.a.freertos, "-Optimization", "-" + opt, "-BuildRoot", directory,
                "-Cm0Only", "-KeepBuild"], "unchanged old CM0-focused O2/Os contract", timeout=300)
            need("CM0_FOCUSED_PARITY_PASS" in result["Stdout"], "Old focused marker changed")
            receipt = directory / "CM0-FOCUSED/result.json"
            data = json.loads(receipt.read_text(encoding="utf-8-sig"))
            need(data["Status"] == "PASS" and data["Configurations"] == 3 and data["CompiledObjects"] == 6 and
                 len(data["Mechanisms"]) == 18 and data["SourceDrift"] == 0, "Old focused inventory changed")
            self.legacy_pairs.append(dict(Optimization=opt, Status="PASS", Receipt=str(receipt), Sha256=digest(receipt)))

    def compile_objects(self, sources, flags, directory, providers, reference=False, mutation=None):
        objects, maps = [], []
        for index, original in enumerate(sources):
            source = self.mutate(original, mutation, directory) if mutation and original == providers[0] else original
            need(str(original.resolve()) in self.inputs, "Unenrolled original source: " + str(original))
            obj = directory / ("%02d-" % index + original.stem + ".o")
            dep = obj.with_suffix(".d")
            result = self.command([self.tools["gcc"], *flags, "-I" + str(original.parent), "-MD", "-MF", dep,
                                   "-c", source, "-o", obj], "compile actual " + original.name)
            for line in result["Stderr"].splitlines():
                if "warning:" in line:
                    need("Selected ARMv6-M port has no SCB->VTOR; falling back to base table at 0x00000000." in line,
                         "Unexpected compiler warning: " + result["Record"])
            self.dependency_check(dep)
            if reference:
                dependencies = self.dependencies[-1]["Dependencies"]
                need(all(not Path(d["Path"]).is_relative_to(self.repo) or
                         Path(d["Path"]).is_relative_to(HERE / "reference") for d in dependencies),
                     "Pinned reference consumed project/CMSIS declarations")
            if "-flto" in flags and original.suffix == ".c":
                with obj.open("rb") as stream:
                    image = self.ELFFile(stream)
                    need(any(s.name.startswith(".gnu.lto_") for s in image.iter_sections()) and
                         not any(s.name.startswith(".text") and s["sh_size"] for s in image.iter_sections()),
                         "LTO input is not slim IR; no fat/native fallback")
            objects.append(obj)
            maps.append(dict(Original=str(original), Compiled=str(source), SourceSha256=digest(source),
                Object=str(obj), ObjectSha256=digest(obj), Command=result["Record"],
                Role="port" if original in providers else "common" if original.is_relative_to(self.repo / "context") else "fixture"))
        save(directory / "source-object-map.json", maps)
        return objects, maps

    def mutate(self, source, name, directory):
        text = source.read_text()
        anchor = "void PendSV_Handler(void)"
        need(text.count(anchor) == 1, "Actual PendSV mutation anchor changed")
        head, body = text.split(anchor)
        if name == "restore-r9":
            pattern, replacement = r'"mov\s+r9,\s*r5\s+\\n"', '"nop \\n"'
        elif name == "mask-restore":
            pattern, replacement = r"\bfiber_portASM_EXIT_SCHEDULER_CRITICAL\b", '"nop \\n"'
        else:
            pattern, replacement = r'"subs\s+r0,\s*#%c\[swbytes\]\s+\\n"', '"subs r0, #32 \\n"'
        matches = list(re.finditer(pattern, body))
        need(len(matches) == (2 if name == "save-stride" else 1), "Actual mutation count changed: " + name)
        match = matches[0]
        changed = head + anchor + body[:match.start()] + replacement + body[match.end():]
        target = directory / "mutant-fiber_port.c"
        target.write_text(changed, encoding="ascii", newline="\n")
        self.generated[str(target.resolve())] = dict(Path=str(target.resolve()), Sha256=digest(target), Role="CompiledMutation")
        save(directory / "mutation.json", dict(Name=name, Original=str(source), OriginalSha256=digest(source),
                                               Compiled=str(target), CompiledSha256=digest(target)))
        return target

    def link(self, row, directory, objects, archived):
        if row["Archive"]:
            archive = directory / "libactualport.a"
            self.command([self.tools["ar"], "rcs", archive, *archived], "archive actual selected providers")
            linked = [o for o in objects if o not in archived] + [archive]
        else:
            linked = objects
        elf = directory / "runtime.elf"
        flags = ["-mcpu=" + row["Cpu"], "-mthumb", "-mfloat-abi=soft", "-" + row["Optimization"], "-nostdlib"]
        if row["LTO"]:
            flags += ["-flto", "-save-temps=obj"]
        arguments = [*flags, "-Wl,--gc-sections,--no-undefined,--fatal-warnings,-z,noexecstack",
                     "-T", HERE / "link.ld", "-Wl,-Map=" + str(directory / "runtime.map"), *linked, "-o", elf]
        if row["LTO"]:
            trace = self.command([self.tools["gcc"], "-###", *arguments], "actual link LTO plugin provenance")
            matches = re.findall(r'-plugin(?:\s+|=)(?:"([^"\n]+)"|([^\s]+))', trace["Stderr"])
            paths = [Path((quoted or bare).replace("\\\\", "\\")).resolve(strict=True) for quoted, bare in matches]
            need(paths == [self.plugin], "Used driver LTO plugin does not match queried/hashed plugin")
        self.command([self.tools["gcc"], *arguments], "link actual final executable")
        for tool, args, filename in (("objdump", ["-drwC", "-Mreg-names-std"], "runtime.dis"),
                                    ("readelf", ["-hASsrW", "-A", "-l"], "runtime.readelf.txt"),
                                    ("nm", ["-a"], "runtime.nm.txt")):
            text = self.command([self.tools[tool], *args, elf], "inspect final executable")["Stdout"]
            (directory / filename).write_text(text, encoding="ascii")
        check.elf_basics(elf, self.ELFFile)
        attrs = (directory / "runtime.readelf.txt").read_text()
        need(re.search(r"Tag_CPU_arch: v6S?-M\b", attrs) and "Tag_THUMB_ISA_use: Thumb-1" in attrs and
             not re.search(r"Tag_(FP_arch|MVE_arch|Advanced_SIMD_arch|ABI_VFP_args|PAC_extension|BTI_extension):", attrs),
             "Wrong final CPU/Thumb/FP attributes")
        return elf

    def reference_owners(self, maps, directory):
        expected = {name: "portasm.c" for name in ("SVC_Handler", "PendSV_Handler", "vStartFirstTask", "vRestoreContextOfFirstTask")}
        expected.update({name: "port.c" for name in ("pxPortInitialiseStack", "xPortStartScheduler", "SysTick_Handler", "vPortSVCHandler_C")})
        found = {name: [] for name in expected}
        for record in maps:
            output = self.command([self.tools["nm"], "-P", "--defined-only", record["Object"]], "prelink actual upstream ownership")
            for line in output["Stdout"].splitlines():
                fields = line.split()
                if fields and fields[0] in found:
                    found[fields[0]].append(dict(Source=record["Original"], NmType=fields[1], Object=record["Object"]))
        owners = {}
        port = Path(self.a.freertos) / "portable/GCC/ARM_CM0"
        for name, filename in expected.items():
            need(len(found[name]) == 1 and found[name][0]["NmType"] == "T" and
                 Path(found[name][0]["Source"]) == port / filename, "Actual upstream strong prelink owner: " + name)
            owners[name] = found[name][0]
        save(directory / "reference-owners.json", owners)
        return owners

    def build_side(self, row, reference, mutation=None):
        directory = self.build / "pairs" / row["Name"] / ("reference" if reference else mutation or "fiber")
        directory.mkdir(parents=True)
        flags = ["-mcpu=" + row["Cpu"], *COMPILE, "-" + row["Optimization"]]
        if row["LTO"]:
            flags.append("-flto")
        if reference:
            port = Path(self.a.freertos) / "portable/GCC/ARM_CM0"
            ref = HERE / "reference"
            providers = [port / n for n in ("portasm.c", "port.c")]
            sources = [ref / n for n in ("main.c", "providers.c", "startup.S")] + providers
            flags += ["-I" + str(ref), "-I" + str(Path(self.a.freertos) / "include"), "-I" + str(port)]
        else:
            reader = load("cm0_freeze_runtime_sources", self.repo / "tools/runtime_sources.py")
            sources = list(reader.get_runtime_source_paths(self.repo, ("engine", "state", "panic")))
            port = self.repo / "fiber/port/ARM_CM0"
            providers = [port / n for n in ("fiber_port.c", "fiber_port_boot.c", "fiber_port_exception.c")]
            sources += providers + [HERE / "application.c", HERE / "startup.S", self.repo / "fiber/port/fiber_port_context_cohort_expectation.c"]
            flags += ["-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV6M=1", "-DFREEZE_CM0PLUS=" + str(row["Vtor"]),
                "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=1", "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1",
                "-DFIBER_STACK_CANARY=1", "-DFIBER_REWIND_MSP=1", "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=0",
                "-I" + str(HERE), "-I" + str(port), "-I" + str(self.repo / "fiber"), "-I" + str(self.repo), "-I" + self.a.cmsis]
        objects, maps = self.compile_objects(sources, flags, directory, providers, reference, mutation)
        proof = None
        if reference:
            owners = self.reference_owners(maps, directory)
        else:
            self.audit_provider([Path(m["Object"]) for m in maps if m["Role"] == "port"], directory)
            state = reader.get_runtime_source_paths(self.repo, ("state",))
            need(len(state) == 1, "Exactly one actual Context state owner")
            proof = self.audit_common_private(maps, {common.SLOT: str(state[0]), common.REVERSE: str(state[0]), common.CONFIG_ANCHOR: None}, directory)
        elf = self.link(row, directory, objects, [Path(m["Object"]) for m in maps if m["Role"] == "port"])
        if reference:
            audit = check.reference_elf(elf, self.ELFFile, owners, row["LTO"])
            disassembly = (directory / "runtime.dis").read_text()
            for name in ("vTaskSwitchContext", "xTaskIncrementTick", "reference_assert_failed", "reference_reset_forbidden"):
                check.ordered(check.body(disassembly, name), [("REFERENCE.FAILSTOP", r"\b(?:bl|b(?:\.n|\.w)?)\s+[^\n]*<reference_fail_stop>")])
            need(re.search(r"\budf[^\n]*#(?:90|0x5a)\b", check.body(disassembly, "reference_fail_stop")), "Reference boundary lacks UDF #90")
        else:
            audit = self.audit_elf(elf, row, proof)
            expected = ("fiber_port_context_cohort_armv6m_p0x434D3030u_l0x00010001u_f0_e0_h0_j0_v" + str(row["Vtor"]) +
                        "_d0_r0_z8u_y0_w1_g2_u00000000_i0_o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0")
            need(audit["RuntimeCohort"] == expected and audit["StorageCohort"] == "fiber_port_storage_cohort_arm_cm0_v1_r0",
                 "Exact CM0/CM0+ private/storage cohort")
        audit.update(Executed=False, Scope=__doc__)
        save(directory / "elf-audit.json", audit)
        return elf, (directory / "runtime.dis").read_text()

    def run_pair(self, row):
        reference, ref_dis = self.build_side(row, True)
        fiber, fiber_dis = self.build_side(row, False)
        row.update(ReferenceElf=str(reference), ReferenceSha256=digest(reference), FiberElf=str(fiber), FiberSha256=digest(fiber))
        row["ReferenceMechanisms"] = check.mechanisms(ref_dis, True)
        row["FiberMechanisms"] = check.mechanisms(fiber_dis, False)
        for name, code in MUTANTS.items():
            control = dict(Pair=row["Name"], Mutant=name, ExpectedRejection=code, Status="STAGED")
            self.controls.append(control)
            elf, disassembly = self.build_side(row, False, name)
            try:
                check.mechanisms(disassembly, False)
            except check.Rejection as error:
                need(error.code == code, "Wrong compiled-control rejection: " + str(error))
                control.update(Status="PASS", Elf=str(elf), ElfSha256=digest(elf), Diagnostic=str(error))
            else:
                raise RuntimeError("Actual compiled mutation survived: " + name)
            save(elf.parent / "control.json", control)
        row["Status"] = "PASS"
        save(self.build / "pairs" / row["Name"] / "pair.json", row)
        print("PASS bounded final-ELF pair " + row["Name"], flush=True)

    def finish(self, error):
        self.report["Error"] = error
        if not error:
            self.reference_identity()
            self.check_repository_inventory()
            need(len(self.rows) == 28 and all(r["Status"] == "PASS" for r in self.rows), "Incomplete final-ELF pairs")
            need(len(self.controls) == 84 and all(r["Status"] == "PASS" for r in self.controls), "Incomplete compiled controls")
            need(len(self.normal_pairs) == 5 and all(r["Status"] == "PASS" for r in self.normal_pairs), "Incomplete ordinary parity")
            need(len(self.legacy_pairs) == 2 and all(r["Status"] == "PASS" for r in self.legacy_pairs), "Incomplete legacy focused parity")
            mirror = json.loads((self.build / "input-mirror.json").read_text())
            need(all(digest(r["Copy"]) == r["Sha256"] for r in mirror), "Captured input bytes changed")
        drift = self.input_drift()
        self.report.update(InputDrift=drift, InputCount=len(self.inputs), FinalElfPairs=sum(r["Status"] == "PASS" for r in self.rows),
                           CompiledControls=sum(r["Status"] == "PASS" for r in self.controls))
        save(self.build / "inputs.after.json", [dict(Path=p, Sha256=digest(p) if Path(p).is_file() else None) for p in self.inputs])
        save(self.build / "dependencies.json", self.dependencies)
        save(self.build / "generated-inputs.json", list(self.generated.values()))
        save(self.build / "results.json", self.report)
        self.artifact_manifest(verify=True)
        if not error:
            need(not drift and not self.input_drift(), "Input/generated bytes changed; no qualification")
            self.report.update(Verdict="PASS", CompleteSuite=True, ArtifactsVerifiedBeforePass=True)
            save(self.build / "results.json", self.report)
            self.artifact_manifest(verify=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "gcc", "cmsis", "freertos", "build-root"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    suite = Suite(args)
    print("CM0 freeze parity evidence: " + str(suite.build), flush=True)
    error = None
    try:
        suite.stage()
        suite.preflight()
        suite.ordinary_parity()
        for row in suite.rows:
            row["Status"] = "RUNNING"
            suite.run_pair(row)
    except Exception as failure:
        error = str(failure)
        suite.report["Traceback"] = traceback.format_exc()
    try:
        suite.finish(error)
    except Exception as failure:
        error = str(failure)
        suite.report.update(Verdict="FAIL", CompleteSuite=False, Error=error, FinalizationTraceback=traceback.format_exc())
        save(suite.build / "results.json", suite.report)
        suite.artifact_manifest()
    if error:
        raise SystemExit("FAIL CM0 freeze parity: " + error + "; " + str(suite.build))
    print("PASS CM0/CM0+ bounded freeze parity: " + str(suite.build), flush=True)


if __name__ == "__main__":
    main()
