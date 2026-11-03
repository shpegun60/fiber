"""Development-only CM4 MPU pilot. Compilation is the default; execution is opt-in."""
from __future__ import annotations
import argparse
from collections import Counter
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fp = load("cm4_mpu_pilot_fp_tools", HERE.parent / "classic_fp_context_runtime/run.py")
common = fp.common
need, save, digest = common.need, common.save, common.digest
CPU = ("-mcpu=cortex-m4", "-mthumb", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard")
PORT = "fiber/port/ARM_CM4_MPU"
STORAGE = "fiber_port_storage_cohort_arm_cm4_mpu_v1_r8"
PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
EXPECTED_ROWS = (("context", 0), ("context", 1), ("context", 2),
                 ("fiber", 0), ("fiber", 1), ("fiber", 2))


def semihost_lines(actual):
    if (type(actual) is not dict or type(actual.get("Exit")) is not int or actual["Exit"] != 0 or
            actual.get("TimedOut") is not False or
            not all(type(actual.get(k)) is str for k in ("Stdout", "Stderr")) or actual["Stdout"] != ""):
        return None
    return actual["Stderr"].splitlines()


def frame_in_worker_a(psp, xpsr):
    frame_bytes = 32 + (4 if xpsr & 0x200 else 0)
    return (psp % 8 == 0 and 0x20002000 <= psp <= 0x20003000 - frame_bytes and
            xpsr & 0x010001FF == 0x01000000)


def terminal(actual, consumer, case, addresses):
    lines = semihost_lines(actual)
    if lines is None or consumer not in ("context", "fiber"):
        return False
    label = "CONTEXT" if consumer == "context" else "FIBERV1"
    if len(lines) != 2 or lines[1] != "PASS:CM4-MPU:" + label:
        return False
    if case == 0:
        match = re.fullmatch(r"RETURN:CM4-MPU:CODE=00000052:IPSR=0000000B:PC=([0-9A-F]{8}):PSP=([0-9A-F]{8}):XPSR=([0-9A-F]{8}):CALLS=00000008:SELF=00000001:CROSS=00000006", lines[0])
        return bool(match and int(match[1], 16) == addresses["return"] and
                    frame_in_worker_a(int(match[2], 16), int(match[3], 16)))
    if case not in (1, 2):
        return False
    match = re.fullmatch(r"FAULT:CM4-MPU:IPSR=00000004:EXC=FFFFFFFD:CFSR=00000082:HFSR=00000000:MMFAR=([0-9A-F]{8}):PC=([0-9A-F]{8}):PSP=([0-9A-F]{8}):XPSR=([0-9A-F]{8})", lines[0])
    return bool(match and int(match[1], 16) == (0x20000000 if case == 1 else 0x20004080) and
                int(match[2], 16) == addresses["slot" if case == 1 else "peer"] and
                frame_in_worker_a(int(match[3], 16), int(match[4], 16)))


def model_terminal(actual):
    lines = semihost_lines(actual)
    need(lines is not None, "Model probe terminal transport/status")
    need(len(lines) == 2 and lines[1] == "PASS:CM4-MPU:MODEL", "Model probe terminal grammar")
    match = re.fullmatch(r"MODEL:CM4-MPU:CPUID=([0-9A-F]{8}):MPU_TYPE=([0-9A-F]{8}):NVIC_MASK=([0-9A-F]{8}):MVFR0=([0-9A-F]{8}):MPU_CTRL=([0-9A-F]{8})", lines[0])
    need(match is not None, "Model probe field grammar")
    facts = dict(zip(("CPUID", "MPU_TYPE", "NVIC_MASK", "MVFR0", "MPU_CTRL"), (int(v, 16) for v in match.groups())))
    need(facts["CPUID"] & 0xFF0FFFF0 == 0x410FC240 and facts["MPU_TYPE"] == 0x800 and
         facts["NVIC_MASK"] == 0xFF and facts["MVFR0"] & 0xFFF == 0x21 and facts["MPU_CTRL"] == 0,
         "Actual AN386 facts do not admit the pilot manifest")
    return facts


def terminal_controls():
    addresses = dict(return_=0x1010, slot=0x1020, peer=0x1030)
    addresses["return"] = addresses.pop("return_")
    rows = []
    for consumer in ("context", "fiber"):
        label = "CONTEXT" if consumer == "context" else "FIBERV1"
        for case in range(3):
            line = ("RETURN:CM4-MPU:CODE=00000052:IPSR=0000000B:PC=00001010:PSP=20002FC0:XPSR=01000000:CALLS=00000008:SELF=00000001:CROSS=00000006" if case == 0 else
                    "FAULT:CM4-MPU:IPSR=00000004:EXC=FFFFFFFD:CFSR=00000082:HFSR=00000000:MMFAR=" +
                    ("20000000:PC=00001020" if case == 1 else "20004080:PC=00001030") + ":PSP=20002FC0:XPSR=01000000")
            good = dict(Exit=0, TimedOut=False, Stdout="", Stderr=line + "\nPASS:CM4-MPU:" + label + "\n")
            candidates = [("positive", good, True)]
            for name, field, value in (("timeout", "TimedOut", True), ("exit", "Exit", 66), ("bool-exit", "Exit", False)):
                candidates.append((name, dict(good, **{field: value}), False))
            for name, before, after in (("wrong-origin", "IPSR=0000000B" if case == 0 else "IPSR=00000004", "IPSR=00000003"),
                    ("wrong-pc", "PC=00001010" if case == 0 else "PC=00001020" if case == 1 else "PC=00001030", "PC=00001040"),
                    ("bad-psp", "PSP=20002FC0", "PSP=20008000"), ("generic-fault", line, "HardFault"),
                    ("extra-output", line, "noise\n" + line), ("case", "CM4-MPU", "cm4-mpu")):
                candidates.append((name, dict(good, Stderr=good["Stderr"].replace(before, after)), False))
            for name, frame_psp, frame_xpsr, accepted in (
                    ("upper-unpadded", "20002FE0", "01000000", True),
                    ("upper-padded-overflow", "20002FE0", "01000200", False),
                    ("upper-padded-contained", "20002FD8", "01000200", True),
                    ("upper-basic-overflow", "20002FE8", "01000000", False),
                    ("padded-misaligned", "20002FDC", "01000200", False),
                    ("thumb-clear", "20002FD8", "00000200", False),
                    ("stacked-handler", "20002FD8", "0100020B", False)):
                changed = good["Stderr"].replace("PSP=20002FC0", "PSP=" + frame_psp).replace("XPSR=01000000", "XPSR=" + frame_xpsr)
                candidates.append((name, dict(good, Stderr=changed), accepted))
            split = good["Stderr"].index("\n") + 1
            candidates += [("all-stdout", dict(good, Stdout=good["Stderr"], Stderr=""), False),
                           ("split-lines", dict(good, Stdout=good["Stderr"][:split], Stderr=good["Stderr"][split:]), False),
                           ("split-midline", dict(good, Stdout=good["Stderr"][:7], Stderr=good["Stderr"][7:]), False),
                           ("stdout-type", dict(good, Stdout=None), False),
                           ("stderr-type", dict(good, Stderr=[]), False)]
            if case:
                candidates += [("status", dict(good, Stderr=good["Stderr"].replace("CFSR=00000082", "CFSR=00000002")), False),
                               ("thread-origin", dict(good, Stderr=good["Stderr"].replace("EXC=FFFFFFFD", "EXC=FFFFFFF9")), False)]
            for name, actual, accepted in candidates:
                need(terminal(actual, consumer, case, addresses) is accepted, "Terminal discriminator failed: " + name)
                rows.append(dict(Consumer=consumer, Case=case, Name=name, Accepted=accepted))
    need(len(rows) == 140 and sum(r["Accepted"] for r in rows) == 18, "Literal terminal boundary/channel controls")
    return dict(Controls=rows, Scope="Synthetic parser discriminators, not firmware execution")


def model_controls():
    line = "MODEL:CM4-MPU:CPUID=410FC241:MPU_TYPE=00000800:NVIC_MASK=000000FF:MVFR0=10110021:MPU_CTRL=00000000\nPASS:CM4-MPU:MODEL\n"
    good = dict(Exit=0, TimedOut=False, Stdout="", Stderr=line)
    cases = [("positive", good, True), ("timeout", dict(good, TimedOut=True), False),
             ("bool-exit", dict(good, Exit=False), False), ("fault-exit", dict(good, Exit=70), False)]
    split = line.index("\n") + 1
    cases += [("all-stdout", dict(good, Stdout=line, Stderr=""), False),
              ("split-lines", dict(good, Stdout=line[:split], Stderr=line[split:]), False),
              ("split-midline", dict(good, Stdout=line[:7], Stderr=line[7:]), False),
              ("stdout-type", dict(good, Stdout=None), False),
              ("stderr-type", dict(good, Stderr=[]), False)]
    for name, old, new in (("wrong-cpu", "410FC241", "411FC271"), ("regions", "00000800", "00001000"),
                          ("priority", "000000FF", "000000F0"), ("fpu", "10110021", "00000000"),
                          ("mpu-enabled", "MPU_CTRL=00000000", "MPU_CTRL=00000001"),
                          ("extra-output", "PASS:", "noise\nPASS:")):
        cases.append((name, dict(good, Stderr=line.replace(old, new)), False))
    for name, actual, accepted in cases:
        try:
            model_terminal(actual)
            valid = True
        except RuntimeError:
            valid = False
        need(valid is accepted, "Model discriminator failed: " + name)
    need(len(cases) == 15, "Literal model terminal/channel controls")
    return [dict(Name=n, Accepted=a) for n, _, a in cases]


def validate_closing_contract(report, execute):
    need(type(execute) is bool and type(report) is dict, "closing: request/report types")
    verdict = "PILOT-PASS" if execute else "COMPILE-PREFLIGHT-PASS"
    execution = "PILOT_ONLY" if execute else "NOT_RUN"
    need(type(report.get("Verdict")) is str and report["Verdict"] == verdict and
         type(report.get("Execution")) is str and report["Execution"] == execution and
         type(report.get("CompleteSuite")) is bool and report["CompleteSuite"] is False and
         type(report.get("CompileOnly")) is bool and report["CompileOnly"] is (not execute), "closing: request-bound mode")
    need(type(report.get("ArtifactsVerifiedBeforePass")) is bool and report["ArtifactsVerifiedBeforePass"] is True,
         "closing: artifacts not verified before pass")
    rows = report.get("Rows")
    need(type(rows) is list and len(rows) == 6, "closing: six ordered rows")
    for row, (consumer, case) in zip(rows, EXPECTED_ROWS):
        need(type(row) is dict and type(row.get("Consumer")) is str and row["Consumer"] == consumer and
             type(row.get("Case")) is int and row["Case"] == case, "closing: exact ordered consumer/case")
        need(type(row.get("Status")) is str and row["Status"] == ("PASS" if execute else "COMPILED") and
             type(row.get("Executed")) is bool and row["Executed"] is execute, "closing: row execution state")
        if execute:
            need(type(row.get("Audit")) is dict and type(row["Audit"].get("Addresses")) is dict and
                 terminal(row.get("Actual"), consumer, case, row["Audit"]["Addresses"]), "closing: row terminal evidence")
        else:
            need("Actual" not in row, "closing: compile row has execution evidence")
    need(len({(r["Consumer"], r["Case"]) for r in rows}) == 6, "closing: duplicate rows")
    model = report.get("ModelProbe")
    need(type(model) is dict and model.get("Name") == "model" and model.get("Consumer") == "context" and
         type(model.get("Case")) is int and model["Case"] == 0, "closing: explicit model identity")
    need(type(model.get("Status")) is str and model["Status"] == ("PASS" if execute else "COMPILED") and
         type(model.get("Executed")) is bool and model["Executed"] is execute, "closing: model execution state")
    if execute:
        facts = model_terminal(model.get("Actual"))
        need(type(report.get("ObservedModel")) is dict and all(type(v) is int for v in report["ObservedModel"].values()) and
             report["ObservedModel"] == facts,
             "closing: observed model evidence")
    else:
        need("Actual" not in model and "ObservedModel" not in report, "closing: compile model has execution evidence")


def closing_controls():
    addresses = {"return": 0x1010, "slot": 0x1020, "peer": 0x1030}
    model_actual = dict(Exit=0, TimedOut=False, Stdout="", Stderr="MODEL:CM4-MPU:CPUID=410FC241:MPU_TYPE=00000800:NVIC_MASK=000000FF:MVFR0=10110021:MPU_CTRL=00000000\nPASS:CM4-MPU:MODEL\n")
    records = []
    def record(name, request, report, accepted):
        try:
            validate_closing_contract(report, request)
            valid = True
        except RuntimeError:
            valid = False
        need(valid is accepted, "Closing discriminator failed: " + name)
        records.append(dict(Name=name, ExecutePilot=request, Accepted=accepted, Receipt=report))
    for execute in (False, True):
        base = dict(Verdict="PILOT-PASS" if execute else "COMPILE-PREFLIGHT-PASS", CompleteSuite=False,
                    CompileOnly=not execute, Execution="PILOT_ONLY" if execute else "NOT_RUN", Rows=[], ArtifactsVerifiedBeforePass=True,
                    ModelProbe=dict(Name="model", Consumer="context", Case=0, Status="PASS" if execute else "COMPILED", Executed=execute))
        for consumer, case in EXPECTED_ROWS:
            row = dict(Consumer=consumer, Case=case, Status="PASS" if execute else "COMPILED", Executed=execute,
                       Audit=dict(Addresses=dict(addresses)))
            if execute:
                line = ("RETURN:CM4-MPU:CODE=00000052:IPSR=0000000B:PC=00001010:PSP=20002FC0:XPSR=01000000:CALLS=00000008:SELF=00000001:CROSS=00000006" if case == 0 else
                        "FAULT:CM4-MPU:IPSR=00000004:EXC=FFFFFFFD:CFSR=00000082:HFSR=00000000:MMFAR=" +
                        ("20000000:PC=00001020" if case == 1 else "20004080:PC=00001030") + ":PSP=20002FC0:XPSR=01000000")
                row["Actual"] = dict(Exit=0, TimedOut=False, Stdout="", Stderr=line + "\nPASS:CM4-MPU:" + ("CONTEXT" if consumer == "context" else "FIBERV1") + "\n")
            base["Rows"].append(row)
        if execute:
            base["ModelProbe"]["Actual"] = deepcopy(model_actual)
            base["ObservedModel"] = model_terminal(model_actual)
        prefix = "execute-" if execute else "compile-"
        record(prefix + "positive", execute, deepcopy(base), True)
        mutations = (
            ("verdict", lambda r: r.update(Verdict="COMPILE-PREFLIGHT-PASS" if execute else "PILOT-PASS")),
            ("execution", lambda r: r.update(Execution="NOT_RUN" if execute else "PILOT_ONLY")),
            ("completion", lambda r: r.update(CompleteSuite=True)),
            ("completion-type", lambda r: r.update(CompleteSuite="false")),
            ("compile-only", lambda r: r.update(CompileOnly=execute)),
            ("artifacts-unverified", lambda r: r.update(ArtifactsVerifiedBeforePass=False)),
            ("artifacts-type", lambda r: r.update(ArtifactsVerifiedBeforePass="true")),
            ("artifacts-missing", lambda r: r.pop("ArtifactsVerifiedBeforePass")),
            ("order", lambda r: r["Rows"].reverse()),
            ("duplicate", lambda r: r["Rows"].__setitem__(1, deepcopy(r["Rows"][0]))),
            ("missing", lambda r: r["Rows"].pop()),
            ("case-bool", lambda r: r["Rows"][0].update(Case=False)),
            ("consumer", lambda r: r["Rows"][0].update(Consumer="CONTEXT")),
            ("row-status", lambda r: r["Rows"][0].update(Status="COMPILED" if execute else "PASS")),
            ("row-executed", lambda r: r["Rows"][0].update(Executed=not execute)),
            ("row-executed-type", lambda r: r["Rows"][0].update(Executed="true")),
            ("model-status", lambda r: r["ModelProbe"].update(Status="COMPILED" if execute else "PASS")),
            ("model-executed", lambda r: r["ModelProbe"].update(Executed=not execute)),
            ("model-executed-type", lambda r: r["ModelProbe"].update(Executed="true")))
        for name, mutate in mutations:
            altered = deepcopy(base); mutate(altered); record(prefix + name, execute, altered, False)
        for name in ("row", "model"):
            altered = deepcopy(base)
            target = altered["Rows"][0] if name == "row" else altered["ModelProbe"]
            if execute:
                target.pop("Actual")
            else:
                target["Actual"] = deepcopy(model_actual)
            record(prefix + name + "-actual", execute, altered, False)
        altered = deepcopy(base)
        altered["ObservedModel"] = {}
        record(prefix + "observed-model", execute, altered, False)
        if execute:
            for index in range(7):
                altered = deepcopy(base)
                target = altered["ModelProbe"] if index == 6 else altered["Rows"][index]
                target.update(Status="COMPILED", Executed=False)
                target.pop("Actual")
                record("execute-skipped-" + ("model" if index == 6 else str(index)), True, altered, False)
    need(len(records) == 53 and sum(r["Accepted"] for r in records) == 2, "Literal request-bound closing controls")
    return dict(Controls=records, Scope="Synthetic orchestration/receipt mutations, not target executions or CPU evidence")


class Pilot(common.Suite):
    def __init__(self, args):
        args.development_smoke = True
        super().__init__(args)
        self.fixture = HERE
        self.profile = SimpleNamespace(machine="mps2-an386")
        self.report.update(CompleteSuite=False, Scope="Development-only ARM_CM4_MPU eight-region basic-frame AN386 pilot; no FP-active, CM7, 16-region, softfp, board or full-grid claim",
                           Execution="NOT_RUN", Profile="ARM_CM4_MPU", CompileOnly=not args.execute_pilot,
                           ExistingReferenceMechanismGate="tools/freertos_asm_parity.ps1 ARM_CM4_MPU SVC-dispatch/first-restore/PendSV-MPU; not replayed here",
                           NewFinalReferenceParity=False, ReferenceExecuted=False)

    def repo_inventory(self):
        roots = (self.repo / "context", self.repo / "fiber", self.repo / "fiber/port", self.repo / PORT,
                 self.repo / "fiber/lifecycle")
        paths = {p for root in roots for p in root.glob("*.h")}
        paths.update(self.fixture.glob("*"))
        paths.update(self.repo / n for n in ("basic_types.h", "mcu_core.h", "tools/runtime_sources.json", "tools/runtime_sources.py",
            "tools/runtime_sources.ps1", "tools/test_classic_cm4_mpu_context_runtime.ps1", "tools/freertos_asm_parity.ps1",
            "tools/fixtures/classic_context_runtime/run.py", "tools/fixtures/classic_context_runtime/qemu.sh",
            "tools/fixtures/classic_fp_context_runtime/run.py", "tools/fixtures/arm_control/qemu.sh", "fiber/port/ARM_CM4_MPU/FREERTOS_PARITY.md"))
        reader = load("cm4_mpu_pilot_sources", self.repo / "tools/runtime_sources.py")
        paths.update(reader.get_runtime_source_inputs(self.repo, ("engine", "state", "panic", "optional_configuration")))
        paths.update(self.repo / n for n in (PORT + "/fiber_port.c", PORT + "/fiber_port_boot.c", "fiber/lifecycle/fiber_v1.c",
                                            "fiber/port/fiber_port_context_cohort_expectation.c"))
        for p in sorted(paths):
            if p.is_file():
                self.enroll(p, "SelectedSourceClosure")
        self.reader = reader

    def inspect_qemu(self, name):
        if not self.a.execute_pilot:
            return dict(Execution="NOT_RUN", Reason="Compile preflight must not invoke QEMU or WSL")
        return fp.Suite.inspect_qemu(self, name)

    def preflight(self):
        super().preflight()
        native_nm = (self.tools["gcc"].parent / "arm-none-eabi-nm.exe").resolve(strict=True)
        self.enroll(native_nm, "Tool")
        self.tools["nm"] = native_nm
        self.report["NativeNm"] = dict(Path=str(native_nm), Sha256=digest(native_nm), Scope="Native objects only; no gcc-nm delegation or LTO claim")
        save(self.build / "inputs.before.json", list(self.inputs.values()))

    def flags(self, consumer, case, model=False):
        return [*CPU, *fp.COMPILE, "-O2", "-mgeneral-regs-only", "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV7EM=1",
                "-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=8", "-DFIBER_SCHEDULER_BASEPRI=0x80u", "-DFIBER_FPU_LAZY=0",
                "-DFIBER_STACK_CANARY=1", "-DFIBER_REWIND_MSP=1", "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=0",
                "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=0", "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=0",
                "-DPILOT_MODEL_PROBE=" + str(int(model)), "-DPILOT_FIBER=" + str(int(consumer == "fiber")), "-DPILOT_CASE=" + str(case),
                "-I" + str(self.fixture), "-I" + str(self.repo / PORT), "-I" + str(self.repo), "-I" + str(self.repo / "fiber"), "-I" + self.a.cmsis]

    def build_image(self, consumer, case, model=False):
        name = "model" if model else consumer + "-case" + str(case)
        directory = self.build / name
        directory.mkdir()
        roles = ("engine", "state", "panic") + (("optional_configuration",) if consumer == "fiber" else ())
        providers = [self.repo / PORT / n for n in ("fiber_port.c", "fiber_port_boot.c")]
        sources = [] if model else list(self.reader.get_runtime_source_paths(self.repo, roles))
        if consumer == "fiber" and not model:
            sources.append(self.repo / "fiber/lifecycle/fiber_v1.c")
        if not model:
            sources += providers + [self.repo / "fiber/port/fiber_port_context_cohort_expectation.c", self.fixture / "access.S"]
        sources += [self.fixture / n for n in ("startup.S", "transport.c", "model.c" if model else "application.c")]
        objects, maps = fp.Suite.compile_objects(self, sources, directory, self.flags(consumer, case, model), providers)
        if not model:
            state = self.reader.get_runtime_source_paths(self.repo, ("state",))[0]
            configuration = self.reader.get_runtime_source_paths(self.repo, ("optional_configuration",))[0]
            self.audit_common_private(maps, {common.SLOT: str(state), common.REVERSE: str(state), common.CONFIG_ANCHOR: str(configuration) if consumer == "fiber" else None}, directory)
            self.audit_provider([Path(m["Object"]) for m in maps if m["Role"] == "port"], directory)
            for record in maps:
                if record["Role"] in ("port", "expectation"):
                    text = self.command([self.tools["objdump"], "-drwC", "-Mreg-names-std", record["Object"]], "actual provider/expectation relocations")["Stdout"]
                    Path(record["Object"]).with_suffix(".dis").write_text(text, encoding="ascii")
        elf = directory / "runtime.elf"
        self.command([self.tools["gcc"], *CPU, "-O2", "-nostdlib", "-Wl,--gc-sections,--no-undefined,--fatal-warnings,-z,noexecstack",
            "-Wl,-Map=" + str(directory / "runtime.map"), "-T", self.fixture / "link.ld", *objects, "-o", elf], "link actual pilot image")
        for tool, arguments, suffix in (("objdump", ["-drwC", "-Mreg-names-std"], ".dis"), ("readelf", ["-hASsrW", "-A"], ".readelf.txt"), ("nm", ["-a"], ".nm.txt")):
            elf.with_suffix(suffix).write_text(self.command([self.tools[tool], *arguments, elf], "inspect native pilot ELF")["Stdout"], encoding="ascii")
        image = fp.Image(elf, self.ELFFile)
        audit = self.audit_image(image, maps, consumer, model)
        save(directory / "elf-audit.json", audit)
        row = dict(Name=name, Consumer=consumer, Case=case, Elf=str(elf), ElfSha256=digest(elf), Audit=audit,
                   Status="COMPILED", Executed=False, Optimization="O2", LTO=False, Archive=False)
        return row

    def audit_image(self, image, maps, consumer, model):
        def address(name): return image.symbol(name, local=True)["Address"] & ~1
        def strong(name): return image.symbol(name, "STT_FUNC")
        bootstrap = image.sections[".boot_vectors"]
        vector = image.sections[".isr_vector"]
        code = image.sections[".privileged_code"]
        need(bootstrap["Address"] == 0 and bootstrap["Size"] == 8 and bootstrap["Flags"] & 3 == 2,
             "Exact read-only bootstrap reset words")
        need(vector["Address"] == 0x400 and vector["Size"] == 1024 and vector["Flags"] & 3 == 2,
             "Exact nonzero read-only active vector placement")
        need(code["Address"] == 0x800 and code["Address"] + code["Size"] <= 0x10000,
             "Privileged code must follow both vector sections")
        for name, begin, size in (("fixture_boot_vectors", 0, 8), ("fixture_vectors", 0x400, 1024)):
            symbol = image.symbol(name, "STT_OBJECT")
            need(symbol["Address"] == begin and symbol["Size"] == size, "Exact vector symbol ownership: " + name)
        words = struct.unpack("<256I", vector["Data"])
        reset = strong("Reset_Handler")["Address"]
        need(struct.unpack("<2I", bootstrap["Data"]) == words[:2] and words[0] == 0x20010000 and
             words[1] == reset and reset & 1 and words[4] == strong("MemManage_Handler")["Address"],
             "Pilot bootstrap/active reset and fault vector ownership")
        # Decode the fixed startup tail and resolve its literal values from ELF bytes.
        body = [i for i in image.body("Reset_Handler") if not image.is_data(i, "Reset_Handler")]
        installs = []
        for index in range(len(body) - 5):
            group = body[index:index + 6]
            operands = [i["Operands"].split("@")[0].strip() for i in group]
            first = re.fullmatch(r"r0,\s*\[pc,\s*#(\d+)\]", operands[0])
            second = re.fullmatch(r"r1,\s*\[pc,\s*#(\d+)\]", operands[1])
            if not (group[0]["Mnemonic"] == group[1]["Mnemonic"] == "ldr" and first and second and
                    group[2]["Mnemonic"] == "str" and re.fullmatch(r"r0,\s*\[r1,\s*#0\]", operands[2]) and
                    [i["Mnemonic"] for i in group[3:]] == ["dsb", "isb", "bl"]):
                continue
            literal = lambda ins, match: image.word(((ins["Address"] + 4) & ~3) + int(match[1]))
            need(literal(group[0], first) == 0x400 and literal(group[1], second) == 0xE000ED08,
                 "Startup must install the nonzero active table into VTOR")
            need(fp.control_form(group[5]) == ("call", address("fixture_main")), "VTOR install must precede fixture_main")
            installs.append(group[2]["Address"])
        need(len(installs) == 1, "Exact startup VTOR install sequence missing/duplicated")
        vectors = dict(BootstrapAddress=0, BootstrapBytes=8, ActiveAddress=0x400, ActiveBytes=1024,
                       PrivilegedCodeAddress=0x800, ResetWordsMatch=True, StartupVtorStore=installs[0])
        if model:
            return dict(ModelProbe=True, RuntimeProviders=False, NoUndefined=True, VectorBootstrap=vectors)
        for name in ("SVC_Handler", "PendSV_Handler", *common.FORWARD): strong(name)
        need(words[11] == strong("SVC_Handler")["Address"] and words[14] == strong("PendSV_Handler")["Address"] and words[11] & words[14] & 1, "Real strong Thumb exception vectors")
        slot = image.symbol(common.SLOT, "STT_OBJECT")
        need(slot["Address"] == 0x20000000 and slot["Size"] == 4 and slot["Section"] == ".current_slot" and image.sections[".current_slot"]["Size"] == 32, "Isolated actual common-owned aperture")
        cohorts = [n for n in image.symbols if n.startswith("fiber_port_context_cohort_armv7em_")]
        need(len(cohorts) == 1 and cohorts[0].startswith("fiber_port_context_cohort_armv7em_p0x434D344Du_"), "Exact CM4 MPU runtime cohort")
        storage = [n for n in image.symbols if n.startswith("fiber_port_storage_cohort_") and
                   n != "fiber_port_storage_cohort_consumer_expectation"]
        need(storage == [STORAGE], "Exact eight-region public storage cohort")
        expectation = image.sections[".fiber_port_context_cohort_expectation"]
        storage_references = 2 if consumer == "fiber" else 1
        pointer_count = 1 + storage_references
        need(expectation["Size"] == 4 * pointer_count and not expectation["Flags"] & 5 and
             Counter(struct.unpack("<" + str(pointer_count) + "I", expectation["Data"])) ==
             Counter({image.symbol(cohorts[0])["Address"]: 1, image.symbol(STORAGE)["Address"]: storage_references}),
             "Read-only exact context/storage expectation pointers")
        expected = ("ctxrt_v1_current", "ctxrt_v1_yield") + (("fiber_v1_current", "fiber_v1_yield") if consumer == "fiber" else ())
        for name in ("ctxrt_v1_init", "ctxrt_v1_current", "ctxrt_v1_yield", "ctxrt_v1_start", "ctxrt_v1_set_dispatcher"):
            strong(name)
        if consumer == "fiber":
            for name in ("fiber_v1_init", "fiber_v1_current", "fiber_v1_yield", "fiber_v1_start", "fiber_v1_set_scheduler"):
                strong(name)
        for name in (*expected, "fixture_task_entry", "fixture_task_current", "fixture_task_yield", "fiber_internal_runtime_load_current_context", "fiber_port_runtime_memory_barrier", "fiber_port_runtime_schedule", "fiber_port_unprivileged_task_return"):
            need(0x10000 <= address(name) < 0x20000, "Thread call chain escaped user code: " + name)
        need(not any(n in image.symbols for n in ("fiber_init", "fiber_start", "fiber_current", "fiber_schedule", "fiber_scheduler_set_pick_next")), "Legacy substitution in pilot")
        if consumer == "context":
            need(not any(n.startswith("fiber_v1_") or n == common.CONFIG_ANCHOR for n in image.symbols), "Pure Context consumed lifecycle/configuration provider")
        workers = image.symbols["workers"][0]
        need(workers["Address"] >= 0x20008000 and workers["Address"] + workers["Size"] <= 0x2000e000, "Metadata is not privileged")
        closure = image.no_fp_closure(["fixture_task_entry"])
        for name in closure:
            need(0x10000 <= address(name) < 0x20000, "Unprivileged closure has a privileged target: " + name)
        svc = "\n".join(i["Text"] for i in image.body("SVC_Handler"))
        pendsv = "\n".join(i["Text"] for i in image.body("PendSV_Handler"))
        for text, patterns in ((svc, [r"\btst(?:\.w)?\s+lr,\s*#4", r"\bmrs(?:eq)?\s+r0,\s*MSP", r"\bmrs(?:ne)?\s+r0,\s*PSP", "fiber_port_svc_dispatch"]),
                (pendsv, [r"\bmrs\s+r0,\s*PSP", "fiber_port_pendsv_validate_save_current", "fiber_port_scheduler_pick_next_from_pendsv", "fiber_port_mpu_switch_to_context", r"\bmsr\s+CONTROL", r"\bbx\s+lr"])):
            cursor = 0
            for pattern in patterns:
                match = re.search(pattern, text[cursor:], re.I)
                need(match is not None, "Actual pilot provider mechanism missing: " + pattern)
                cursor += match.end()
        return dict(StrongProductionHandlers=True, AllEightForwardProviders=True, NoUndefined=True, RuntimeCohort=cohorts[0], StorageCohort=storage[0],
            VectorBootstrap=vectors,
            ExternalReadOnlyExpectation=True, ExpectationBytes=expectation["Size"], StorageReferences=storage_references,
            NoFpThreadClosure=closure, ActualProviderRelocationsCaptured=True,
            ReferenceBoundary="Bounded final pilot patterns from existing ARM_CM4_MPU gate, not a new paired reference/final-LTO proof",
            Addresses={"return": address("fiber_port_svc_return_return_site"), "slot": address("fixture_slot_write_access"), "peer": address("fixture_peer_read_access")})

    def execute(self, row):
        directory = Path(row["Elf"]).parent
        result = self.command(["wsl.exe", "-d", self.a.wsl_distro, "--", "bash", self.wsl_path(self.repo / "tools/fixtures/arm_control/qemu.sh"),
            "run", self.a.qemu_root, self.wsl_path(directory), "mps2-an386", self.wsl_path(row["Elf"]), "12"], "actual MPU pilot " + row["Name"], timeout=25, expected=None)
        if row["Name"] == "model":
            self.report["ObservedModel"] = model_terminal(result)
        else:
            need(terminal(result, row["Consumer"], row["Case"], row["Audit"]["Addresses"]), "Wrong exact pilot terminal: " + row["Name"])
        row.update(Actual=result, Executed=True, Status="PASS")

    def run(self):
        self.preflight()
        self.report["TerminalControls"] = terminal_controls()
        self.report["ModelControls"] = model_controls()
        self.report["ClosingContractControls"] = closing_controls()
        self.report["FinalizerControls"] = self.finalizer_controls()
        self.report["ModelProbe"] = self.build_image("context", 0, model=True)
        if self.a.execute_pilot:
            self.execute(self.report["ModelProbe"])
        for consumer, case in EXPECTED_ROWS:
            row = self.build_image(consumer, case)
            self.rows.append(row)
            if self.a.execute_pilot:
                self.execute(row)
        need(tuple((r["Consumer"], r["Case"]) for r in self.rows) == EXPECTED_ROWS, "Exact pilot inventory")
        self.report["Execution"] = "PILOT_ONLY" if self.a.execute_pilot else "NOT_RUN"

    def finalizer_controls(self):
        root = self.build / "orchestration-finalizer-controls"
        root.mkdir()
        cases = []
        base = next(r["Receipt"] for r in self.report["ClosingContractControls"]["Controls"] if r["Name"] == "compile-positive")
        for name, fail_verification, run_error in (("positive", 0, None), ("first-manifest", 1, None),
                ("final-manifest", 2, None), ("prior-error", 0, "SYNTHETIC_RUN_FAILURE")):
            directory = root / name
            directory.mkdir()
            receiver = Pilot.__new__(Pilot)
            receiver.a = SimpleNamespace(execute_pilot=False)
            receiver.build = directory
            receiver.report = deepcopy(base)
            receiver.report["Scope"] = "Synthetic finalizer orchestration only; no compiled/CPU/QEMU evidence"
            receiver.inputs, receiver.generated, receiver.dependencies = {}, {}, []
            receiver.reference_identity = lambda: None
            receiver.input_drift = lambda: []
            def prohibit_command(*args, **kwargs):
                raise RuntimeError("FORBIDDEN_COMMAND_IN_FINALIZER_CONTROL")
            receiver.command = prohibit_command
            calls = []
            def manifest(verify=False):
                persisted = json.loads((directory / "results.json").read_text())
                calls.append(dict(Verify=verify, Verdict=persisted["Verdict"], ArtifactsVerifiedBeforePass=persisted["ArtifactsVerifiedBeforePass"]))
                if verify and sum(c["Verify"] for c in calls) == fail_verification:
                    raise RuntimeError("SYNTHETIC_MANIFEST_FAILURE_" + str(fail_verification))
                return common.Suite.artifact_manifest(receiver, verify=verify)
            receiver.artifact_manifest = manifest
            accepted = Pilot.finish(receiver, run_error)
            persisted = json.loads((directory / "results.json").read_text())
            expected = name == "positive"
            need(accepted is expected and persisted["ArtifactsVerifiedBeforePass"] is expected and
                 persisted["Verdict"] == ("COMPILE-PREFLIGHT-PASS" if expected else "FAIL"), "Actual finalizer control failed: " + name)
            need(calls[0] == dict(Verify=True, Verdict="FAIL", ArtifactsVerifiedBeforePass=False), "First artifact verification observed premature PASS")
            if fail_verification:
                need(persisted["Error"] == "finalizer: SYNTHETIC_MANIFEST_FAILURE_" + str(fail_verification), "Wrong causal manifest failure")
                need(calls[-1]["Verify"] is False and calls[-1]["Verdict"] == "FAIL" and
                     calls[-1]["ArtifactsVerifiedBeforePass"] is False, "Failure recovery did not persist FAIL before best-effort manifest")
            elif run_error:
                need(persisted["Error"] == run_error and len(calls) == 1, "Prior run error was promoted or replaced")
            else:
                need(len(calls) == 2 and calls[1] == dict(Verify=True, Verdict="COMPILE-PREFLIGHT-PASS", ArtifactsVerifiedBeforePass=True), "Final artifact verification missing")
            cases.append(dict(Name=name, Accepted=accepted, PersistedVerdict=persisted["Verdict"], Error=persisted["Error"],
                Calls=calls, Receipt=str(directory / "results.json"), ReceiptSha256=digest(directory / "results.json")))
        need(len(cases) == 4 and sum(c["Accepted"] for c in cases) == 1, "Literal actual-finish controls")
        return dict(Controls=cases, Scope="Actual Pilot.finish with only reference/drift stubs and manifest fault injection; synthetic orchestration, no builds/CPU/WSL/QEMU")

    def finish(self, error):
        # No success verdict reaches disk before the first artifact verification.
        self.report.update(Verdict="FAIL", ArtifactsVerifiedBeforePass=False, Error=error, InputCount=len(self.inputs))
        try:
            save(self.build / "results.json", self.report)
            if not error:
                if self.a.execute_pilot:
                    after = self.inspect_qemu("qemu-after")
                    need(after == self.qemu_before, "QEMU/tool/library drift")
                self.reference_identity()
            drift = self.input_drift()
            self.report["InputDrift"] = drift
            need(not drift, "Pilot inputs changed during preflight/execution")
            save(self.build / "inputs.after.json", [dict(Path=p, Sha256=digest(p) if Path(p).is_file() else None) for p in self.inputs])
            save(self.build / "dependencies.json", self.dependencies)
            save(self.build / "generated-inputs.json", list(self.generated.values()))
            save(self.build / "results.json", self.report)
            self.artifact_manifest(verify=True)
            if error:
                return False
            need(not self.input_drift(), "Inputs changed during artifact verification")
            candidate = dict(self.report, Verdict="PILOT-PASS" if self.a.execute_pilot else "COMPILE-PREFLIGHT-PASS",
                             ArtifactsVerifiedBeforePass=True, Error=None)
            validate_closing_contract(candidate, self.a.execute_pilot)
            self.report.update(candidate)
            save(self.build / "results.json", self.report)
            self.artifact_manifest(verify=True)
            need(not self.input_drift(), "Inputs changed during final manifest verification")
            return True
        except Exception as failure:
            error = (error + "; " if error else "") + "finalizer: " + str(failure)
            self.report.update(Verdict="FAIL", ArtifactsVerifiedBeforePass=False, Error=error)
            try:
                save(self.build / "results.json", self.report)
            except Exception as write_failure:
                self.report["FailureReceiptWriteError"] = str(write_failure)
            try:
                self.artifact_manifest(verify=False)
            except Exception as manifest_failure:
                self.report["FailureManifestError"] = str(manifest_failure)
                try:
                    save(self.build / "results.json", self.report)
                except Exception as write_failure:
                    self.report["FailureReceiptWriteError"] = str(write_failure)
            return False


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for key in ("repo", "gcc", "cmsis", "freertos", "qemu-root", "build-root"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--wsl-distro", default="Ubuntu-24.04")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--compile-preflight", action="store_true")
    mode.add_argument("--execute-pilot", action="store_true")
    args = parser.parse_args()
    need(Path(args.repo).resolve() == REPO, "Runner must belong to selected repository")
    suite = Pilot(args)
    error = None
    try:
        suite.run()
    except Exception as failure:
        error = str(failure)
    if not suite.finish(error):
        raise RuntimeError("Pilot failed; preserve " + str(suite.build) + ": " + suite.report["Error"])
    print(suite.report["Verdict"] + " " + str(suite.build), flush=True)


if __name__ == "__main__":
    main()
