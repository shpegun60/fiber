"""Bounded actual CM4F Context/Fiber execution and pinned link-only references."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import re
import struct
import sys
import traceback
from typing import NamedTuple

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
HERE = Path(__file__).resolve().parent
COMMON_PATH = HERE.parent / "classic_context_runtime/run.py"
_spec = importlib.util.spec_from_file_location("cm4f_runtime_evidence_common", COMMON_PATH)
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)
need, digest, save = common.need, common.digest, common.save

CHECK = ("CHECK:CM4F:CPUID=C24:FPV4=SP-D16:WORKERS=3:INACTIVE=1:SELF=1:"
         "BIDIR=1:ROUNDS=16:PUBLIC+DIRECT=1:FP=S0-S31")
PASS = "PASS:CM4F-CONTEXT-RUNTIME"
MUTANTS = {"pendsv-r4": 121, "pendsv-r9": 121, "high-fp-save": 131,
           "high-fp-restore": 131, "low-fp-frame": 134, "fpscr-frame": 132,
           "publication": 31}
CPU = ["-mcpu=cortex-m4", "-mthumb", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard"]
COMPILE = ["-std=gnu11", "-ffreestanding", "-fno-builtin", "-fno-common",
           "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra", "-Wundef",
           "-Werror=undef", "-Werror=implicit-function-declaration", "-Werror=return-type"]
EXPLICIT = ("tools/fixtures/classic_context_runtime/run.py",
            "tools/fixtures/classic_context_runtime/qemu.sh",
            "tools/fixtures/arm_control/qemu.sh",
            "tools/test_classic_fp_context_runtime.ps1")
REF_HANDLERS = ("vPortSVCHandler", "xPortPendSVHandler", "xPortSysTickHandler")
REF_ROOTS = ("pxPortInitialiseStack", "xPortStartScheduler")
REF_BOUNDARIES = ("vTaskSwitchContext", "xTaskIncrementTick", "reference_assert_failed")


class Profile(NamedTuple):
    name: str
    label: str
    cpu: str
    fpu: str
    fixture_relative: str
    wrapper_relative: str
    port_relative: str
    machine: str
    runtime_prefix: str
    storage_symbol: str
    fp_attribute: str
    report_bytes: int
    upstream_relative: str
    header_facts: tuple[int, ...]
    check_line: str
    model_line: str | None
    scope: str

    @property
    def cpu_flags(self):
        return ("-mcpu="+self.cpu, "-mthumb", "-mfpu="+self.fpu, "-mfloat-abi=hard")

    @property
    def pass_line(self):
        return "PASS:"+self.label+"-CONTEXT-RUNTIME"

    @property
    def evidence_paths(self):
        paths = (*EXPLICIT[:3], self.wrapper_relative)
        return paths if self.name == "CM4" else (*paths, "tools/fixtures/classic_fp_context_runtime/run.py")


CM4 = Profile("CM4", "CM4F", "cortex-m4", "fpv4-sp-d16", "tools/fixtures/classic_fp_context_runtime",
    "tools/test_classic_fp_context_runtime.ps1", "fiber/port/ARM_CM4", "mps2-an386",
    "fiber_port_context_cohort_armv7em_p0x434D3034u_", "fiber_port_storage_cohort_arm_cm4_v1_r0", "VFPv4-D16",
    312, "portable/GCC/ARM_CM4F", (1, 4, 4, 4, 8, 4, 1, 0x80), CHECK, None,
    "QEMU mps2-an386 Cortex-M4F fpv4-sp-d16 hard-float; NVIC8/PendSVFF/BASEPRI80; no STM32 NVIC-width, softfp, board, whole-kernel or global parity claim")
CM7 = Profile("CM7", "CM7F", "cortex-m7", "fpv5-d16", "tools/fixtures/classic_cm7_fp_context_runtime",
    "tools/test_classic_cm7_fp_context_runtime.ps1", "fiber/port/ARM_CM7/r0p1", "mps2-an500",
    "fiber_port_context_cohort_armv7em_p0x434D3701u_", "fiber_port_storage_cohort_arm_cm7_r0p1_v1_r0", "FPv5/FP-D16 for ARMv8",
    316, "portable/GCC/ARM_CM7/r0p1", (1, 4, 4, 4, 8, 14, 1, 0x80),
    "CHECK:CM7F:CPUID=C27:FPV5=DP-D16:WORKERS=3:INACTIVE=1:SELF=1:BIDIR=1:ROUNDS=16:PUBLIC+DIRECT=1:FP=S0-S31",
    "MODEL:CM7F:CPUID=411FC272:MVFR0=10110221:MVFR1=12000011:MVFR2=00000040",
    "QEMU mps2-an500 Cortex-M7 r1p2 fpv5-d16 hard-float; NVIC8/PendSVFF/BASEPRI80; S0-S31 storage only, not DP arithmetic, STM32, affected-r0p1 erratum, cache/TCM, board, whole-kernel or global parity qualification")


DEFAULT_MODES = (("O2", False), ("O2", True), ("Os", False), ("Os", True))
FULL_MODES = (("O0", False), ("Og", False), ("O2", False), ("Os", False), ("O3", False), ("O2", True), ("Os", True))


class GridCounts(NamedTuple):
    Rows: int
    Positive: int
    CompiledControl: int
    References: int
    Pairs: int
    CompleteSuite: bool


def grid_counts(full, development):
    need(type(full) is bool and type(development) is bool, "FP grid options must be booleans")
    if development:
        return GridCounts(11, 4, 7, 14, 4, False) if full else GridCounts(9, 2, 7, 8, 2, False)
    return GridCounts(504, 112, 392, 14, 112, True) if full else GridCounts(288, 64, 224, 8, 64, True)


def execution_plan(full, development):
    grid_counts(full, development)
    modes = FULL_MODES if full else DEFAULT_MODES
    plan = []
    if development:
        if full:
            plan.extend((("context", "O0", False, False, False, "primary", None),
                         ("fiber", "Og", False, True, True, "validation", None),
                         ("context", "O3", False, True, True, "validation", None),
                         ("fiber", "O2", True, False, False, "primary", None)))
        else:
            plan.extend((("context", "O2", False, False, False, "primary", None),
                         ("fiber", "O2", True, True, True, "validation", None)))
        plan.extend(("context", "O0" if full else "O2", False, False, True, "primary", m) for m in MUTANTS)
    else:
        for consumer, (opt, lto), archive, lazy in itertools.product(("context", "fiber"), modes, (False, True), (False, True)):
            plan.extend((consumer, opt, lto, archive, lazy, p, None) for p in ("primary", "validation"))
            plan.extend((consumer, opt, lto, archive, lazy, "primary", m) for m in MUTANTS)
    return plan


def validate_execution_grid(rows, full, development):
    counts = grid_counts(full, development)
    fields = ("Consumer", "Optimization", "LTO", "Archive", "Lazy", "Policy", "Mutant")
    need(all(type(r[k]) is bool for r in rows for k in ("LTO", "Archive", "Lazy")), "FP grid boolean variant field")
    actual = [tuple(r[k] for k in fields) for r in rows]
    need(len(rows) == counts.Rows and len(set(actual)) == len(rows), "FP grid missing/duplicate execution cell")
    need(set(actual) == set(execution_plan(full, development)), "FP grid exact variant tuples mismatch")
    need(all(r["Kind"] == ("CompiledControl" if r["Mutant"] else "Positive") for r in rows), "FP grid case kind mismatch")
    need(dict(Counter(r["Kind"] for r in rows)) == dict(Positive=counts.Positive, CompiledControl=counts.CompiledControl),
         "FP grid literal positive/causal counts mismatch")
    return counts


def grid_controls():
    records = []
    fields = ("Consumer", "Optimization", "LTO", "Archive", "Lazy", "Policy", "Mutant")
    def record(name, accepted, expected):
        need(accepted == expected, "FP grid control failed: "+name)
        records.append(dict(Name=name, Accepted=accepted))
    for full, development, expected in ((False, False, (288, 64, 224, 8, 64, True)),
            (True, False, (504, 112, 392, 14, 112, True)), (False, True, (9, 2, 7, 8, 2, False)),
            (True, True, (11, 4, 7, 14, 4, False))):
        rows = [dict(zip(fields, spec), Kind="CompiledControl" if spec[-1] else "Positive") for spec in execution_plan(full, development)]
        record("contract-%s-%s" % (full, development), tuple(validate_execution_grid(rows, full, development)) == expected, True)
        bad_sets = [("missing", rows[:-1]), ("duplicate", rows[:-1]+[dict(rows[0])]),
                    ("kind", [dict(r, Kind="Positive") if n == len(rows)-1 else dict(r) for n, r in enumerate(rows)]),
                    ("boolean", [dict(r, LTO=int(r["LTO"])) if n == 0 else dict(r) for n, r in enumerate(rows)])]
        for name, bad in bad_sets:
            try:
                validate_execution_grid(bad, full, development)
                accepted = True
            except RuntimeError as error:
                need(str(error).startswith("FP grid"), "Incidental grid negative failure")
                accepted = False
            record(name+"-%s-%s" % (full, development), accepted, False)
    for n, (full, development) in enumerate(((1, False), (False, 0), ("true", False), (True, None))):
        try:
            grid_counts(full, development)
            accepted = True
        except RuntimeError as error:
            need(str(error) == "FP grid options must be booleans", "Incidental option negative failure")
            accepted = False
        record("option-type-%d" % n, accepted, False)
    class ControlParser(argparse.ArgumentParser):
        def error(self, message):
            raise RuntimeError("CLI option rejected: "+message)
    parser = argument_parser(ControlParser)
    base = [s for name in ("repo", "gcc", "cmsis", "freertos", "qemu-root", "wsl-distro", "build-root") for s in ("--"+name, "control")]
    for full, development in itertools.product((False, True), repeat=2):
        args = parser.parse_args(base+(["--full-optimization-grid-fp"] if full else [])+(["--development-smoke"] if development else []))
        record("cli-%s-%s" % (full, development), args.full_optimization_grid_fp is full and args.development_smoke is development, True)
    for n, extra in enumerate((["--full-opt"], ["--full-optimization-grid-fp", "false"],
                               ["--full-optimization-grid"], ["--full-optimization-grid-fp=0"])):
        try:
            parser.parse_args(base+extra)
            accepted = True
        except RuntimeError as error:
            need(str(error).startswith("CLI option rejected:"), "Incidental CLI negative failure")
            accepted = False
        record("cli-reject-%d" % n, accepted, False)
    record("default-mode-order", DEFAULT_MODES == (("O2", False), ("O2", True), ("Os", False), ("Os", True)), True)
    record("full-seven-modes", FULL_MODES == (("O0", False), ("Og", False), ("O2", False), ("Os", False), ("O3", False), ("O2", True), ("Os", True)), True)
    need(len(records) == 34, "FP grid literal option/control count")
    return dict(Controls=records, Scope="Synthetic option/count controls, not additional executions or CPU/model qualification")


def expected_terminal(lazy, validation, mutant=None, profile=CM4):
    if mutant:
        return dict(Exit=66, Lines=["REASON:%08X" % MUTANTS[mutant], "FAIL:"+profile.label+"-ORACLE"])
    observation = "OBS:"+profile.label+":PRE_SAVE=DISABLED"
    if validation:
        observation = "OBS:"+profile.label+(":LAZY=1:PRE_LSPACT=FP1-GRO0:POST_LSPACT=0" if lazy else
                                           ":LAZY=0:PRE_LSPACT=FP0-GRO0:POST_LSPACT=0")
    return dict(Exit=0, Lines=([profile.model_line] if profile.model_line else [])+[profile.check_line, observation, profile.pass_line])


def terminal(actual, expected):
    return (actual.get("TimedOut") is False and type(actual.get("Exit")) is int and
            actual["Exit"] == expected["Exit"] and
            (actual["Stdout"] + actual["Stderr"]).replace("\r\n", "\n") ==
            "\n".join(expected["Lines"]) + "\n")


def terminal_controls(profile=CM4):
    eager = expected_terminal(False, True, profile=profile)
    lazy = expected_terminal(True, True, profile=profile)
    primary = expected_terminal(True, False, profile=profile)
    oracle = expected_terminal(True, False, "high-fp-save", profile=profile)
    def result(expectation, **changes):
        value = dict(Exit=expectation["Exit"], Stdout="", Stderr="\n".join(expectation["Lines"])+"\n", TimedOut=False)
        value.update(changes)
        return value
    tests = [("positive-eager", result(eager), eager, True),
             ("positive-lazy", result(lazy), lazy, True),
             ("positive-primary", result(primary), primary, True),
             ("compiled-oracle", result(oracle), oracle, True),
             ("wrong-policy", result(eager), lazy, False),
             ("missing-observer", result(primary), eager, False),
             ("marker-wrong-exit", result(eager, Exit=66), eager, False),
             ("timeout", result(oracle, TimedOut=True), oracle, False),
             ("timeout-exit", result(oracle, Exit=124), oracle, False),
             ("signal-exit", result(oracle, Exit=-15), oracle, False),
             ("boolean-exit", result(primary, Exit=False), primary, False),
             ("fault", result(oracle, Exit=65, Stderr="FAIL:"+profile.label+"-FAULT\n"), oracle, False),
             ("panic", result(oracle, Exit=64, Stderr="PANIC:x\n"), oracle, False),
             ("wrong-reason", result(oracle, Stderr="REASON:00000086\nFAIL:"+profile.label+"-ORACLE\n"), oracle, False),
             ("missing-reason", result(oracle, Stderr="FAIL:"+profile.label+"-ORACLE\n"), oracle, False),
             ("duplicate", result(oracle, Stderr=result(oracle)["Stderr"]*2), oracle, False),
             ("prefix", result(oracle, Stderr="debug\n"+result(oracle)["Stderr"]), oracle, False),
             ("traceback", result(oracle, Stderr="RuntimeError: "+result(oracle)["Stderr"]), oracle, False),
             ("truncated", result(eager, Stderr=profile.check_line+"\n"+profile.pass_line+"\n"), eager, False),
             ("trailing", result(eager, Stderr=result(eager)["Stderr"]+"\n"), eager, False)]
    for name, actual, expected, accepted in tests:
        need(terminal(actual, expected) == accepted, "CM4F terminal control: "+name)
    return [dict(Name=n, Accepted=v) for n, _, _, v in tests]


def capability_matches(profile, attributes, flags):
    exact = {"-mcpu=": profile.cpu, "-mfpu=": profile.fpu, "-mfloat-abi=": "hard"}
    return (all([f[len(prefix):] for f in flags if f.startswith(prefix)] == [value]
                for prefix, value in exact.items()) and "-mthumb" in flags and "-marm" not in flags and
            re.findall(r"(?m)^\s*Tag_CPU_arch:\s*([^\r\n]+)", attributes) == ["v7E-M"] and
            re.findall(r"(?m)^\s*Tag_FP_arch:\s*([^\r\n]+)", attributes) == [profile.fp_attribute] and
            re.findall(r"(?m)^\s*Tag_ABI_VFP_args:\s*([^\r\n]+)", attributes) == ["VFP registers"])


def cohort_matches(profile, runtime, storage):
    return (len(runtime) == len(storage) == 1 and runtime[0].startswith(profile.runtime_prefix) and
            storage[0] == profile.storage_symbol)


def basepri_patterns(profile, reference):
    scheduler = "vTaskSwitchContext" if reference else "fiber_port_scheduler_pick_next_from_pendsv"
    call = r"\bbl\s+[^\n]*<"+scheduler+r">"
    if profile.name == "CM4":
        return ([r"\bmov[^\n]*#(?:128|0x80)\b", r"\bmsr\s+BASEPRI", r"\bdsb\b", r"\bisb\b",
                 call, r"\bmov[^\n]*#0\b", r"\bmsr\s+BASEPRI"] if reference else
                [r"\bmrs[^\n]*BASEPRI", r"\bmov[^\n]*#(?:128|0x80)\b", r"\bpush\b",
                 r"\bmsr\s+BASEPRI", r"\bdsb\b", r"\bisb\b", call,
                 r"\bpop\b", r"\bmsr\s+BASEPRI", r"\bdsb\b", r"\bisb\b"])
    need(profile.name == "CM7", "Unknown BASEPRI profile")
    if reference:
        return [r"\bmov[^\n]*r0,\s*#(?:128|0x80)\b", r"\bcpsid\s+i\b", r"\bmsr\s+BASEPRI,\s*r0\b",
                r"\bdsb\b", r"\bisb\b", r"\bcpsie\s+i\b", call,
                r"\bmov[^\n]*r0,\s*#0\b", r"\bmsr\s+BASEPRI,\s*r0\b"]
    sync = lambda reg: [r"\bmrs\s+r12,\s*PRIMASK\b", r"\bcpsid\s+i\b", r"\bmsr\s+BASEPRI,\s*"+reg+r"\b",
                        r"\bdsb\b", r"\bisb\b", r"\bmsr\s+PRIMASK,\s*r12\b", r"\bdsb\b", r"\bisb\b"]
    return ([r"\bmrs\s+r3,\s*BASEPRI\b", r"\bmov[^\n]*r2,\s*#(?:128|0x80)\b",
             r"\bpush[^\n]*\{r2,\s*r3\}"]+sync("r2")+[call, r"\bpop[^\n]*\{r2,\s*r3\}"]+sync("r3"))


def check_basepri(profile, reference, text):
    patterns = basepri_patterns(profile, reference)
    cursor = 0
    for pattern in patterns:
        match = re.search(pattern, text[cursor:], re.I)
        need(match is not None, "BASEPRI scheduler envelope missing: "+pattern)
        cursor += match.end()
    if profile.name == "CM4":
        need(not re.search(r"\b(?:cpsid|cpsie)\b|\b(?:mrs|msr)[^\n]*PRIMASK", text, re.I),
             "BASEPRI profile acquired a foreign CM7 PRIMASK sequence")
    elif not reference:
        need(not re.search(r"\bcpsie\b", text, re.I), "BASEPRI CM7 owner must restore PRIMASK, not unconditionally enable IRQs")
    return patterns


def profile_controls():
    controls = []
    def check(name, actual, expected):
        need(actual == expected, "Profile discriminator control: "+name)
        controls.append(dict(Name=name, Accepted=actual))
    for p, other in ((CM4, CM7), (CM7, CM4)):
        expected = expected_terminal(True, True, profile=p)
        own = dict(Exit=0, Stdout="", Stderr="\n".join(expected["Lines"])+"\n", TimedOut=False)
        foreign = dict(own, Stderr="\n".join(expected_terminal(True, True, profile=other)["Lines"])+"\n")
        check(p.name+"-terminal", terminal(own, expected), True)
        check(p.name+"-foreign-terminal", terminal(foreign, expected), False)
        attrs = "Tag_CPU_name: 7E-M\nTag_CPU_arch: v7E-M\nTag_FP_arch: "+p.fp_attribute+"\nTag_ABI_VFP_args: VFP registers\n"
        check(p.name+"-capability", capability_matches(p, attrs, p.cpu_flags), True)
        check(p.name+"-foreign-capability", capability_matches(other, attrs, p.cpu_flags), False)
        check(p.name+"-foreign-flags", capability_matches(p, attrs, other.cpu_flags), False)
        check(p.name+"-masked-flags", capability_matches(p, attrs, (*p.cpu_flags, "-mfpu="+other.fpu)), False)
        check(p.name+"-cohort", cohort_matches(p, [p.runtime_prefix+"test"], [p.storage_symbol]), True)
        check(p.name+"-foreign-cohort", cohort_matches(p, [other.runtime_prefix+"test"], [other.storage_symbol]), False)
        check(p.name+"-foreign-storage", cohort_matches(p, [p.runtime_prefix+"test"], [other.storage_symbol]), False)
    cm4_ours = "mrs r3,BASEPRI\nmovs r2,#128\npush {r2,r3}\nmsr BASEPRI,r2\ndsb\nisb\nbl 100 <fiber_port_scheduler_pick_next_from_pendsv>\npop {r2,r3}\nmsr BASEPRI,r3\ndsb\nisb"
    cm4_ref = "mov r0,#128\nmsr BASEPRI,r0\ndsb\nisb\nbl 100 <vTaskSwitchContext>\nmov r0,#0\nmsr BASEPRI,r0"
    cm7_ref = "mov r0,#128\ncpsid i\nmsr BASEPRI,r0\ndsb\nisb\ncpsie i\nbl 100 <vTaskSwitchContext>\nmov r0,#0\nmsr BASEPRI,r0"
    sync = lambda reg: "mrs r12,PRIMASK\ncpsid i\nmsr BASEPRI,"+reg+"\ndsb\nisb\nmsr PRIMASK,r12\ndsb\nisb"
    cm7_ours = "mrs r3,BASEPRI\nmovs r2,#128\npush {r2,r3}\n"+sync("r2")+"\nbl 100 <fiber_port_scheduler_pick_next_from_pendsv>\npop {r2,r3}\n"+sync("r3")
    for p, reference, text, other in ((CM4, False, cm4_ours, cm7_ours), (CM4, True, cm4_ref, cm7_ref),
                                    (CM7, False, cm7_ours, cm4_ours), (CM7, True, cm7_ref, cm4_ref)):
        for name, value, expected in (("own", text, True), ("foreign", other, False),
                                      ("missing-msr", text.replace("msr BASEPRI", "nop @ removed BASEPRI"), False)):
            try:
                check_basepri(p, reference, value)
                accepted = True
            except RuntimeError as error:
                need(str(error).startswith("BASEPRI"), "Incidental profile mask rejection")
                accepted = False
            check(p.name+("-reference-" if reference else "-owner-")+name, accepted, expected)
    model = expected_terminal(False, False, profile=CM7)
    check("CM7-missing-model", terminal(dict(Exit=0, Stdout="", Stderr="\n".join(model["Lines"][1:])+"\n", TimedOut=False), model), False)
    check("CM7-wrong-model", terminal(dict(Exit=0, Stdout="", Stderr="\n".join(model["Lines"]).replace("411FC272", "411FC271")+"\n", TimedOut=False), model), False)
    need(len(controls) == 32, "Literal cross-profile discriminator count")
    return dict(Controls=controls, Scope="Synthetic classifier controls, not production manifests, additional runtime cases or reference execution")


def instructions(text):
    result = []
    pattern = r"^\s*([0-9a-f]+):\s+((?:(?:[0-9a-f]{8}|[0-9a-f]{4})\s+)+)([.a-z][.a-z0-9]*)\s*(.*?)\s*$"
    for line in text.splitlines():
        match = re.match(pattern, line)
        if match:
            raw = b"".join(int(word, 16).to_bytes(len(word)//2, "little") for word in match[2].split())
            result.append(dict(Address=int(match[1], 16), Bytes=raw,
                               Mnemonic=match[3], Operands=match[4], Text=line))
    return result


def decoder_controls():
    cases = [("thumb16", "  100: bf00 nop", b"\x00\xbf"),
             ("thumb32-halfwords", "  102: f3ef 8305 mrs r3, IPSR", b"\xef\xf3\x05\x83"),
             ("literal32", "  108: e000ef34 .word 0xe000ef34", b"\x34\xef\x00\xe0")]
    for name, text, expected in cases:
        parsed = instructions(text)
        need(len(parsed) == 1 and parsed[0]["Bytes"] == expected, "Little-endian objdump decoder: "+name)
    return [dict(Name=n, ExpectedBytes=e.hex()) for n, _, e in cases]


CONDITIONS = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al")
DATA_OPS = {"mov", "movs", "movw", "movt", "mvn", "mvns", "add", "adds", "sub", "subs", "adr",
            "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrd", "ldmia", "ldm", "pop", "push",
            "str", "strb", "strh", "strd", "stmdb", "stmia", "stm", "cmp", "cmn", "tst", "teq",
            "and", "ands", "orr", "orrs", "eor", "eors", "bic", "bics", "lsl", "lsls", "lsr", "lsrs",
            "asr", "asrs", "mul", "muls", "ubfx", "uxtb", "uxth", "sxtb", "sxth", "mrs", "msr"}
RETURN_VALUE = ("return", 0)
NORETURN = ("fiber_panic", "fixture_check_fail", "fixture_exit", "reference_fail_stop")


def register(text):
    value = text.strip().lower()
    return {"r13": "sp", "r14": "lr", "r15": "pc", "ip": "r12", "fp": "r11", "sl": "r10", "sb": "r9"}.get(value, value)


def operation(instruction):
    raw = instruction["Mnemonic"].split(".")[0].lower()
    if raw in DATA_OPS or raw in ("b", "bl", "blx", "bx", "cbz", "cbnz"):
        return raw, False
    for base in ("blx", "bx", "bl", "b"):
        if raw.startswith(base) and raw[len(base):] in CONDITIONS:
            return base, True
    for condition in CONDITIONS:
        if raw.endswith(condition) and raw[:-len(condition)] in DATA_OPS:
            return raw[:-len(condition)], True
    return raw, False


def register_list(text):
    match = re.search(r"\{([^}]+)\}", text)
    need(match is not None, "Malformed register list")
    result = []
    for item in match[1].split(","):
        if "-" in item:
            first, last = (register(s) for s in item.split("-"))
            need(re.fullmatch(r"r\d+", first) and re.fullmatch(r"r\d+", last), "Unknown register range")
            result.extend("r%d" % n for n in range(int(first[1:]), int(last[1:])+1))
        else:
            result.append(register(item))
    order = {**{"r%d" % n: n for n in range(13)}, "sp": 13, "lr": 14, "pc": 15}
    need(result and len(set(result)) == len(result) and all(n in order for n in result), "Unknown/duplicate register list")
    return sorted(result, key=order.__getitem__)


def control_form(instruction):
    op, conditional = operation(instruction)
    operands = instruction["Operands"].split("@")[0].strip().lower()
    if op in ("b", "bl", "blx", "cbz", "cbnz"):
        match = re.search(r"(?:^|,\s*)([0-9a-f]+)\s+<", operands)
        need(match is not None, "Unresolved control transfer: "+instruction["Text"])
        return ("call" if op in ("bl", "blx") else "conditional" if conditional or op in ("cbz", "cbnz") else "branch", int(match[1], 16))
    if op == "bx":
        need(register(operands) == "lr", "Unresolved control transfer: "+instruction["Text"])
        return "return", None
    if op.startswith(("tbb", "tbh", "rfe", "eret")):
        raise RuntimeError("Unresolved control transfer: "+instruction["Text"])
    if op == "pop" and "pc" in register_list(operands):
        return "return", None
    if op in ("ldm", "ldmia") and re.search(r"\b(?:pc|r15)\b", operands):
        need(re.fullmatch(r"(?:sp|r13)!\s*,\s*\{[^}]+\}", operands), "Unresolved PC write: "+instruction["Text"])
        return "return", None
    if op.startswith("ldm") and re.search(r"\b(?:pc|r15)\b", operands):
        raise RuntimeError("Unresolved PC write: "+instruction["Text"])
    if re.match(r"(?:pc|r15)\s*,", operands):
        need(op == "ldr" and re.fullmatch(r"(?:pc|r15),\s*\[(?:sp|r13)\],\s*#(?:4|0x4)", operands),
             "Unresolved PC write: "+instruction["Text"])
        return "return", None
    if op == "ldrd" and re.match(r"[^,]+,\s*(?:pc|r15)\s*,", operands):
        raise RuntimeError("Unresolved PC write: "+instruction["Text"])
    return "next", None


class Image:
    def __init__(self, path, elf_type):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        with self.path.open("rb") as stream:
            elf = elf_type(stream)
            need(elf.elfclass == 32 and elf.little_endian and elf["e_machine"] == "EM_ARM" and
                 elf["e_type"] == "ET_EXEC", "Expected final ARM ELF32 executable")
            self.sections = {s.name: dict(Address=s["sh_addr"], Size=s["sh_size"], Flags=s["sh_flags"],
                                         Type=s["sh_type"], Data=s.data()) for s in elf.iter_sections()}
            table = elf.get_section_by_name(".symtab")
            need(table is not None, "Final ELF has no symbol inventory")
            self.symbols = {}
            self.mapping = []
            for symbol in table.iter_symbols():
                if not symbol.name:
                    continue
                need(symbol["st_shndx"] != "SHN_UNDEF", "Unresolved final symbol: "+symbol.name)
                index = symbol["st_shndx"]
                record = dict(Name=symbol.name, Address=symbol["st_value"], Size=symbol["st_size"],
                              Kind=symbol["st_info"]["type"], Binding=symbol["st_info"]["bind"],
                              Section=elf.get_section(index).name if isinstance(index, int) else index)
                self.symbols.setdefault(symbol.name, []).append(record)
                if re.fullmatch(r"\$[dt](?:\..*)?", symbol.name):
                    self.mapping.append((record["Address"], record["Section"], symbol.name[1]))
            self.segments = [dict(Type=s["p_type"], Address=s["p_vaddr"], Size=s["p_memsz"],
                                  Flags=s["p_flags"]) for s in elf.iter_segments()]
        self.dis = instructions(self.path.with_suffix(".dis").read_text())

    def symbol(self, name, kind=None, local=False):
        matches = self.symbols.get(name, [])
        need(len(matches) == 1, "Missing/duplicate final symbol: "+name)
        value = matches[0]
        need(value["Binding"] == "STB_GLOBAL" or (local and value["Binding"] == "STB_LOCAL"),
             "Final weak/local binding not admitted: "+name)
        if kind:
            need(value["Kind"] == kind and value["Size"] > 0, "Wrong final symbol type/size: "+name)
        return value

    def bytes(self, symbol):
        section = self.sections[symbol["Section"]]
        offset = (symbol["Address"] & (~1 if symbol["Kind"] == "STT_FUNC" else -1))-section["Address"]
        need(0 <= offset and offset+symbol["Size"] <= len(section["Data"]), "Symbol outside section")
        return section["Data"][offset:offset+symbol["Size"]]

    def body(self, name):
        value = self.symbols[name][0]
        begin = value["Address"] & ~1
        body = [i for i in self.dis if begin <= i["Address"] < begin+value["Size"]]
        cursor = begin
        raw = self.bytes(value)
        for ins in body:
            need(ins["Address"] == cursor, "Noncontiguous function disassembly: "+name)
            offset = cursor-begin
            need(raw[offset:offset+len(ins["Bytes"])] == ins["Bytes"], "Disassembly/ELF byte disagreement: "+name)
            cursor += len(ins["Bytes"])
        need(body and cursor == begin+value["Size"], "Incomplete function disassembly: "+name)
        return body

    def is_data(self, instruction, owner):
        section = self.symbols[owner][0]["Section"]
        mappings = [m for m in self.mapping if m[1] == section and m[0] <= instruction["Address"]]
        need(mappings, "Missing ARM code/data mapping: "+owner)
        return max(mappings, key=lambda m: m[0])[2] == "d"

    def word(self, address):
        for section in self.sections.values():
            offset = address-section["Address"]
            if section["Flags"] & 2 and 0 <= offset and offset+4 <= len(section["Data"]):
                return struct.unpack_from("<I", section["Data"], offset)[0]
        raise RuntimeError("Unresolvable literal address: %x" % address)

    def resolve(self, address):
        matches = []
        for name, values in self.symbols.items():
            for value in values:
                begin = value["Address"] & ~1
                if value["Kind"] == "STT_FUNC" and value["Size"] and begin <= address < begin+value["Size"]:
                    matches.append((name, begin, value["Size"]))
        need(matches, "Unknown final code target: %x" % address)
        shapes = {(b, s) for _, b, s in matches}
        need(len(shapes) == 1, "Ambiguous final code target")
        return sorted(matches)[0][0]

    def targets(self, body, owner, bounded_prefix=False):
        result = set()
        boundaries = {}
        for ins in body:
            if self.is_data(ins, owner):
                continue
            kind, address = control_form(ins)
            if kind in ("call", "branch", "conditional"):
                target = self.resolve(address)
                if target not in boundaries:
                    boundaries[target] = {i["Address"] for i in self.body(target)
                                          if not self.is_data(i, target)}
                need(address in boundaries[target],
                     "Explicit target is not a decoded instruction boundary: "+ins["Text"])
                source_record = self.symbols[owner][0]
                target_record = self.symbols[target][0]
                same_body = all(source_record[k] == target_record[k]
                                for k in ("Address", "Size", "Section"))
                need((same_body and kind != "call") or address == (target_record["Address"] & ~1),
                     "Transfer does not enter exact function entry: "+ins["Text"])
                need(not self.is_data(dict(Address=address), target), "Branch into mapped literal data")
                if target != owner:
                    result.add(target)
        self.effects(body, owner, bounded_prefix=bounded_prefix)
        return result

    def no_fp_closure(self, roots, forbid_cpu_write=False):
        pending, visited = list(roots), set()
        while pending:
            name = pending.pop()
            if name in visited:
                continue
            visited.add(name)
            body = self.body(name)
            for ins in body:
                op = ins["Mnemonic"].split(".")[0]
                if self.is_data(ins, name):
                    continue
                need(not ins["Mnemonic"].startswith(".") and op not in ("undefined", "unknown"),
                     "Undecoded executable instruction in GRO closure: "+ins["Text"])
                need(not op.startswith("v") and not re.match(r"(?:mcr|mrc|mrrc|mcrr|ldc|stc|cdp)", op),
                     "FP/coprocessor instruction in GRO closure: "+name+": "+ins["Text"])
                if forbid_cpu_write:
                    need(operation(ins)[0] not in ("msr", "cpsid", "cpsie", "svc", "bkpt", "udf"),
                         "CPU-state write/trap in observer: "+name)
            targets = self.targets(body, name)
            if forbid_cpu_write:
                need(not any(n.startswith(("ctxrt_v1_", "fiber_v1_", "fiber_internal_")) for n in targets),
                     "Observer calls a runtime API/service")
            pending.extend(targets-visited)
        return sorted(visited)

    def effects(self, body, owner, allowed_stores=None, bounded_prefix=False):
        """Finite constants/stack slots only; no index ranges or general pointer proof."""
        by_address = {i["Address"]: i for i in body}
        states, pending, reads, writes, checked_returns = {}, [], {}, {}, set()
        def merge(a, b):
            return {k: v for k, v in a.items() if v is not None and b.get(k) == v}
        def enqueue(address, regs, slots, sequential=False):
            if address not in by_address:
                need(not sequential or bounded_prefix, "Reachable sized-function fallthrough: "+owner)
                return
            state = (regs, slots)
            if address in states:
                previous = states[address]
                state = (merge(previous[0], regs), merge(previous[1], slots))
                if state == previous:
                    return
            states[address] = state
            pending.append(address)
        def plus(value, offset):
            if isinstance(value, int):
                return (value+offset) & 0xFFFFFFFF
            if isinstance(value, tuple) and value[0] == "stack":
                return ("stack", value[1]+offset)
            return None
        enqueue(body[0]["Address"], {"sp": ("stack", 0), "lr": RETURN_VALUE}, {})
        steps = 0
        while pending:
            address = pending.pop()
            steps += 1
            need(steps <= 20000, "Observer constant/stack CFG did not converge")
            ins = by_address[address]
            need(not self.is_data(ins, owner), "Control reaches mapped literal data")
            before_regs, before_slots = states[address]
            regs, slots = dict(before_regs), dict(before_slots)
            op, conditional = operation(ins)
            operands = ins["Operands"].split("@")[0].strip().lower()
            form, target = control_form(ins)
            if allowed_stores is not None:
                need(op in DATA_OPS or op in ("b", "bl", "blx", "bx", "cbz", "cbnz", "nop", "dsb", "isb", "dmb") or
                     re.fullmatch(r"it[te]{0,3}", op), "Observer unsupported instruction family: "+ins["Text"])
            following = address+len(ins["Bytes"])
            def value(token):
                token = token.strip()
                if token.startswith("#"):
                    return int(token[1:], 0)
                r = register(token)
                return ((address+4) & ~3) if r == "pc" else regs.get(r)
            def setreg(r, v):
                r = register(r)
                if v is None:
                    regs.pop(r, None)
                else:
                    regs[r] = v
            def store(location, width, values):
                if allowed_stores is not None:
                    need(location is not None, "Observer unresolved store destination: "+ins["Text"])
                    if isinstance(location, int):
                        need(not 0xE0000000 <= location < 0xE0100000, "Observer MMIO store: "+ins["Text"])
                        need(location % min(width, 4) == 0 and any(begin <= location and location+width <= end
                             for begin, end in allowed_stores), "Observer store outside exact fixture footprint: "+ins["Text"])
                    else:
                        sp = regs.get("sp")
                        need(location[0] == "stack" and isinstance(sp, tuple) and sp[0] == "stack" and
                             -8192 <= sp[1] <= location[1] and location[1]+width <= 0,
                             "Observer store outside allocated stack frame: "+ins["Text"])
                    writes[address] = dict(Instruction=ins["Text"], Destination=location, Width=width)
                if isinstance(location, tuple) and location[0] == "stack":
                    offset = location[1]
                    for key in list(slots):
                        if key < offset+width and offset < key+4:
                            slots.pop(key)
                    if width % 4 == 0:
                        for n, v in enumerate(values):
                            if v is not None:
                                slots[offset+n*4] = v
            stack_push = op == "push" or op == "stmdb" and re.match(r"(?:sp|r13)!\s*,", operands)
            stack_pop = op == "pop" or op in ("ldm", "ldmia") and re.match(r"(?:sp|r13)!\s*,", operands)
            if stack_push:
                names = register_list(operands)
                need("sp" not in names and "pc" not in names, "Unsupported stack save")
                location = plus(regs.get("sp"), -4*len(names))
                setreg("sp", location)
                store(location, 4*len(names), [regs.get(n) for n in names])
            elif stack_pop:
                names = register_list(operands)
                need("sp" not in names, "Unsupported stack restore")
                sp = regs.get("sp")
                need(isinstance(sp, tuple) and sp[0] == "stack", "Unproven stack return/frame")
                for n, name in enumerate(names):
                    saved = slots.get(sp[1]+4*n)
                    if name == "pc":
                        need(saved == RETURN_VALUE and sp[1]+4*len(names) == 0, "Unproven stack return: "+ins["Text"])
                        checked_returns.add(address)
                    else:
                        setreg(name, saved)
                setreg("sp", plus(sp, 4*len(names)))
            elif op.startswith(("str", "ldr")):
                widths = {"str": 4, "strb": 1, "strh": 2, "strd": 8,
                          "ldr": 4, "ldrb": 1, "ldrh": 2, "ldrsb": 1, "ldrsh": 2, "ldrd": 8}
                is_store = op.startswith("str")
                if op not in widths:
                    need(not is_store or allowed_stores is None, "Observer unsupported store width/family: "+ins["Text"])
                    setreg(operands.split(",")[0], None)
                else:
                    match = re.fullmatch(r"(.+?),\s*\[([^]]+)\](!)?(?:,\s*(#[^,]+))?", operands)
                    need(match is not None, "Unsupported memory form: "+ins["Text"])
                    destinations = [register(s) for s in match[1].split(",")]
                    parts = [s.strip() for s in match[2].split(",")]
                    base = register(parts[0])
                    indexed = len(parts) > 1 and not parts[1].startswith("#")
                    need(len(destinations) == (2 if widths[op] == 8 else 1) and
                         (len(parts) == 1 or len(parts) == 2 and not indexed or indexed and len(parts) <= 3),
                         "Unsupported memory operands: "+ins["Text"])
                    need(not (is_store and allowed_stores is not None and indexed), "Observer indexed store unsupported: "+ins["Text"])
                    offset = int(parts[1][1:], 0) if len(parts) > 1 and parts[1].startswith("#") else 0
                    location = None if indexed else plus(value(base), offset)
                    writeback = bool(match[3] or match[4])
                    if writeback and is_store and allowed_stores is not None:
                        need(base == "sp" and match[3] and not match[4] and offset == -widths[op],
                             "Observer writeback store unsupported: "+ins["Text"])
                        setreg("sp", location)
                    if is_store:
                        store(location, widths[op], [regs.get(n) for n in destinations])
                    else:
                        loaded = None
                        if isinstance(location, tuple) and location[0] == "stack" and widths[op] == 4:
                            loaded = slots.get(location[1])
                        elif base == "pc" and isinstance(location, int) and op == "ldr":
                            loaded = self.word(location)
                        elif isinstance(location, int) and 0xE0000000 <= location < 0xE0100000:
                            reads[address] = dict(Instruction=ins["Text"], Address=location, Width=widths[op])
                        for destination in destinations:
                            if destination == "pc":
                                next_sp = plus(regs.get("sp"), int(match[4][1:], 0)) if match[4] else None
                                need(loaded == RETURN_VALUE and next_sp == ("stack", 0), "Unproven stack return: "+ins["Text"])
                                checked_returns.add(address)
                            else:
                                setreg(destination, loaded if len(destinations) == 1 else None)
                    if writeback:
                        setreg(base, plus(value(base), int(match[4][1:], 0)) if match[4] else location)
            elif op.startswith("st"):
                need(allowed_stores is None, "Observer unsupported store width/family: "+ins["Text"])
            elif op.startswith("ldm"):
                need(allowed_stores is None, "Observer unsupported memory family: "+ins["Text"])
                for name in register_list(operands):
                    setreg(name, None)
                if "!" in operands.split(",")[0]:
                    setreg(operands.split(",")[0].rstrip("!"), None)
            elif op in ("mov", "movs", "movw", "movt", "mvn", "mvns", "add", "adds", "sub", "subs", "adr"):
                parts = [s.strip() for s in operands.split(",")]
                destination = parts[0]
                operands_values = [value(p) for p in parts[1:]]
                result = None
                if op.startswith("mov") and len(operands_values) == 1:
                    result = operands_values[0]
                    if op == "movt":
                        old = regs.get(register(destination))
                        result = ((old & 0xFFFF) | (result << 16)) if isinstance(old, int) and isinstance(result, int) else None
                elif op.startswith("mvn") and len(operands_values) == 1 and isinstance(operands_values[0], int):
                    result = operands_values[0] ^ 0xFFFFFFFF
                elif op in ("add", "adds", "sub", "subs") and len(parts) in (2, 3):
                    left, right = (regs.get(register(destination)), operands_values[0]) if len(parts) == 2 else operands_values[:2]
                    if isinstance(right, int):
                        result = plus(left, -right if op.startswith("sub") else right)
                setreg(destination, result)
            elif op not in ("b", "bl", "blx", "bx", "cbz", "cbnz", "cmp", "cmn", "tst", "teq", "nop", "dsb", "isb", "dmb", "bkpt", "udf") and not op.startswith("it"):
                destination = register(operands.split(",")[0])
                if re.fullmatch(r"r\d+|lr|sp", destination):
                    setreg(destination, None)
            if form == "return":
                if op == "bx":
                    need(regs.get("lr") == RETURN_VALUE and regs.get("sp") == ("stack", 0), "Unproven LR return: "+ins["Text"])
                    checked_returns.add(address)
                if conditional:
                    enqueue(following, before_regs, before_slots, sequential=True)
                continue
            if form in ("branch", "conditional"):
                if target not in by_address and self.resolve(target) not in NORETURN:
                    need(regs.get("sp") == ("stack", 0) and regs.get("lr") == RETURN_VALUE,
                         "Unproven tail-call return/frame: "+ins["Text"])
                enqueue(target, regs, slots)
                if form == "conditional":
                    enqueue(following, regs, slots, sequential=True)
                continue
            if form == "call":
                for name in ("r0", "r1", "r2", "r3", "r12", "lr"):
                    regs.pop(name, None)
                target_name = self.resolve(target)
                if target_name in NORETURN:
                    continue
            if op == "udf":
                continue
            if conditional:
                regs, slots = merge(regs, before_regs), merge(slots, before_slots)
            enqueue(following, regs, slots, sequential=True)
        for ins in body:
            if self.is_data(ins, owner):
                continue
            if control_form(ins)[0] == "return":
                need(ins["Address"] in checked_returns, "Unproven stack/LR return")
            if allowed_stores is not None and (operation(ins)[0].startswith("st") or operation(ins)[0] == "push"):
                need(ins["Address"] in writes, "Observer unproved emitted store: "+ins["Text"])
        return dict(Reads=list(reads.values()), Stores=list(writes.values()), States=len(states), Steps=steps)

    def mmio_loads(self, name):
        allowed = []
        for symbol in ("fixture_report", "fixture_observer_arm"):
            if symbol in getattr(self, "symbols", {}):
                record = self.symbol(symbol, "STT_OBJECT", local=symbol in getattr(self, "observer_local_objects", set()))
                section = self.sections[record["Section"]]
                need(section["Flags"] & 3 == 3, "Observer output object is not allocated writable storage")
                allowed.append((record["Address"], record["Address"]+record["Size"]))
        pending, visited, reads, stores = [name], set(), [], []
        while pending:
            owner = pending.pop()
            if owner in visited:
                continue
            visited.add(owner)
            body = self.body(owner)
            targets = self.targets(body, owner)
            proof = self.effects(body, owner, allowed_stores=allowed)
            reads.extend(dict(Owner=owner, **r) for r in proof["Reads"])
            stores.extend(dict(Owner=owner, **s) for s in proof["Stores"])
            pending.extend(targets-visited)
        self.observer_store_proof = dict(Owners=sorted(visited), AllowedObjects=["fixture_report", "fixture_observer_arm"],
            AllowedIntervals=allowed, Stores=stores, Scope="Finite constants and matched allocated stack slots; no variable-index/range/writeback generalization")
        return reads


def cpacr_spill_proof(image, owner):
    """Exact CPACR admission at every normal exit; no general pointer algebra."""
    address, mask = 0xE000ED88, 0x00F00000
    body = image.body(owner)
    for ins in body:
        if not image.is_data(ins, owner):
            op, conditional = operation(ins)
            need(not (conditional and op in ("bl", "blx")), "CPACR_PROOF_CONDITIONAL_CALL")
    image.targets(body, owner)  # Keep the established exact-edge and return admission.
    decoded = {i["Address"]: i for i in body}
    states, pending, stores, elsewhere, exits = {}, [], {}, {}, {}
    def merge(a, b):
        return {k: v for k, v in a.items() if v is not None and b.get(k) == v}
    def enqueue(pc, regs, slots):
        need(pc in decoded, "CPACR_PROOF_UNSUPPORTED_FLOW")
        state = (regs, slots)
        if pc in states:
            old = states[pc]
            state = (merge(old[0], regs), merge(old[1], slots))
            if state == old:
                return
        states[pc] = state
        pending.append(pc)
    def plus(value, offset):
        if isinstance(value, int):
            return (value+offset) & 0xFFFFFFFF
        if isinstance(value, tuple) and value[0] == "stack":
            return ("stack", value[1]+offset)
        return None
    def read_value(value):
        return isinstance(value, tuple) and value[0] == "read"
    def bit_or(a, b):
        if isinstance(a, int) and isinstance(b, int):
            return a | b
        if isinstance(a, int) and read_value(b):
            return ("read", b[1], b[2], b[3] | a, b[4])
        if read_value(a) and isinstance(b, int):
            return ("read", a[1], a[2], a[3] | b, a[4])
        if read_value(a) and read_value(b) and a[1:3] == b[1:3]:
            return ("read", a[1], a[2], a[3] | b[3], a[4] | b[4])
        return None
    def bit_and(a, b):
        if isinstance(a, int) and isinstance(b, int):
            return a & b
        if isinstance(a, int) and read_value(b):
            a, b = b, a
        if read_value(a) and isinstance(b, int):
            return ("read", a[1], a[2], a[3] & b, a[4] & b)
        return None
    def full_compare(a, b):
        if isinstance(a, int) and read_value(b):
            a, b = b, a
        return read_value(a) and a[1:] == (address, 4, 0, mask) and b == mask
    def condition_state(regs, condition, taken):
        result = dict(regs)
        if result.get("$full_compare") and condition in ("eq", "ne") and taken == (condition == "eq"):
            result["$admitted"] = True
        return result
    enqueue(body[0]["Address"], {"sp": ("stack", 0)}, {})
    steps = 0
    while pending:
        pc = pending.pop()
        steps += 1
        need(steps <= 20000, "CPACR_PROOF_CFG_LIMIT")
        ins = decoded[pc]
        need(not image.is_data(ins, owner), "CPACR_PROOF_UNSUPPORTED_FLOW")
        before_regs, before_slots = states[pc]
        regs, slots = dict(before_regs), dict(before_slots)
        op, conditional = operation(ins)
        need(op in DATA_OPS or op in ("b", "bl", "blx", "bx", "cbz", "cbnz", "nop", "dsb", "isb", "dmb") or
             re.fullmatch(r"it[te]{0,3}", op), "CPACR_PROOF_UNSUPPORTED_OPERATION")
        operands = ins["Operands"].split("@")[0].strip().lower()
        form, target = control_form(ins)
        need(not (form == "call" and conditional), "CPACR_PROOF_CONDITIONAL_CALL")
        # Only a single predicated store/return is modeled; arbitrary IT dataflow is not.
        need(not conditional or form in ("conditional", "return") or op.startswith("str"),
             "CPACR_PROOF_UNSUPPORTED_CONDITION")
        condition = ins["Mnemonic"].split(".")[0].lower()[len(op):] if conditional else ""
        if conditional:
            regs = condition_state(regs, condition, True)
        skipped_regs = condition_state(before_regs, condition, False)
        following = pc+len(ins["Bytes"])
        def value(token):
            token = token.strip()
            if token.startswith("#"):
                return int(token[1:], 0)
            name = register(token)
            return ((pc+4) & ~3) if name == "pc" else regs.get(name)
        def put(name, v):
            name = register(name)
            if name == "sp":
                old = regs.get("sp")
                if not (isinstance(v, tuple) and v[0] == "stack"):
                    slots.clear()
                elif isinstance(old, tuple) and old[0] == "stack" and v[1] > old[1]:
                    for key in list(slots):
                        if key < v[1]:
                            slots.pop(key)
            if v is None:
                regs.pop(name, None)
            else:
                regs[name] = v
        def store(location, width, values):
            need(location is not None, "CPACR_PROOF_UNRESOLVED_STORE")
            if isinstance(location, tuple):
                sp = regs.get("sp")
                need(location[0] == "stack" and isinstance(sp, tuple) and sp[0] == "stack" and
                     -8192 <= sp[1] <= location[1] and location[1]+width <= 0,
                     "CPACR_PROOF_UNSUPPORTED_STACK")
                for key in list(slots):
                    if key < location[1]+width and location[1] < key+4:
                        slots.pop(key)
                if width % 4 == 0:
                    for n, v in enumerate(values):
                        if v is not None:
                            slots[location[1]+n*4] = v
            elif location < address+4 and address < location+width:
                need(location == address and width == 4, "CPACR_PROOF_WRONG_WIDTH")
                v = values[0]
                need(read_value(v), "CPACR_PROOF_UNRELATED_MASK")
                need(v[1] == address and v[2] == 4, "CPACR_PROOF_WRONG_ADDRESS")
                need(v[3] != 0, "CPACR_PROOF_UNRELATED_MASK")
                need(v[3] == mask and (v[4] | v[3]) == 0xFFFFFFFF, "CPACR_PROOF_WRONG_MASK")
                regs["$admitted"] = True
                stores[pc] = dict(Instruction=ins["Text"], Destination=location, Width=width,
                                  ReadAddress=v[1], ReadWidth=v[2], OrMask=v[3])
            elif any(read_value(v) and v[3] == mask for v in values):
                elsewhere[pc] = ins["Text"]
        push = op == "push" or op == "stmdb" and re.match(r"sp!\s*,", operands)
        pop = op == "pop" or op in ("ldm", "ldmia") and re.match(r"sp!\s*,", operands)
        if push:
            names = register_list(operands)
            location = plus(regs.get("sp"), -4*len(names))
            put("sp", location)
            store(location, 4*len(names), [regs.get(n) for n in names])
        elif pop:
            names = register_list(operands)
            sp = regs.get("sp")
            need(isinstance(sp, tuple) and sp[0] == "stack", "CPACR_PROOF_UNSUPPORTED_STACK")
            for n, name in enumerate(names):
                put(name, slots.get(sp[1]+n*4))
            put("sp", plus(sp, 4*len(names)))
        elif op.startswith(("ldr", "str")):
            widths = {"ldr": 4, "ldrb": 1, "ldrh": 2, "ldrsb": 1, "ldrsh": 2, "ldrd": 8,
                      "str": 4, "strb": 1, "strh": 2, "strd": 8}
            need(op in widths, "CPACR_PROOF_UNSUPPORTED_MEMORY")
            match = re.fullmatch(r"(.+?),\s*\[([^]]+)\]", operands)
            need(match is not None, "CPACR_PROOF_UNSUPPORTED_MEMORY")
            names = [register(s) for s in match[1].split(",")]
            parts = [s.strip() for s in match[2].split(",")]
            need(len(names) == (2 if widths[op] == 8 else 1) and len(parts) in (1, 2) and
                 (len(parts) == 1 or re.fullmatch(r"#-?(?:0x[0-9a-f]+|[0-9]+)", parts[1])),
                 "CPACR_PROOF_UNSUPPORTED_MEMORY")
            base = register(parts[0])
            location = plus(value(base), int(parts[1][1:], 0) if len(parts) == 2 else 0)
            if op.startswith("str"):
                store(location, widths[op], [regs.get(n) for n in names])
            else:
                loaded = None
                if isinstance(location, tuple) and location[0] == "stack" and widths[op] == 4:
                    sp = regs.get("sp")
                    need(isinstance(sp, tuple) and sp[0] == "stack" and
                         sp[1] <= location[1] and location[1]+4 <= 0, "CPACR_PROOF_UNSUPPORTED_STACK")
                    loaded = slots.get(location[1])
                elif isinstance(location, int):
                    loaded = image.word(location) if base == "pc" and op == "ldr" else ("read", location, widths[op], 0, 0xFFFFFFFF)
                for name in names:
                    put(name, loaded if len(names) == 1 else None)
        elif op.startswith(("st", "ldm")):
            raise RuntimeError("CPACR_PROOF_UNSUPPORTED_MEMORY")
        elif op in ("mov", "movs", "movw", "movt", "mvn", "mvns", "add", "adds", "sub", "subs", "orr", "orrs", "and", "ands", "bic", "bics"):
            parts = [s.strip() for s in operands.split(",")]
            result = None
            if op.startswith("mov") and len(parts) == 2:
                result = value(parts[1])
                if op == "movt":
                    old = regs.get(register(parts[0]))
                    result = ((old & 0xFFFF) | result << 16) if isinstance(old, int) and isinstance(result, int) else None
            elif op.startswith("mvn") and len(parts) == 2 and isinstance(value(parts[1]), int):
                result = value(parts[1]) ^ 0xFFFFFFFF
            elif len(parts) in (2, 3):
                a, b = (value(parts[0]), value(parts[1])) if len(parts) == 2 else (value(parts[1]), value(parts[2]))
                if op.startswith("orr"):
                    result = bit_or(a, b)
                elif op.startswith(("and", "bic")):
                    if op.startswith("bic"):
                        need(isinstance(b, int), "CPACR_PROOF_NONCONSTANT_BIC")
                        b ^= 0xFFFFFFFF
                    result = bit_and(a, b)
                elif isinstance(b, int):
                    result = plus(a, -b if op.startswith("sub") else b)
            put(parts[0], result)
        elif op == "cmp":
            parts = [s.strip() for s in operands.split(",")]
            if len(parts) == 2 and full_compare(value(parts[0]), value(parts[1])):
                regs["$full_compare"] = True
            else:
                regs.pop("$full_compare", None)
        elif op not in ("b", "bl", "blx", "bx", "cbz", "cbnz", "cmp", "cmn", "tst", "teq", "nop", "dsb", "isb", "dmb", "msr") and not op.startswith("it"):
            name = register(operands.split(",")[0])
            if re.fullmatch(r"r\d+|lr|sp", name):
                put(name, None)
        if op in ("movs", "mvns", "adds", "subs", "orrs", "ands", "bics", "eors", "lsls", "lsrs", "asrs", "muls", "cmn", "tst", "teq") or op == "msr" and operands.startswith("apsr"):
            regs.pop("$full_compare", None)
        if form == "return":
            exits[pc] = bool(regs.get("$admitted"))
            if conditional:
                enqueue(following, skipped_regs, before_slots)
            continue
        if form in ("branch", "conditional"):
            if target in decoded:
                enqueue(target, regs, slots)
            elif image.resolve(target) not in NORETURN:
                exits[pc] = bool(regs.get("$admitted"))
            if form == "conditional":
                enqueue(following, skipped_regs, slots)
            continue
        if form == "call":
            if image.resolve(target) in NORETURN:
                continue
            slots.clear()
            regs = {k: v for k, v in regs.items() if not read_value(v) and k != "$full_compare"}
            for n in ("r0", "r1", "r2", "r3", "r12", "lr"):
                regs.pop(n, None)
        if conditional:
            regs, slots = merge(regs, skipped_regs), merge(slots, before_slots)
        enqueue(following, regs, slots)
    need(stores, "CPACR_PROOF_WRONG_ADDRESS" if elsewhere else "CPACR_PROOF_MISSING_STORE")
    need(exits, "CPACR_PROOF_NO_NORMAL_EXIT")
    need(all(exits.values()), "CPACR_PROOF_MISSING_ON_EXIT")
    return dict(Mode="bounded-constant-stack-spill", Owner=owner, Stores=list(stores.values()), States=len(states), Steps=steps,
                NormalExits=[dict(Address=pc, Admitted=ok) for pc, ok in sorted(exits.items())],
                Scope="Every decoded normal exit follows an exact CPACR word-read/OR/word-store or full-mask read guard; freed/call-crossing spills are unknown; no general pointer or whole-provider proof")


def legacy_cpacr_check(text, reference):
    need(re.search(r"\borr[^\n]*#(?:15728640|0xf00000)\b", text, re.I) and
         re.search(r"\bstr", text), "CP10/CP11 enable/store mechanism missing")
    need(("0xe000ed88" in text.lower()) if reference else
         ("0xe000ed88" in text.lower() or "0xe000e000" in text.lower() and
          re.search(r"\bstr[^\n]*#(?:3464|0xd88)\b", text, re.I)), "CPACR address/store evidence missing")
    return dict(Mode="legacy-immediate-pattern", Scope="Existing bounded mask/address/store pattern; not whole-provider dataflow")


def cpacr_mechanism_proof(image, owner, reference, full_grid, optimization):
    if full_grid and optimization == "O0" and not reference:
        return cpacr_spill_proof(image, owner)
    return legacy_cpacr_check("\n".join(i["Text"] for i in image.body(owner)), reference)


class Suite(common.Suite):
    def __init__(self, args, profile=CM4):
        need(profile in (CM4, CM7), "Only the two immutable classic FP profiles are admitted")
        self.profile = profile
        self.grid = grid_counts(args.full_optimization_grid_fp, args.development_smoke)
        self.modes = FULL_MODES if args.full_optimization_grid_fp else DEFAULT_MODES
        super().__init__(args)
        self.fixture = self.repo/profile.fixture_relative
        self.pairs = []
        self.report.update(Scope=profile.scope, Profile=profile._asdict(),
                           FullOptimizationGridFP=args.full_optimization_grid_fp, DevelopmentSmoke=args.development_smoke,
                           OptimizationModes=[dict(Optimization=opt, LTO=lto) for opt, lto in self.modes], GridContract=self.grid._asdict(),
                           ReferencePairs=self.pairs, ReferenceExecuted=False,
                           ReferencePolicy="Pinned upstream always lazy; Fiber eager is an intentional divergence")

    def repo_inventory(self):
        super().repo_inventory()
        for name in self.profile.evidence_paths:
            self.enroll(self.repo/name, "ExplicitEvidenceHelper")
        relative = {Path(k).relative_to(self.repo).as_posix(): v["Sha256"] for k, v in self.inputs.items()
                    if Path(k).is_relative_to(self.repo)}
        encoded = json.dumps(relative, sort_keys=True, separators=(",", ":")).encode("ascii")
        self.report["RepositoryIdentity"]["TreeSha256"] = hashlib.sha256(encoded).hexdigest().upper()
        self.repo_paths_before = set(relative)

    def check_repository_inventory(self):
        if self.exact_git:
            names = self.git(self.repo, "ls-files", "-z")["Stdout"].split("\0")
            paths = {self.repo/n for n in names if n and "__pycache__" not in Path(n).parts}
        else:
            paths = set(common.directory_files(self.repo))
        paths.update(common.directory_files(self.fixture))
        paths.update(self.repo/n for n in (*self.profile.evidence_paths, "tools/test_classic_context_runtime.ps1",
            "tools/freertos_asm_parity.ps1", "tools/runtime_sources.py", "tools/runtime_sources.ps1", "tools/runtime_sources.json"))
        relative = {p.relative_to(self.repo).as_posix() for p in paths}
        self.report["RepositoryInventoryDrift"] = sorted(relative ^ self.repo_paths_before)
        need(not self.report["RepositoryInventoryDrift"], "Repository/export inventory changed")

    def inspect_qemu(self, name):
        directory = self.build/name
        directory.mkdir()
        self.command(["wsl.exe", "-d", self.a.wsl_distro, "--", "bash",
            self.wsl_path(self.repo/"tools/fixtures/classic_context_runtime/qemu.sh"), "inspect",
            self.a.qemu_root, self.wsl_path(directory)], "inspect existing QEMU prefix")
        required = ("qemu-version.txt", "qemu-machines.txt", "qemu-cpus.txt", "qemu-ldd.txt",
                    "qemu-sha256.txt", "qemu-libraries-sha256.txt", "wsl-tools-sha256.txt", "wsl-user.txt",
                    "wsl-system.txt", "wsl-os-release.txt", "deb-sha256.txt", "deb-versions.txt", "qemu-root.txt")
        result = {}
        for filename in required:
            path = directory/filename
            need(path.is_file() and path.stat().st_size, "Missing QEMU identity: "+filename)
            if filename != "qemu-ldd.txt":
                result[filename] = digest(path)
        need(re.search(r"(?m)^"+re.escape(self.profile.machine)+r"\s", (directory/"qemu-machines.txt").read_text()), "QEMU lacks "+self.profile.machine)
        return result

    def preflight(self):
        super().preflight()
        self.tools["nm"] = (self.tools["gcc"].parent/"arm-none-eabi-gcc-nm.exe").resolve(strict=True)
        self.enroll(self.tools["nm"], "SlimLtoNm")
        self.report["TerminalControls"] = terminal_controls(self.profile)
        self.report["ProfileControls"] = profile_controls()
        self.report["GridOptionControls"] = grid_controls()
        self.report["DecoderControls"] = decoder_controls()
        self.report["ObserverParserControls"] = self.observer_parser_controls()
        self.report["ObserverCompiledControls"] = self.observer_compiled_controls()
        if self.a.full_optimization_grid_fp:
            self.report["CpacrSpillControls"] = self.cpacr_spill_controls()
        self.report["InheritedEvidenceHelper"] = dict(Path=str(COMMON_PATH), Sha256=digest(COMMON_PATH),
            Roles=["input/tool/reference identity", "dependency closure", "prelink private owner", "artifact verification"])
        self.report["PreflightComplete"] = True
        save(self.build/"inputs.before.json", list(self.inputs.values()))

    def cpacr_spill_controls(self):
        header = self.repo/self.profile.port_relative/"fiber_portmacro.h"
        need(str(header.resolve()) in self.inputs, "CPACR control source must already be enrolled")
        text = header.read_text()
        begin = "\tconst uint32_t cpacr_cp10_cp11_full = (0xFu << 20);"
        end = "\tFIBER_REQUIRE((*cpacr_reg"
        need(text.count(begin) == text.count(end) == 1, "Exact production CPACR block anchors")
        fragment = text[text.index(begin):text.index(end, text.index(begin))]
        assignment = "value = (value & ~cpacr_cp10_cp11_full) | cpacr_cp10_cp11_full;"
        variants = [("positive", None, None, None),
                    ("wrong_mask", "(0xFu << 20)", "(0x7u << 20)", "CPACR_PROOF_WRONG_MASK"),
                    ("wrong_address", "0xE000ED88u", "0xE000ED8Cu", "CPACR_PROOF_WRONG_ADDRESS"),
                    ("missing_store", "*cpacr_reg = value;", "(void)value;", "CPACR_PROOF_MISSING_STORE"),
                    ("unrelated_mask", assignment, "cpacr_control_witness |= cpacr_cp10_cp11_full;", "CPACR_PROOF_UNRELATED_MASK"),
                    ("unknown_address", "(uint32_t *)0xE000ED88u", "destination", "CPACR_PROOF_UNRESOLVED_STORE"),
                    ("wrong_width", "*cpacr_reg = value;", "*(volatile unsigned char *)cpacr_reg = (unsigned char)value;", "CPACR_PROOF_WRONG_WIDTH"),
                    ("branch_skip", "*cpacr_reg = value;", "if (cpacr_control_witness) { *cpacr_reg = value; }", "CPACR_PROOF_MISSING_ON_EXIT")]
        chunks = ["typedef unsigned int uint32_t;", "_Static_assert(sizeof(uint32_t) == 4, \"control word\");",
                  "volatile uint32_t cpacr_control_witness;",
                  "#define fiber_portDATA_SYNC_BARRIER() __asm volatile(\"dsb\" ::: \"memory\")",
                  "#define fiber_portINST_SYNC_BARRIER() __asm volatile(\"isb\" ::: \"memory\")",
                  "#define CONTROL __attribute__((used,noipa,target(\"general-regs-only\")))"]
        for name, old, new, _ in variants:
            body = fragment
            if old is not None:
                need(body.count(old) == 1, "Unique source-derived CPACR mutation: "+name)
                body = body.replace(old, new)
            args = "uint32_t *destination" if name == "unknown_address" else "void"
            chunks.append("CONTROL void cpacr_control_"+name+"("+args+") {\n"+body+"}\n")
        directory = self.build/"cpacr-spill-controls"
        directory.mkdir()
        source = directory/"controls.c"
        source.write_text("\n".join(chunks)+"\n", encoding="ascii", newline="\n")
        self.generated[str(source.resolve())] = dict(Path=str(source.resolve()), Sha256=digest(source), Role="SourceDerivedCpacrControls")
        cpacr = "movw r3,#0xed88\nmovt r3,#0xe000\nldr r1,[r3]\n"
        update = "orr.w r1,r1,#0x00f00000\nstr r1,[r3]\n"
        asm_variants = [
            ("it_skip", cpacr+"orr.w r1,r1,#0x00f00000\ncmp r0,#0\nit ne\nstrne r1,[r3]\nbx lr\n",
             "CPACR_PROOF_MISSING_ON_EXIT"),
            ("guard_spill", "push {r4,lr}\nsub sp,#8\nmov.w r2,#0x00f00000\nstr r2,[sp,#4]\n"+cpacr+
             "ldr r2,[sp,#4]\nand.w r0,r1,r2\ncmp r0,r2\nbeq 1f\norrs r1,r2\nstr r1,[r3]\n1: add sp,#8\npop {r4,pc}\n", None),
            ("it_guard", cpacr+"orr.w r2,r1,#0x00f00000\nand.w r1,r1,#0x00f00000\ncmp.w r1,#0x00f00000\nit ne\nstrne r2,[r3]\nbx lr\n", None),
            ("constant_bic", cpacr+"bic.w r1,r1,#0x00f00000\n"+update+"bx lr\n", None),
            ("read_rhs_bic", cpacr+"mov.w r2,#0x00f00000\nbic.w r0,r2,r1\ncmp r0,r2\nbeq 1f\norr.w r1,r1,r2\nstr r1,[r3]\n1: bx lr\n", "CPACR_PROOF_NONCONSTANT_BIC"),
            ("reclaimed_spill", "push {r4,lr}\nsub sp,#8\nmov.w r2,#0x00f00000\nstr r2,[sp,#4]\nadd sp,#8\nsub sp,#8\nldr r2,[sp,#4]\n"+
             cpacr+"orrs r1,r2\nstr r1,[r3]\nadd sp,#8\npop {r4,pc}\n", "CPACR_PROOF_UNRELATED_MASK"),
            ("call_spill", "push {r4,lr}\nsub sp,#8\nmov.w r2,#0x00f00000\nstr r2,[sp,#4]\nadd sp,#8\nbl cpacr_clobber_below_sp\nsub sp,#8\nldr r2,[sp,#4]\n"+
             cpacr+"orrs r1,r2\nstr r1,[r3]\nadd sp,#8\npop {r4,pc}\n", "CPACR_PROOF_UNRELATED_MASK"),
            ("indirect_call_spill", "push {r4,lr}\nsub sp,#8\nmov.w r2,#0x00f00000\nstr r2,[sp,#4]\nmovw r0,#:lower16:cpacr_control_spill_pointer\nmovt r0,#:upper16:cpacr_control_spill_pointer\nstr sp,[r0]\nbl cpacr_clobber_indirect\nldr r2,[sp,#4]\n"+
             cpacr+"orrs r1,r2\nstr r1,[r3]\nadd sp,#8\npop {r4,pc}\n", "CPACR_PROOF_UNRELATED_MASK"),
            ("conditional_noreturn", "push {r4,lr}\n"+cpacr+update+
             "cmp r0,#0\nit eq\nbleq fixture_check_fail\npop {r4,pc}\n", "CPACR_PROOF_CONDITIONAL_CALL"),
            ("no_normal_exit", cpacr+update+"1: b 1b\n", "CPACR_PROOF_NO_NORMAL_EXIT")]
        assembly = directory/"controls.S"
        asm_chunks = [".syntax unified\n.thumb\n.text\n"]
        for name, body, _ in asm_variants:
            symbol = "cpacr_control_"+name
            asm_chunks.append(".global "+symbol+"\n.type "+symbol+",%function\n.thumb_func\n"+symbol+":\n"+body+".size "+symbol+",.-"+symbol+"\n")
        asm_chunks.append(".global cpacr_clobber_below_sp\n.type cpacr_clobber_below_sp,%function\n.thumb_func\ncpacr_clobber_below_sp:\nsub sp,#8\nmovs r1,#0\nstr r1,[sp,#4]\nadd sp,#8\nbx lr\n.size cpacr_clobber_below_sp,.-cpacr_clobber_below_sp\n")
        asm_chunks.append(".global cpacr_clobber_indirect\n.type cpacr_clobber_indirect,%function\n.thumb_func\ncpacr_clobber_indirect:\nldr r0,[r0]\nmovs r1,#0\nstr r1,[r0,#4]\nbx lr\n.size cpacr_clobber_indirect,.-cpacr_clobber_indirect\n.bss\n.balign 4\n.global cpacr_control_spill_pointer\n.type cpacr_control_spill_pointer,%object\ncpacr_control_spill_pointer: .space 4\n.size cpacr_control_spill_pointer,4\n.text\n")
        asm_chunks.append(".global fixture_check_fail\n.type fixture_check_fail,%function\n.thumb_func\nfixture_check_fail:\nb fixture_check_fail\n.size fixture_check_fail,.-fixture_check_fail\n.section .note.GNU-stack,\"\",%progbits\n")
        assembly.write_text("\n".join(asm_chunks), encoding="ascii", newline="\n")
        self.generated[str(assembly.resolve())] = dict(Path=str(assembly.resolve()), Sha256=digest(assembly), Role="CpacrCompiledCfgAndSpillControls")
        cases = []
        for opt in ("O0", "O2"):
            obj, elf = directory/(opt+".o"), directory/(opt+".elf")
            asm_obj = directory/(opt+"-asm.o")
            compile_record = self.command([self.tools["gcc"], *self.profile.cpu_flags, *COMPILE, "-"+opt,
                                          "-c", source, "-o", obj], "compile source-derived CPACR controls "+opt)
            need(not compile_record["Stderr"], "CPACR control compilation warning")
            asm_record = self.command([self.tools["gcc"], *self.profile.cpu_flags, "-"+opt,
                                       "-c", assembly, "-o", asm_obj], "assemble CPACR CFG/spill controls "+opt)
            need(not asm_record["Stderr"], "CPACR assembly control warning")
            link_record = self.command([self.tools["gcc"], *self.profile.cpu_flags, "-"+opt, "-nostdlib",
                "-Wl,--no-undefined,--fatal-warnings,-z,noexecstack,-Ttext=0x1000,-Tbss=0x20000000,-e,cpacr_control_positive",
                obj, asm_obj, "-o", elf], "link source-derived CPACR controls "+opt)
            dis = self.command([self.tools["objdump"], "-drwC", "-Mreg-names-std", elf], "disassemble CPACR controls "+opt)
            elf.with_suffix(".dis").write_text(dis["Stdout"], encoding="ascii")
            image = Image(elf, self.ELFFile)
            for name, reason in ([(n, r) for n, _, _, r in variants]+[(n, r) for n, _, r in asm_variants]):
                symbol = "cpacr_control_"+name
                record = dict(Name=name, Optimization=opt, Symbol=symbol, ExpectedReason=reason,
                    Elf=str(elf), ElfSha256=digest(elf), Object=str(obj), ObjectSha256=digest(obj),
                    ExecutableBytes=image.bytes(image.symbol(symbol, "STT_FUNC")).hex(),
                    AssemblyObject=str(asm_obj), AssemblyObjectSha256=digest(asm_obj),
                    Compile=compile_record["Record"], Assemble=asm_record["Record"], Link=link_record["Record"], Disassembly=dis["Record"])
                try:
                    proof = (cpacr_mechanism_proof(image, symbol, False, True, opt) if opt == "O0" else
                             cpacr_spill_proof(image, symbol))
                except RuntimeError as error:
                    need(reason is not None and str(error) == reason, "Wrong CPACR causal rejection: "+name+" "+opt+": "+str(error))
                    record.update(Accepted=False, Reason=str(error))
                else:
                    need(reason is None, "CPACR causal false acceptance: "+name+" "+opt)
                    record.update(Accepted=True, Proof=proof)
                cases.append(record)
        need(len(cases) == 36 and sum(c["Accepted"] for c in cases) == 8, "Literal CPACR compiled control coverage")
        report = dict(ProductionHeader=str(header), ProductionHeaderSha256=digest(header),
            ExtractedBlockSha256=hashlib.sha256(fragment.encode("ascii")).hexdigest().upper(),
            Source=str(source), SourceSha256=digest(source), AssemblySource=str(assembly), AssemblySourceSha256=digest(assembly),
            OriginalSourceDerivedControls=14, AddedSourceDerivedControls=2, AddedAssemblyControls=20, Controls=cases,
            Scope="Original fourteen actual-header C controls retained, plus compiled branch/IT admission, constant/nonconstant BIC, active/freed/call-crossing spills, conditional no-return and no-normal-exit controls; static checks only, no CPU execution or runtime grid rows")
        save(directory/"results.json", report)
        return report

    def observer_parser_controls(self):
        # These are the review counterexamples, not disassembly generated from a passing subject.
        cases = [
            ("review-ldr-pc", "100: f8d3 f000 ldr.w pc,[r3]", "Unresolved PC write:"),
            ("review-indexed-mmio", "100: f64e 7234 movw r2,#61236\n104: f2ce 0200 movt r2,#57344\n"
             "108: 2300 movs r3,#0\n10a: 50d0 str r0,[r2,r3]\n10c: 6810 ldr r0,[r2,#0]\n10e: 4770 bx lr",
             "Observer indexed store unsupported:"),
            ("unknown-width", "100: f843 0e00 strt r0,[r3]\n104: 4770 bx lr", "Observer unsupported instruction family:"),
            ("indexed-shift", "100: f842 0023 str.w r0,[r2,r3,lsl #2]\n104: 4770 bx lr", "Observer indexed store unsupported:"),
            ("malformed-immediate", "100: f842 0023 str.w r0,[r2,#4,lsl #2]\n104: 4770 bx lr", "Unsupported memory operands:"),
            ("unknown-memory-family", "100: eec3 0100 stc 1,cr0,[r3]", "FP/coprocessor instruction in GRO closure:"),
            ("unmatched-stack-return", "100: bd10 pop {r4,pc}", "Unproven stack return:"),
            ("matched-stack-return", "100: b510 push {r4,lr}\n102: bd10 pop {r4,pc}", None),
            ("entry-lr-return", "100: 4770 bx lr", None)]
        result = []
        for name, text, expected in cases:
            image = object.__new__(Image)
            image.body = lambda _, text=text: instructions(text)
            image.is_data = lambda *_: False
            try:
                image.no_fp_closure([name], forbid_cpu_write=True)
                image.mmio_loads(name)
            except RuntimeError as error:
                need(expected is not None and str(error).startswith(expected), "Wrong observer parser rejection: "+name+": "+str(error))
                result.append(dict(Name=name, Accepted=False, Diagnostic=str(error)))
            else:
                need(expected is None, "Observer parser false acceptance: "+name)
                result.append(dict(Name=name, Accepted=True))
        need(len(result) == 9, "Literal observer parser control count")
        return result

    def observer_compiled_controls(self):
        cases = [
            ("report", "ldr r2,=fixture_report\nstr r0,[r2]\nstrb r0,[r2,#4]\nstrh r0,[r2,#6]\nstrd r0,r1,[r2,#8]\nbx lr", None),
            ("stack", "push {r4,lr}\nsub sp,sp,#8\nstr r0,[sp]\nstrh r0,[sp,#4]\nstrb r0,[sp,#6]\nadd sp,sp,#8\npop {r4,pc}", None),
            ("stack_ldr_return", "push {lr}\nldr pc,[sp],#4", None),
            ("mmio_read", "ldr r2,=0xe000ef34\nldr r0,[r2]\nbx lr", None),
            ("call_report", "push {r4,lr}\nbl control_report\npop {r4,pc}", None),
            ("ldr_pc", "ldr.w pc,[r3]", "Unresolved PC write:"),
            ("mov_pc", "mov pc,r3", "Unresolved PC write:"),
            ("table_pc", "tbb [r3,r0]", "Unresolved control transfer:"),
            ("ldmia_pc", "ldmia r3!,{r4,pc}", "Unresolved PC write:"),
            ("pop_unmatched", "pop {r4,pc}", "Unproven stack return:"),
            ("ldr_stack_unmatched", "ldr pc,[sp],#4", "Unproven stack return:"),
            ("lr_overwrite", "mov lr,r3\nbx lr", "Unproven LR return:"),
            ("review_indexed_mmio", "movw r2,#61236\nmovt r2,#57344\nmovs r3,#0\nstr r0,[r2,r3]\nldr r0,[r2]\nbx lr",
             "Observer indexed store unsupported:"),
            ("mmio_store", "ldr r2,=0xe000ef34\nstr r0,[r2]\nbx lr", "Observer MMIO store:"),
            ("unknown_store", "str r0,[r3]\nbx lr", "Observer unresolved store destination:"),
            ("shifted_address", "ldr r2,=fixture_report\nmovs r3,#4\nadd.w r2,r2,r3,lsl #20\nstr r0,[r2]\nbx lr",
             "Observer unresolved store destination:"),
            ("report_indexed", "ldr r2,=fixture_report\nmovs r3,#0\nstr r0,[r2,r3]\nbx lr", "Observer indexed store unsupported:"),
            ("report_writeback", "ldr r2,=fixture_report\nstr r0,[r2],#4\nbx lr", "Observer writeback store unsupported:"),
            ("foreign_store", "ldr r2,=0x20010000\nstr r0,[r2]\nbx lr", "Observer store outside exact fixture footprint:"),
            ("past_end_byte", "ldr r2,=fixture_observer_arm+4\nstrb r0,[r2]\nbx lr", "Observer store outside exact fixture footprint:"),
            ("cross_end_double", "ldr r2,=fixture_report+316\nstrd r0,r1,[r2]\nbx lr", "Observer store outside exact fixture footprint:"),
            ("misaligned_word", "ldr r2,=fixture_report+1\nstr r0,[r2]\nbx lr", "Observer store outside exact fixture footprint:"),
            ("exclusive_store", "strex r0,r1,[r2]\nbx lr", "Observer unsupported instruction family:"),
            ("stm_store", "stmia r2!,{r0,r1}\nbx lr", "Observer unsupported store width/family:"),
            ("unallocated_stack", "str r0,[sp,#-4]\nbx lr", "Observer store outside allocated stack frame:"),
            ("stack_return_overwrite", "push {r4,lr}\nstr r0,[sp,#4]\npop {r4,pc}", "Unproven stack return:"),
            ("hidden_helper_store", "push {r4,lr}\nbl control_mmio_store\npop {r4,pc}", "Observer MMIO store:"),
            ("external_middle", "push {r4,lr}\nmovw r2,#61236\nmovt r2,#57344\nbl control_report+2\npop {r4,pc}",
             "Transfer does not enter exact function entry:"),
            ("same_body_call", "push {r4,lr}\nldr r2,=fixture_report\n.Lcontrol_store:\nstr r0,[r2]\n"
             "movw r2,#61236\nmovt r2,#57344\nbl .Lcontrol_store\npop {r4,pc}",
             "Transfer does not enter exact function entry:"),
            ("branch_halfword", "b .Lcontrol_wide+2\n.Lcontrol_wide:\n.inst.w 0xf2406008\nbx lr",
             "Explicit target is not a decoded instruction boundary:"),
            ("fallthrough_adjacent", "nop\nnop", "Reachable sized-function fallthrough:"),
            ("fallthrough_data", "nop\nnop\n.word 0x47704770", "Control reaches mapped literal data")]
        need(len(cases) == 32, "Literal compiled observer control count")
        directory = self.build/"observer-compiled-controls"
        directory.mkdir()
        source = directory/"controls.S"
        lines = [".syntax unified", ".thumb", ".cpu "+self.profile.cpu, ".fpu "+self.profile.fpu, ".text", ".balign 4"]
        for name, body, _ in cases:
            symbol = "control_"+name
            lines += [".global "+symbol, ".type "+symbol+",%function", ".thumb_func", symbol+":", body,
                      ".ltorg", ".size "+symbol+",.-"+symbol, ".balign 4"]
        lines += [".bss", ".balign 4", ".global fixture_report", ".type fixture_report,%object",
                  "fixture_report:", ".space 320", ".size fixture_report,320", ".global fixture_observer_arm",
                  ".type fixture_observer_arm,%object", "fixture_observer_arm:", ".space 4", ".size fixture_observer_arm,4"]
        source.write_text("\n".join(lines)+"\n", encoding="ascii", newline="\n")
        self.generated[str(source.resolve())] = dict(Path=str(source.resolve()), Sha256=digest(source), Role="CompiledObserverCheckerControls")
        obj, elf = directory/"controls.o", directory/"controls.elf"
        compile_record = self.command([self.tools["gcc"], *self.profile.cpu_flags, "-c", source, "-o", obj], "compile actual observer controls")
        link_record = self.command([self.tools["gcc"], *self.profile.cpu_flags, "-nostdlib", "-Wl,--no-undefined,--fatal-warnings,-z,noexecstack",
            "-Wl,-Ttext=0x1000,-Tbss=0x20000000,-e,control_report", obj, "-o", elf], "link actual observer controls")
        dis = self.command([self.tools["objdump"], "-drwC", "-Mreg-names-std", elf], "disassemble actual observer controls")
        elf.with_suffix(".dis").write_text(dis["Stdout"], encoding="ascii")
        image = Image(elf, self.ELFFile)
        results = []
        for name, _, expected in cases:
            symbol = "control_"+name
            body = image.body(symbol)
            record = dict(Name=name, Symbol=symbol, ExecutableBytes=image.bytes(image.symbol(symbol, "STT_FUNC")).hex())
            try:
                closure = image.no_fp_closure([symbol], forbid_cpu_write=True)
                reads = image.mmio_loads(symbol)
            except RuntimeError as error:
                need(expected is not None and str(error).startswith(expected), "Wrong compiled observer rejection: "+name+": "+str(error))
                record.update(Accepted=False, Diagnostic=str(error))
            else:
                need(expected is None, "Compiled observer false acceptance: "+name)
                record.update(Accepted=True, Closure=closure, Reads=reads, StoreProof=image.observer_store_proof)
                if name == "mmio_read":
                    need(len(reads) == 1 and reads[0]["Address"] == 0xE000EF34 and reads[0]["Width"] == 4,
                         "Compiled observer read-only MMIO positive lost its exact read")
            results.append(record)
        need(sum(r["Accepted"] for r in results) == 5 and len(results) == 32, "Compiled observer positive/negative coverage")
        report = dict(Source=str(source), SourceSha256=digest(source), Object=str(obj), ObjectSha256=digest(obj),
            Elf=str(elf), ElfSha256=digest(elf), Compile=compile_record["Record"], Link=link_record["Record"],
            Disassembly=dis["Record"], Controls=results, Scope="Actual assembled checker controls, never QEMU-executed; not firmware grid rows")
        save(directory/"results.json", report)
        return report

    def stage(self):
        header = (self.fixture/"fixture.h").read_text()
        facts = {"FIXTURE_REQUIRED_ROUNDS": 16, "FIXTURE_STACK_BYTES": 4096,
                 "FIXTURE_REASON_GPR": 121, "FIXTURE_REASON_HIGH_FP": 131,
                 "FIXTURE_REASON_FPSCR": 132, "FIXTURE_REASON_FPCA": 133,
                 "FIXTURE_REASON_LOW_FP": 134, "FIXTURE_REASON_OBSERVER": 141}
        for key, value in facts.items():
            need(re.search(r"(?m)^#define "+key+" "+str(value)+r"\s*$", header), "Fixture numeric contract changed: "+key)
        need("(FIXTURE_CASE != 0)" in header, "Fixture no longer has the explicit case-zero contract")
        def add(consumer, opt, lto, archive, lazy, policy, mutant=None):
            name = "-".join((consumer, opt, "lto" if lto else "normal", "archive" if archive else "direct",
                             "lazy" if lazy else "eager", policy, mutant or "positive"))
            self.rows.append(dict(Name=name, Consumer=consumer, Optimization=opt, LTO=lto, Archive=archive,
                Lazy=lazy, Policy=policy, Mutant=mutant, Kind="CompiledControl" if mutant else "Positive",
                Expected=expected_terminal(lazy, policy == "validation", mutant, profile=self.profile), Status="STAGED"))
        for spec in execution_plan(self.a.full_optimization_grid_fp, self.a.development_smoke):
            add(*spec)
        counts = dict(Counter(row["Kind"] for row in self.rows))
        need(len({r["Name"] for r in self.rows}) == len(self.rows), "Duplicate FP execution cell")
        validate_execution_grid(self.rows, self.a.full_optimization_grid_fp, self.a.development_smoke)
        self.report["ExpectedGrid"] = counts
        self.report["FixtureFacts"] = facts
        self.report["MutantReasons"] = MUTANTS
        save(self.build/"staged.json", self.rows)

    def mutate(self, source, name, directory):
        original = source.read_text()
        if name == "publication":
            anchor = "fiber_internal_runtime_current_context_slot = next;"
            need(original.count(anchor) == 1, "Publication mutation anchor")
            changed = original.replace(anchor, "if (fiber_internal_runtime_current_context_slot == 0) { "+anchor+" }")
        else:
            anchor = "void PendSV_Handler(void)"
            need(original.count(anchor) == 1, "PendSV mutation scope")
            head, body = original.split(anchor)
            def replace_instruction(pattern, replacement):
                nonlocal body
                body, count = re.subn(pattern, lambda _: replacement, body)
                need(count == 1, "Exact production instruction mutation failed: "+name)
            core = r'"ldmia\s+r0!,\s*\{r4-r11,\s*r14\}\s+\\n"'
            save_fp = r'"vstmdb\s+r0!,\s*\{s16-s31\}\s+\\n"'
            restore_fp = r'"vldmia\s+r0!,\s*\{s16-s31\}\s+\\n"'
            if name in ("pendsv-r4", "pendsv-r9"):
                register = "r4" if name == "pendsv-r4" else "r9"
                body, count = re.subn(core, lambda m: m[0]+'\n\t\t\t"mov.w '+register+', #0 \\n"', body)
                need(count == 1, "Core restore mutation count")
            elif name == "high-fp-save":
                replace_instruction(save_fp, '"vmov s0, s0 \\n"\n\t\t\t"sub r0, r0, #64 \\n"')
            elif name == "high-fp-restore":
                replace_instruction(restore_fp, '"add r0, r0, #64 \\n"')
            else:
                need(name in ("low-fp-frame", "fpscr-frame"), "Unknown production mutation")
                # After high-FP restore, r0 is the actual hardware core-frame base.
                # Low S0 follows the 32-byte core; FPSCR follows sixteen low S regs.
                offset = 32 if name == "low-fp-frame" else 96
                injected = ('\n\t\t\t"ldr r3, [r0, #'+str(offset)+'] \\n"'
                            '\n\t\t\t"eor r3, r3, #1 \\n"'
                            '\n\t\t\t"str r3, [r0, #'+str(offset)+'] \\n"')
                body, count = re.subn(restore_fp, lambda m: m[0]+injected, body)
                need(count == 1, "Extended hardware-frame mutation count")
            changed = head+anchor+body
            need(changed.split(anchor)[0] == head, "Mutation changed first-SVC/prefix")
        target = directory/("mutant-"+source.name)
        target.write_text(changed, encoding="ascii", newline="\n")
        self.generated[str(target.resolve())] = dict(Path=str(target.resolve()), Sha256=digest(target), Role="CompiledMutation")
        save(directory/"mutation.json", dict(Name=name, Reason=MUTANTS[name], Original=str(source),
             OriginalSha256=digest(source), Compiled=str(target), CompiledSha256=digest(target),
             Scope="Actual production PendSV/common publication; geometry preserved; high-save omission retains lazy materialization"))
        return target

    def compile_objects(self, sources, directory, flags, port_sources=(), reference=False, mutant=None):
        objects, maps = [], []
        for index, original in enumerate(sources):
            need(str(original.resolve()) in self.inputs, "Source was not enrolled before compilation: "+str(original))
            source = original
            if mutant and ((mutant == "publication" and original == self.repo/"context/context_runtime_state.c") or
                           (mutant != "publication" and original == self.repo/self.profile.port_relative/"fiber_port.c")):
                source = self.mutate(source, mutant, directory)
            obj = directory/("%02d-" % index+original.stem+".o")
            dep = obj.with_suffix(".d")
            command = self.command([self.tools["gcc"], *flags, "-I"+str(original.parent),
                                   "-MMD", "-MF", dep, "-c", source, "-o", obj], "compile "+str(obj))
            need("warning:" not in command["Stderr"], "Unexpected compiler warning: "+command["Record"])
            self.dependency_check(dep)
            if reference:
                for record in self.dependencies[-1]["Dependencies"]:
                    p = Path(record["Path"])
                    need(not p.is_relative_to(self.repo) or p.is_relative_to(self.fixture/"reference"),
                         "Reference consumed a Context/Fiber/CMSIS/private project dependency")
                    need(not p.is_relative_to(Path(self.a.cmsis)), "Reference consumed CMSIS")
            role = "port" if original in port_sources else "reference_upstream" if reference and original.name == "port.c" else "reference_fixture" if reference else "expectation" if original.name == "fiber_port_context_cohort_expectation.c" else "fixture" if original.is_relative_to(self.fixture) else "common"
            maps.append(dict(Original=str(original), Compiled=str(source), SourceSha256=digest(source),
                Object=str(obj), ObjectSha256=digest(obj), Command=command["Record"], Role=role))
            objects.append(obj)
        save(directory/"source-object-map.json", maps)
        return objects, maps

    def link(self, directory, row, objects, archived, script):
        if row["Archive"]:
            archive = directory/"libactual-port.a"
            self.command([self.tools["ar"], "rcs", archive, *archived], "archive actual port")
            linked = [p for p in objects if p not in archived]+[archive]
        else:
            linked = objects
        elf = directory/"runtime.elf"
        flags = [*self.profile.cpu_flags, "-"+row["Optimization"], "-nostdlib"]+(["-flto"] if row["LTO"] else [])
        self.command([self.tools["gcc"], *flags, "-Wl,--gc-sections,--no-undefined,--fatal-warnings,-z,noexecstack",
                      "-T", script, "-Wl,-Map="+str(directory/"runtime.map"), *linked, "-o", elf], "link actual final ELF")
        for tool, args, suffix in (("objdump", ["-drwC", "-Mreg-names-std"], ".dis"),
                                   ("readelf", ["-hASsrW", "-A", "-lW"], ".readelf.txt"),
                                   ("nm", ["-a"], ".nm.txt")):
            text = self.command([self.tools[tool], *args, elf], "inspect final "+str(elf))["Stdout"]
            elf.with_suffix(suffix).write_text(text, encoding="ascii")
        return elf

    def audit_architecture(self, image, flash=0x80000):
        attrs = image.path.with_suffix(".readelf.txt").read_text()
        need(capability_matches(self.profile, attrs, self.profile.cpu_flags) and "Tag_THUMB_ISA_use: Thumb-2" in attrs,
             "Final ELF is not the selected hard-float "+self.profile.name+" cohort")
        need(not re.search(r"Tag_(MVE_arch|Advanced_SIMD_arch|PAC_extension|BTI_extension):", attrs), "Foreign ISA feature")
        stacks = [s for s in image.segments if s["Type"] == "PT_GNU_STACK"]
        need(len(stacks) == 1 and not stacks[0]["Flags"] & 1, "Missing/executable GNU_STACK")
        for segment in image.segments:
            if segment["Type"] == "PT_LOAD":
                begin, end = segment["Address"], segment["Address"]+segment["Size"]
                need(0 <= begin <= end <= flash or 0x20000000 <= begin <= end <= 0x20010000,
                     "Final load segment outside the bounded link map")

    def audit_runtime(self, elf, row, proof):
        image = Image(elf, self.ELFFile)
        self.audit_architecture(image)
        for name in (*common.PUBLIC, "Reset_Handler", "SVC_Handler", "PendSV_Handler"):
            image.symbol(name, "STT_FUNC")
        need(not set(common.LEGACY) & set(image.symbols), "Legacy shim in pure/current Context consumer")
        bindings = {}
        for name in (common.SLOT, common.REVERSE, common.CONFIG_ANCHOR):
            if name == common.CONFIG_ANCHOR and row["Consumer"] == "context":
                need(name not in image.symbols and common.CONFIG not in image.symbols and
                     not any(n.startswith("fiber_v1_") for n in image.symbols), "Pure Context acquired Fiber/configuration")
                continue
            value = image.symbol(name, "STT_OBJECT", local=row["LTO"] and name in proof)
            need(value["Size"] == (4 if name == common.SLOT else 1), "Common private object geometry")
            section = image.sections[value["Section"]]
            if name == common.SLOT:
                need(section["Flags"] & 3 == 3 and section["Type"] == "SHT_NOBITS", "Current slot is not writable zeroed storage")
            else:
                need(not section["Flags"] & 1 and image.bytes(value) == b"\x01", "ABI anchor value/read-only geometry")
            bindings[name] = value["Binding"]
        if row["Consumer"] == "fiber":
            image.symbol(common.CONFIG, "STT_FUNC")
        runtime = [n for n in image.symbols if n.startswith("fiber_port_context_cohort_arm")]
        storage = [n for n in image.symbols if n.startswith("fiber_port_storage_cohort_") and "consumer_expectation" not in n]
        need(cohort_matches(self.profile, runtime, storage), "Wrong actual "+self.profile.name+" runtime/storage cohort")
        for name in runtime+storage:
            need(image.bytes(image.symbol(name, "STT_OBJECT")) == b"\x01", "Cohort provider value")
        self.audit_vectors(image, "Reset_Handler", ((11, "SVC_Handler"), (14, "PendSV_Handler")), 0x20010000)
        expectation = image.sections[".fiber_port_context_cohort_expectation"]
        need(expectation["Flags"] & 2 and not expectation["Flags"] & 1, "Expectation is not allocated read-only data")
        expected = [image.symbol(runtime[0])["Address"], image.symbol(storage[0])["Address"]]
        if row["Consumer"] == "fiber":
            expected.append(expected[1])
        need(len(expectation["Data"]) == len(expected)*4 and
             sorted(struct.unpack("<"+"I"*len(expected), expectation["Data"])) == sorted(expected), "Exact expectation pointers")
        need(not any(re.search(r"__cyg_profile|__stack_chk|__gcov|__ubsan|__asan|__sanitizer_cov|mcount", n)
                     for n in image.symbols), "Instrumentation escaped into runtime ELF")
        observer_owners = json.loads((elf.parent/"observer-object-owners.json").read_text())
        need(set(observer_owners) == {"fixture_report", "fixture_observer_arm"}, "Exact observer prelink owner proof missing")
        image.observer_local_objects = set(observer_owners) if row["LTO"] else set()
        for name, size in (("fixture_report", self.profile.report_bytes), ("fixture_observer_arm", 4)):
            record = image.symbol(name, "STT_OBJECT", local=name in image.observer_local_objects)
            section = image.sections[record["Section"]]
            need(record["Size"] == size and section["Flags"] & 3 == 3 and section["Type"] == "SHT_NOBITS" and
                 0x20000000 <= record["Address"] < record["Address"]+size <= 0x20010000,
                 "Observer object geometry/zeroed RAM ownership: "+name)
        observer = self.audit_observer(image, row)
        observer["PrelinkObjectOwners"] = observer_owners
        return image, dict(StrongHandlers=True, NoUnresolved=True, NoLegacy=True, RuntimeCohort=runtime[0],
            StorageCohort=storage[0], ExpectationPointers=expected, CommonPrivateBindings=bindings,
            PrelinkCommonOwners=proof, Observer=observer, Architecture=self.profile.name+" hard-float "+self.profile.fpu,
            ForwardDefinitions="All eight actual input-object definitions checked; unused panic-wait may be GCed")

    def audit_vectors(self, image, reset, handlers, top):
        vector = image.sections[".isr_vector"]
        need(vector["Address"] == 0 and vector["Size"] == 1024 and vector["Flags"] & 2 and
             not vector["Flags"] & 1, "Exact allocated read-only 256-word vector inventory")
        words = struct.unpack("<256I", vector["Data"])
        need(words[0] == top and words[1] == image.symbol(reset, "STT_FUNC")["Address"] | 1, "Reset vector/MSP")
        for slot, name in handlers:
            need(words[slot] == image.symbol(name, "STT_FUNC")["Address"] | 1 and words[slot] & 1,
                 "Strong Thumb vector mismatch: "+name)

    def audit_observer(self, image, row):
        observer = image.no_fp_closure(["fiber_addr_plausible_ram"], forbid_cpu_write=True)
        pd = image.body("PendSV_Handler")
        first = next((n for n, i in enumerate(pd) if i["Mnemonic"].startswith("v")), None)
        need(first is not None, "PendSV lost its first FP/lazy-materialization instruction")
        prefix = pd[:first]
        calls = image.targets(prefix, "PendSV_Handler", bounded_prefix=True)
        need("fiber_port_context_validate_save_current" in calls, "Pre-save validator does not precede first handler FP instruction")
        closure = image.no_fp_closure(calls)
        mmio = image.mmio_loads("fiber_addr_plausible_ram")
        captures = {"fixture_capture_worker_"+str(n) for n in range(3)}
        if row["Policy"] == "validation":
            need("fiber_addr_plausible_ram" in closure, "Validation pre-save closure lost observer hook")
            need(captures <= set(observer), "Validation observer lost exact per-worker capture helpers")
            for helper in captures:
                need(any(i["Owner"] == helper and i["Address"] == 0xE000EF34 and i["Width"] == 4 for i in mmio),
                     "Per-worker observer FPCCR word read is missing: "+helper)
        else:
            need(not captures.intersection(observer) and not mmio, "Primary observer acquired validation/MMIO effects")
        return dict(NoFpClosure=observer, PreFirstFpClosure=closure,
                    FirstHandlerFp=pd[first]["Text"], ValidationObserver=row["Policy"] == "validation",
                    ConstantAddressMmioReads=mmio, ObserverStoreProof=image.observer_store_proof,
                    Scope="Whole emitted observer/helper bodies and pre-first-FP call closure; no Thread/Handler CONTROL conflation")

    def build_case(self, row):
        directory = self.build/"cases"/row["Name"]
        directory.mkdir(parents=True)
        spec = importlib.util.spec_from_file_location("cm4f_runtime_source_recipe", self.repo/"tools/runtime_sources.py")
        reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reader)
        roles = ("engine", "state", "panic")+(("optional_configuration",) if row["Consumer"] == "fiber" else ())
        sources = list(reader.get_runtime_source_paths(self.repo, roles))
        if row["Consumer"] == "fiber":
            sources.append(self.repo/"fiber/lifecycle/fiber_v1.c")
        port = self.repo/self.profile.port_relative
        providers = [port/n for n in ("fiber_port.c", "fiber_port_boot.c", "fiber_port_exception.c")]
        sources += providers+[self.fixture/n for n in ("application.c", "startup.S", "probe.S")]
        sources.append(self.repo/"fiber/port/fiber_port_context_cohort_expectation.c")
        validation = int(row["Policy"] == "validation")
        flags = [*self.profile.cpu_flags, *COMPILE, "-"+row["Optimization"], "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV7EM=1",
            "-DFIXTURE_CASE=0", "-DFIXTURE_USE_FIBER="+str(int(row["Consumer"] == "fiber")),
            "-DFIXTURE_FP_LAZY="+str(int(row["Lazy"])), "-DFIBER_FPU_LAZY="+str(int(row["Lazy"])),
            "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH="+str(validation),
            "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH="+str(validation), "-DFIBER_STACK_CANARY=1",
            "-DFIBER_REWIND_MSP=1", "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=0",
            "-I"+str(self.fixture), "-I"+str(port), "-I"+str(self.repo/"fiber"), "-I"+str(self.repo), "-I"+self.a.cmsis]
        if row["LTO"]:
            flags.append("-flto")
        objects, maps = self.compile_objects(sources, directory, flags, providers, mutant=row["Mutant"])
        state = reader.get_runtime_source_paths(self.repo, ("state",))
        config = reader.get_runtime_source_paths(self.repo, ("optional_configuration",)) if row["Consumer"] == "fiber" else ()
        need(len(state) == 1 and len(config) == int(row["Consumer"] == "fiber"), "Exact common private owner recipe")
        proof = self.audit_common_private(maps, {common.SLOT: str(state[0]), common.REVERSE: str(state[0]),
             common.CONFIG_ANCHOR: str(config[0]) if config else None}, directory)
        self.audit_observer_owners(maps, directory)
        port_objects = [Path(m["Object"]) for m in maps if m["Role"] == "port"]
        self.audit_provider(port_objects, directory)
        elf = self.link(directory, row, objects, port_objects, self.fixture/"link.ld")
        _, audit = self.audit_runtime(elf, row, proof)
        save(directory/"elf-audit.json", audit)
        row.update(Elf=str(elf), ElfSha256=digest(elf), SourceObjectMap=str(directory/"source-object-map.json"),
                   ElfAudit=str(directory/"elf-audit.json"), CommonPrivateProviders=str(directory/"common-private-providers.json"))
        result = self.command(["wsl.exe", "-d", self.a.wsl_distro, "--", "bash",
            self.wsl_path(self.repo/"tools/fixtures/arm_control/qemu.sh"), "run", self.a.qemu_root,
            self.wsl_path(directory), self.profile.machine, self.wsl_path(elf), "20"],
            "actual "+self.profile.label+" "+row["Name"], timeout=35, expected=None)
        row["Actual"] = result
        need(terminal(result, row["Expected"]), "Wrong exact FP terminal outcome: "+row["Name"]+"; "+result["Record"])
        row["Status"] = "PASS"
        save(directory/"execution.json", row)
        print("PASS "+row["Name"], flush=True)

    def audit_observer_owners(self, maps, directory):
        found = {n: [] for n in ("fixture_report", "fixture_observer_arm")}
        for record in maps:
            command = self.command([self.tools["nm"], "-P", "--defined-only", record["Object"]], "prelink observer object owner")
            for line in command["Stdout"].splitlines():
                fields = line.split()
                if fields and fields[0] in found:
                    need(len(fields) >= 3, "Malformed observer object definition")
                    found[fields[0]].append(dict(Source=record["Original"], Compiled=record["Compiled"],
                        Object=record["Object"], ObjectSha256=record["ObjectSha256"], Role=record["Role"],
                        NmType=fields[1], Command=command["Record"]))
        for name, definitions in found.items():
            need(len(definitions) == 1 and definitions[0]["NmType"] == "B" and definitions[0]["Role"] == "fixture" and
                 definitions[0]["Source"] == definitions[0]["Compiled"] == str(self.fixture/"application.c"),
                 "Observer object must have one GLOBAL actual application C owner: "+name)
        save(directory/"observer-object-owners.json", {name: definitions[0] for name, definitions in found.items()})

    def audit_reference_owners(self, maps, directory):
        names = (*REF_HANDLERS, *REF_ROOTS, "vPortSetupTimerInterrupt")
        found = {n: [] for n in names}
        for record in maps:
            command = self.command([self.tools["nm"], "-P", "--defined-only", record["Object"]], "reference prelink owner")
            for line in command["Stdout"].splitlines():
                fields = line.split()
                if fields and fields[0] in found:
                    need(len(fields) >= 3, "Malformed reference definition")
                    found[fields[0]].append(dict(Source=record["Original"], Object=record["Object"],
                        Role=record["Role"], NmType=fields[1], Command=command["Record"]))
        for name, definitions in found.items():
            need(len(definitions) == 1 and definitions[0]["Role"] == "reference_upstream" and
                 definitions[0]["NmType"] == ("W" if name == "vPortSetupTimerInterrupt" else "T"),
                 "Reference definition is not owned by actual upstream: "+name)
        save(directory/"upstream-owners.json", found)
        return found

    def reference_parity(self):
        for (opt, lto), archive in itertools.product(self.modes, (False, True)):
            name = "-".join((opt, "lto" if lto else "normal", "archive" if archive else "direct"))
            directory = self.build/"reference"/name
            directory.mkdir(parents=True)
            row = dict(Name=name, Optimization=opt, LTO=lto, Archive=archive, Status="STAGED", Executed=False)
            self.parity.append(row)
            ref = self.fixture/"reference"
            port = Path(self.a.freertos).resolve()/self.profile.upstream_relative
            sources = [ref/n for n in ("main.c", "providers.c", "startup.S")]+[port/"port.c"]
            flags = [*self.profile.cpu_flags, *COMPILE, "-"+opt, "-I"+str(ref), "-I"+str(Path(self.a.freertos).resolve()/"include"), "-I"+str(port)]
            if lto:
                flags.append("-flto")
            objects, maps = self.compile_objects(sources, directory, flags, reference=True)
            owners = self.audit_reference_owners(maps, directory)
            elf = self.link(directory, row, objects, [objects[-1]], ref/"link.ld")
            image = Image(elf, self.ELFFile)
            self.audit_architecture(image, flash=0x40000)
            self.audit_vectors(image, "reference_reset_handler", ((11, REF_HANDLERS[0]), (14, REF_HANDLERS[1]), (15, REF_HANDLERS[2])), 0x20010000)
            roots = []
            for symbol in REF_ROOTS:
                value = image.symbol(symbol, "STT_FUNC", local=lto and bool(owners[symbol]))
                roots.append(value["Address"] | 1)
            root_section = image.sections[".reference_roots"]
            need(root_section["Flags"] & 2 and not root_section["Flags"] & 1 and root_section["Data"] == struct.pack("<2I", *roots),
                 "Reference retained roots are not exactly the actual upstream functions")
            facts = image.sections[".reference_contract"]
            need(not facts["Flags"] & 1 and facts["Data"] == struct.pack("<8I", *self.profile.header_facts), "Reference real header facts")
            tcb = image.symbol("pxCurrentTCB", "STT_OBJECT")
            need(tcb["Size"] == 4 and image.sections[tcb["Section"]]["Type"] == "SHT_NOBITS", "Reference null opaque TCB boundary")
            for boundary in REF_BOUNDARIES:
                image.symbol(boundary, "STT_FUNC")
                closure = image.no_fp_closure([boundary])
                need("reference_fail_stop" in closure, "Reference boundary does not lead to fail-stop: "+boundary)
            stop = image.body("reference_fail_stop")
            need(any(i["Mnemonic"].startswith("udf") and re.search(r"#(?:90|0x5a)\b", i["Operands"]) for i in stop), "Reference fail-stop UDF #90 missing")
            need(not any(n.startswith(("fiber_", "ctxrt_")) for n in image.symbols), "Reference acquired Fiber/Context code")
            mechanisms = self.mechanisms(image, reference=True, optimization=opt)
            audit = dict(Status="PASS", Executed=False, Scope="Actual pinned final ELF; retained bounded mechanisms, not whole-port/kernel equivalence",
                UpstreamOwners=owners, CodeRoots=roots, RootBindings={n: image.symbol(n, "STT_FUNC", local=lto)["Binding"] for n in REF_ROOTS},
                StrongHandlers=list(REF_HANDLERS), Mechanisms=mechanisms, Policy="Upstream always ASPEN+LSPEN; never executed")
            save(directory/"elf-audit.json", audit)
            row.update(Status="PASS", Elf=str(elf), ElfSha256=digest(elf), ElfAudit=str(directory/"elf-audit.json"),
                       SourceObjectMap=str(directory/"source-object-map.json"), Mechanisms=mechanisms)
            print("PASS link-only reference "+name, flush=True)
        need(len(self.parity) == self.grid.References and
             {(r["Optimization"], r["LTO"], r["Archive"]) for r in self.parity} ==
             {(opt, lto, archive) for (opt, lto), archive in itertools.product(self.modes, (False, True))},
             "Literal exact reference ELF grid")
        for row in self.rows:
            if row["Kind"] != "Positive":
                continue
            matches = [r for r in self.parity if all(r[k] == row[k] for k in ("Optimization", "LTO", "Archive"))]
            need(len(matches) == 1, "Positive/reference tuple does not pair uniquely")
            image = Image(row["Elf"], self.ELFFile)
            mechanisms = self.mechanisms(image, reference=False, optimization=row["Optimization"])
            pair = dict(Execution=row["Name"], ExecutionElfSha256=row["ElfSha256"], Reference=matches[0]["Name"],
                        ReferenceElfSha256=matches[0]["ElfSha256"], Mechanisms=mechanisms,
                        PolicyDifference="Fiber eager vs upstream always lazy" if not row["Lazy"] else "Both initialize lazy preservation",
                        ReferenceExecuted=False, Scope="Ordered common CPU mechanisms; not byte equality or whole-kernel equivalence")
            self.pairs.append(pair)
        need(len(self.pairs) == self.grid.Pairs, "Literal positive/reference association count")

    def mechanisms(self, image, reference, optimization=None):
        handler = "xPortPendSVHandler" if reference else "PendSV_Handler"
        body = image.body(handler)
        text = "\n".join(i["Text"] for i in body)
        patterns = [r"\bmrs\s+r0,\s*PSP", r"\btst[^\n]*#(?:16|0x10)\b", r"\bvstmdb[^\n]*\{s16-s31\}",
                    r"\bstmdb[^\n]*\{r4[^\n]*(?:lr|r14)\}",
                    r"\bbl\s+[^\n]*<"+("vTaskSwitchContext" if reference else "fiber_port_scheduler_pick_next_from_pendsv")+r">",
                    r"\bldmia[^\n]*\{r4[^\n]*(?:lr|r14)\}", r"\bvldmia[^\n]*\{s16-s31\}", r"\bmsr\s+PSP", r"\bbx\s+(?:lr|r14)\b"]
        cursor = 0
        for pattern in patterns:
            match = re.search(pattern, text[cursor:], re.I)
            need(match is not None, "Missing ordered final-ELF "+handler+" mechanism: "+pattern)
            cursor += match.end()
        conditional = []
        for mnemonic in ("vstmdb", "vldmia"):
            indices = [n for n, ins in enumerate(body) if ins["Mnemonic"].startswith(mnemonic)]
            need(len(indices) == 1 and indices[0] >= 2, "Conditional FP transfer inventory")
            index = indices[0]
            test, guard, transfer = body[index-2:index+1]
            need(test["Mnemonic"].startswith("tst") and
                 re.search(r"(?:lr|r14),\s*#(?:16|0x10)\b", test["Operands"]), "FP predicate is not EXC_RETURN bit 4")
            if reference:
                need(guard["Mnemonic"] == "it" and guard["Operands"].strip() == "eq" and
                     transfer["Mnemonic"].endswith("eq"), "Reference FP transfer lost IT EQ coupling")
            else:
                target = re.match(r"([0-9a-f]+)\s+<", guard["Operands"])
                need(guard["Mnemonic"].startswith("bne") and target is not None and
                     int(target[1], 16) == transfer["Address"]+len(transfer["Bytes"]),
                     "Fiber FP guard no longer skips exactly its transfer")
            conditional.append(dict(Test=test["Text"], Guard=guard["Text"], Transfer=transfer["Text"]))
        envelope = check_basepri(self.profile, reference, text)
        svc = "vPortSVCHandler" if reference else "SVC_Handler"
        svc_text = "\n".join(i["Text"] for i in image.body(svc))
        need(re.search(r"\bldmia[^\n]*\{r4[^\n]*(?:lr|r14)\}", svc_text) and re.search(r"\bmsr\s+PSP", svc_text, re.I) and
             re.search(r"\bbx\s+(?:lr|r14)\b", svc_text), "First restore CPU mechanism missing")
        start = "prvPortStartFirstTask" if reference else "fiber_port_start_first_context"
        names = [n for n in image.symbols if n == start or n.startswith(start+".")]
        need(len(names) == 1, "First-start local helper identity")
        start_text = "\n".join(i["Text"] for i in image.body(names[0]))
        need(re.search(r"\bmsr\s+MSP", start_text, re.I) and re.search(r"\bmsr\s+CONTROL", start_text, re.I) and
             re.search(r"\bsvc\s+(?:0x0*0|0)\b" if reference else r"\bsvc\s+(?:0x0*46|70)\b", start_text), "First-start SVC/reset mechanism")
        if reference:
            scheduler = "\n".join(i["Text"] for i in image.body("xPortStartScheduler"))
            need(re.search(r"\borr[^\n]*#(?:3221225472|0xc0000000)\b", scheduler, re.I), "Pinned always-lazy initialization missing")
        cpacr_name = "vPortEnableVFP" if reference else "fiber_port_runtime_prepare"
        cpacr_names = [n for n in image.symbols if n == cpacr_name or n.startswith(cpacr_name+".")]
        need(len(cpacr_names) == 1, "CPACR helper identity")
        cpacr_proof = cpacr_mechanism_proof(image, cpacr_names[0], reference, self.a.full_optimization_grid_fp, optimization)
        return dict(PendSvOrderedPatterns=patterns, ConditionalFpTransfers=conditional,
                    BasepriEnvelopePatterns=envelope, CpacrHelper=cpacr_names[0], CpacrProof=cpacr_proof,
                    FirstRestore=svc, FirstStart=names[0], Reference=reference,
                    Scope="Bounded ordered/predicate/mask/CPACR patterns plus execution; not whole-provider or byte equivalence",
                    Differences=["SVC number and provenance/seals", "common vs TCB publication", "r9 initialization policy", "eager initialization when selected"]+
                    (["Upstream unconditionally re-enables IRQs; Fiber restores PRIMASK and saved BASEPRI"] if self.profile.name == "CM7" else []))

    def finish(self, error):
        self.report["Error"] = error
        if not error:
            after = self.inspect_qemu("qemu-after")
            self.report["QemuDrift"] = [k for k in self.qemu_before if self.qemu_before[k] != after.get(k)]
            need(not self.report["QemuDrift"], "QEMU/tool/library drift")
            self.reference_identity()
            self.check_repository_inventory()
            validate_execution_grid(self.rows, self.a.full_optimization_grid_fp, self.a.development_smoke)
            need(self.report["CompleteSuite"] is self.grid.CompleteSuite, "Completion verdict does not match requested grid")
            need(all(r["Status"] == "PASS" for r in self.rows) and len(self.parity) == self.grid.References and
                 all(r["Status"] == "PASS" and r["Executed"] is False for r in self.parity), "Execution/reference coverage mismatch")
            need(len(self.pairs) == self.grid.Pairs and
                 {p["Execution"] for p in self.pairs} == {r["Name"] for r in self.rows if r["Kind"] == "Positive"},
                 "Reference association coverage mismatch")
        drift = self.input_drift()
        self.report["InputDrift"] = drift
        if not (self.build/"inputs.before.json").is_file():
            save(self.build/"inputs.before.json", list(self.inputs.values()))
        save(self.build/"inputs.after.json", [dict(Path=p, Sha256=digest(p) if Path(p).is_file() else None) for p in self.inputs])
        save(self.build/"dependencies.json", self.dependencies)
        save(self.build/"generated-inputs.json", list(self.generated.values()))
        self.report["InputCount"] = len(self.inputs)
        save(self.build/"results.json", self.report)
        self.artifact_manifest(verify=True)
        if not error:
            need(not drift and not self.input_drift(), "Source/tool/generated input drift")
            self.report.update(Verdict="PASS", ArtifactsVerifiedBeforePass=True)
            save(self.build/"results.json", self.report)
            self.artifact_manifest(verify=True)


def argument_parser(parser_type=argparse.ArgumentParser):
    parser = parser_type(description=__doc__, allow_abbrev=False)
    for name in ("repo", "gcc", "cmsis", "freertos", "qemu-root", "wsl-distro", "build-root"):
        parser.add_argument("--"+name, required=True)
    parser.add_argument("--development-smoke", action="store_true")
    parser.add_argument("--full-optimization-grid-fp", action="store_true")
    return parser


def main(profile=CM4):
    args = argument_parser().parse_args()
    suite = Suite(args, profile=profile)
    print("Classic FP Context runtime evidence: "+str(suite.build), flush=True)
    error = None
    try:
        suite.stage()
        suite.preflight()
        for row in suite.rows:
            row["Status"] = "RUNNING"
            try:
                suite.build_case(row)
            except Exception as failure:
                row.update(Status="FAIL", Error=str(failure))
                raise
        suite.reference_parity()
    except Exception as failure:
        error = str(failure)
        suite.report["Traceback"] = traceback.format_exc()
    try:
        suite.finish(error)
    except Exception as failure:
        error = str(failure)
        suite.report.update(Verdict="FAIL", Error=error, FinalizationTraceback=traceback.format_exc())
        save(suite.build/"results.json", suite.report)
        suite.artifact_manifest()
    if error:
        raise SystemExit("FAIL classic FP Context runtime: "+error+"; "+str(suite.build))
    print("PASS classic FP Context runtime "+("development smoke " if args.development_smoke else "complete ")+str(suite.build), flush=True)


if __name__ == "__main__":
    main()
