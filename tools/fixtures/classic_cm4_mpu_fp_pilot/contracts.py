"""Strict pilot receipt/terminal grammar; synthetic controls are not executions."""
from copy import deepcopy
import re

from cm4_mpu_basic_engine import need, pilot

MUTATIONS = ("omit-high-save", "omit-high-restore", "omit-low-save",
             "omit-low-restore", "corrupt-fpscr-save")
REASONS = dict(zip(MUTATIONS, (131, 131, 134, 134, 132)))
CODEGEN = dict(zip(MUTATIONS, ("FP_HIGH_SAVE", "FP_HIGH_RESTORE", "FP_LOW_SAVE", "FP_LOW_RESTORE", None)))
KEYS = tuple((c, lazy) for c in ("context", "fiber") for lazy in (False, True))
CONTROL_KEYS = tuple((lazy, mutation) for lazy in (False, True) for mutation in MUTATIONS)


def sha(value):
    return type(value) is str and re.fullmatch(r"[0-9A-F]{64}", value) is not None


def parse_actual(actual, row):
    need(type(actual) is dict and type(actual.get("Exit")) is int and
         type(actual.get("TimedOut")) is bool and actual["TimedOut"] is False and
         actual.get("Stdout") == "" and type(actual.get("Stdout")) is str and
         type(actual.get("Stderr")) is str, "terminal-transport")
    if row["Model"]:
        return pilot.model_terminal(actual)
    mutation = row["Mutation"]
    if mutation is not None:
        need(actual["Exit"] == 66, "control-exit")
        match = re.fullmatch(r"REASON:CM4-MPU-FP:CODE=([0-9A-F]{8}):WORKER=([0-9A-F]{8}):PHASE=([0-9A-F]{8})\nFAIL:CM4-MPU-FP\n", actual["Stderr"])
        need(match is not None, "control-terminal")
        code, worker, phase = (int(v, 16) for v in match.groups())
        need(code == REASONS[mutation] and worker == 0 and
             phase == (1 if mutation.startswith("omit-high-") else 2), "control-causality")
        return dict(Reason=code, Worker=worker, Phase=phase)
    label = "CONTEXT" if row["Consumer"] == "context" else "FIBERV1"
    lazy = str(int(row["Lazy"]))
    pattern = (r"CHECK:CM4-MPU-FP:API=" + label + ":LAZY=" + lazy +
        r":CALLS=00000017:SELF=00000001:CROSS=00000015:EXT0=00000008:EXT1=00000007:BASIC2=00000007:CHALLENGE=0000000F:POSTCONTROL=([0-9A-F]{8}):LSPACT=00000000\n"
        r"RETURN:CM4-MPU-FP:CODE=00000052:IPSR=0000000B:PC=([0-9A-F]{8}):PSP=([0-9A-F]{8}):XPSR=([0-9A-F]{8})\n"
        r"PASS:CM4-MPU-FP:" + label + ":LAZY=" + lazy + r"\n")
    match = re.fullmatch(pattern, actual["Stderr"])
    need(actual["Exit"] == 0 and match is not None, "positive-terminal")
    control, pc, psp, xpsr = (int(v, 16) for v in match.groups())
    need(control != 0 and control & ~0x22 == 0 and pc == row["Audit"]["ReturnPC"] and
         psp % 8 == 0 and 0x20002200 <= psp <= 0x20003000 - 104 - (4 if xpsr & 512 else 0) and
         xpsr & 0x010001ff == 0x01000000, "positive-frame")
    return dict(PostControlMask=control, PostSaveLspact=0, ReturnPC=pc, ReturnPSP=psp, ReturnXPSR=xpsr)


def row_key(row):
    need(type(row) is dict and type(row.get("Consumer")) is str and
         type(row.get("Lazy")) is bool and type(row.get("Model")) is bool and
         type(row.get("Case")) is int and row["Case"] == 0 and
         row.get("Optimization") == "O2" and type(row.get("Optimization")) is str and
         type(row.get("LTO")) is bool and row["LTO"] is False and
         type(row.get("Archive")) is bool and row["Archive"] is False and
         type(row.get("Elf")) is str and bool(row["Elf"].strip()) and sha(row.get("ElfSha256")), "row-types")
    return row["Consumer"], row["Lazy"]


def validate(report, execute):
    need(type(execute) is bool and type(report) is dict, "receipt-types")
    need("Error" in report and report["Error"] is None, "non-null-error")
    need(report.get("Verdict") == ("FP-PILOT-PASS" if execute else "COMPILE-PREFLIGHT-PASS") and
         report.get("Execution") == ("FP_ACTIVE_PILOT" if execute else "NOT_RUN"), "request-mode")
    for field, value in (("CompleteSuite", False), ("RequestedInventoryComplete", True),
            ("CompileOnly", not execute), ("ArtifactsVerifiedBeforePass", True),
            ("ReferenceExecuted", False), ("NewFinalReferenceParity", False), ("PreSaveLspactObserved", False)):
        need(type(report.get(field)) is bool and report[field] is value, field)
    need(type(report.get("InputDrift")) is list and not report["InputDrift"], "input-drift")
    for field, count in (("Rows", 4), ("Controls", 10), ("References", 1), ("Associations", 4)):
        need(type(report.get(field)) is list and len(report[field]) == count, field + "-count")
    need(tuple(row_key(r) for r in report["Rows"]) == KEYS and
         all(r.get("Mutation") is None and r["Model"] is False for r in report["Rows"]), "ordered-positives")
    need(tuple((row_key(r), r.get("Mutation")) for r in report["Controls"]) ==
         tuple((("context", lazy), mutation) for lazy, mutation in CONTROL_KEYS) and
         all(r["Model"] is False and r.get("CodegenRejection") == CODEGEN[r["Mutation"]]
             for r in report["Controls"]), "ordered-controls")
    model = report.get("ModelProbe")
    need(row_key(model) == ("context", False) and model.get("Name") == "model" and
         model["Model"] is True and model.get("Mutation") is None, "model-identity")
    binding = report.get("ModelArtifactBinding")
    need(type(binding) is dict and binding.get("Verified") is True and
         binding.get("ArtifactRelative") == "model/runtime.elf" and
         (binding.get("Elf"), binding.get("ElfSha256"), binding.get("ManifestEntrySha256")) ==
         (model["Elf"], model["ElfSha256"], model["ElfSha256"]), "model-binding")
    reference = report["References"][0]
    need(type(reference) is dict and reference.get("Optimization") == "O2" and
         type(reference.get("LTO")) is bool and reference["LTO"] is False and
         type(reference.get("Archive")) is bool and reference["Archive"] is False and
         reference.get("Status") == "LINKED" and reference.get("Executed") is False and
         type(reference.get("Elf")) is str and sha(reference.get("ElfSha256")) and
         type(reference.get("FpMechanisms")) is dict, "reference-state")
    for row, association in zip(report["Rows"], report["Associations"]):
        need(type(row.get("Mechanism")) is dict and row.get("CodegenRejection") is None and
             type(association) is dict and association.get("Consumer") == row["Consumer"] and
             type(association.get("Lazy")) is bool and association["Lazy"] is row["Lazy"] and
             association.get("Executed") is False and
             type(association.get("NamedMechanismResults")) is int and association["NamedMechanismResults"] == 3 and
             sha(association.get("EvidenceSha256")) and
             (association.get("SubjectElf"), association.get("SubjectSha256")) == (row["Elf"], row["ElfSha256"]) and
             (association.get("ReferenceElf"), association.get("ReferenceSha256")) == (reference["Elf"], reference["ElfSha256"]) and
             association.get("SubjectFp") == row["Mechanism"] and
             association.get("ReferenceFp") == reference["FpMechanisms"], "bound-association")
    all_rows = [model, *report["Rows"], *report["Controls"]]
    need(len({r["Elf"] for r in [*all_rows, reference]}) == 16, "unique-16-elfs")
    for row in all_rows:
        status = "COMPILED" if not execute else "EXPECTED_FP_MISMATCH" if row["Mutation"] else "PASS"
        need(type(row.get("Executed")) is bool and row["Executed"] is execute and row.get("Status") == status, "row-status")
        if execute:
            facts = parse_actual(row.get("Actual"), row)
            need(type(row.get("Observed")) is dict and row["Observed"] == facts and
                 all(type(v) is int for v in row["Observed"].values()), "observed-facts")
        else:
            need("Actual" not in row and "Observed" not in row, "invented-observation")


def synthetic(execute):
    h = "A" * 64
    report = dict(Error=None, Verdict="FP-PILOT-PASS" if execute else "COMPILE-PREFLIGHT-PASS",
        Execution="FP_ACTIVE_PILOT" if execute else "NOT_RUN", CompleteSuite=False, RequestedInventoryComplete=True,
        CompileOnly=not execute, ArtifactsVerifiedBeforePass=True, ReferenceExecuted=False,
        NewFinalReferenceParity=False, PreSaveLspactObserved=False, InputDrift=[], Rows=[], Controls=[], References=[], Associations=[])
    def row(c, lazy, mutation=None, model=False):
        name = "model" if model else c + str(lazy) + str(mutation)
        r = dict(Name=name, Consumer=c, Lazy=lazy, Mutation=mutation, Model=model, Optimization="O2", LTO=False,
            Archive=False, Case=0, Elf=name + "/runtime.elf", ElfSha256=h, Audit=dict(ReturnPC=0x1010),
            Mechanism={}, CodegenRejection=CODEGEN.get(mutation), Executed=execute,
            Status="COMPILED" if not execute else "EXPECTED_FP_MISMATCH" if mutation else "PASS")
        if execute:
            if model:
                text = "MODEL:CM4-MPU:CPUID=410FC241:MPU_TYPE=00000800:NVIC_MASK=000000FF:MVFR0=10110021:MPU_CTRL=00000000\nPASS:CM4-MPU:MODEL\n"
            elif mutation:
                text = "REASON:CM4-MPU-FP:CODE=%08X:WORKER=00000000:PHASE=%08X\nFAIL:CM4-MPU-FP\n" % (REASONS[mutation], 1 if mutation.startswith("omit-high-") else 2)
            else:
                label = "CONTEXT" if c == "context" else "FIBERV1"
                text = ("CHECK:CM4-MPU-FP:API=%s:LAZY=%d:CALLS=00000017:SELF=00000001:CROSS=00000015:EXT0=00000008:EXT1=00000007:BASIC2=00000007:CHALLENGE=0000000F:POSTCONTROL=00000022:LSPACT=00000000\n"
                    "RETURN:CM4-MPU-FP:CODE=00000052:IPSR=0000000B:PC=00001010:PSP=20002F00:XPSR=01000000\nPASS:CM4-MPU-FP:%s:LAZY=%d\n") % (label, lazy, label, lazy)
            r["Actual"] = dict(Exit=66 if mutation else 0, TimedOut=False, Stdout="", Stderr=text)
            r["Observed"] = parse_actual(r["Actual"], r)
        return r
    report["Rows"] = [row(c, lazy) for c, lazy in KEYS]
    report["Controls"] = [row("context", lazy, m) for lazy, m in CONTROL_KEYS]
    model = row("context", False, model=True)
    report["ModelProbe"] = model
    report["ModelArtifactBinding"] = dict(Verified=True, ArtifactRelative="model/runtime.elf", Elf=model["Elf"], ElfSha256=h, ManifestEntrySha256=h)
    ref = dict(Optimization="O2", LTO=False, Archive=False, Status="LINKED", Executed=False, Elf="reference/runtime.elf", ElfSha256=h, FpMechanisms={})
    report["References"].append(ref)
    for r in report["Rows"]:
        report["Associations"].append(dict(Consumer=r["Consumer"], Lazy=r["Lazy"], Executed=False, NamedMechanismResults=3,
            SubjectElf=r["Elf"], SubjectSha256=h, ReferenceElf=ref["Elf"], ReferenceSha256=h,
            EvidenceSha256=h, SubjectFp={}, ReferenceFp={}))
    return report


def control_tests():
    controls = []
    def test(name, report, execute, expected, reason=None):
        rejection = None
        try:
            validate(report, execute)
            accepted = True
        except (RuntimeError, KeyError, TypeError, AttributeError) as failure:
            accepted = False
            rejection = str(failure)
        need(accepted is expected and (reason is None or rejection == reason), "contract-control: " + name)
        controls.append(dict(Name=name, Expected=expected, Rejection=rejection))
    for execute in (False, True):
        prefix = "execute-" if execute else "compile-"
        good = synthetic(execute)
        test(prefix + "positive", good, execute, True)
        for field, value in (("Error", ""), ("Error", 0), ("Error", False), ("CompleteSuite", True),
                ("RequestedInventoryComplete", False), ("PreSaveLspactObserved", True), ("CompileOnly", execute),
                ("ReferenceExecuted", True), ("InputDrift", ["drift"]), ("Execution", "PASS")):
            bad = deepcopy(good); bad[field] = value
            test(prefix + field + repr(value), bad, execute, False)
        for name, action in (
                ("row-missing", lambda r: r["Rows"].pop()),
                ("row-order", lambda r: r["Rows"].reverse()),
                ("control-order", lambda r: r["Controls"].reverse()),
                ("lazy-int", lambda r: r["Rows"][0].__setitem__("Lazy", 0)),
                ("case-bool", lambda r: r["Rows"][0].__setitem__("Case", False)),
                ("model-binding", lambda r: r.pop("ModelArtifactBinding")),
                ("model-substitute", lambda r: r["ModelProbe"].__setitem__("Elf", r["Rows"][0]["Elf"])),
                ("reference-hash", lambda r: r["References"][0].__setitem__("ElfSha256", "B" * 64)),
                ("mechanism-bool", lambda r: r["Associations"][0].__setitem__("NamedMechanismResults", True)),
                ("codegen-reason", lambda r: r["Controls"][0].__setitem__("CodegenRejection", "INCIDENTAL"))):
            bad = deepcopy(good); action(bad); test(prefix + name, bad, execute, False)
        if execute:
            for name, field, value in (("timeout", "TimedOut", True), ("exit-bool", "Exit", False),
                    ("stdout", "Stdout", "noise"), ("terminal", "Stderr", "HardFault\n")):
                bad = deepcopy(good); bad["Rows"][0]["Actual"][field] = value
                test(prefix + name, bad, execute, False)
            for name, before, after, field, value in (("return-pc", "PC=00001010", "PC=00001020", "ReturnPC", 0x1020),
                    ("frame-upper-bound", "PSP=20002F00", "PSP=20002FA0", "ReturnPSP", 0x20002fa0),
                    ("xpsr", "XPSR=01000000", "XPSR=0100000B", "ReturnXPSR", 0x0100000b),
                    ("mask", "POSTCONTROL=00000022", "POSTCONTROL=00000004", "PostControlMask", 4)):
                bad = deepcopy(good); r = bad["Rows"][0]; r["Actual"]["Stderr"] = r["Actual"]["Stderr"].replace(before, after)
                r["Observed"][field] = value
                test(prefix + name, bad, execute, False, "positive-frame")
            bad = deepcopy(good); bad["Rows"][0]["Observed"]["ReturnPSP"] += 8
            test(prefix + "stale-observed-facts", bad, execute, False, "observed-facts")
            for i in range(10):
                bad = deepcopy(good); bad["Controls"][i]["Actual"]["Stderr"] = "REASON:CM4-MPU-FP:CODE=00000403:WORKER=00000000:PHASE=00000001\nFAIL:CM4-MPU-FP\n"
                bad["Controls"][i]["Observed"] = dict(Reason=0x403, Worker=0, Phase=1)
                test(prefix + "generic-fault-" + str(i), bad, execute, False, "control-causality")
            for field, before, after, value in (("Worker", "WORKER=00000000", "WORKER=00000001", 1),
                    ("Phase", "PHASE=00000001", "PHASE=00000002", 2)):
                bad = deepcopy(good); r = bad["Controls"][0]
                r["Actual"]["Stderr"] = r["Actual"]["Stderr"].replace(before, after)
                r["Observed"][field] = value
                test(prefix + "wrong-" + field, bad, execute, False, "control-causality")
        else:
            bad = deepcopy(good); bad["Rows"][0]["Actual"] = {}
            test(prefix + "invented-observation", bad, execute, False)
    return dict(Controls=controls, Scope="Synthetic receipt/terminal controls; not CPU observations")
