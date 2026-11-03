"""Request-bound inventory for the separate O2/Os FP execution grid."""
from copy import deepcopy

from cm4_mpu_basic_engine import need
from cm4_mpu_fp_contracts import MUTATIONS, CODEGEN, parse_actual, sha

KEYS = tuple((c, lazy, opt, lto, archive) for c in ("context", "fiber")
             for lazy in (False, True) for opt in ("O2", "Os")
             for lto in (False, True) for archive in (False, True))
REF_KEYS = tuple((opt, lto, archive) for opt in ("O2", "Os")
                 for lto in (False, True) for archive in (False, True))
CONTROL_KEYS = tuple((c, lazy, opt, lto, archive, mutation)
    for c, opt, lto, archive in (("context", "O2", False, False), ("fiber", "Os", True, True))
    for lazy in (False, True) for mutation in MUTATIONS)


def key(row):
    need(type(row) is dict and type(row.get("Consumer")) is str and type(row.get("Lazy")) is bool and
         type(row.get("Optimization")) is str and type(row.get("LTO")) is bool and
         type(row.get("Archive")) is bool, "typed-grid-key")
    return row["Consumer"], row["Lazy"], row["Optimization"], row["LTO"], row["Archive"]


def ref_key(row):
    need(type(row) is dict and type(row.get("Optimization")) is str and
         type(row.get("LTO")) is bool and type(row.get("Archive")) is bool, "typed-reference-key")
    return row["Optimization"], row["LTO"], row["Archive"]


def validate(report, execute):
    need(type(report) is dict and type(execute) is bool, "receipt-types")
    need("Error" in report and report["Error"] is None, "non-null-error")
    need(report.get("Verdict") == ("FP-GRID-PASS" if execute else "COMPILE-PREFLIGHT-PASS") and
         report.get("Execution") == ("BOUNDED_FP_GRID" if execute else "NOT_RUN"), "request-mode")
    for field, value in (("CompleteSuite", False), ("RequestedInventoryComplete", True),
            ("CompileOnly", not execute), ("ArtifactsVerifiedBeforePass", True),
            ("ReferenceExecuted", False), ("NewFinalReferenceParity", False), ("PreSaveLspactObserved", False)):
        need(type(report.get(field)) is bool and report[field] is value, field)
    need(type(report.get("InputDrift")) is list and not report["InputDrift"], "input-drift")
    for field, count in (("Rows", 32), ("Controls", 20), ("References", 8), ("Associations", 32)):
        need(type(report.get(field)) is list and len(report[field]) == count, field + "-count")
    need(tuple(key(r) for r in report["Rows"]) == KEYS, "ordered-32-grid")
    need(tuple(ref_key(r) for r in report["References"]) == REF_KEYS, "ordered-8-references")
    need(tuple((*key(r), r.get("Mutation")) for r in report["Controls"]) == CONTROL_KEYS, "ordered-20-controls")
    refs = {ref_key(r): r for r in report["References"]}
    for row in refs.values():
        need(row.get("Status") == "LINKED" and row.get("Executed") is False and
             type(row.get("Elf")) is str and bool(row["Elf"].strip()) and sha(row.get("ElfSha256")) and
             type(row.get("FpMechanisms")) is dict, "reference-identity")
    for row in report["Rows"]:
        need(row.get("Mutation") is None and row.get("Model") is False and
             row.get("CodegenRejection") is None and type(row.get("Mechanism")) is dict, "positive-codegen")
    for row in report["Controls"]:
        need(row.get("Model") is False and row.get("CodegenRejection") == CODEGEN[row["Mutation"]], "control-codegen")
    for row, assoc in zip(report["Rows"], report["Associations"]):
        reference = refs[ref_key(row)]
        need(key(assoc) == key(row) and assoc.get("Executed") is False and
             type(assoc.get("NamedMechanismResults")) is int and assoc["NamedMechanismResults"] == 3 and
             sha(assoc.get("EvidenceSha256")) and
             (assoc.get("SubjectElf"), assoc.get("SubjectSha256")) == (row["Elf"], row["ElfSha256"]) and
             (assoc.get("ReferenceElf"), assoc.get("ReferenceSha256")) == (reference["Elf"], reference["ElfSha256"]) and
             assoc.get("SubjectFp") == row["Mechanism"] and
             assoc.get("ReferenceFp") == reference["FpMechanisms"], "same-config-bound-association")
    model = report.get("ModelProbe")
    need(key(model) == ("context", False, "O2", False, False) and model.get("Name") == "model" and
         model.get("Model") is True and model.get("Mutation") is None, "model-identity")
    binding = report.get("ModelArtifactBinding")
    need(type(binding) is dict and binding.get("Verified") is True and
         binding.get("ArtifactRelative") == "model/runtime.elf" and
         (binding.get("Elf"), binding.get("ElfSha256"), binding.get("ManifestEntrySha256")) ==
         (model["Elf"], model["ElfSha256"], model["ElfSha256"]), "model-binding")
    rows = [model, *report["Rows"], *report["Controls"]]
    need(len({r.get("Elf") for r in [*rows, *refs.values()]}) == 61, "unique-61-elfs")
    for row in rows:
        need(type(row.get("Case")) is int and row["Case"] == 0 and type(row.get("Model")) is bool and
             type(row.get("Elf")) is str and bool(row["Elf"].strip()) and sha(row.get("ElfSha256")) and
             type(row.get("Executed")) is bool and row["Executed"] is execute, "row-identity")
        status = "COMPILED" if not execute else "EXPECTED_FP_MISMATCH" if row["Mutation"] else "PASS"
        need(row.get("Status") == status, "row-status")
        if execute:
            facts = parse_actual(row.get("Actual"), row)
            need(type(row.get("Observed")) is dict and row["Observed"] == facts and
                 all(type(v) is int for v in row["Observed"].values()), "observed-facts")
        else:
            need("Actual" not in row and "Observed" not in row, "invented-execution")


def synthetic(execute):
    from cm4_mpu_fp_contracts import synthetic as pilot_synthetic
    seed = pilot_synthetic(execute)
    report = {k: deepcopy(v) for k, v in seed.items() if k not in
              ("Rows", "Controls", "References", "Associations", "ModelProbe", "ModelArtifactBinding")}
    report.update(Verdict="FP-GRID-PASS" if execute else "COMPILE-PREFLIGHT-PASS",
                  Execution="BOUNDED_FP_GRID" if execute else "NOT_RUN", Rows=[], Controls=[], References=[], Associations=[])
    def row(c, lazy, opt, lto, archive, mutation=None):
        original = next(r for r in (seed["Controls"] if mutation else seed["Rows"])
                        if r["Consumer"] == ("context" if mutation else c) and r["Lazy"] is lazy and r["Mutation"] == mutation)
        value = deepcopy(original)
        value.update(Consumer=c, Optimization=opt, LTO=lto, Archive=archive,
                     Elf="/".join(map(str, (c, lazy, opt, lto, archive, mutation))) + "/runtime.elf")
        return value
    report["Rows"] = [row(*k) for k in KEYS]
    report["Controls"] = [row(*k) for k in CONTROL_KEYS]
    report["ModelProbe"] = deepcopy(seed["ModelProbe"])
    report["ModelArtifactBinding"] = deepcopy(seed["ModelArtifactBinding"])
    for opt, lto, archive in REF_KEYS:
        r = deepcopy(seed["References"][0]); r.update(Optimization=opt, LTO=lto, Archive=archive,
            Elf="reference/" + "/".join(map(str, (opt, lto, archive))) + "/reference.elf")
        report["References"].append(r)
    refs = {ref_key(r): r for r in report["References"]}
    for r in report["Rows"]:
        reference = refs[ref_key(r)]
        assoc = {k: r[k] for k in ("Consumer", "Lazy", "Optimization", "LTO", "Archive")}
        assoc.update(Executed=False, NamedMechanismResults=3, EvidenceSha256="A" * 64,
            SubjectElf=r["Elf"], SubjectSha256=r["ElfSha256"], ReferenceElf=reference["Elf"],
            ReferenceSha256=reference["ElfSha256"], SubjectFp={}, ReferenceFp={})
        report["Associations"].append(assoc)
    return report


def control_tests():
    controls = []
    def test(name, report, execute, expected, reason=None):
        rejection = None
        try:
            validate(report, execute)
            accepted = True
        except (RuntimeError, KeyError, TypeError, AttributeError) as failure:
            accepted, rejection = False, str(failure)
        need(accepted is expected and (reason is None or rejection == reason), "grid-control:" + name)
        controls.append(dict(Name=name, Expected=expected, Rejection=rejection))
    for execute in (False, True):
        prefix = "execute-" if execute else "compile-"
        good = synthetic(execute)
        test(prefix + "positive", good, execute, True)
        for field, value in (("Error", ""), ("Error", 0), ("Error", False), ("CompleteSuite", True),
                ("CompileOnly", execute), ("RequestedInventoryComplete", False), ("PreSaveLspactObserved", True),
                ("Execution", "FP_ACTIVE_PILOT"), ("InputDrift", ["drift"])):
            bad = deepcopy(good); bad[field] = value; test(prefix + field + repr(value), bad, execute, False)
        for name, action in (("missing-row", lambda x: x["Rows"].pop()),
                ("row-order", lambda x: x["Rows"].reverse()),
                ("lazy-int", lambda x: x["Rows"][0].__setitem__("Lazy", 0)),
                ("lto-int", lambda x: x["Rows"][0].__setitem__("LTO", 0)),
                ("ref-order", lambda x: x["References"].reverse()),
                ("control-order", lambda x: x["Controls"].reverse()),
                ("codegen", lambda x: x["Controls"][0].__setitem__("CodegenRejection", "INCIDENTAL")),
                ("model-binding", lambda x: x.pop("ModelArtifactBinding")),
                ("model-duplicate", lambda x: x["ModelProbe"].__setitem__("Elf", x["Rows"][0]["Elf"])),
                ("assoc-config", lambda x: x["Associations"][0].__setitem__("LTO", True)),
                ("assoc-reference", lambda x: x["Associations"][0].__setitem__("ReferenceElf", x["References"][1]["Elf"]))):
            bad = deepcopy(good); action(bad); test(prefix + name, bad, execute, False)
        if execute:
            for i in range(32):
                bad = deepcopy(good); bad["Rows"][i].update(Executed=False, Status="COMPILED")
                test(prefix + "skipped-" + str(i), bad, execute, False)
            bad = deepcopy(good); r = bad["Rows"][0]
            r["Actual"]["Stderr"] = r["Actual"]["Stderr"].replace("PC=00001010", "PC=00001020")
            r["Observed"]["ReturnPC"] = 0x1020
            test(prefix + "per-elf-pc", bad, execute, False, "positive-frame")
        else:
            bad = deepcopy(good); bad["Rows"][0]["Actual"] = {}
            test(prefix + "invented-execution", bad, execute, False)
    return dict(Controls=controls, Scope="Synthetic grid orchestration controls, never CPU observations")
