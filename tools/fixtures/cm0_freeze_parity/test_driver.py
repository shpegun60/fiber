"""Pure CM0 driver admission/result controls; no ELF or CPU execution."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cm0_driver_controls", HERE.parents[1] / "freeze_cm0_mechanisms.py")
driver = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = driver
spec.loader.exec_module(driver)


def main():
    records = []

    def test(name, callback, accept):
        error = None
        try:
            callback()
        except (RuntimeError, KeyError, TypeError, ValueError) as failure:
            error = str(failure)
        driver.need((error is None) is accept, "cm0-driver-control-" + name + ": " + str(error))
        records.append(dict(Name=name, Accepted=error is None, Rejection=error))

    manifest = json.loads((HERE.parents[1] / "freeze_cohorts.json").read_text())
    for identity in driver.COHORTS:
        artifact = next(c for c in manifest["cohorts"] if c["id"] == identity)["artifacts"][0]
        test(identity + "/cohort", lambda: driver.require_cohort(artifact, identity), True)
        for key, value in artifact["target"].items():
            altered = deepcopy(artifact)
            altered["target"][key] = not value if type(value) is bool else value + 1 if type(value) is int else "foreign"
            test(identity + "/target-" + key, lambda a=altered: driver.require_cohort(a, identity), False)
        for key in ("vtor", "mpu_regions"):
            altered = deepcopy(artifact)
            altered["target"][key] = int(artifact["target"][key]) if key == "vtor" else False
            test(identity + "/target-type-" + key, lambda a=altered: driver.require_cohort(a, identity), False)
        for key, value in (("role", "secure_companion"), ("source_group_id", "CM0MPU"),
                           ("abi_contract", "foreign"), ("compile_flags", artifact["compile_flags"][:-1])):
            altered = deepcopy(artifact)
            altered[key] = value
            test(identity + "/artifact-" + key, lambda a=altered: driver.require_cohort(a, identity), False)
    for mode in driver.shared.inventory.OBJECT_MODES:
        proof = dict(Verdict="CM0-CLOSED-ROOTS-PASS", Mode=mode,
            Roots={key: list(value) for key, value in driver.ROOTS.items()},
            ProofScope="CM0_P2_NO_MPU_EIGHT_CLOSED_ROOT_PROTOCOLS_ONLY", ClosedBodies=8,
            RequiredCellSatisfied=False, RequiredCellsSatisfied=0, CompleteObjectProof=False,
            InstructionEquivalence=False, CpuExecution=False, BoardExecution=False,
            FinalElfProof=False, GlobalFreezeQualified=False, DifferenceIds=sorted(driver.DIFFERENCES),
            PolicyEquivalence=False, CSourceSemanticProof=False,
            ReferenceSvcObligation=dict(DispatcherRoot="SVC_Handler", CHandlerRoot="vPortSVCHandler_C",
                RestoreRoot="vRestoreContextOfFirstTask", DispatchChainProtocolsMatched=True,
                FirstContextExcReturnProtocolMatched=True, HandlerRoutingProven=False, UnreachabilityProven=False),
            FirstRestoreDifference=dict(DifferenceId="FAP-CM0-STAGED-FRAME", InitialRegisterValueEquivalenceProven=False),
            SchedulerThreshold="BASEPRI-NOT-APPLICABLE;PRIMASK-ENVELOPE",
            RootEvidence=[dict(Side=side, Name=name, Tokens=1, LiteralIslands=0, TailNops=0,
                               BodySha256="A" * 64) for side, names in driver.ROOTS.items() for name in names])
        test(mode + "/proof", lambda: driver.require_proof(proof, mode), True)
        mutations = [
            ("mode", lambda p: p.update(Mode="foreign")),
            ("roots", lambda p: p["Roots"]["Reference"].pop()),
            ("scope", lambda p: p.update(ProofScope="CPU_EQUIVALENCE")),
            ("count", lambda p: p.update(ClosedBodies=7)),
            ("bool-count", lambda p: p.update(ClosedBodies=True)),
            ("bool-counter", lambda p: p.update(RequiredCellsSatisfied=False)),
            ("missing-counter", lambda p: p.pop("RequiredCellsSatisfied")),
            ("nonzero-counter", lambda p: p.update(RequiredCellsSatisfied=1)),
            ("differences", lambda p: p["DifferenceIds"].pop()),
            ("duplicate-difference", lambda p: p["DifferenceIds"].append(p["DifferenceIds"][0])),
            ("evidence", lambda p: p["RootEvidence"].pop()),
            ("duplicate-evidence", lambda p: p["RootEvidence"].__setitem__(0, deepcopy(p["RootEvidence"][1]))),
            ("foreign-root", lambda p: p["RootEvidence"][0].update(Name="foreign")),
            ("empty-body", lambda p: p["RootEvidence"][0].update(Tokens=0)),
            ("invalid-layout", lambda p: p["RootEvidence"][0].update(TailNops=-1)),
            ("bool-layout", lambda p: p["RootEvidence"][0].update(LiteralIslands=True)),
            ("hash", lambda p: p["RootEvidence"][0].update(BodySha256="bad")),
            ("routing-proof", lambda p: p["ReferenceSvcObligation"].update(HandlerRoutingProven=True)),
            ("unreachability-proof", lambda p: p["ReferenceSvcObligation"].update(UnreachabilityProven=True)),
            ("missing-dispatch-root", lambda p: p["ReferenceSvcObligation"].update(CHandlerRoot="foreign")),
            ("missing-dispatch-proof", lambda p: p["ReferenceSvcObligation"].update(DispatchChainProtocolsMatched=False)),
            ("register-equivalence", lambda p: p["FirstRestoreDifference"].update(InitialRegisterValueEquivalenceProven=True)),
            ("BASEPRI", lambda p: p.update(SchedulerThreshold="16")),
        ]
        for key in ("RequiredCellSatisfied", "CompleteObjectProof", "InstructionEquivalence",
                    "CpuExecution", "BoardExecution", "FinalElfProof", "GlobalFreezeQualified",
                    "PolicyEquivalence", "CSourceSemanticProof"):
            altered = deepcopy(proof)
            altered[key] = True
            test(mode + "/promotion-" + key, lambda p=altered: driver.require_proof(p, mode), False)
        for name, mutate in mutations:
            altered = deepcopy(proof)
            mutate(altered)
            test(mode + "/" + name, lambda p=altered: driver.require_proof(p, mode), False)
    attributes = '\n'.join(('Tag_CPU_name: "6S-M"', 'Tag_CPU_arch: v6S-M',
                            'Tag_CPU_arch_profile: Microcontroller', 'Tag_THUMB_ISA_use: Thumb-1')) + '\n'
    test("attributes", lambda: driver.require_attributes(attributes), True)
    for name, text in (("Thumb2", attributes.replace("Thumb-1", "Thumb-2")),
                       ("CM3", attributes.replace("v6S-M", "v7")),
                       ("duplicate", attributes + "Tag_CPU_arch: v6S-M\n")):
        test("attributes-" + name, lambda t=text: driver.require_attributes(t), False)
    for tag in ("Tag_FP_arch", "Tag_ABI_VFP_args", "Tag_MVE_arch", "Tag_Advanced_SIMD_arch",
                "Tag_PAC_extension", "Tag_BTI_extension"):
        test("attributes-" + tag, lambda t=tag: driver.require_attributes(attributes + t + ": foreign\n"), False)
    print(json.dumps(dict(Verdict="PASS", Controls=len(records), CompilerInvocations=0,
                          CpuExecution=False, Records=records), indent=2))


if __name__ == "__main__":
    main()
