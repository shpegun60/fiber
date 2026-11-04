"""Pure outer-driver result/attribute controls; no compiler, ELF or CPU proof."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


driver = load("classic_fp_driver_controls", HERE.parents[1] / "freeze_classic_fp_mechanisms.py")
check = load("classic_fp_checker_controls", HERE / "check.py")


def provider(protocols, tail):
    def function(name, *, literal_islands=False):
        driver.need(literal_islands is True, "explicit-structural-reader-required")
        return deepcopy(protocols[name]) + [("nop", "")] * tail
    return SimpleNamespace(function=function)


def main():
    controls = []

    def test(name, call, accept):
        error = None
        try:
            call()
        except (RuntimeError, KeyError, TypeError, ValueError) as failure:
            error = str(failure)
        driver.need((error is None) is accept, "driver-control-" + name + ": " + str(error))
        controls.append(dict(Name=name, Accepted=error is None, Rejection=error))

    for profile in driver.PROFILES:
        prefix = profile + "/"
        manifest = json.loads((HERE.parents[1] / "freeze_cohorts.json").read_text())
        artifact = next(c for c in manifest["cohorts"] if c["id"] == driver.PROFILES[profile][0])["artifacts"][0]
        test(prefix + "cohort", lambda: driver.require_cohort(artifact, profile), True)
        for key, original in artifact["target"].items():
            altered = deepcopy(artifact)
            altered["target"][key] = (not original if type(original) is bool else
                                       original + 1 if type(original) is int else "foreign")
            test(prefix + "target-" + key, lambda a=altered: driver.require_cohort(a, profile), False)
        for key in ("vtor", "mpu_regions"):
            altered = deepcopy(artifact)
            altered["target"][key] = int(artifact["target"][key]) if key == "vtor" else False
            test(prefix + "target-type-" + key, lambda a=altered: driver.require_cohort(a, profile), False)
        for key, value in (("role", "secure_companion"), ("source_group_id", "foreign"),
                           ("abi_contract", "foreign"), ("compile_flags", artifact["compile_flags"][:-1])):
            altered = deepcopy(artifact)
            altered[key] = value
            test(prefix + "artifact-" + key, lambda a=altered: driver.require_cohort(a, profile), False)
        for mode in driver.shared.inventory.OBJECT_MODES:
            proof = check.check_pair(provider(check._NATIVE[profile], 1 if mode == "O0" else 0),
                                     provider(check._REFERENCE[profile], 1 if mode == "O0" else 0), profile)
            test(prefix + mode, lambda p=proof, m=mode: driver.require_proof(p, profile, m), True)
        proof = check.check_pair(provider(check._NATIVE[profile], 1), provider(check._REFERENCE[profile], 1), profile)
        mutations = [
            ("wrong-profile", lambda p: p.update(Profile="CM7" if profile == "CM4" else "CM4")),
            ("partial-body-count", lambda p: p.update(ClosedBodies=5)),
            ("bool-body-count", lambda p: p.update(ClosedBodies=True)),
            ("partial-roots", lambda p: p["Roots"].pop()),
            ("global-promotion", lambda p: p.update(GlobalFreezeQualified=True)),
            ("instruction-equivalence", lambda p: p.update(InstructionEquivalence=True)),
            ("invented-board-run", lambda p: p.update(BoardExecution=True)),
            ("bool-counter", lambda p: p.update(RequiredCellsSatisfied=False)),
            ("nonzero-counter", lambda p: p.update(RequiredCellsSatisfied=1)),
            ("missing-counter", lambda p: p.pop("RequiredCellsSatisfied")),
            ("policy-promotion", lambda p: p["FPCCRPolicy"].update(PolicyEquivalenceProven=True)),
            ("routing-promotion", lambda p: p["ReferenceSvcObligation"].update(HandlerRoutingProven=True)),
            ("missing-difference", lambda p: p["DifferenceIds"].pop()),
            ("missing-evidence", lambda p: p["RootEvidence"].pop()),
            ("duplicate-evidence", lambda p: p["RootEvidence"].__setitem__(0, deepcopy(p["RootEvidence"][1]))),
            ("foreign-root", lambda p: p["RootEvidence"][0].update(Name="foreign")),
            ("empty-body", lambda p: p["RootEvidence"][0].update(Tokens=0)),
            ("bad-body-hash", lambda p: p["RootEvidence"][0].update(BodySha256="fake")),
            ("mixed-layout", lambda p: p["RootEvidence"][0].update(TailNops=0)),
        ]
        test(prefix + "no-proof", lambda: driver.require_proof(None, profile, "O0"), False)
        test(prefix + "mode-mismatch", lambda: driver.require_proof(proof, profile, "O2"), False)
        for name, mutate in mutations:
            altered = deepcopy(proof)
            mutate(altered)
            test(prefix + name, lambda p=altered: driver.require_proof(p, profile, "O0"), False)
        attributes = '\n'.join(('Tag_CPU_name: "7E-M"', 'Tag_CPU_arch: v7E-M',
            'Tag_CPU_arch_profile: Microcontroller', 'Tag_THUMB_ISA_use: Thumb-2',
            'Tag_FP_arch: ' + driver.PROFILES[profile][1], 'Tag_ABI_VFP_args: VFP registers')) + '\n'
        test(prefix + "attributes", lambda: driver.require_attributes(attributes, profile), True)
        for name, text in (
            ("foreign-cpu", attributes.replace('"7E-M"', '"7-M"')),
            ("foreign-arch", attributes.replace('v7E-M', 'v7')),
            ("foreign-fpu", attributes.replace(driver.PROFILES[profile][1], 'foreign')),
            ("softfp-abi", attributes.replace('Tag_ABI_VFP_args: VFP registers', '')),
            ("duplicate-tag", attributes + 'Tag_CPU_arch: v7E-M\n'),
            ("mve", attributes + 'Tag_MVE_arch: MVE Integer and FP\n'),
        ):
            test(prefix + name, lambda t=text: driver.require_attributes(t, profile), False)
    print(json.dumps(dict(Verdict="PASS", Controls=len(controls), CompilerInvocations=0,
                          CpuExecution=False, Records=controls), indent=2))


if __name__ == "__main__":
    main()
