"""Opt-in classic-FP final mechanism join; no tool or target execution."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
PROFILES, MODES = ("CM4", "CM7"), ("O0", "Og", "O2", "Os", "O3")
MODULES = {
    "native": "tools/fixtures/classic_final_image/run.py",
    "reference": "tools/fixtures/classic_final_image/reference_run.py",
    "attributes": "tools/freeze_classic_fp_mechanisms.py",
    "checker": "tools/fixtures/cm4_cm7_freeze_parity/check.py",
    "decoder": "tools/fixtures/cm55_tfm_parity/elf.py",
    "final": "tools/fixtures/classic_final_image/elf.py",
    "reference_final": "tools/fixtures/classic_final_image/reference_elf.py",
    "admission": "tools/fixtures/classic_final_join/admission.py",
}
SUPPORT = ("tools/freeze_cm3_mechanisms.py", "tools/freeze_cohorts.py", "tools/runtime_sources.py",
           "tools/fixtures/freeze_cohorts/build_recipe.py", "tools/fixtures/freeze_cohorts/reference_recipe.py",
           "tools/fixtures/freeze_cohorts/process_runner.py")


def need(ok, message):
    if not ok:
        raise ValueError("classic-final-join: " + message)


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def digest_text(value):
    need(type(value) is str and re.fullmatch(r"[A-F0-9]{64}", value) is not None, "exact SHA256 required")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def regular(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), "regular non-symlink input required")
    return path.resolve(strict=True)


def output_directory(path, native, reference):
    output = Path(path).resolve()
    roots = [REPO, Path(native).resolve(strict=True), Path(reference).resolve(strict=True)]
    need(roots[1] != roots[2] and all(root.is_dir() for root in roots), "distinct build directories")
    need(not roots[1].is_relative_to(roots[2]) and not roots[2].is_relative_to(roots[1]), "overlapping builds")
    need(not output.exists() and all(not output.is_relative_to(root) and not root.is_relative_to(output)
                                   for root in roots), "fresh external non-overlapping output required")
    return output


class Watch:
    def __init__(self, output):
        self.output = Path(output)
        self.hashes, self.copies, self.memberships = {}, {}, {}

    def read(self, path, expected=None, capture=False):
        path = regular(path)
        data = path.read_bytes()
        value = digest(data)
        need(expected is None or value == digest_text(expected), "input hash mismatch")
        need(path not in self.hashes or self.hashes[path] == value, "input changed during join")
        self.hashes[path] = value
        if capture and path not in self.copies:
            target = self.output / "inputs" / ("%04d-" % len(self.copies) + path.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.copies[path] = target
        return data

    def structured(self, path, expected=None):
        return json.loads(self.read(path, expected, capture=True), object_pairs_hook=unique_object)

    def copied(self, path):
        original = regular(path)
        self.read(original, capture=True)
        return self.copies[original]

    def membership(self, root, names):
        root = Path(root).resolve(strict=True)
        actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
        need(actual == names, "artifact membership mismatch")
        need(root not in self.memberships or self.memberships[root] == names, "artifact membership changed")
        self.memberships[root] = set(names)

    def close(self):
        for path, expected in tuple(self.hashes.items()):
            self.read(path, expected)
        for original, captured in self.copies.items():
            need(digest(regular(captured).read_bytes()) == self.hashes[original], "captured input changed")
        for root, names in tuple(self.memberships.items()):
            self.membership(root, names)


def relative_file(root, name):
    need(type(name) is str and "\\" not in name, "portable artifact path required")
    relative = PurePosixPath(name)
    need(not relative.is_absolute() and relative.parts and all(p not in ("", ".", "..") for p in relative.parts)
         and relative.as_posix() == name, "safe artifact path required")
    path = regular(Path(root) / name)
    need(path.is_relative_to(Path(root).resolve()), "artifact escaped build directory")
    return path


def close_build(watch, root):
    root = Path(root).resolve(strict=True)
    artifacts = watch.structured(root / "artifacts.json")["Artifacts"]
    need(type(artifacts) is dict and artifacts, "nonempty artifact inventory required")
    watch.membership(root, set(artifacts) | {"artifacts.json"})
    for name, value in artifacts.items():
        watch.read(relative_file(root, name), value)
    inputs = watch.structured(root / "inputs.json")
    need(type(inputs["Files"]) is list and inputs["Files"] and type(inputs["Generated"]) is dict
         and inputs["Generated"], "nonempty producer input closure required")
    originals = set()
    for row in inputs["Files"]:
        path = regular(row["Original"])
        need(path not in originals, "duplicate producer original")
        originals.add(path)
        watch.read(path, row["Sha256"])
        watch.read(row["Captured"], row["Sha256"])
    for path, value in inputs["Generated"].items():
        watch.read(path, value)
    return artifacts


def physical_roles(roles, providers):
    need(set(roles) == {"Prelink", "Final", "Plain", "Disassembly", "LinkMap"}, "exact image roles required")
    need(len(providers) == len(set(providers)) and roles["Prelink"] in providers,
         "unique providers including prelink required")
    expected = len(providers) + 4
    paths = list(dict.fromkeys([*roles.values(), *providers]))
    need(len(paths) == expected, "cross-role/provider alias")
    need(all(not left.samefile(right) for index, left in enumerate(paths) for right in paths[index + 1:]),
         "physical input alias")


def source_paths(root, side, profile, api):
    fixture = "tools/fixtures/classic_final_image/"
    if side == "Native":
        names = (*api["native"].COMMON_SOURCES, *api["native"].selection(profile, "O2")[3],
                 "fiber/port/fiber_port_context_cohort_expectation.c", fixture + "application.c", fixture + "startup.S")
        return [str(root / "source" / name) for name in names]
    return [str(root / "freertos" / api["reference"].port_paths(profile)[0]),
            *(str(root / "source" / (fixture + "reference/") / name) for name in ("providers.c", "consumer.c", "startup.S"))]


def bind_parser(watch, native_root):
    root = Path(native_root).resolve(strict=True)
    package = root / "python/elftools"
    artifacts = watch.structured(root / "artifacts.json")["Artifacts"]
    names = {path.relative_to(package).as_posix() for path in package.rglob("*") if path.is_file()}
    need("__init__.py" in names, "captured parser package required")
    watch.membership(package, names)
    for name in sorted(names):
        path = regular(package / name)
        relative = path.relative_to(root).as_posix()
        need(relative in artifacts, "parser file missing from producer seal")
        watch.read(path, artifacts[relative], capture=True)
    for name, module in tuple(sys.modules.items()):
        if name == "elftools" or name.startswith("elftools."):
            path = regular(getattr(module, "__file__", ""))
            need(path.is_relative_to(package) and path in watch.hashes, "ambient parser import rejected")
    sys.path.insert(0, str(package.parent))
    return package


def load_api(watch, native_root):
    package = bind_parser(watch, native_root)
    sources = [Path(__file__), *(REPO / name for name in (*MODULES.values(), *SUPPORT))]
    for source in sources:
        watch.read(source, capture=True)
    api = {}
    for name, relative in MODULES.items():
        path = REPO / relative
        spec = importlib.util.spec_from_file_location("classic_final_join_" + name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        exec(compile(watch.read(path), str(path), "exec"), module.__dict__)
        api[name] = module
    import elftools
    need(elftools.__version__ == "0.33", "pyelftools 0.33 required")
    for name, module in tuple(sys.modules.items()):
        if name == "elftools" or name.startswith("elftools."):
            path = regular(getattr(module, "__file__", ""))
            need(path.is_relative_to(package) and path in watch.hashes, "parser module escaped captured package")
            watch.read(path, watch.hashes[path])
    return api


def require_codegen_records(result, artifact, mode):
    for source in result["Sources"]:
        flags = source["CompileFlags"]
        need(type(flags) is list and all(type(flag) is str for flag in flags)
             and flags[:5] == [*artifact["compile_flags"], "-" + mode], "exact target/mode flag prefix")
        need([flag for flag in flags if flag.startswith("-O")] == ["-" + mode]
             and not any(flag.startswith(("-flto", "-march=", "-mabi=")) for flag in flags)
             and not any(flag.startswith(("-mcpu=", "-mfpu=", "-mfloat-abi=")) for flag in flags[4:]),
             "unadmitted codegen override")
        commands = [row["Argv"] for row in result["Commands"] if "-c" in row["Argv"]
                    and source["Source"] in row["Argv"]]
        need(len(commands) == 1, "exactly one actual compile command per source")
        argv = commands[0]
        need(argv[1:1 + len(flags)] == flags and argv[argv.index("-c") + 1] == source["Source"]
             and argv[argv.index("-o") + 1] == source["Object"], "actual compiler flag/source/object binding")


def prepare_group(watch, root, expected, side, profile, mode, api):
    root = Path(root).resolve(strict=True)
    result = watch.structured(root / "results.json", digest_text(expected))
    artifacts = close_build(watch, root)
    inventory = Path(result["SourceInventoryReceipt"]).resolve(strict=True)
    manifest = watch.structured(inventory / "inputs/tools/freeze_cohorts.json")
    inventory_result = watch.structured(inventory / "results.json")
    need(inventory_result["Verdict"] == "INVENTORY-PLAN-PASS" and inventory_result["Error"] is None
         and inventory_result["GlobalFreezeQualified"] is False and inventory_result["InputDrift"] == []
         and inventory_result["ManifestSha256"] == digest(watch.read(inventory / "inputs/tools/freeze_cohorts.json"))
         and inventory_result["SourceInventorySha256"] == result["SourceInventorySha256"],
         "source inventory receipt binding")
    need(manifest["reference_commit"] == PIN, "inventory reference pin")
    artifact = api["reference"].require_artifact(manifest, api["attributes"], profile, mode)
    cohort = api["native"].selection(profile, mode)[0]
    api["admission"].validate_receipt(result, side=side, profile=profile, mode=mode, expected_cohort=cohort,
        expected_artifact=artifact, expected_sources=source_paths(root, side, profile, api))
    require_codegen_records(result, artifact, mode)
    for link in result["Links"]:
        name = link["Kind"]
        need(Path(link["Path"]) == root / (name + ".elf") and Path(link["Map"]) == root / (name + ".map"),
             "exact final link paths")
        watch.read(link["Path"], link["Sha256"])
        watch.read(link["Map"], link["MapSha256"])
    if side == "Reference":
        need(result["ArtifactSealVerified"] is True, "reference artifact seal not verified")
        need(result["ReferenceCommit"] == PIN and result["ReferenceClosingIdentityVerified"] is True, "reference pin not closed")
        need(result["PortmacroProvider"] == api["reference"].port_paths(profile)[1]
             and result["BaseConfig"] == api["reference"].PROFILES[profile][2], "reference provider/config binding")
        bindings = result["ReferenceFileBindings"]
        expected_paths = {path.relative_to(root / "freertos").as_posix() for path in (root / "freertos/include").rglob("*.h")}
        expected_paths.update(api["reference"].port_paths(profile))
        need(type(bindings) is list and len(bindings) == len(expected_paths)
             and {row["Path"] for row in bindings} == expected_paths, "exact pinned source/blob bindings")
        for row in bindings:
            captured = relative_file(root, "freertos/" + row["Path"])
            blob = relative_file(root, "reference-blobs/" + row["Path"])
            need(Path(row["Captured"]) == captured and Path(row["GitBlob"]) == blob, "pinned source/blob paths")
            source_bytes = watch.read(captured, row["WorktreeSha256"])
            watch.read(row["Original"], row["WorktreeSha256"])
            blob_bytes = watch.read(blob, row["GitBlobSha256"])
            need(api["attributes"].shared.inventory.reference_bytes_match(source_bytes, blob_bytes) == row["ByteComparison"],
                 "pinned source/blob byte comparison")
    objects = []
    for index, row in enumerate(result["Sources"]):
        source = regular(row["Source"])
        obj = regular(row["Object"])
        need(obj == root / "objects" / ("%02d-" % index + source.stem + ".o"), "exact provider object path")
        watch.read(source, row["SourceSha256"])
        watch.read(obj, row["ObjectSha256"], capture=True)
        objects.append(obj)
    index = 3 if side == "Native" else 0
    prelink = objects[index]
    roles = dict(Prelink=prelink, Final=regular(root / "emit-relocs.elf"), Plain=regular(root / "ordinary.elf"),
                 Disassembly=regular(root / "emit-relocs.dis"), LinkMap=regular(root / "emit-relocs.map"))
    physical_roles(roles, objects)
    prelink_dis, attributes = prelink.with_suffix(".dis"), prelink.with_suffix(".attributes")
    for path in (*roles.values(), prelink_dis, attributes):
        relative = path.relative_to(root).as_posix()
        need(relative in artifacts, "replay input missing from producer seal")
        watch.read(path, artifacts[relative], capture=True)
    api["attributes"].require_attributes(watch.read(attributes).decode("ascii"), profile)
    mechanism = api["decoder"].Object(watch.copied(prelink), watch.copied(prelink_dis))
    need(not any(name.startswith(".gnu.lto_") for name in mechanism.names), "ordinary object required")
    provider_bindings = {str(path): watch.copied(path) for path in objects}
    final_class = (api["final"].FinalImage if side == "Native" else
                   {"CM4": api["reference_final"].ReferenceCM4FinalImage,
                    "CM7": api["reference_final"].ReferenceCM7FinalImage}[profile])
    options = dict(float_abi="hard") if side == "Native" else dict(mode=mode)
    image = final_class(watch.copied(prelink), watch.copied(roles["Final"]), watch.copied(roles["Disassembly"]),
                        provider_objects=provider_bindings, link_map=watch.copied(roles["LinkMap"]), **options)
    names = ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler") if side == "Native" else api["reference"].ROOTS
    roots = [image.function(name) for name in names]
    twins = api["final"].compare_load_images(watch.copied(roles["Plain"]), watch.copied(roles["Final"]))
    return dict(Result=result, Root=root, Inventory=inventory, MechanismObject=mechanism, Roots=roots, Twins=twins,
                ReceiptSha256=expected, UniqueImageInputs=len(objects) + 4, PrelinkSha256=digest(watch.read(prelink)))


def require_pairings(proof, profile):
    need(type(profile) is str and profile in PROFILES, "exact mechanism profile required")
    expected = [
        dict(Name="first-start", NativeRoot="fiber_port_start_first_context", ReferenceRoot="prvPortStartFirstTask",
             DifferenceIds=["FAP-COMMON-START", "FAP-COMMON-PROVENANCE"]),
        dict(Name="first-restore", NativeRoot="SVC_Handler", ReferenceRoot="vPortSVCHandler",
             DifferenceIds=["FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-FP-VALIDATION"]),
        dict(Name="PendSV-FP", NativeRoot="PendSV_Handler", ReferenceRoot="xPortPendSVHandler",
             DifferenceIds=["FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-FP-VALIDATION"]),
    ]
    if profile == "CM7":
        for row in expected[1:]:
            row["DifferenceIds"].append("FAP-CM7-ERRATA-PRIMASK")
    need(proof["Mechanisms"] == expected, "exact mechanism/difference assignment required")


def scope_report(profile, mode):
    return dict(Status="FAIL", Scope="CLASSIC_FP_FINAL_MECHANISM_COMPOSITION_ONLY", Profile=profile, Mode=mode,
                ClosedBodies=0, Mechanisms=[], RequiredCellsSatisfied=0, FinalReferenceParity=False,
                InstructionEquivalence=False, PolicyEquivalence=False, CompleteObjectProof=False,
                ArchiveExtraction=False, LTO=False, NativeCommandsExecuted=0, CpuExecution=False,
                BoardExecution=False, GlobalFreezeQualified=False)


def run(args, output, watch):
    for root, receipt_hash, artifact_hash in (
            (args.native_build, args.native_receipt_sha256, args.native_artifacts_sha256),
            (args.reference_build, args.reference_receipt_sha256, args.reference_artifacts_sha256)):
        watch.structured(Path(root) / "results.json", digest_text(receipt_hash))
        watch.structured(Path(root) / "artifacts.json", digest_text(artifact_hash))
    api = load_api(watch, args.native_build)
    native, reference = [prepare_group(watch, root, expected, side, args.profile, args.mode, api) for root, expected, side in
        ((args.native_build, args.native_receipt_sha256, "Native"),
         (args.reference_build, args.reference_receipt_sha256, "Reference"))]
    need(native["Inventory"] == reference["Inventory"] and
         native["Result"]["SourceInventorySha256"] == reference["Result"]["SourceInventorySha256"], "same captured source inventory required")
    proof = api["checker"].check_pair(native["MechanismObject"], reference["MechanismObject"], args.profile)
    api["attributes"].require_proof(proof, args.profile, args.mode)
    require_pairings(proof, args.profile)
    ledger = watch.read(native["Inventory"] / "inputs/FREERTOS_ASM_PARITY.md", capture=True).decode("ascii")
    identities = proof["DifferenceIds"]
    need(all(re.search(r"^### " + re.escape(identity) + r"\s*$", ledger, re.MULTILINE) for identity in identities),
         "captured difference rationale missing")
    policy = watch.read(HERE / "POLICY_DIFFERENCES.md", capture=True)
    need(re.search(r"^### FAP-FP-SETUP-POLICY\s*$", policy.decode("ascii"), re.MULTILINE), "policy supplement missing")
    report = scope_report(args.profile, args.mode)
    report.update(Status="PASS", ClosedBodies=6, Mechanisms=proof["Mechanisms"], ProtocolProof=proof,
        NativeFinalRoots=native["Roots"], ReferenceFinalRoots=reference["Roots"],
        NativeTwins=native["Twins"], ReferenceTwins=reference["Twins"],
        ProducerBindings=[dict(Side=side, Build=str(group["Root"]), ReceiptSha256=group["ReceiptSha256"],
            PrelinkSha256=group["PrelinkSha256"], UniqueImageInputs=group["UniqueImageInputs"])
            for side, group in (("Native", native), ("Reference", reference))],
        SourceInventorySha256=native["Result"]["SourceInventorySha256"], ReferenceCommit=PIN,
        FPSetupDifferenceId="FAP-FP-SETUP-POLICY", LedgerSha256=digest(ledger.encode("ascii")),
        PolicySupplementSha256=digest(policy),
        NativeArtifactsSha256=args.native_artifacts_sha256, ReferenceArtifactsSha256=args.reference_artifacts_sha256)
    return report


def seal(output, report, watch):
    path = output / "results.json"
    try:
        watch.close()
        report["ClosingFilesVerified"] = len(watch.hashes)
        report["InputDrift"] = []
        report["Inputs"] = [dict(Original=str(original), Captured=str(watch.copies[original]) if original in watch.copies else None,
                                Sha256=value) for original, value in watch.hashes.items()]
        report["OutputSealVerified"] = True
        result_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("ascii")
        expected = {copy.relative_to(output).as_posix(): watch.hashes[original] for original, copy in watch.copies.items()}
        expected["results.json"] = digest(result_bytes)
        manifest_bytes = (json.dumps(dict(Artifacts=expected), indent=2, sort_keys=True) + "\n").encode("ascii")
        path.write_bytes(result_bytes)
        (output / "artifacts.json").write_bytes(manifest_bytes)
        expected["artifacts.json"] = digest(manifest_bytes)
        watch.close()
        actual = {item.relative_to(output).as_posix(): digest(item.read_bytes())
                  for item in output.rglob("*") if item.is_file()}
        need(actual == expected, "complete output seal mismatch")
    except Exception as error:
        report.update(Status="FAIL", OutputSealVerified=False, Error=type(error).__name__ + ": " + str(error))
        try:
            path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
            artifacts = {item.relative_to(output).as_posix(): digest(item.read_bytes()) for item in output.rglob("*")
                         if item.is_file() and item != output / "artifacts.json"}
            (output / "artifacts.json").write_text(json.dumps(dict(Artifacts=artifacts), indent=2, sort_keys=True) + "\n", encoding="ascii")
        except Exception:
            pass
        return False
    return report["Status"] == "PASS"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("native-build", "native-receipt-sha256", "native-artifacts-sha256",
                 "reference-build", "reference-receipt-sha256", "reference-artifacts-sha256", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--mode", choices=MODES, required=True)
    args = parser.parse_args(argv)
    need(not sys.flags.optimize, "unoptimized Python required")
    digest_text(args.native_receipt_sha256)
    digest_text(args.reference_receipt_sha256)
    digest_text(args.native_artifacts_sha256)
    digest_text(args.reference_artifacts_sha256)
    output = output_directory(args.output_dir, args.native_build, args.reference_build)
    output.mkdir(parents=True)
    watch, report = Watch(output), scope_report(args.profile, args.mode)
    try:
        report = run(args, output, watch)
    except Exception as error:
        report["Error"] = type(error).__name__ + ": " + str(error)
    passed = seal(output, report, watch)
    print(report["Status"], report.get("Error", ""), str(output))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
