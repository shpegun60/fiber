"""Opt-in CM0-family final mechanism join; no tool or target execution."""
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
PROFILES, MODES = ("CM0", "CM0PLUS", "CM0PLUSVTOR"), ("O0", "Og", "O2", "Os", "O3")
MODULES = {
    "native": "tools/fixtures/classic_final_image/run.py",
    "reference": "tools/fixtures/cm0_final_image/reference_run.py",
    "attributes": "tools/freeze_cm0_mechanisms.py",
    "checker": "tools/fixtures/cm0_freeze_parity/closed_roots.py",
    "decoder": "tools/fixtures/cm55_tfm_parity/elf.py",
    "final": "tools/fixtures/classic_final_image/elf.py",
    "reference_final": "tools/fixtures/cm0_final_roots/reference_elf.py",
    "admission": "tools/fixtures/cm0_final_join/admission.py",
}
SUPPORT = ("tools/freeze_cm3_mechanisms.py", "tools/freeze_cohorts.py", "tools/runtime_sources.py",
           "tools/fixtures/freeze_cohorts/build_recipe.py", "tools/fixtures/freeze_cohorts/reference_recipe.py",
           "tools/fixtures/freeze_cohorts/process_runner.py", "tools/fixtures/classic_final_join/join.py",
           "tools/fixtures/classic_final_image/reference_run.py")


# Reuse the qualified byte/identity/seal helpers without changing their globals.
_SHARED_PATH = HERE.with_name("classic_final_join") / "join.py"
_spec = importlib.util.spec_from_file_location("cm0_join_shared", _SHARED_PATH)
shared = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = shared
_SHARED_BYTES = _SHARED_PATH.read_bytes()
exec(compile(_SHARED_BYTES, str(_SHARED_PATH), "exec"), shared.__dict__)
Watch, need, digest, digest_text = shared.Watch, shared.need, shared.digest, shared.digest_text
regular, relative_file, close_build = shared.regular, shared.relative_file, shared.close_build
bind_parser, physical_roles = shared.bind_parser, shared.physical_roles
output_directory, seal = shared.output_directory, shared.seal


def source_paths(root, side, profile, api):
    native_fixture = "tools/fixtures/classic_final_image/"
    if side == "Native":
        names = (*api["native"].COMMON_SOURCES, *api["native"].selection(profile, "O2")[3],
                 "fiber/port/fiber_port_context_cohort_expectation.c", native_fixture + "application.c",
                 native_fixture + "startup.S")
        return [str(root / "source" / name) for name in names]
    return [*(str(root / "freertos" / name) for name in api["reference"].PORT_SOURCES),
            *(str(root / "source/tools/fixtures/cm0_final_image/reference" / name)
              for name in ("providers.c", "consumer.c", "startup.S"))]

def load_api(watch, native_root):
    watch.read(_SHARED_PATH, digest(_SHARED_BYTES), capture=True)
    package = bind_parser(watch, native_root)
    sources = [Path(__file__), *(REPO / name for name in (*MODULES.values(), *SUPPORT))]
    for source in sources:
        watch.read(source, capture=True)
    api = {}
    for name, relative in MODULES.items():
        path = REPO / relative
        spec = importlib.util.spec_from_file_location("cm0_final_join_" + name, path)
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
    base = artifact["compile_flags"]
    for index, source in enumerate(result["Sources"]):
        flags = source["CompileFlags"]
        need(type(flags) is list and all(type(flag) is str for flag in flags) and
             flags[:len(base)+1] == [*base, "-" + mode], "exact target/mode flag prefix")
        need([flag for flag in flags if flag.startswith("-O")] == ["-" + mode] and
             not any(flag.startswith(("-flto", "-march=", "-mabi=", "-mcpu=", "-mfpu=", "-mfloat-abi="))
                     for flag in flags[len(base):]), "unadmitted codegen override")
        commands = [row["Argv"] for row in result["Commands"] if "-c" in row["Argv"] and source["Source"] in row["Argv"]]
        need(len(commands) == 1, "exactly one actual compile command per source")
        argv = commands[0]
        tail = ["-MD", "-MF", source["CompileDependencyFile"], "-MT", "pilot-source-" + str(index),
                "-c", source["Source"], "-o", source["Object"]]
        need(argv[1:] == [*flags, *tail], "actual compiler flag/source/object binding")


def require_input_coverage(watch, root, result, artifacts, side):
    inputs = watch.structured(root / "inputs.json")
    captures = {row["Captured"]: row for row in inputs["Files"]}
    originals = {row["Original"]: row for row in inputs["Files"]}
    generated = inputs["Generated"]
    need(len(originals) == len(inputs["Files"]), "unique original input bindings")
    for source in result["Sources"]:
        need(source["Source"] in captures, "consumed source capture coverage")
        for dependency in source["Dependencies"]:
            need(dependency["Path"] in captures or dependency["Path"] in originals or
                 dependency["Path"] in generated, "compile dependency input coverage")
    need(result["Interpreter"]["ModulePath"] in originals and
         all(row["Argv"][0] in originals for row in result["Commands"]), "tool input coverage")
    inventory = Path(result["SourceInventoryReceipt"])
    need(str(inventory / "artifacts.json") in originals, "inventory input coverage")
    inventory_artifacts = watch.structured(inventory / "artifacts.json",
        originals[str(inventory / "artifacts.json")]["Sha256"])["Artifacts"]
    need(inventory_artifacts and all(str(inventory / name) in originals for name in inventory_artifacts),
         "inventory input coverage")
    workers = {}
    for index, command in enumerate(result["Commands"]):
        if command["Label"].startswith("resolve "):
            name = command["Label"][8:]
            need(name not in workers, "duplicate worker resolution")
            relative = "command-%04d.stdout" % index
            data = watch.read(root / relative, artifacts[relative])
            workers[name] = str(Path(data.decode("utf-8").strip()).resolve())
    need(set(workers) == {"cc1", "collect2", "as", "ld", "lto1", "lto-wrapper"} and
         all(path in originals for path in workers.values()), "worker input coverage")
    consumed_sources = {source["Source"] for source in result["Sources"]}
    compilers = {command["Argv"][0] for command in result["Commands"] if "-c" in command["Argv"] and
                 any(source in command["Argv"] for source in consumed_sources)}
    need(len(compilers) == 1, "one compiler input coverage")
    tool_root = Path(next(iter(compilers))).parent.parent
    binary_dirs = {Path(path).parent for path in originals if path.endswith(".exe") and
                   Path(path).parent.is_relative_to(tool_root)}
    dlls = {str(path.resolve()) for directory in binary_dirs for path in directory.glob("*.dll")}
    need(dlls and dlls <= set(originals), "DLL input coverage")
    parsers = {str(root / name) for name in artifacts if name.startswith("python/elftools/") and name.endswith(".py")}
    need(parsers and parsers <= set(captures), "parser input coverage")
    fixture = root / "source/tools/fixtures" / ("classic_final_image" if side == "Native" else "cm0_final_image/reference")
    need(str(fixture / "link.ld") in captures, "link script input coverage")
    if side == "Reference":
        need(str(fixture / "FreeRTOSConfig.h") in generated and
             str(fixture / "freeze_base_FreeRTOSConfig.h") in captures, "reference config input coverage")
        for binding in result["ReferenceFileBindings"]:
            need(binding["Captured"] in captures and
                 captures[binding["Captured"]]["Original"] == binding["Original"] and
                 binding["GitBlob"] in generated, "pinned binding input coverage")


def require_link_commands(result, artifact, root, side, mode):
    fixture = "classic_final_image" if side == "Native" else "cm0_final_image/reference"
    script = root / "source/tools/fixtures" / fixture / "link.ld"
    objects = [source["Object"] for source in result["Sources"]]
    compiler = result["Sources"][0]["CompileFlags"]
    compile_commands = [row["Argv"] for row in result["Commands"]
                        if "-c" in row["Argv"] and result["Sources"][0]["Source"] in row["Argv"]]
    need(len(compile_commands) == 1 and compiler, "link compiler binding")
    for link in result["Links"]:
        commands = [row["Argv"] for row in result["Commands"] if row["Label"] == "link " + link["Kind"]]
        expected = [compile_commands[0][0], *artifact["compile_flags"], "-" + mode, "-nostdlib",
                    "-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack",
                    "-T", str(script), *objects]
        if link["Kind"] == "emit-relocs":
            expected.append("-Wl,--emit-relocs")
        expected.extend(("-Wl,-Map=" + link["Map"], "-o", link["Path"]))
        need(len(commands) == 1 and commands[0] == expected, "exact ordered twin link command")


def pinned_comparison(actual, blob):
    if actual == blob:
        return "exact"
    need(b"\r" not in blob and actual == blob.replace(b"\n", b"\r\n"), "exact LF or whole-file CRLF required")
    return "git-lf-worktree-crlf"


class ReferenceOwners:
    """The C dispatcher and assembly roots retain their separate owning objects."""
    def __init__(self, port, assembly):
        self.images = (port, assembly)

    def function(self, name, **options):
        need(name in ("vStartFirstTask", "SVC_Handler", "vPortSVCHandler_C",
                      "vRestoreContextOfFirstTask", "PendSV_Handler"), "exact reference root required")
        return self.images[int(name != "vPortSVCHandler_C")].function(name, **options)


def prepare_group(watch, root, expected, side, profile, mode, api):
    root = Path(root).resolve(strict=True)
    result = watch.structured(root / "results.json", digest_text(expected))
    artifacts = close_build(watch, root)
    inventory = Path(result["SourceInventoryReceipt"]).resolve(strict=True)
    manifest = watch.structured(inventory / "inputs/tools/freeze_cohorts.json")
    inventory_result = watch.structured(inventory / "results.json")
    need(inventory_result["Verdict"] == "INVENTORY-PLAN-PASS" and inventory_result["Error"] is None and
         inventory_result["GlobalFreezeQualified"] is False and inventory_result["InputDrift"] == [] and
         inventory_result["ManifestSha256"] == digest(watch.read(inventory / "inputs/tools/freeze_cohorts.json")) and
         inventory_result["SourceInventorySha256"] == result["SourceInventorySha256"], "source inventory receipt binding")
    need(manifest["reference_commit"] == PIN, "inventory reference pin")
    artifact = api["reference"].require_artifact(manifest, api["attributes"], profile, mode)
    cohort = api["native"].selection(profile, mode)[0]
    api["admission"].validate_receipt(result, side=side, profile=profile, mode=mode, expected_cohort=cohort,
        expected_artifact=artifact, expected_sources=source_paths(root, side, profile, api))
    require_codegen_records(result, artifact, mode)
    require_input_coverage(watch, root, result, artifacts, side)
    require_link_commands(result, artifact, root, side, mode)
    for link in result["Links"]:
        name = link["Kind"]
        need(Path(link["Path"]) == root / (name + ".elf") and Path(link["Map"]) == root / (name + ".map"),
             "exact final link paths")
        watch.read(link["Path"], link["Sha256"])
        watch.read(link["Map"], link["MapSha256"])
        commands = [row["Argv"] for row in result["Commands"]
                    if "-o" in row["Argv"] and row["Argv"][row["Argv"].index("-o")+1] == link["Path"]]
        need(len(commands) == 1 and commands[0][commands[0].index("-o")+1] == link["Path"], "actual twin link command")
    if side == "Reference":
        need(result["ArtifactSealVerified"] is True and result["ReferenceCommit"] == PIN and
             result["ReferenceClosingIdentityVerified"] is True, "reference pin/seal not closed")
        need(result["PortmacroProvider"] == api["reference"].PORT_HEADERS[0] and
             result["AdditionalPortHeaders"] == [api["reference"].PORT_HEADERS[1]] and
             result["BaseConfig"] == api["reference"].BASE_CONFIG, "reference provider/config binding")
        need(result["DeclaredVTOR"] is artifact["target"]["vtor"] and
             result["FixtureHandlerInstallationCheck"] == int(artifact["target"]["vtor"]) and
             result["HandlerInstallationOverrideScope"] == "VTOR0-DISABLED;VTOR1-BASELINE-ONE;NO-MMIO-PROOF" and
             result["SchedulerThreshold"] == "BASEPRI-NOT-APPLICABLE;PRIMASK-ENVELOPE" and
             result["FPPolicy"] == "NOT-APPLICABLE-NO-FPU", "reference VTOR/no-FP policy")
        bindings = result["ReferenceFileBindings"]
        paths = {path.relative_to(root / "freertos").as_posix() for path in (root / "freertos/include").rglob("*.h")}
        paths.update((*api["reference"].PORT_SOURCES, *api["reference"].PORT_HEADERS))
        need(type(bindings) is list and len(bindings) == len(paths) and
             {row["Path"] for row in bindings} == paths, "exact pinned source/blob bindings")
        for row in bindings:
            captured = relative_file(root, "freertos/" + row["Path"])
            blob = relative_file(root, "reference-blobs/" + row["Path"])
            need(Path(row["Captured"]) == captured and Path(row["GitBlob"]) == blob, "pinned source/blob paths")
            data = watch.read(captured, row["WorktreeSha256"])
            watch.read(row["Original"], row["WorktreeSha256"])
            blob_data = watch.read(blob, row["GitBlobSha256"])
            need(pinned_comparison(data, blob_data) == row["ByteComparison"], "pinned source/blob byte comparison")
        configuration = root / "source/tools/fixtures/cm0_final_image/reference/FreeRTOSConfig.h"
        need(watch.read(configuration) == result["ConfigText"].encode("ascii"), "actual generated reference config")
    objects = []
    for index, row in enumerate(result["Sources"]):
        source, obj = regular(row["Source"]), regular(row["Object"])
        need(obj == root / "objects" / ("%02d-" % index + source.stem + ".o"), "exact provider object path")
        watch.read(source, row["SourceSha256"])
        watch.read(obj, row["ObjectSha256"], capture=True)
        objects.append(obj)
    prelinks = [objects[3]] if side == "Native" else objects[:2]
    roles = dict(Prelink=prelinks[0], Final=regular(root / "emit-relocs.elf"), Plain=regular(root / "ordinary.elf"),
                 Disassembly=regular(root / "emit-relocs.dis"), LinkMap=regular(root / "emit-relocs.map"))
    physical_roles(roles, objects)
    mechanisms = []
    for prelink in prelinks:
        prelink_dis, attributes = prelink.with_suffix(".dis"), prelink.with_suffix(".attributes")
        for path in (*roles.values(), prelink_dis, attributes):
            relative = path.relative_to(root).as_posix()
            need(relative in artifacts, "replay input missing from producer seal")
            watch.read(path, artifacts[relative], capture=True)
        api["attributes"].require_attributes(watch.read(attributes).decode("ascii"))
        mechanism = api["decoder"].Object(watch.copied(prelink), watch.copied(prelink_dis))
        need(not any(name.startswith(".gnu.lto_") for name in mechanism.names), "ordinary object required")
        mechanisms.append(mechanism)
    providers = {str(path): watch.copied(path) for path in objects}
    common = (watch.copied(roles["Final"]), watch.copied(roles["Disassembly"]))
    options = dict(provider_objects=providers, link_map=watch.copied(roles["LinkMap"]))
    if side == "Native":
        image = api["final"].FinalImage(watch.copied(prelinks[0]), *common, float_abi="soft", **options)
        mechanism = mechanisms[0]
    else:
        image = api["reference_final"].ReferenceCM0FinalImage(
            *(watch.copied(path) for path in prelinks), *common, mode=mode, **options)
        mechanism = ReferenceOwners(*mechanisms)
    roots = [image.function(name) for name in api["checker"].ROOTS[side]]
    twins = api["final"].compare_load_images(watch.copied(roles["Plain"]), watch.copied(roles["Final"]))
    return dict(Result=result, Root=root, Inventory=inventory, MechanismObject=mechanism, Roots=roots, Twins=twins,
                ReceiptSha256=expected, UniqueImageInputs=len(objects)+4,
                Prelinks=[dict(Path=str(path), Sha256=digest(watch.read(path))) for path in prelinks])


def require_pairings(proof, profile):
    need(type(profile) is str and profile in PROFILES, "exact mechanism profile required")
    expected = [
        dict(Name="first-start", NativeRoot="fiber_port_start_first_context", ReferenceRoots=["vStartFirstTask"],
             DifferenceIds=["FAP-COMMON-START", "FAP-COMMON-PROVENANCE"]),
        dict(Name="first-restore", NativeRoot="SVC_Handler",
             ReferenceRoots=["SVC_Handler", "vPortSVCHandler_C", "vRestoreContextOfFirstTask"],
             DifferenceIds=["FAP-COMMON-PROVENANCE", "FAP-CM0-STAGED-FRAME"]),
        dict(Name="PendSV", NativeRoot="PendSV_Handler", ReferenceRoots=["PendSV_Handler"],
             DifferenceIds=["FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE",
                            "FAP-COMMON-MASK-RESTORE", "FAP-CM0-STAGED-FRAME"]),
    ]
    need(proof["Mechanisms"] == expected, "exact mechanism/difference assignment required")


def scope_report(profile, mode):
    return dict(Status="FAIL", Scope="CM0_FAMILY_FINAL_MECHANISM_COMPOSITION_ONLY", Profile=profile, Mode=mode,
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
         native["Result"]["SourceInventorySha256"] == reference["Result"]["SourceInventorySha256"],
         "same captured source inventory required")
    proof = api["checker"].check_pair(native["MechanismObject"], reference["MechanismObject"], args.mode)
    api["attributes"].require_proof(proof, args.mode)
    require_pairings(proof, args.profile)
    ledger = watch.read(native["Inventory"] / "inputs/FREERTOS_ASM_PARITY.md", capture=True).decode("ascii")
    need(all(re.search(r"^### " + re.escape(identity) + r"\s*$", ledger, re.MULTILINE)
             for identity in proof["DifferenceIds"]), "captured difference rationale missing")
    report = scope_report(args.profile, args.mode)
    report.update(Status="PASS", ClosedBodies=8, Mechanisms=proof["Mechanisms"], ProtocolProof=proof,
        NativeFinalRoots=native["Roots"], ReferenceFinalRoots=reference["Roots"],
        NativeTwins=native["Twins"], ReferenceTwins=reference["Twins"],
        ProducerBindings=[dict(Side=side, Build=str(group["Root"]), ReceiptSha256=group["ReceiptSha256"],
            Prelinks=group["Prelinks"], UniqueImageInputs=group["UniqueImageInputs"])
            for side, group in (("Native", native), ("Reference", reference))],
        SourceInventorySha256=native["Result"]["SourceInventorySha256"], ReferenceCommit=PIN,
        LedgerSha256=digest(ledger.encode("ascii")), NativeArtifactsSha256=args.native_artifacts_sha256,
        ReferenceArtifactsSha256=args.reference_artifacts_sha256)
    return report

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
