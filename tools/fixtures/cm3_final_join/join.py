"""Fixed CM3 final mechanism composition; no compiler, target or parity promotion."""
import argparse
from contextlib import contextmanager
import copy
import importlib.util
import json
from pathlib import Path
import re
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
PROFILES, MODES = ("CM3",), ("O0", "Og", "O2", "Os", "O3")
CLASSIC = "tools/fixtures/classic_final_image/"
REFERENCE = "tools/fixtures/cm3_final_image/"
MODULES = dict(native=CLASSIC + "run.py", reference=REFERENCE + "reference_run.py",
    attributes=REFERENCE + "admission.py", inventory="tools/freeze_cm3_mechanisms.py",
    native_recipe="tools/fixtures/freeze_cohorts/build_recipe.py",
    reference_recipe="tools/fixtures/freeze_cohorts/reference_recipe.py",
    checker="tools/fixtures/cm3_freeze_parity/check.py", decoder="tools/fixtures/cm55_tfm_parity/elf.py",
    final=CLASSIC + "elf.py", reference_final="tools/fixtures/cm3_final_roots/reference_elf.py",
    admission="tools/fixtures/cm3_final_join/admission.py")
SUPPORT = (CLASSIC + "reference_run.py", CLASSIC + "reference_elf.py",
    "tools/freeze_cohorts.py", "tools/runtime_sources.py", "tools/fixtures/freeze_cohorts/process_runner.py",
    "tools/fixtures/cm3_final_roots/reference_witness.py")


def _load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


_SELF_BYTES = Path(__file__).read_bytes()
_SHARED_PATH = HERE.with_name("classic_final_join") / "join.py"
_SHARED_BYTES = _SHARED_PATH.read_bytes()
shared = _load("cm3_join_shared", _SHARED_PATH, _SHARED_BYTES)
_GENERIC_PATH = HERE.with_name("cm0_final_join") / "join.py"
_GENERIC_BYTES = _GENERIC_PATH.read_bytes()
generic = _load("cm3_join_generic_codegen", _GENERIC_PATH, _GENERIC_BYTES)
need, digest, digest_text = shared.need, shared.digest, shared.digest_text
Watch, close_build, bind_parser = shared.Watch, shared.close_build, shared.bind_parser
physical_roles, seal = shared.physical_roles, shared.seal
regular, relative_file = shared.regular, shared.relative_file
require_codegen_records = generic.require_codegen_records


def _same(actual, expected, detail):
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    need(encode(actual) == encode(expected), detail)


def _selection(profile, mode):
    need(type(profile) is str and profile == "CM3" and type(mode) is str and mode in MODES,
         "exact CM3 and five ordinary modes required")


def _side(side):
    need(type(side) is str and side in ("Native", "Reference"), "exact producer side required")


def scope_report(profile="CM3", mode="O2"):
    _selection(profile, mode)
    return dict(Status="FAIL", Scope="CM3_FINAL_MECHANISM_COMPOSITION_ONLY", Profile=profile, Mode=mode,
        ClosedBodies=0, Mechanisms=[], RequiredCellsSatisfied=0, FinalReferenceParity=False,
        InstructionEquivalence=False, PolicyEquivalence=False, CompleteObjectProof=False,
        KernelRuntimeProof=False, HandlerRoutingProven=False, ArchiveExtraction=False, LTO=False,
        NativeCommandsExecuted=0, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        ProducerCompilersReexecuted=False, MutantsReexecuted=False)


def expected_mechanisms():
    return [dict(Name="first-start", NativeRoot="fiber_port_start_first_context", ReferenceRoot="prvPortStartFirstTask",
                 DifferenceIds=["FAP-COMMON-START", "FAP-COMMON-PROVENANCE", "FAP-CM3-LOCAL-LITERAL-POOLS"]),
        dict(Name="first-restore", NativeRoot="SVC_Handler", ReferenceRoot="vPortSVCHandler",
             DifferenceIds=["FAP-COMMON-PROVENANCE", "FAP-COMMON-MASK-RESTORE", "FAP-CM3-EXC-RETURN", "FAP-CM3-LOCAL-LITERAL-POOLS"]),
        dict(Name="PendSV", NativeRoot="PendSV_Handler", ReferenceRoot="xPortPendSVHandler",
             DifferenceIds=["FAP-COMMON-SCHEDULER", "FAP-COMMON-PROVENANCE", "FAP-CM3-EXC-RETURN", "FAP-CM3-LOCAL-LITERAL-POOLS"])]


def require_mechanisms(proof):
    need(type(proof) is dict and "Mechanisms" in proof, "mechanism proof object required")
    rows = proof["Mechanisms"]
    need(type(rows) is list and all(type(row) is dict and type(row.get("DifferenceIds")) is list
         and all(type(value) is str for value in row["DifferenceIds"]) for row in rows), "typed mechanism rows required")
    _same(proof["Mechanisms"], expected_mechanisms(), "exact CM3 mechanism/difference assignments required")


def require_ledger(ledger, proof):
    need(type(ledger) is str, "captured textual difference ledger required")
    need(type(proof) is dict and type(proof.get("DifferenceIds")) is list, "difference identity proof required")
    identities = proof["DifferenceIds"]
    expected = list(dict.fromkeys(identity for row in expected_mechanisms() for identity in row["DifferenceIds"]))
    _same(identities, expected, "exact captured rationale identities required")
    rationales = {}
    for identity in identities:
        matches = list(re.finditer(r"^### " + re.escape(identity) + r"[^\S\r\n]*\r?$", ledger, re.MULTILINE))
        need(len(matches) == 1, "one captured rationale heading required: " + identity)
        start = matches[0].end()
        following = re.search(r"^#{1,6}\s+", ledger[start:], re.MULTILINE)
        body = ledger[start:start + following.start()] if following else ledger[start:]
        need(re.search(r"[A-Za-z0-9]", re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL)) is not None,
             "nonempty captured difference rationale required: " + identity)
        rationales[identity] = dict(Text=body.strip(), TextSha256=digest(body.strip().encode("ascii")))
    return rationales


def require_cross_side_inputs(native, reference):
    need(type(native) is dict and type(reference) is dict and
         type(native.get("ImageInputs")) is list and native["ImageInputs"] and
         type(reference.get("ImageInputs")) is list and reference["ImageInputs"], "nonempty cross-side image inputs required")
    native_paths = [regular(_safe(path)) for path in native["ImageInputs"]]
    reference_paths = [regular(_safe(path)) for path in reference["ImageInputs"]]
    need(all(not left.samefile(right) for left in native_paths for right in reference_paths),
         "cross-side physical image/provider aliases are forbidden")


def _fixture(root, side):
    _side(side)
    return Path(root) / "source" / (CLASSIC if side == "Native" else REFERENCE + "reference/")


def source_paths(root, side, profile, api):
    _selection(profile, "O2")
    _side(side)
    root = Path(root)
    if side == "Native":
        names = (*api["native"].COMMON_SOURCES, *api["native"].selection(profile, "O2")[3],
                 "fiber/port/fiber_port_context_cohort_expectation.c", CLASSIC + "application.c", CLASSIC + "startup.S")
        return [str(root / "source" / name) for name in names]
    return [str(root / "freertos" / api["reference"].PORT),
            *(str(_fixture(root, side) / name) for name in ("providers.c", "consumer.c", "startup.S"))]


def require_link_commands(result, artifact, root, side, mode):
    _selection("CM3", mode)
    fixture = _fixture(root, side)
    links, sources = result["Links"], result["Sources"]
    need(type(sources) is list and sources, "nonempty ordered link providers")
    _same([row["Kind"] for row in links], ["ordinary", "emit-relocs"], "two ordered twin links required")
    commands = [row["Argv"] for row in result["Commands"] if "-c" in row["Argv"] and sources[0]["Source"] in row["Argv"]]
    need(len(commands) == 1, "one source-zero compiler binding required")
    compiler = commands[0][0]
    for link in links:
        expected = [compiler, *artifact["compile_flags"], "-" + mode, "-nostdlib",
            "-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack",
            "-T", str(fixture / "link.ld"), *[row["Object"] for row in sources]]
        if link["Kind"] == "emit-relocs":
            expected.append("-Wl,--emit-relocs")
        expected.extend(("-Wl,-Map=" + link["Map"], "-o", link["Path"]))
        actual = [row["Argv"] for row in result["Commands"] if row["Label"] == "link " + link["Kind"]]
        _same(actual, [expected], "exact ordered CM3 twin link command")


def _safe(path):
    path = Path(path)
    forbidden = {"cm33f_secure_transfer_reference", "m55_secure_closed_parity",
                 "test_cm33f_secure_transfer_reference.ps1", "test_m55_secure_closed_parity.ps1"}
    need(not forbidden.intersection(part.lower() for part in path.parts), "protected source/input")
    return path


def _deny_output(output, records):
    denied = set()
    def declaration(value):
        need(type(value) is str and value and "\0" not in value, "output denial requires a declared absolute path")
        selected = _safe(value)
        need(selected.is_absolute(), "output denial requires a declared absolute path")
        return selected.resolve(strict=False)
    for result, inputs in records:
        need(type(result) is dict and type(inputs) is dict and type(inputs.get("Files")) is list
             and type(inputs.get("Generated")) is dict, "output denial declarations required")
        denied.add(declaration(result["SourceInventoryReceipt"]))
        for row in inputs["Files"]:
            need(type(row) is dict, "output denial input declaration required")
            denied.add(declaration(row["Original"]).parent)
            denied.add(declaration(row["Captured"]).parent)
        denied.update(declaration(value).parent for value in inputs["Generated"])
        commands = result.get("Commands", [])
        need(type(commands) is list and all(type(row) is dict for row in commands), "output denial command declarations required")
        for command in commands:
            label = command.get("Label", "")
            if type(label) is str and label.startswith("reference git "):
                argv = command.get("Argv")
                need(type(argv) is list and all(type(arg) is str for arg in argv) and argv.count("-C") == 1,
                     "output denial Git checkout declaration required")
                index = argv.index("-C") + 1
                need(index < len(argv), "output denial Git checkout declaration required")
                denied.add(declaration(argv[index]))
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in denied),
         "output overlaps declared original/config/tool/inventory/reference inputs")
    return output


def output_directory(path, native, reference):
    output = shared.output_directory(path, native, reference)
    records = []
    # Synthetic callers retain a declaration-only deny gate; the CLI authenticates first.
    for root in (Path(native), Path(reference)):
        result = json.loads(regular(_safe(root / "results.json")).read_bytes(), object_pairs_hook=shared.unique_object)
        inputs = json.loads(regular(_safe(root / "inputs.json")).read_bytes(), object_pairs_hook=shared.unique_object)
        records.append((result, inputs))
    return _deny_output(output, records)


def prepare_output(args):
    output = shared.output_directory(args.output_dir, args.native_build, args.reference_build)
    watch = Watch(output)
    groups = []
    for root, receipt_hash, manifest_hash in (
            (args.native_build, args.native_receipt_sha256, args.native_artifacts_sha256),
            (args.reference_build, args.reference_receipt_sha256, args.reference_artifacts_sha256)):
        root = _safe(root).resolve(strict=True)
        result = json.loads(watch.read(root / "results.json", digest_text(receipt_hash)),
                            object_pairs_hook=shared.unique_object)
        manifest = json.loads(watch.read(root / "artifacts.json", digest_text(manifest_hash)),
                              object_pairs_hook=shared.unique_object)
        need(type(result) is dict and type(manifest) is dict
             and type(manifest.get("Artifacts")) is dict and manifest["Artifacts"],
             "authenticated output admission records required")
        artifacts = manifest["Artifacts"]
        need(artifacts.get("results.json") == digest_text(receipt_hash),
             "output admission receipt/manifest binding required")
        groups.append((root, result, digest_text(artifacts["inputs.json"])))
    records = []
    for root, result, inputs_hash in groups:
        inputs = json.loads(watch.read(root / "inputs.json", inputs_hash), object_pairs_hook=shared.unique_object)
        records.append((result, inputs))
    _deny_output(output, records)
    watch.close()
    return output


def _authenticate(watch, root, receipt_hash, manifest_hash):
    root = Path(root).resolve(strict=True)
    result = watch.structured(root / "results.json", digest_text(receipt_hash))
    artifacts = watch.structured(root / "artifacts.json", digest_text(manifest_hash))["Artifacts"]
    inputs = watch.structured(root / "inputs.json")
    for row in inputs["Files"]:
        _safe(row["Original"])
        _safe(row["Captured"])
    for path in inputs["Generated"]:
        _safe(path)
    for name in artifacts:
        _safe(root / name)
    _same(close_build(watch, root), artifacts, "authenticated complete producer seal")
    return dict(Root=root, Result=result, Artifacts=artifacts, Inputs=inputs,
                ReceiptSha256=receipt_hash, ManifestSha256=manifest_hash)


@contextmanager
def load_api(watch, native, reference):
    watch.read(Path(__file__), digest(_SELF_BYTES), capture=True)
    watch.read(_SHARED_PATH, digest(_SHARED_BYTES), capture=True)
    watch.read(_GENERIC_PATH, digest(_GENERIC_BYTES), capture=True)
    need(generic._SHARED_BYTES == _SHARED_BYTES, "executed generic/shared helper identity")
    packages = [{name: value for name, value in group["Artifacts"].items() if name.startswith("python/elftools/")}
                for group in (native, reference)]
    need(packages[0], "nonempty sealed parser package")
    _same(packages[0], packages[1], "identical producer parser artifacts required")
    package = bind_parser(watch, native["Root"])
    buffers = {}
    for group in (native, reference):
        root, inputs = group["Root"], group["Inputs"]
        captures = {row["Captured"]: row for row in inputs["Files"]}
        for name, value in group["Artifacts"].items():
            if name.startswith("source/") and name.endswith(".py"):
                path, original = root / name, REPO / name.removeprefix("source/")
                need(str(path) in captures and Path(captures[str(path)]["Original"]) == original,
                     "captured executed-helper source identity")
                buffers[path] = watch.read(path, value, capture=True)
                buffers[original] = watch.read(original, value, capture=True)
    paths = {REPO / name for name in (*MODULES.values(), *SUPPORT)} | {_SHARED_PATH, _GENERIC_PATH, Path(__file__)}
    paths |= {path for path in HERE.rglob("*") if path.is_file()}
    watch.membership(HERE, {path.relative_to(HERE).as_posix() for path in paths if path.is_relative_to(HERE)})
    for path in sorted(paths):
        data = watch.read(_safe(path), capture=True)
        if path.suffix == ".py":
            buffers[path] = data
    frozen_path = REPO / "tools/fixtures/cm3_final_roots/reference_witness.py"
    loader = _load("cm3_join_frozen_sources", frozen_path, buffers[frozen_path])
    frozen = loader.FrozenSources(buffers)
    raw_read = Path.read_bytes
    def source_read(path):
        selected = Path(path).resolve()
        return buffers[selected] if selected in buffers else raw_read(path)
    api = {}
    with frozen.active(), patch.object(Path, "read_bytes", source_read):
        for name, relative in MODULES.items():
            if name in ("reference_final", "admission"):
                path = REPO / relative
            else:
                group = reference if name in ("reference", "reference_recipe") else native
                path = group["Root"] / "source" / relative
            api[name] = frozen.load("cm3_final_join_" + name, path)
        api["ExecutedSourceBuffers"] = frozen.executed
        yield api
    bind_parser(watch, native["Root"])
    for name, module in tuple(sys.modules.items()):
        if name == "elftools" or name.startswith("elftools."):
            path = regular(module.__file__)
            need(path.is_relative_to(package) and path in watch.hashes, "imported parser escaped authenticated package")
            watch.read(path, watch.hashes[path])


def require_input_coverage(watch, group, side, api):
    _side(side)
    root, result, artifacts, inputs = (group[name] for name in ("Root", "Result", "Artifacts", "Inputs"))
    originals = {row["Original"]: row for row in inputs["Files"]}
    captures = {row["Captured"]: row for row in inputs["Files"]}
    generated = inputs["Generated"]
    need(originals and len(originals) == len(inputs["Files"]) and generated, "complete nonempty input bindings")
    for row in inputs["Files"]:
        need(Path(row["Captured"]).is_relative_to(root), "capture outside producer directory")
    for source in result["Sources"]:
        need(source["Source"] in captures, "consumed source input missing")
        for dependency in source["Dependencies"]:
            path = dependency["Path"]
            expected = generated.get(path) if path in generated else (captures.get(path) or originals.get(path) or {}).get("Sha256")
            _same(expected, dependency["Sha256"], "actual dependency input coverage")
            watch.read(_safe(path), dependency["Sha256"])
    need(result["Interpreter"]["ModulePath"] in originals and
         all(row["Argv"][0] in originals for row in result["Commands"]), "interpreter/tool input coverage")
    inventory = Path(result["SourceInventoryReceipt"])
    need(str(inventory / "artifacts.json") in originals, "inventory manifest input missing")
    manifest = watch.structured(inventory / "artifacts.json", originals[str(inventory / "artifacts.json")]["Sha256"])["Artifacts"]
    need(manifest and all(str(inventory / name) in originals and originals[str(inventory / name)]["Sha256"] == value
                         for name, value in manifest.items()), "entire captured inventory input coverage")
    workers = {}
    for index, command in enumerate(result["Commands"]):
        need(command["Cwd"] == str(root), "actual command working directory")
        _same(watch.structured(root / ("command-%04d.json" % index)), command, "actual command record")
        if command["Label"].startswith("resolve "):
            name = command["Label"][8:]
            need(name not in workers, "duplicate worker resolution")
            data = watch.read(root / ("command-%04d.stdout" % index), artifacts["command-%04d.stdout" % index])
            workers[name] = str(Path(data.decode("utf-8").strip()).resolve(strict=True))
    need(set(workers) == {"cc1", "collect2", "as", "ld", "lto1", "lto-wrapper"} and
         all(path in originals for path in workers.values()), "six resolved worker captures required")
    sources = {row["Source"] for row in result["Sources"]}
    compilers = {row["Argv"][0] for row in result["Commands"] if "-c" in row["Argv"] and sources.intersection(row["Argv"])}
    need(len(compilers) == 1, "one actual compiler required")
    tool_root = Path(next(iter(compilers))).parent.parent
    directories = {Path(path).parent for path in originals if path.endswith(".exe") and Path(path).is_relative_to(tool_root)}
    dlls = {str(path.resolve()) for directory in directories for path in directory.glob("*.dll")}
    need(dlls and dlls <= set(originals), "DLL input coverage")
    for directory in directories:
        watch.membership(directory, {path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()})
    parser_paths = {str(root / name) for name in artifacts if name.startswith("python/elftools/") and name.endswith(".py")}
    need(parser_paths and parser_paths <= set(captures), "entire parser input coverage")
    if side == "Reference" or "ImportedPackageModules" in result:
        modules = result["ImportedPackageModules"]
        need(type(modules) is dict and "elftools" in modules, "producer imported parser closure")
        for name, row in modules.items():
            path = Path(row["Path"])
            need((name == "elftools" or name.startswith("elftools.")) and path.is_relative_to(root / "python/elftools"),
                 "producer imported parser origin")
            _same(artifacts[path.relative_to(root).as_posix()], row["Sha256"], "producer imported parser hash")
    fixture = _fixture(root, side)
    need(str(fixture / "link.ld") in captures, "actual link script input coverage")
    if side == "Reference":
        need(str(fixture / "FreeRTOSConfig.h") in generated and str(fixture / "freeze_base_FreeRTOSConfig.h") in captures,
             "reference generated/base configuration input coverage")
        need(Path(captures[str(fixture / "freeze_base_FreeRTOSConfig.h")]["Original"]) == REPO / api["reference"].BASE_CONFIG,
             "reference base configuration original provider identity")
        for row in result["ReferenceFileBindings"]:
            need(row["Captured"] in captures and captures[row["Captured"]]["Original"] == row["Original"] and row["GitBlob"] in generated,
                 "reference pinned blob/input coverage")
    helpers = (*api["native"].HELPERS, *api["native"].CM3_HELPERS) if side == "Native" else api["reference"].HELPERS
    need(all(str(root / "source" / name) in captures for name in helpers), "selected helper capture coverage")


def _pinned_reference(watch, group, api):
    root, result, files = (group[key] for key in ("Root", "Result", "Artifacts"))
    producer = api["reference"]
    rows = result["ReferenceFileBindings"]
    expected = {name.removeprefix("freertos/") for name in files if name.startswith("freertos/include/") and name.endswith(".h")}
    expected |= {producer.PORT, producer.PORTMACRO}
    need(type(rows) is list and len(rows) == len(expected) and {row["Path"] for row in rows} == expected,
         "exact complete pinned source/header/blob bindings")
    port = next(row for row in rows if row["Path"] == producer.PORT)
    reference = Path(port["Original"]).parents[len(Path(producer.PORT).parts) - 1]
    git_rows = [row for row in result["Commands"] if row["Label"].startswith("reference git ")]
    need(git_rows and len({row["Argv"][0] for row in git_rows}) == 1, "single reference Git identity")
    prefix = [git_rows[0]["Argv"][0], "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(reference)]
    for row in rows:
        captured, blob = root / "freertos" / row["Path"], root / "reference-blobs" / row["Path"]
        _same([row["Original"], row["Captured"], row["GitBlob"]],
              [str(reference / row["Path"]), str(captured), str(blob)], "pinned source/checkout/capture identities")
        original = watch.read(_safe(row["Original"]), row["WorktreeSha256"])
        need(watch.read(captured, row["WorktreeSha256"]) == original, "pinned source capture bytes")
        blob_data = watch.read(blob, row["GitBlobSha256"])
        _same(generic.pinned_comparison(original, blob_data), row["ByteComparison"], "exact LF or whole-file CRLF pin binding")
        commands = [(index, command) for index, command in enumerate(result["Commands"])
                    if command["Label"] == "reference git show" and command["Argv"][-2:] == ["show", PIN + ":" + row["Path"]]]
        need(len(commands) == 1, "one actual pinned blob query required")
        index, command = commands[0]
        _same(command["Argv"], [*prefix, "show", PIN + ":" + row["Path"]], "actual Git blob source binding")
        need(watch.read(root / ("command-%04d.stdout" % index)) == blob_data, "actual pinned Git blob stdout")
    for label, tail in (("reference git rev-parse", ["rev-parse", "HEAD"]),
                        ("reference git status", ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"])):
        commands = [(index, row) for index, row in enumerate(result["Commands"]) if row["Label"] == label]
        need(len(commands) == 2, "opening and closing pinned Git identity required")
        for index, command in commands:
            _same(command["Argv"], [*prefix, *tail], "actual clean/pinned checkout command")
            data = watch.read(root / ("command-%04d.stdout" % index))
            need(data.decode("ascii").strip() == PIN if tail[0] == "rev-parse" else data == b"", "actual pinned/clean checkout result")


def prepare_group(watch, group, side, profile, mode, api):
    _selection(profile, mode)
    root, result = group["Root"], group["Result"]
    inventory = Path(result["SourceInventoryReceipt"]).resolve(strict=True)
    bundle = api["inventory"].Bundle(inventory)
    watch.membership(inventory, set(bundle.files) | {"artifacts.json"})
    watch.read(inventory / "artifacts.json", digest(bundle.manifest_bytes))
    for name, value in bundle.files.items():
        watch.read(relative_file(inventory, name), value)
    manifest = api["inventory"].captured_inventory(bundle)
    artifact = api["reference"].require_artifact(manifest, api["attributes"], profile, mode)
    need(manifest["reference_commit"] == PIN and api["reference"].PIN == PIN, "fixed reference pin")
    _same(result["SourceInventorySha256"], bundle.result["SourceInventorySha256"], "source inventory fingerprint")
    api["admission"].validate_receipt(result, side=side, profile=profile, mode=mode,
        expected_cohort=COHORT, expected_artifact=artifact, expected_sources=source_paths(root, side, profile, api))
    require_codegen_records(result, artifact, mode)
    require_link_commands(result, artifact, root, side, mode)
    require_input_coverage(watch, group, side, api)
    fixture, source_root = _fixture(root, side), root / "source"
    if side == "Native":
        port_directory = api["native"].selection(profile, mode)[1]
        flags = api["native_recipe"].native_flags(artifact, mode, fixture,
            source_root / "fiber/port" / port_directory, source_root, root / "cmsis")
        need(watch.read(fixture / "main.h") == api["native_recipe"].cmsis_main(artifact["target"]).encode("ascii"),
             "exact generated native CMSIS traits")
    else:
        binding = api["reference_recipe"].reference_recipe(artifact, mode, fixture, root / "freertos")
        flags = binding["Flags"]
        config = api["reference"].configuration_text(binding["ConfigText"])
        _same([result["CompileFlags"], result["RecipeDifferences"], result["PortmacroProvider"], result["BaseConfig"], result["ConfigText"]],
              [flags, binding["Differences"], api["reference"].PORTMACRO, api["reference"].BASE_CONFIG, config], "reference exact recipe/config")
        need(watch.read(fixture / "FreeRTOSConfig.h") == config.encode("ascii"), "actual generated reference configuration")
        _pinned_reference(watch, group, api)
    objects, sources = [], []
    for index, row in enumerate(result["Sources"]):
        source, obj = Path(row["Source"]), Path(row["Object"])
        need(obj == root / "objects" / ("%02d-" % index + source.stem + ".o"), "canonical ordered provider object")
        watch.read(source, row["SourceSha256"], capture=True)
        watch.read(obj, row["ObjectSha256"], capture=True)
        if side == "Native":
            expected = api["native"].startup_flags(artifact, mode) if source.suffix == ".S" else [*flags, "-I" + str(source.parent)]
        else:
            expected = [*artifact["compile_flags"], "-" + mode, "-g0"] if source.suffix == ".S" else flags
            api["reference"].require_dependency_roles([Path(dep["Path"]) for dep in row["Dependencies"]], source, fixture, root / "freertos")
        _same(row["CompileFlags"], expected, "complete consumed target/include/define flags")
        api["attributes"].require_attributes(watch.read(obj.with_suffix(".attributes")).decode("ascii"))
        sources.append(source)
        objects.append(obj)
    prelink = objects[3 if side == "Native" else 0]
    roles = dict(Prelink=prelink, Final=root / "emit-relocs.elf", Plain=root / "ordinary.elf",
                 Disassembly=root / "emit-relocs.dis", LinkMap=root / "emit-relocs.map")
    physical_roles(roles, objects)
    for link in result["Links"]:
        kind = link["Kind"]
        _same([link["Path"], link["Map"]], [str(root / (kind + ".elf")), str(root / (kind + ".map"))], "canonical final ELF/map paths")
        watch.read(link["Path"], link["Sha256"], capture=True)
        watch.read(link["Map"], link["MapSha256"], capture=True)
        api["attributes"].require_attributes(watch.read(Path(link["Path"]).with_suffix(".attributes")).decode("ascii"))
    cls = api["native"].Pilot if side == "Native" else api["reference"].Reference
    pilot = cls.__new__(cls)
    pilot.profile, pilot.mode, pilot.root, pilot.fixture_copy = profile, mode, source_root, fixture
    pilot.sources, pilot.objects, pilot.artifact, pilot.admission = sources, objects, artifact, api["attributes"]
    pilot.report, pilot.object_hashes = copy.deepcopy(result), tuple((row["Object"], row["ObjectSha256"]) for row in result["Sources"])
    if side == "Native":
        pilot.final_reader = api["final"]
        pilot.storage = api["native"].selection(profile, mode)[2]
        keys = ("PrelinkNativeRoots", "PrelinkNativeProtocolScope", "PrelinkStartupLiteralGuard", "PrelinkOwners", "PrelinkCalleeProviders", "PrelinkSlotProvider")
    else:
        pilot.structural, pilot.kernel = api["final"], root / "freertos"
        keys = ("PrelinkReferenceRoots", "PrelinkReferenceOwners", "PrelinkReferenceProtocolScope", "ClosedPrelinkBodies", "PrelinkOwnObjectsOnly")
    pilot.prelink()
    for key in keys:
        _same(pilot.report[key], result[key], "own-source prelink replay: " + key)
    if side == "Reference":
        pilot.report["FinalStructuralChecks"] = []
    for link in result["Links"]:
        pilot.audit_final(Path(link["Path"]))
    if side == "Reference":
        _same(pilot.report["FinalStructuralChecks"], result["FinalStructuralChecks"], "reference structural final replay")
    for path in (*roles.values(), prelink.with_suffix(".dis")):
        value = group["Artifacts"][path.relative_to(root).as_posix()]
        watch.read(path, value, capture=True)
    mechanism = api["decoder"].Object(watch.copied(prelink), watch.copied(prelink.with_suffix(".dis")))
    need(not any(name.startswith(".gnu.lto_") for name in mechanism.names), "ordinary owning object required")
    options = dict(provider_objects={str(path): watch.copied(path) for path in objects}, link_map=watch.copied(roles["LinkMap"]))
    arguments = (watch.copied(prelink), watch.copied(roles["Final"]), watch.copied(roles["Disassembly"]))
    image = (api["final"].FinalImage(*arguments, float_abi="soft", **options) if side == "Native" else
             api["reference_final"].ReferenceCM3FinalImage(*arguments, mode=mode, **options))
    names = api["checker"]._NATIVE if side == "Native" else api["checker"]._REFERENCE
    roots = [image.function(name) for name in names]
    twins = api["final"].compare_load_images(watch.copied(roles["Plain"]), watch.copied(roles["Final"]))
    need(twins["Identical"] is True and all(row["Complete"] is True for row in roots), "complete preserved roots/twins")
    group.update(Inventory=inventory, MechanismObject=mechanism, Roots=roots, Twins=twins,
        Prelink=str(prelink), PrelinkSha256=digest(watch.read(prelink)), UniqueImageInputs=len(objects) + 4,
        ImageInputs=list(dict.fromkeys([*roles.values(), *objects])),
        ReplayedOwnerEvidence={key: pilot.report[key] for key in keys})
    return group


def run(args, output, watch):
    _selection(args.profile, args.mode)
    # Authenticate both caller-bound receipts and both full artifact maps before parser import.
    native = _authenticate(watch, args.native_build, args.native_receipt_sha256, args.native_artifacts_sha256)
    reference = _authenticate(watch, args.reference_build, args.reference_receipt_sha256, args.reference_artifacts_sha256)
    for group in (native, reference):
        result = group["Result"]
        need(type(result.get("Profile")) is str and result["Profile"] == "CM3", "exact CM3 producer profile required")
        need(type(result.get("Mode")) is str and result["Mode"] == args.mode, "exact selected producer mode required")
        need(type(result.get("Cohort")) is str and result["Cohort"] == COHORT, "exact CM3 producer cohort required")
    with patch("subprocess.Popen", side_effect=AssertionError("CM3 join cannot execute any child process")):
        with load_api(watch, native, reference) as api:
            native = prepare_group(watch, native, "Native", args.profile, args.mode, api)
            reference = prepare_group(watch, reference, "Reference", args.profile, args.mode, api)
            need(native["Inventory"] == reference["Inventory"] and
                 native["Result"]["SourceInventorySha256"] == reference["Result"]["SourceInventorySha256"], "same captured source inventory required")
            require_cross_side_inputs(native, reference)
            proof = api["checker"].check_pair(native["MechanismObject"], reference["MechanismObject"])
            api["inventory"].require_proof(proof, args.mode)
            require_mechanisms(proof)
            _same(proof["DifferenceIds"], list(dict.fromkeys(identity for row in expected_mechanisms() for identity in row["DifferenceIds"])),
                  "exact ordered six difference identities")
            _same(proof["RootEvidence"], [*native["Result"]["PrelinkNativeRoots"], *reference["Result"]["PrelinkReferenceRoots"]],
                  "six root token records bound to the same actual producer objects")
            ledger_bytes = watch.read(native["Inventory"] / "inputs/FREERTOS_ASM_PARITY.md", capture=True)
            ledger = ledger_bytes.decode("ascii")
            rationales = require_ledger(ledger, proof)
            report = scope_report(args.profile, args.mode)
            report.update(Status="PASS", ClosedBodies=6, Mechanisms=proof["Mechanisms"], ProtocolProof=proof,
                NativeFinalRoots=native["Roots"], ReferenceFinalRoots=reference["Roots"],
                NativeTwins=native["Twins"], ReferenceTwins=reference["Twins"], ReferenceCommit=PIN,
                SourceInventorySha256=native["Result"]["SourceInventorySha256"], LedgerSha256=digest(ledger_bytes),
                DifferenceRationales=rationales,
                HashDomains=dict(PrelinkProtocol="SHA256-JSON-TOKENS", FinalRoot="SHA256-APPLIED-ELF-FUNCTION-BYTES",
                                 Ledger="SHA256-CAPTURED-LEDGER-BYTES"),
                ProducerBindings=[dict(Side=side, Build=str(group["Root"]), ReceiptSha256=group["ReceiptSha256"],
                    ArtifactsSha256=group["ManifestSha256"], Prelink=group["Prelink"], PrelinkSha256=group["PrelinkSha256"],
                    UniqueImageInputs=group["UniqueImageInputs"], OwnerEvidence=group["ReplayedOwnerEvidence"])
                    for side, group in (("Native", native), ("Reference", reference))],
                NativeArtifactsSha256=args.native_artifacts_sha256, ReferenceArtifactsSha256=args.reference_artifacts_sha256,
                FrameContract=dict(NativeCoreSlots=9, NativeExcReturn="PER-CONTEXT-SAVED-LR",
                    ReferenceCoreSlots=8, ReferenceFirstRestoreExcReturn="ORR-LR-13", EquivalenceProven=False),
                ExecutedSourceBuffers=list(api["ExecutedSourceBuffers"]))
    # Closing file/input validation and final sealing must observe real files, outside the source hook.
    for group, side in ((native, "Native"), (reference, "Reference")):
        close_build(watch, group["Root"])
        require_input_coverage(watch, group, side, api)
    return report


def main(argv=None):
    need(not sys.flags.optimize, "unoptimized Python required")
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("native-build", "native-receipt-sha256", "native-artifacts-sha256", "reference-build",
                 "reference-receipt-sha256", "reference-artifacts-sha256", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--mode", choices=MODES, required=True)
    args = parser.parse_args(argv)
    _selection(args.profile, args.mode)
    for value in (args.native_receipt_sha256, args.native_artifacts_sha256, args.reference_receipt_sha256, args.reference_artifacts_sha256):
        digest_text(value)
    output = prepare_output(args)
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
