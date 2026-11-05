"""Fixed native CM3 O2-LTO capture feasibility, not final-root qualification."""
import argparse
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import sys
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
CLASSIC = "tools/fixtures/classic_final_image/"
RECIPE = "tools/fixtures/freeze_cohorts/build_recipe.py"
PROCESS = "tools/fixtures/freeze_cohorts/process_runner.py"
MODEL = "tools/fixtures/cm3_final_image/admission.py"
FROZEN = "tools/fixtures/cm3_final_roots/reference_witness.py"
PARSER_BINDING = "tools/fixtures/classic_final_join/join.py"
CAPTURE_SYMBOLS = ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler", "fiber_panic",
    "fiber_port_context_validate_restore", "fiber_port_context_validate_save_current",
    "fiber_port_scheduler_pick_next_from_pendsv", "fiber_internal_runtime_current_context_slot")
SOURCES = ("context/context_core.c", "context/context_runtime_state.c", "context/context_panic.c",
    "fiber/port/ARM_CM3/fiber_port.c", "fiber/port/ARM_CM3/fiber_port_boot.c",
    "fiber/port/ARM_CM3/fiber_port_exception.c", "fiber/port/fiber_port_context_cohort_expectation.c",
    CLASSIC + "application.c", CLASSIC + "startup.S")
WORKERS = ("cc1", "collect2", "as", "ld", "lto1", "lto-wrapper")
TARGET_FLAGS = ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft"]
LINK_OPTIONS = "-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack"
PROTECTED = {"cm33f_secure_transfer_reference", "m55_secure_closed_parity",
             "test_cm33f_secure_transfer_reference.ps1", "test_m55_secure_closed_parity.ps1"}


def need(condition, message):
    if not condition:
        raise ValueError("cm3-lto-probe: " + message)


def sha(data):
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


def mode_flags(base):
    need(type(base) is list and all(type(value) is str for value in base), "literal compile flags required")
    need([value for value in base if re.match(r"-O", value)] == ["-O2"], "exact O2 baseline required")
    need(not any(value.startswith(("-flto", "-fno-lto", "-ffat-lto", "-fno-fat-lto")) for value in base),
         "baseline must not override LTO")
    return [*base, "-flto", "-fno-fat-lto-objects"]


def link_flags(artifact, objects, script, output, map, emit):
    need(type(artifact) is dict and artifact.get("compile_flags") == TARGET_FLAGS, "exact CM3 target flags required")
    need(type(emit) is bool, "literal emit selector required")
    need(type(objects) in (list, tuple) and objects and len(set(str(path) for path in objects)) == len(objects),
         "ordered unique link providers required")
    flags = [*TARGET_FLAGS, "-O2", "-flto", "-flto-partition=one", "-save-temps=obj", "-v",
             "-nostdlib", "-Wl,-plugin-opt=-save-temps", LINK_OPTIONS, "-T", str(script),
             *(str(path) for path in objects)]
    if emit:
        flags.append("-Wl,--emit-relocs")
    return [*flags, "-Wl,-Map=" + str(map), "-o", str(output)]


def require_saved_machine_name(path, output):
    """output is the final image path, not its containing directory."""
    path, output = Path(path).absolute(), Path(output).absolute()
    need(path.parent == output.parent and path.name == output.name + ".ltrans0.ltrans.o",
         "only exact single-partition saved machine object admitted; WPA IR is not machine authority")
    return path


def scope_report():
    return dict(Status="FAIL", Scope="NATIVE_CM3_O2_LTO_CAPTURE_FEASIBILITY_ONLY", Profile="CM3", Mode="O2-lto",
        Cohort=COHORT, Linkage="direct", LTO=True, TranslationUnits=0, SlimIRObjects=0, FinalExecutableLinks=0,
        SavedMachineObjects=0, FinalRootRelocationProof=False, FinalReferenceParity=False, CompleteObjectProof=False,
        SourceToMachineSemanticProof=False, OrdinaryOwnerContractSatisfied=False, PolicyEquivalence=False,
        ReferenceBuilt=False, ArchiveExtraction=False, CpuExecution=False, BoardExecution=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, GlobalFreezeQualified=False,
        TwinLoadImageCompared=False, TwinLoadImageIdentical=False, TwinAllocatedSectionsIdentical=False,
        TwinLoadImages={}, Commands=[], Sources=[], Links=[])


def checked_path(path, must_exist=True):
    path = Path(os.path.abspath(path))
    need(not PROTECTED.intersection(part.lower() for part in path.parts), "protected input/output")
    for ancestor in (path, *path.parents):
        if ancestor.exists() or ancestor.is_symlink():
            info = ancestor.lstat()
            need(not ancestor.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400,
                 "symlink/reparse path")
    return path.resolve(strict=must_exist)


def regular(path):
    path = checked_path(path)
    need(path.is_file(), "regular file required: " + str(path))
    return path


def files_under(root):
    root = checked_path(root)
    result = {}
    for directory, names, files in os.walk(root):
        for name in names:
            checked_path(Path(directory) / name)
        for name in files:
            path = regular(Path(directory) / name)
            result[path.relative_to(root).as_posix()] = path
    return result


def same(actual, expected, message):
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    need(encode(actual) == encode(expected), message)


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="ascii")


class Closure:
    def __init__(self):
        self.hashes, self.memberships = {}, {}

    def read(self, path, expected=None):
        path = regular(path)
        data = path.read_bytes()
        value = sha(data)
        need(expected is None or value == digest_text(expected), "input hash mismatch: " + str(path))
        need(path not in self.hashes or self.hashes[path] == value, "input changed: " + str(path))
        self.hashes[path] = value
        return data

    def structured(self, path, expected=None):
        return json.loads(self.read(path, expected), object_pairs_hook=unique_object)

    def tree(self, root, artifacts):
        root = checked_path(root)
        actual = files_under(root)
        need(set(actual) == set(artifacts), "complete artifact membership required")
        self.memberships[root] = set(actual)
        for name, path in actual.items():
            self.read(path, artifacts[name])

    def close(self):
        for path, value in tuple(self.hashes.items()):
            self.read(path, value)
        for root, expected in self.memberships.items():
            need(set(files_under(root)) == expected, "input membership changed")


def load_buffer(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


class Seed:
    def __init__(self, args):
        self.closure = Closure()
        self.root = checked_path(args.native_build)
        self.result = self.closure.structured(self.root / "results.json", digest_text(args.native_receipt_sha256))
        manifest = self.closure.structured(self.root / "artifacts.json", digest_text(args.native_artifacts_sha256))
        self.artifacts = manifest["Artifacts"]
        need(type(self.artifacts) is dict and self.artifacts, "nonempty authenticated seed artifacts required")
        same(self.artifacts["results.json"], args.native_receipt_sha256, "seed receipt/manifest binding")
        self.closure.tree(self.root, dict(self.artifacts, **{"artifacts.json": args.native_artifacts_sha256}))
        self.inputs = self.closure.structured(self.root / "inputs.json", self.artifacts["inputs.json"])
        rows, generated = self.inputs["Files"], self.inputs["Generated"]
        need(type(rows) is list and rows and type(generated) is dict and generated, "nonempty seed inputs required")
        self.originals, self.captures = {}, {}
        for row in rows:
            original, captured = regular(row["Original"]), regular(row["Captured"])
            need(original not in self.originals and captured.is_relative_to(self.root), "seed input identity")
            value = digest_text(row["Sha256"])
            same(self.artifacts[captured.relative_to(self.root).as_posix()], value, "capture/manifest binding")
            self.closure.read(original, value)
            self.closure.read(captured, value)
            self.originals[original] = row
            if captured in self.captures:
                same(self.captures[captured]["Sha256"], value, "shared capture bytes")
            self.captures[captured] = row
        for path, value in generated.items():
            selected = regular(path)
            need(selected.is_relative_to(self.root), "generated seed input escaped build")
            same(self.artifacts[selected.relative_to(self.root).as_posix()], value, "generated/manifest binding")
            self.closure.read(selected, value)
        self.inventory = checked_path(self.result["SourceInventoryReceipt"])
        inventory_manifest = self.inventory / "artifacts.json"
        need(inventory_manifest in self.originals, "inventory manifest input coverage")
        inventory_hash = self.originals[inventory_manifest]["Sha256"]
        inventory_files = self.closure.structured(inventory_manifest, inventory_hash)["Artifacts"]
        need(type(inventory_files) is dict and inventory_files, "complete inventory input coverage")
        for name, value in inventory_files.items():
            path = regular(self.inventory / portable_name(name))
            need(path.is_relative_to(self.inventory) and path in self.originals, "inventory input omitted")
            same(self.originals[path]["Sha256"], value, "inventory input hash")
        self.closure.tree(self.inventory, dict(inventory_files, **{"artifacts.json": inventory_hash}))
        self.output = checked_path(args.output_dir, must_exist=False)
        denied = {REPO, self.root, self.inventory}
        denied.update(path.parent for path in self.originals)
        denied.update(path.parent for path in self.captures)
        denied.update(checked_path(path).parent for path in generated)
        need(not self.output.exists() and all(not self.output.is_relative_to(root) and not root.is_relative_to(self.output)
             for root in denied), "fresh output must not overlap any authenticated input root")
        self.buffers = {path: self.closure.read(path, row["Sha256"]) for path, row in self.captures.items()
                        if path.suffix == ".py"}
        frozen_path = regular(REPO / FROZEN)
        frozen_data = self.closure.read(frozen_path)
        frozen_api = load_buffer("cm3_lto_frozen_source_loader", frozen_path, frozen_data)
        self.frozen = frozen_api.FrozenSources(self.buffers)
        self.loader_evidence = dict(Path=str(frozen_path), Sha256=sha(frozen_data))
        source_files = [regular(row["Source"]) for row in self.result["Sources"]]
        need(len(source_files) == 9 and all(not path.samefile(other) for index, path in enumerate(source_files)
             for other in source_files[:index]), "nine physically distinct source providers required")
        self.validate()
        self.closure.read(__file__)
        self.interpreter = self.native.interpreter_path()
        self.closure.read(self.interpreter)
        need(all(not self.output.is_relative_to(root) and not root.is_relative_to(self.output)
                 for root in (self.tool_root, self.interpreter.parent)), "output overlaps compiler/interpreter root")
        self.closure.close()

    def module(self, relative):
        path = self.root / "source" / relative
        need(path in self.captures and regular(self.captures[path]["Original"]) == regular(REPO / relative),
             "executed captured helper original identity")
        original_read = Path.read_bytes
        def buffer_read(selected):
            selected = selected.resolve()
            if selected in self.buffers:
                return self.buffers[selected]
            need(not (selected.suffix == ".py" and (selected.is_relative_to(REPO) or selected.is_relative_to(self.root))),
                 "unknown helper source read")
            return original_read(selected)
        with self.frozen.active(), patch.object(Path, "read_bytes", buffer_read):
            return self.frozen.load("cm3_lto_seed_" + Path(relative).stem, path)

    def validate(self):
        r = self.result
        same([r.get("Verdict"), r.get("Profile"), r.get("Mode"), r.get("Cohort"), r.get("ProofScope")],
             ["NATIVE-FINAL-TWIN-BUILD-PASS", "CM3", "O2", COHORT, "NATIVE_CM3_DIRECT_TWIN_BUILD_ONLY"],
             "exact qualified native CM3 O2 seed required")
        for key in ("LTO", "ReferenceBuilt", "RequiredCellSatisfied", "FinalElfProof", "FinalRootRelocationProof",
                    "CompleteObjectProof", "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified"):
            need(r.get(key) is False, "literal false seed scope: " + key)
        need(type(r.get("RequiredCellsSatisfied")) is int and r["RequiredCellsSatisfied"] == 0,
             "literal zero seed required-cell count")
        same([r["TranslationUnits"], r["FinalExecutableLinks"], r["InputDrift"]], [9, 2, []], "seed closure counters")
        need(r.get("TwinLoadImageIdentical") is True and r.get("TwinAllocatedSectionsIdentical") is True,
             "seed twin comparison required")
        same([row["Stage"] for row in r["ObjectChecks"]],
             ["before-prelink", "after-prelink", "before-link-ordinary", "after-link-ordinary",
              "before-link-emit-relocs", "after-link-emit-relocs", "closing"], "seven seed object checkpoints")
        need(all(row["Status"] == "PASS" and row["Error"] is None for row in r["ObjectChecks"]), "seed object checks")
        self.native, self.recipe, self.model = self.module(CLASSIC + "run.py"), self.module(RECIPE), self.module(MODEL)
        self.process = self.module(PROCESS)
        self.artifact = r["CohortArtifact"]
        self.model.require_cohort(self.artifact, COHORT)
        fixture = self.root / "source" / CLASSIC
        self.script = regular(fixture / "link.ld")
        need(self.script in self.captures, "actual script capture required")
        expected_flags = self.recipe.native_flags(self.artifact, "O2", fixture,
            self.root / "source/fiber/port/ARM_CM3", self.root / "source", self.root / "cmsis")
        same(r["CompileFlags"], expected_flags, "exact seed C recipe")
        need(self.closure.read(fixture / "main.h") == self.recipe.cmsis_main(self.artifact["target"]).encode("ascii"),
             "exact seed CMSIS target header")
        self.sources = r["Sources"]
        same([row["Source"] for row in self.sources], [str(self.root / "source" / name) for name in SOURCES],
             "exact ordered nine native source providers")
        commands = r["Commands"]
        need(type(commands) is list and commands, "nonempty seed commands")
        self.workers = {}
        compiler = set()
        for index, command in enumerate(commands):
            need(command["Status"] == "PASS" and type(command["Exit"]) is int and command["Exit"] == 0
                 and command["TimedOut"] is False and command["Error"] is None and command["Cwd"] == str(self.root),
                 "successful bound seed command")
            same(self.closure.structured(self.root / ("command-%04d.json" % index)), command, "seed command record")
            need(regular(command["Argv"][0]) in self.originals, "seed command tool coverage")
            if command["Label"].startswith("resolve "):
                name = command["Label"][8:]
                need(name not in self.workers, "duplicate worker resolution")
                data = self.closure.read(self.root / ("command-%04d.stdout" % index))
                self.workers[name] = regular(data.decode("utf-8").strip())
            if "-c" in command["Argv"] and any(row["Source"] in command["Argv"] for row in self.sources):
                compiler.add(regular(command["Argv"][0]))
        need(set(self.workers) == set(WORKERS) and all(path in self.originals for path in self.workers.values()),
             "all six captured workers required")
        need(len(compiler) == 1, "one seed source-bound compiler required")
        self.gcc = next(iter(compiler))
        self.tool_root = self.gcc.parent.parent
        plugins = [path for path in self.originals if path.is_relative_to(self.tool_root)
                   and re.fullmatch(r"liblto_plugin(?:-[0-9]+)?\.dll", path.name, re.IGNORECASE)]
        need(len(plugins) == 1, "one unambiguous captured LTO plugin required")
        self.plugin = plugins[0]
        for directory in {path.parent for path in self.originals if path.suffix.lower() == ".exe"
                          and path.is_relative_to(self.tool_root)}:
            dlls = {regular(path) for path in directory.glob("*.dll")}
            need(dlls <= set(self.originals), "complete tool DLL capture required")
        for index, row in enumerate(self.sources):
            source = regular(row["Source"])
            need(source in self.captures and row["CompileDependenciesVerified"] is True, "bound source/actual dependencies")
            flags = self.native.startup_flags(self.artifact, "O2") if index == 8 else [*expected_flags, "-I" + str(source.parent)]
            same(row["CompileFlags"], flags, "exact source-specific compile recipe")
            same(row["ActualCompileDependencies"], row["Dependencies"], "seed actual/discovery dependency equality")
            for dependency in row["Dependencies"]:
                path = regular(dependency["Path"])
                need(path in self.captures or path in self.originals or str(path) in self.inputs["Generated"],
                     "mandatory actual dependency coverage")
                self.closure.read(path, dependency["Sha256"])
            expected = [str(self.gcc), *flags, "-MD", "-MF", row["CompileDependencyFile"],
                        "-MT", "pilot-source-" + str(index), "-c", row["Source"], "-o", row["Object"]]
            same([cmd["Argv"] for cmd in commands if cmd["Label"] == "compile " + source.name],
                 [expected], "full actual source compile command")
            self.closure.read(row["Source"], row["SourceSha256"])
            self.closure.read(row["Object"], row["ObjectSha256"])
        same([row["Kind"] for row in r["Links"]], ["ordinary", "emit-relocs"], "two ordered seed links")
        for link in r["Links"]:
            expected = [str(self.gcc), *TARGET_FLAGS, "-O2", "-nostdlib", LINK_OPTIONS, "-T", str(self.script),
                        *[row["Object"] for row in self.sources]]
            if link["Kind"] == "emit-relocs":
                expected.append("-Wl,--emit-relocs")
            expected.extend(("-Wl,-Map=" + link["Map"], "-o", link["Path"]))
            same([cmd["Argv"] for cmd in commands if cmd["Label"] == "link " + link["Kind"]],
                 [expected], "full exact ordinary seed link recipe")
            self.closure.read(link["Path"], link["Sha256"])
            self.closure.read(link["Map"], link["MapSha256"])
        need(regular(r["Interpreter"]["ModulePath"]) in self.originals, "seed interpreter coverage")
        parser_files = {self.root / name for name in self.artifacts if name.startswith("python/elftools/")}
        need(parser_files and parser_files <= set(self.captures), "complete seed parser capture coverage")


def portable_name(name):
    need(type(name) is str and "\\" not in name, "portable artifact name required")
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.parts and path.as_posix() == name
         and all(part not in (".", "..") for part in path.parts), "safe relative artifact name")
    return Path(name)


def section_records(text):
    rows = []
    pattern = (r"^\s*\[\s*([0-9]+)\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
               r"\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([A-Za-z]*)\s+[0-9]+\s+[0-9]+\s+[0-9]+\s*$")
    lines = text.splitlines()
    if "Section Headers:" in lines:
        need(lines.count("Section Headers:") == 1 and lines.count("Key to Flags:") == 1,
             "one complete readelf section-header block required")
        start, end = lines.index("Section Headers:") + 1, lines.index("Key to Flags:")
        need(start < end, "complete readelf section-header block required")
        lines = lines[start:end]
    else:
        lines = [line for line in lines if line.lstrip().startswith("[")]
    for line in lines:
        if not line.strip() or re.fullmatch(r"\s*\[Nr\]\s+Name\s+Type\s+Addr\s+Off\s+Size\s+ES\s+Flg\s+Lk\s+Inf\s+Al\s*", line):
            continue
        if re.fullmatch(r"\s*\[\s*0\]\s+NULL\s+0+\s+0+\s+0+\s+0+\s+0\s+0\s+0\s*", line):
            rows.append(dict(Index=0, Name="", Type="NULL", Address=0, Offset=0, Size=0, Flags=""))
            continue
        match = re.fullmatch(pattern, line)
        need(match is not None and int(match[1]) > 0 and match[3] != "NULL", "unparsed readelf section-header row")
        rows.append(dict(Index=int(match[1]), Name=match[2], Type=match[3], Address=int(match[4], 16),
                         Offset=int(match[5], 16), Size=int(match[6], 16), Flags=match[8]))
    need(rows, "readelf section records required")
    need(len({row["Index"] for row in rows}) == len(rows), "duplicate readelf section index")
    counts = re.findall(r"^\s*Number of section headers:\s+([0-9]+)\s*$", text, re.MULTILINE)
    if counts:
        need(len(counts) == 1 and [row["Index"] for row in rows] == list(range(int(counts[0]))),
             "complete indexed readelf section inventory required")
    return rows


def require_elf32le(data, kind="REL"):
    need(type(kind) is str and kind in ("REL", "EXEC"), "fixed ELF header kind required")
    need(type(data) is bytes and len(data) >= 52 and data[:7] == b"\x7fELF\x01\x01\x01",
         "actual ELF32 little-endian header required")
    elf_type, machine, version = struct.unpack_from("<HHI", data, 16)
    header_size = struct.unpack_from("<H", data, 40)[0]
    section_offset = struct.unpack_from("<I", data, 32)[0]
    entry_size, count = struct.unpack_from("<HH", data, 46)
    need(elf_type == {"REL": 1, "EXEC": 2}[kind] and machine == 40 and version == 1 and header_size == 52
         and entry_size == 40 and count > 0 and 52 <= section_offset <= len(data) - count * entry_size,
         "bounded ARM ELF32 little-endian section-header authority required")
    return dict(Class="ELF32", Data="little-endian", Type=kind, Machine="ARM", Version=version,
                HeaderSize=header_size, SectionOffset=section_offset, SectionEntrySize=entry_size, SectionCount=count)


def symbol_records(text, sections):
    found = {name: [] for name in CAPTURE_SYMBOLS}
    section_names = {row["Index"]: row["Name"] for row in sections}
    pattern = r"\s*[0-9]+:\s+([0-9a-fA-F]+)\s+([0-9]+|0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*"
    for line in text.splitlines():
        match = re.fullmatch(pattern, line)
        if match and match[7] in found:
            section = int(match[6]) if match[6].isdigit() else match[6]
            found[match[7]].append(dict(Name=match[7], Value=int(match[1], 16),
                Size=int(match[2], 16 if match[2].startswith("0x") else 10), Type=match[3], Binding=match[4],
                Visibility=match[5], Section=section, SectionName=section_names.get(section), SymbolOriginBound=False))
    need(all(len(rows) == 1 for rows in found.values()), "one captured machine symbol fact per fixed declared name required")
    return [found[name][0] for name in CAPTURE_SYMBOLS]


class Probe:
    def __init__(self, seed, args):
        self.seed, self.args, self.output = seed, args, seed.output
        self.report, self.tools, self.tool_hashes = scope_report(), {}, {}
        self.objects, self.object_hashes, self.inputs = [], {}, []
        self.complete = self.twins_verified = False

    def command(self, argv, label, *, cwd=None, timeout=120):
        argv = [str(value) for value in argv]
        index = len(self.report["Commands"])
        cwd = checked_path(cwd or self.output)
        need(cwd.is_relative_to(self.output), "command working directory outside output")
        record = dict(Label=label, Argv=argv, Cwd=str(cwd), Status="ATTEMPT", Exit=None, TimedOut=None, Error=None)
        self.report["Commands"].append(record)
        target = self.output / ("command-%04d.json" % index)
        save(target, record)
        try:
            executable = regular(argv[0])
            need(executable in self.tool_hashes, "command executable not captured")
            self.verify_tools()
            result = self.seed.process.run(argv, cwd=str(cwd), env=self.environment, timeout=timeout)
            record.update(Exit=result.returncode, TimedOut=result.timed_out, Seconds=result.elapsed)
            target.with_suffix(".stdout").write_bytes(result.stdout)
            target.with_suffix(".stderr").write_bytes(result.stderr)
            need(type(result.returncode) is int and result.returncode == 0 and result.timed_out is False,
                 "command failed/timeout: " + label)
            record["Status"] = "PASS"
            return result
        except BaseException as error:
            record.update(Status="FAIL", Error=type(error).__name__ + ": " + str(error))
            raise
        finally:
            try:
                self.verify_tools()
            except BaseException as error:
                record.update(Status="FAIL", Error=type(error).__name__ + ": " + str(error))
                raise
            finally:
                save(target, record)
                save(self.output / "commands.json", self.report["Commands"])

    def verify_tools(self):
        if self.tool_hashes:
            need(set(files_under(self.tool_root).values()) == set(self.tool_hashes), "captured toolchain membership drift")
        for path, value in self.tool_hashes.items():
            need(sha(regular(path).read_bytes()) == value, "captured tool drift: " + str(path))

    def prepare(self):
        self.environment = self.seed.native.process_environment(dict(os.environ))
        for path, value in tuple(self.seed.closure.hashes.items()):
            data = self.seed.closure.read(path, value)
            target = self.output / "input-bytes" / (value + "-" + path.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                target.write_bytes(data)
            self.inputs.append(dict(Original=str(path), Captured=str(target), Sha256=value))
        self.tool_root = self.output / "toolchain"
        for original, row in self.seed.originals.items():
            if original.is_relative_to(self.seed.tool_root):
                target = self.tool_root / original.relative_to(self.seed.tool_root)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(self.seed.closure.read(row["Captured"], row["Sha256"]))
                self.tool_hashes[target] = row["Sha256"]
        self.tools["gcc"] = self.tool_root / self.seed.gcc.relative_to(self.seed.tool_root)
        for name in ("objdump", "readelf", "nm"):
            original = self.seed.gcc.with_name("arm-none-eabi-" + name + ".exe")
            need(original in self.seed.originals, "captured inspector missing")
            self.tools[name] = self.tool_root / original.relative_to(self.seed.tool_root)
        self.workers = {name: self.tool_root / path.relative_to(self.seed.tool_root)
                        for name, path in self.seed.workers.items()}
        self.plugin = self.tool_root / self.seed.plugin.relative_to(self.seed.tool_root)
        temporary = self.output / "tmp"
        temporary.mkdir()
        self.environment.update(TEMP=str(temporary), TMP=str(temporary))
        search = [str(self.tools["gcc"].parent), *(str(path.parent) for path in self.workers.values())]
        system_root = next((value for key, value in self.environment.items() if key.upper() == "SYSTEMROOT"), None)
        if system_root:
            search.append(str(Path(system_root) / "System32"))
        self.environment["PATH"] = os.pathsep.join(dict.fromkeys(search))
        save(self.output / "environment.json", self.environment)
        self.report.update(SeedBuild=str(self.seed.root), SeedReceiptSha256=self.args.native_receipt_sha256,
            SeedArtifactsSha256=self.args.native_artifacts_sha256, SeedCohortArtifact=self.seed.artifact,
            SourceInventoryReceipt=str(self.seed.inventory), CapturedCompiler=str(self.tools["gcc"]),
            ExecutedSourceBuffers=[self.seed.loader_evidence, *self.seed.frozen.executed],
            OrdinaryOwnerContractChecked=False, TwinLoadImageCompared=False,
            Interpreter=dict(ReportedExecutable=sys.executable, ModulePath=str(self.seed.interpreter)),
            SourceToMachineOwnership="LTO-MERGED; NO PER-TU MACHINE-OWNERSHIP CLAIM")
        for name, expected in self.workers.items():
            result = self.command([self.tools["gcc"], "-print-prog-name=" + name], "resolve " + name)
            need(regular(result.stdout.decode("utf-8").strip()) == regular(expected), "captured worker resolution: " + name)
        result = self.command([self.tools["gcc"], "-print-file-name=" + self.plugin.name], "resolve LTO plugin")
        need(regular(result.stdout.decode("utf-8").strip()) == regular(self.plugin), "captured plugin resolution")
        self.report["ResolvedWorkers"] = {name: dict(Path=str(path), Sha256=self.tool_hashes[path])
                                          for name, path in self.workers.items()}
        self.report["LTOPlugin"] = dict(Path=str(self.plugin), Sha256=self.tool_hashes[self.plugin])

    def inspect(self, path):
        text = None
        for tool, flags, suffix in (("readelf", ["-hSWsrA", "-lW"], ".readelf"),
                                    ("objdump", ["-drwC", "-Mreg-names-std"], ".dis"),
                                    ("nm", ["--plugin", str(self.plugin), "-P", "-S", "--defined-only"], ".nm")):
            result = self.command([self.tools[tool], *flags, path], "inspect " + path.name + suffix)
            Path(str(path) + suffix).write_bytes(result.stdout)
            if tool == "readelf":
                text = result.stdout.decode("utf-8")
        return text

    def verify_objects(self, stage):
        need(len(self.object_hashes) == len(self.objects) == 9, "nine frozen actual inputs required")
        for path in self.objects:
            need(sha(regular(path).read_bytes()) == self.object_hashes[path], "slim/startup input drift: " + stage)
        self.report.setdefault("ObjectChecks", []).append(dict(Stage=stage, Status="PASS"))

    def compile(self):
        directory = self.output / "objects"
        directory.mkdir()
        for index, row in enumerate(self.seed.sources):
            source = regular(row["Source"])
            self.seed.closure.read(source, row["SourceSha256"])
            flags = row["CompileFlags"] if index == 8 else mode_flags(row["CompileFlags"])
            obj = directory / ("%02d-" % index + source.stem + ".o")
            dependency_file = obj.with_suffix(".d")
            result = dict(Source=str(source), SourceSha256=row["SourceSha256"], CompileFlags=flags,
                          Object=str(obj), DependencyFile=str(dependency_file), SlimIR=index != 8)
            self.report["Sources"].append(result)
            self.command([self.tools["gcc"], *flags, "-MD", "-MF", dependency_file, "-MT", "pilot-source-" + str(index),
                          "-c", source, "-o", obj], "compile " + source.name)
            header = require_elf32le(regular(obj).read_bytes())
            self.seed.closure.read(source, row["SourceSha256"])
            expected = {regular(dependency["Path"]) for dependency in row["Dependencies"]}
            expected = {self.tool_root / path.relative_to(self.seed.tool_root)
                        if path.is_relative_to(self.seed.tool_root) else path for path in expected}
            actual = set(self.seed.native.read_dependencies(dependency_file))
            need(actual == expected, "actual compile dependency set changed from seed")
            result["ActualCompileDependencies"] = [dict(Path=str(path), Sha256=sha(path.read_bytes())) for path in sorted(actual)]
            for path in actual:
                if path.is_relative_to(self.tool_root):
                    need(sha(path.read_bytes()) == self.tool_hashes[path], "relocated system header drift")
                else:
                    self.seed.closure.read(path, self.seed.closure.hashes[path])
            text = self.inspect(obj)
            need(re.search(r"^\s*Type:\s+REL\b", text, re.MULTILINE) and
                 re.search(r"^\s*Machine:\s+ARM\s*$", text, re.MULTILINE), "actual ARM ET_REL input required")
            sections = section_records(text)
            same([section["Index"] for section in sections], list(range(header["SectionCount"])),
                 "readelf sections must consume actual ELF header inventory")
            if index != 8:
                need(any(section["Name"].startswith(".gnu.lto_") for section in sections) and
                     not any("X" in section["Flags"] and section["Size"] for section in sections),
                     "genuine slim GIMPLE input required; no fat machine fallback")
                self.report["SlimIRObjects"] += 1
            else:
                need(not any(section["Name"].startswith(".gnu.lto_") for section in sections), "startup must remain non-LTO")
            result.update(ObjectSha256=sha(obj.read_bytes()), ELFHeader=header, Sections=sections, CompileDependenciesVerified=True)
            self.objects.append(obj)
            self.object_hashes[obj] = result["ObjectSha256"]
            self.report["TranslationUnits"] += 1
        self.verify_objects("after-compile")

    def trace_identities(self, data):
        observed = set()
        for token in re.findall(r'"[^"\r\n]+"|[^\s"]+', data.decode("utf-8")):
            token = token.strip("\"'")
            for prefix in ("COLLECT_GCC=", "COLLECT_LTO_WRAPPER=", "-plugin-opt="):
                if token.startswith(prefix):
                    token = token[len(prefix):]
            if Path(token).is_absolute() and token.lower().endswith((".exe", ".dll")):
                path = checked_path(token)
                need(path in self.tool_hashes, "verbose link named an uncaptured tool/plugin")
                observed.add(path)
        required = {self.tools["gcc"], self.plugin, *(self.workers[name] for name in ("collect2", "lto-wrapper", "lto1", "as"))}
        need(required <= observed, "actual verbose LTO/assembler/plugin execution identities required")
        return [dict(Path=str(path), Sha256=self.tool_hashes[path]) for path in sorted(observed)]

    def compare_twins(self):
        need(not any(name == "elftools" or name.startswith("elftools.") for name in sys.modules),
             "ambient parser modules rejected")
        binding_path = regular(REPO / PARSER_BINDING)
        binding_bytes = self.seed.closure.read(binding_path)
        captured = self.output / "input-bytes" / (sha(binding_bytes) + "-" + binding_path.name)
        captured.write_bytes(binding_bytes)
        self.inputs.append(dict(Original=str(binding_path), Captured=str(captured), Sha256=sha(binding_bytes)))
        buffers = dict(self.seed.buffers)
        buffers[binding_path] = binding_bytes
        graph = type(self.seed.frozen)(buffers)
        package = self.seed.root / "python/elftools"
        modules = {}
        for path in buffers:
            if path.is_relative_to(package):
                parts = list(path.relative_to(package.parent).with_suffix("").parts)
                is_package = parts[-1] == "__init__"
                if is_package:
                    parts.pop()
                name = ".".join(parts)
                need(name not in modules, "ambiguous captured parser module")
                modules[name] = (path, is_package)
        need("elftools" in modules, "authenticated captured parser package required")
        class CapturedParser(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname != "elftools" and not fullname.startswith("elftools."):
                    return None
                need(fullname in modules and target is None, "parser import escaped captured buffers")
                source, is_package = modules[fullname]
                spec = graph.spec(fullname, source)
                if is_package:
                    spec.submodule_search_locations = [str(source.parent)]
                return spec
        original_read = Path.read_bytes
        def buffer_read(path):
            selected = path.resolve()
            if selected in buffers:
                return buffers[selected]
            need(not (selected.suffix == ".py" and (selected.is_relative_to(REPO) or selected.is_relative_to(self.seed.root))),
                 "unknown local source read during twin comparison")
            return original_read(path)
        old_path, old_meta = list(sys.path), list(sys.meta_path)
        try:
            with graph.active(), patch.object(Path, "read_bytes", buffer_read):
                binding = graph.load("cm3_lto_parser_binding", binding_path)
                self.parser_watch = binding.Watch(self.output / "parser-binding")
                binding.bind_parser(self.parser_watch, self.seed.root)
                sys.meta_path.insert(0, CapturedParser())
                reader_path = self.seed.root / "source" / CLASSIC / "elf.py"
                need(regular(self.seed.captures[reader_path]["Original"]) == regular(REPO / CLASSIC / "elf.py"),
                     "captured twin reader original identity")
                reader = graph.load("cm3_lto_unchanged_twin_reader", reader_path)
                evidence = reader.compare_load_images(self.report["Links"][0]["Path"], self.report["Links"][1]["Path"])
            # Closing checks deliberately use physical files, not the source-buffer hook.
            binding.bind_parser(self.parser_watch, self.seed.root)
            self.parser_watch.close()
            imported = {}
            for name, module in tuple(sys.modules.items()):
                if name == "elftools" or name.startswith("elftools."):
                    path = regular(module.__file__)
                    need(name in modules and path == modules[name][0] and path in buffers, "imported parser origin mismatch")
                    value = sha(buffers[path])
                    self.seed.closure.read(path, value)
                    imported[name] = dict(Path=str(path), Sha256=value)
            need(imported and sys.modules["elftools"].__version__ == "0.33" and evidence.get("Identical") is True,
                 "captured pyelftools 0.33 and identical structural twins required")
            save(self.output / "load-image.json", evidence)
            self.report.update(TwinLoadImageCompared=True, TwinLoadImageIdentical=True,
                TwinAllocatedSectionsIdentical=True, TwinLoadImages=evidence,
                TwinLoadImagesPath=str(self.output / "load-image.json"),
                TwinLoadImagesSha256=sha((self.output / "load-image.json").read_bytes()),
                ImportedPackageModules=imported,
                ExecutedSourceBuffers=[self.seed.loader_evidence, *self.seed.frozen.executed, *graph.executed])
            self.twins_verified = True
        finally:
            sys.path[:], sys.meta_path[:] = old_path, old_meta

    def build(self):
        self.prepare()
        self.compile()
        for kind, emit in (("ordinary", False), ("emit-relocs", True)):
            directory = self.output / kind
            directory.mkdir()
            image, link_map = directory / "image.elf", directory / "image.map"
            self.seed.closure.close()
            self.verify_objects("before-link-" + kind)
            try:
                command = self.command([self.tools["gcc"], *link_flags(self.seed.artifact, self.objects, self.seed.script,
                                        image, link_map, emit)], "link " + kind, cwd=directory)
            finally:
                self.verify_objects("after-link-" + kind)
            machine = require_saved_machine_name(directory / "image.elf.ltrans0.ltrans.o", image)
            need(machine.is_file(), "plugin did not preserve actual machine ET_REL; WPA substitution forbidden")
            machine_bytes = regular(machine).read_bytes()
            header = require_elf32le(machine_bytes)
            text = self.inspect(machine)
            need(re.search(r"^\s*Type:\s+REL\b", text, re.MULTILINE) and
                 re.search(r"^\s*Machine:\s+ARM\s*$", text, re.MULTILINE), "saved machine must be actual ARM ET_REL")
            sections = section_records(text)
            same([row["Index"] for row in sections], list(range(header["SectionCount"])),
                 "saved machine section records must consume actual ELF inventory")
            need(not any(row["Name"].startswith(".gnu.lto_") for row in sections)
                 and any("X" in row["Flags"] and row["Size"] for row in sections),
                 "saved machine contains GIMPLE or lacks executable machine bytes")
            symbols = [dict(row, Artifact=str(machine), ArtifactSha256=sha(machine_bytes))
                       for row in symbol_records(text, sections)]
            self.inspect(image)
            final_header = require_elf32le(regular(image).read_bytes(), "EXEC")
            need(regular(link_map).stat().st_size > 0, "actual retained link map required")
            for suffix in (".res", ".ltrans.out", ".ltrans0.o", ".ltrans0.ltrans.s"):
                need(regular(Path(str(image) + suffix)).stat().st_size > 0, "actual LTO transport record missing: " + suffix)
            observed = self.trace_identities(command.stderr)
            captured = {name: sha(path.read_bytes()) for name, path in files_under(directory).items()}
            self.seed.closure.tree(directory, captured)
            self.report["Links"].append(dict(Kind=kind, Path=str(image), Sha256=sha(image.read_bytes()),
                Map=str(link_map), MapSha256=sha(link_map.read_bytes()), Machine=str(machine), MachineSha256=sha(machine.read_bytes()),
                MachineHeader=header, FinalHeader=final_header, MachineSections=sections, MachineSymbols=symbols,
                VerboseObservedTools=observed, EntireDirectoryArtifacts=captured,
                MachineOwner="ACTUAL-LTRANS-OBJECT; NOT ORIGINAL PORT-TU", OrdinarySymbolPredicatesApplied=False))
            self.report["FinalExecutableLinks"] += 1
            self.report["SavedMachineObjects"] += 1
        self.verify_objects("closing")
        self.compare_twins()
        self.complete = True

    def close_inputs(self):
        self.seed.closure.close()
        if self.twins_verified:
            path = self.output / "load-image.json"
            need(self.report.get("TwinLoadImagesPath") == str(path), "fixed saved twin-evidence path required")
            data = self.seed.closure.read(path, digest_text(self.report["TwinLoadImagesSha256"]))
            same(json.loads(data, object_pairs_hook=unique_object), self.report["TwinLoadImages"],
                 "saved twin comparison differs from receipt")
        if hasattr(self, "parser_watch"):
            self.parser_watch.close()
        self.verify_tools()
        for row in self.inputs:
            need(sha(regular(row["Captured"]).read_bytes()) == row["Sha256"], "retained input capture drift")
        if self.object_hashes:
            need(len(self.objects) == len(self.object_hashes), "actual object membership changed")
            for path, expected in self.object_hashes.items():
                need(path in self.objects and sha(regular(path).read_bytes()) == expected, "closing actual object drift")

    def write_seal(self):
        self.report["OutputSealVerified"] = True
        save(self.output / "results.json", self.report)
        expected = {name: sha(path.read_bytes()) for name, path in files_under(self.output).items() if name != "artifacts.json"}
        manifest = dict(Artifacts=expected)
        save(self.output / "artifacts.json", manifest)
        manifest_bytes = (self.output / "artifacts.json").read_bytes()
        same(json.loads(manifest_bytes, object_pairs_hook=unique_object), manifest,
             "written artifact manifest differs")
        self.manifest_hash = sha(manifest_bytes)
        actual = {name: sha(path.read_bytes()) for name, path in files_under(self.output).items() if name != "artifacts.json"}
        same(actual, expected, "post-manifest exact artifact membership/hash closure")
        need(sha((self.output / "results.json").read_bytes()) == expected["results.json"], "written receipt hash changed")
        return expected

    def finish(self, error=None):
        self.report.update(Error=None if error is None else type(error).__name__ + ": " + str(error),
                           InputClosureVerified=False, OutputSealVerified=False)
        try:
            self.close_inputs()
            self.report["InputClosureVerified"] = True
            need(error is None and self.complete and len(self.report["Sources"]) == 9
                 and len(self.report["Links"]) == 2 and self.report["SlimIRObjects"] == 8
                 and self.report["SavedMachineObjects"] == 2 and self.report["FinalExecutableLinks"] == 2
                 and self.twins_verified and self.report.get("TwinLoadImageCompared") is True
                 and self.report.get("TwinLoadImages", {}).get("Identical") is True
                 and all(row["Status"] == "PASS" for row in self.report["Commands"]), "complete capture build required")
            self.report["Status"] = "PASS"
        except BaseException as failure:
            self.report["Status"] = "FAIL"
            if self.report["Error"] is None:
                self.report["Error"] = type(failure).__name__ + ": " + str(failure)
        self.report["ClosingFilesVerified"] = len(self.seed.closure.hashes)
        try:
            save(self.output / "inputs.json", dict(Files=self.inputs,
                 Watched=[dict(Path=str(path), Sha256=value) for path, value in sorted(self.seed.closure.hashes.items())]))
            expected = self.write_seal()
            self.close_inputs()
            actual = {name: sha(path.read_bytes()) for name, path in files_under(self.output).items() if name != "artifacts.json"}
            same(actual, expected, "late artifact membership/hash drift")
            need(sha((self.output / "artifacts.json").read_bytes()) == self.manifest_hash, "late artifact manifest drift")
            return self.report["Status"] == "PASS"
        except BaseException as failure:
            self.report.update(Status="FAIL", InputClosureVerified=False, OutputSealVerified=False,
                               Error=(self.report.get("Error") or "") + "; sealing: " + type(failure).__name__ + ": " + str(failure))
            try:
                self.write_seal()
            except BaseException as final_error:
                self.report.update(OutputSealVerified=False, SealError=type(final_error).__name__ + ": " + str(final_error))
                try:
                    save(self.output / "results.json", self.report)
                    save(self.output / "artifacts.json", dict(Artifacts={name: sha(path.read_bytes())
                        for name, path in files_under(self.output).items() if name != "artifacts.json"}))
                except BaseException:
                    pass
            return False


def main(argv=None):
    need(not sys.flags.optimize, "unoptimized Python required")
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("native-build", "native-receipt-sha256", "native-artifacts-sha256", "output-dir"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    seed = Seed(args)
    seed.output.mkdir(parents=True)
    probe, error = Probe(seed, args), None
    try:
        probe.build()
    except BaseException as failure:
        error = failure
    passed = probe.finish(error)
    print(probe.report["Status"], probe.report.get("Error") or "", str(seed.output))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
