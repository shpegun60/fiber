"""Pinned CM3 owning-object protocols and direct reference twins, never execution."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SELF_BYTES = Path(__file__).read_bytes()
CLASSIC = HERE.with_name("classic_final_image")
COMMON_BYTES = (CLASSIC / "reference_run.py").read_bytes()
SPEC = importlib.util.spec_from_file_location("cm3_reference_common_envelope", CLASSIC / "reference_run.py")
common = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = common
exec(compile(COMMON_BYTES, str(CLASSIC / "reference_run.py"), "exec"), common.__dict__)
native = common.native
need, sha, save, regular, load = native.need, native.sha, native.save, native.regular, native.load
PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
MODES = ("O0", "Og", "O2", "Os", "O3")
PORT_DIRECTORY = "portable/GCC/ARM_CM3"
PORT, PORTMACRO = (PORT_DIRECTORY + "/" + name for name in ("port.c", "portmacro.h"))
BASE_CONFIG = "tools/fixtures/freertos_asm_parity/FreeRTOSConfig.h"
ROOTS = ("prvPortStartFirstTask", "vPortSVCHandler", "xPortPendSVHandler")
FIXTURE_FILES = ("reference.h", "providers.c", "consumer.c", "startup.S", "link.ld")
MODEL = "tools/fixtures/cm3_final_image/admission.py"
INVENTORY = "tools/freeze_cm3_mechanisms.py"
RECIPE = "tools/fixtures/freeze_cohorts/reference_recipe.py"
PROCESS = "tools/fixtures/freeze_cohorts/process_runner.py"
DECODER = "tools/fixtures/cm55_tfm_parity/elf.py"
CHECKER = "tools/fixtures/cm3_freeze_parity/check.py"
STRUCTURAL = "tools/fixtures/classic_final_image/elf.py"
HELPERS = (MODEL, INVENTORY, "tools/freeze_cohorts.py", RECIPE, PROCESS, DECODER, CHECKER, STRUCTURAL)
CHECKPOINTS = common.CHECKPOINTS
PASS = "REFERENCE-CM3-FINAL-TWIN-BUILD-PASS"


def selection(profile, mode):
    need(type(profile) is str and profile == "CM3" and type(mode) is str and mode in MODES,
         "CM3 reference selection requires CM3 and five ordinary modes")
    return COHORT


def scope_report(profile="CM3", mode="O2"):
    return dict(Verdict="FAIL", Error=None, RecipeVersion=1, Profile=profile, Mode=mode,
        Cohort=selection(profile, mode), SourceGroup="CM3", ReferenceCommit=PIN, Linkage="direct", LTO=False,
        ProofScope="PINNED_REFERENCE_CM3_THREE_OWNING_PRELINK_ROOTS_AND_DIRECT_TWINS_ONLY",
        ReferenceBuilt=False, NativeBuilt=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
        FinalElfProof=False, FinalRootRelocationProof=False, FinalReferenceParity=False,
        CompleteObjectProof=False, PolicyEquivalence=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, SchedulerSemanticsProven=False, CSourceSemanticProof=False,
        ReferenceKernelAvailable=False, HandlerRoutingProven=False, UnreachabilityProven=False,
        FPPolicy="NOT-APPLICABLE-NO-FPU", SchedulerThreshold=16, DeclaredVTOR=True,
        FixtureHandlerInstallationCheck=1, InputDrift=[], Sources=[], Commands=[])


def require_artifact(manifest, model, profile="CM3", mode="O2"):
    selection(profile, mode)
    need(model.COHORT == COHORT and native.PROFILES["CM3"][0] == COHORT, "CM3 fixed helper/cohort binding")
    return native.require_manifest_selection(manifest, profile, mode, model)


def configuration_text(recipe_text):
    expected = ("#ifndef FIBER_FREEZE_REFERENCE_CONFIG_H\n#define FIBER_FREEZE_REFERENCE_CONFIG_H\n"
        '#include "freeze_base_FreeRTOSConfig.h"\n'
        "#undef configMAX_SYSCALL_INTERRUPT_PRIORITY\n#define configMAX_SYSCALL_INTERRUPT_PRIORITY 16U\n"
        "#undef configMAX_API_CALL_INTERRUPT_PRIORITY\n#define configMAX_API_CALL_INTERRUPT_PRIORITY 16U\n#endif\n")
    need(recipe_text == expected, "CM3 exact threshold16 reference config")
    return recipe_text.removesuffix("#endif\n") + (
        "#undef configCHECK_HANDLER_INSTALLATION\n#define configCHECK_HANDLER_INSTALLATION 1\n"
        "#undef configPRIO_BITS\n#define configPRIO_BITS 4\n"
        "#define __NVIC_PRIO_BITS 4\n#endif\n")


def require_header_facts(data):
    need(type(data) is bytes and len(data) == 40 and
         struct.unpack("<10I", data) == (1, 4, 4, 4, 8, 0, 0, 16, 16, 4), "CM3 reference header facts")


def require_dependency_roles(paths, source, fixture, kernel):
    paths = set(paths)
    need(source in paths, "CM3 source missing from dependencies")
    if source.suffix == ".c":
        expected = {kernel / PORTMACRO, fixture / "FreeRTOSConfig.h", fixture / "freeze_base_FreeRTOSConfig.h"}
        selected = {path for path in paths if path.name in ("portmacro.h", "portasm.h", "FreeRTOSConfig.h", "freeze_base_FreeRTOSConfig.h")}
        need(selected == expected, "CM3 exact config/portmacro providers; no portasm")


def match_reference_protocols(image, checker, mode):
    selection("CM3", mode)
    need(tuple(checker._REFERENCE) == ROOTS, "CM3 exact reference protocol roots")
    evidence = [checker._match(image, "Reference", name, checker._REFERENCE[name]) for name in ROOTS]
    need(len(evidence) == 3 and all(type(row["TailNops"]) is int and row["TailNops"] == int(mode == "O0") for row in evidence),
         "CM3 complete protocols/exact mode tail layout")
    return evidence


def file_membership(directory):
    return sorted(path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file())


def local_start(image):
    matches = [symbol for symbol in image.symbols if symbol["name"] == ROOTS[0] and symbol["section"] != "SHN_UNDEF"]
    need(len(matches) == 1, "CM3 unique local first-start definition")
    symbol = matches[0]
    need(symbol["kind"] == "STT_FUNC" and symbol["binding"] == "STB_LOCAL" and type(symbol["section"]) is int
         and 0 < symbol["section"] < len(image.sections) and symbol["size"] > 0 and symbol["value"] & 1,
         "CM3 local first-start binding/type/Thumb")
    header = image.sections[symbol["section"]].header
    begin = symbol["value"] & ~1
    need(header.sh_type == "SHT_PROGBITS" and header.sh_flags & 7 == 6 and header.sh_addr <= begin
         and begin + symbol["size"] <= header.sh_addr + header.sh_size, "CM3 local first-start extent")
    image.read(begin, symbol["size"])
    need(image.mapping(symbol["section"], begin)[0] == "t" and any(load["Flags"] & 1 and load["Vaddr"] <= begin
         and begin + symbol["size"] <= load["Vaddr"] + load["FileSize"] for load in image.loads), "CM3 local first-start executable mapping")
    return symbol


class Reference(native.Pilot):
    git_bytes = common.Reference.git_bytes
    reference_identity = common.Reference.reference_identity
    dependencies = common.Reference.dependencies
    freeze_objects = common.Reference.freeze_objects

    def __init__(self, args):
        selection(args.profile, args.mode)
        reference = Path(args.freertos).resolve(strict=True)
        output = Path(os.path.abspath(args.output_dir)).resolve(strict=False)
        need(reference.is_dir() and not output.is_relative_to(reference) and not reference.is_relative_to(output), "CM3 reference/output overlap")
        super().__init__(args)
        self.reference, self.report = reference, scope_report(self.profile, self.mode)
        self.fixture = HERE / "reference"
        self.fixture_copy = self.root / "tools/fixtures/cm3_final_image/reference"
        self.kernel = self.output / "freertos"
        self.reference_bindings, self.full_memberships = {}, []
        self._reference_opened = self._reference_closed = False

    def capture_reference(self, relative):
        need(relative in (PORT, PORTMACRO) or re.fullmatch(r"include/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+[.]h", relative), "CM3 pinned input scope")
        source = regular(self.reference / relative)
        data = source.read_bytes()
        blob = self.git_bytes("show", PIN + ":" + relative)
        comparison = self.inventory_gate.inventory.reference_bytes_match(data, blob)
        captured = self.capture(source, self.kernel / relative, expected=sha(data))
        blob_path = self.generated_file(self.output / "reference-blobs" / relative, blob)
        self.reference_bindings[relative] = dict(Path=relative, Original=str(source), Captured=str(captured),
            WorktreeSha256=sha(data), GitBlobSha256=sha(blob), GitBlob=str(blob_path), ByteComparison=comparison)

    def prepare(self):
        need(common.PIN == PIN and common.SELF_BYTES == COMMON_BYTES, "CM3 loaded common envelope identity")
        self.capture(CLASSIC / "run.py", self.root / "tools/fixtures/classic_final_image/run.py", expected=sha(common.NATIVE_BYTES))
        self.capture(CLASSIC / "reference_run.py", self.root / "tools/fixtures/classic_final_image/reference_run.py", expected=sha(COMMON_BYTES))
        self.capture(Path(__file__), self.root / "tools/fixtures/cm3_final_image/reference_run.py", expected=sha(SELF_BYTES))
        for name in ("test_reference_run.py", "REFERENCE_CONTRACT.md"):
            self.capture(HERE / name, self.root / "tools/fixtures/cm3_final_image" / name)
        for relative in HELPERS:
            self.capture(self.repo / relative, self.root / relative)
        need(file_membership(self.fixture) == sorted(FIXTURE_FILES), "CM3 exact five fixture providers")
        self.full_memberships.append((self.fixture, file_membership(self.fixture)))
        for name in FIXTURE_FILES:
            self.capture(self.fixture / name, self.fixture_copy / name)
        self.process = load("cm3_reference_managed_process", self.root / PROCESS)
        self.recipe = load("cm3_reference_recipe", self.root / RECIPE)
        self.admission = load("cm3_reference_fixed_admission", self.root / MODEL)
        self.inventory_gate = load("cm3_reference_inventory_gate", self.root / INVENTORY)
        need(self.inventory_gate.inventory.PIN == PIN, "CM3 inventory reference pin")
        inventory = Path(self.args.inventory).resolve(strict=True)
        manifest_path = regular(inventory / "artifacts.json")
        manifest_bytes = manifest_path.read_bytes()
        self.capture(manifest_path, expected=sha(manifest_bytes))
        for relative, digest in self.inventory_gate.inventory.read_json(manifest_bytes)["Artifacts"].items():
            self.inventory_gate.inventory.relative(relative)
            self.capture(inventory / relative, expected=digest)
        self.bundle = self.inventory_gate.Bundle(inventory)
        self.artifact = require_artifact(self.inventory_gate.captured_inventory(self.bundle), self.admission, self.profile, self.mode)
        self.report.update(SourceInventorySha256=self.bundle.result["SourceInventorySha256"], SourceInventoryReceipt=str(inventory), CohortArtifact=self.artifact)
        self.git = regular(self.args.git)
        need(not self.git.is_relative_to(self.reference), "CM3 Git executable inside reference")
        self.capture(self.git)
        self.command([self.git, "--version"], "git version")
        self.reference_identity()
        self._reference_opened = True
        for directory in (self.reference / "include", self.reference / PORT_DIRECTORY):
            self.full_memberships.append((directory, file_membership(directory)))
        headers = [path.relative_to(self.reference).as_posix() for path in sorted((self.reference / "include").rglob("*.h"))]
        need(headers, "CM3 empty pinned include inventory")
        for relative in (*headers, PORT, PORTMACRO):
            self.capture_reference(relative)
        self.capture(self.repo / BASE_CONFIG, self.fixture_copy / "freeze_base_FreeRTOSConfig.h")
        binding = self.recipe.reference_recipe(self.artifact, self.mode, self.fixture_copy, self.kernel)
        need(binding["PortmacroProvider"] == PORTMACRO and binding["ExtraIncludes"] == [] and
             binding["ExactTargetRecipe"] is True and binding["WitnessKind"] == "none", "CM3 exact reference recipe")
        config = configuration_text(binding["ConfigText"])
        self.generated_file(self.fixture_copy / "FreeRTOSConfig.h", config.encode("ascii"))
        self.flags = binding["Flags"]
        prefix = [*self.artifact["compile_flags"], "-" + self.mode]
        need(self.flags[:len(prefix)] == prefix and not any(flag.startswith("-flto") or flag == "-include" for flag in self.flags), "CM3 exact flags/no CMSIS/LTO")
        self.report.update(CompileFlags=self.flags, RecipeDifferences=binding["Differences"], PortmacroProvider=PORTMACRO,
            BaseConfig=BASE_CONFIG, ConfigText=config, ReferenceFileBindings=list(self.reference_bindings.values()))
        self.prepare_tools()
        self.sources = [self.kernel / PORT, *(self.fixture_copy / name for name in ("providers.c", "consumer.c", "startup.S"))]
        for directory in (self.root, self.kernel, self.output / "python"):
            self.full_memberships.append((directory, file_membership(directory)))
        self._prepared = True

    def prepare_tools(self):
        self.report["Interpreter"] = dict(ReportedExecutable=sys.executable, ModulePath=str(native.interpreter_path()))
        self.capture(native.interpreter_path())
        gcc = regular(self.args.gcc)
        self.capture(gcc)
        self.tools["gcc"] = gcc
        for key in ("objdump", "readelf", "nm"):
            self.tools[key] = regular(gcc.with_name("arm-none-eabi-" + key + ".exe"))
            self.capture(self.tools[key])
        save(self.output / "environment.json", self.environment)
        need(self.command([gcc, "-dumpfullversion"], "compiler version").stdout.strip() == b"14.3.1", "CM3 compiler baseline")
        need(self.command([gcc, "-dumpmachine"], "compiler target").stdout.strip() == b"arm-none-eabi", "CM3 compiler target")
        self.command([gcc, "-dumpspecs"], "compiler specs")
        for key in ("cc1", "collect2", "as", "ld", "lto1", "lto-wrapper"):
            path = self.command([gcc, "-print-prog-name=" + key], "resolve " + key).stdout.decode("utf-8").strip()
            self.capture(regular(path))
        for directory in {Path(row["Original"]).parent for row in self.inputs.values() if row["Original"].endswith(".exe")}:
            if directory.is_relative_to(gcc.parent.parent):
                for path in directory.glob("*.dll"):
                    self.capture(path)
        package = Path(self.args.python_modules).resolve(strict=True) / "elftools"
        self.full_memberships.append((package, file_membership(package)))
        for path in sorted(package.rglob("*.py")):
            self.capture(path, self.output / "python/elftools" / path.relative_to(package))
        need(not any(name == "elftools" or name.startswith("elftools.") for name in sys.modules), "CM3 ambient pyelftools")
        sys.path.insert(0, str(self.output / "python"))
        self.structural = load("cm3_reference_structural_elf", self.root / STRUCTURAL)
        need(sys.modules["elftools"].__version__ == "0.33", "CM3 pyelftools version")

    def prelink(self):
        decoder = load("cm3_reference_prelink_decoder", self.root / DECODER)
        checker = load("cm3_reference_closed_protocols", self.root / CHECKER)
        port = self.objects[0]
        evidence = match_reference_protocols(decoder.Object(port, port.with_suffix(".dis")), checker, self.mode)
        expected = {name: (0, "STT_FUNC", "STB_GLOBAL") for name in
            ("vPortSVCHandler", "xPortPendSVHandler", "xPortSysTickHandler", "pxPortInitialiseStack", "xPortStartScheduler")}
        expected[ROOTS[0]] = (0, "STT_FUNC", "STB_LOCAL")
        expected.update({name: (1, "STT_FUNC", "STB_GLOBAL") for name in ("vTaskSwitchContext", "xTaskIncrementTick", "reference_fail_stop")})
        expected["pxCurrentTCB"] = (1, "STT_OBJECT", "STB_GLOBAL")
        owners = {}
        for index, obj in enumerate(self.objects):
            self.admission.require_attributes(obj.with_suffix(".attributes").read_text())
            parsed = self.structural._ELF(obj, "ET_REL")
            need(not any(section.name.startswith(".gnu.lto_") for section in parsed.sections), "CM3 non-LTO objects required")
            for symbol in parsed.symbols:
                name = symbol["name"]
                if name not in expected or symbol["section"] == "SHN_UNDEF":
                    continue
                owner, kind, binding = expected[name]
                need(index == owner and symbol["kind"] == kind and symbol["binding"] == binding and
                     type(symbol["section"]) is int and symbol["size"] > 0 and name not in owners, "CM3 prelink definition owner: " + name)
                section = parsed.sections[symbol["section"]]
                offset = symbol["value"] & ~1 if kind == "STT_FUNC" else symbol["value"]
                need(0 <= offset < offset + symbol["size"] <= section.header.sh_size, "CM3 prelink definition extent")
                if name == "pxCurrentTCB":
                    need(symbol["size"] == 4 and offset % 4 == 0 and section.header.sh_type == "SHT_NOBITS"
                         and section.header.sh_flags & 7 == 3, "CM3 opaque null current-TCB storage")
                row = dict(Source=str(self.sources[index]), SourceSha256=self.report["Sources"][index]["SourceSha256"],
                    Object=str(obj), ObjectSha256=dict(self.object_hashes)[str(obj)], Section=section.name,
                    Offset=offset, Size=symbol["size"], Binding=binding, Kind=kind)
                if name in ROOTS:
                    mappings = [dict(Name=item["name"], Offset=item["value"], Kind=item["kind"], Binding=item["binding"])
                        for item in parsed.symbols if item["section"] == symbol["section"] and re.fullmatch(r"\$[atd](?:\..*)?", item["name"])]
                    relocs = [dict(Offset=position, Kind=relocation[0], Target=dict(relocation[1]))
                        for (number, position), relocation in sorted(parsed.relocations.items()) if number == symbol["section"]]
                    row["OwningSection"] = dict(Index=symbol["section"], Name=section.name, Size=section.header.sh_size,
                        Sha256=sha(section.data()), RootOffset=offset, RootSize=symbol["size"],
                        RootRawBytesSha256=sha(parsed.section_read(symbol["section"], offset, symbol["size"])),
                        MappingSymbols=sorted(mappings, key=lambda item: (item["Offset"], item["Name"])),
                        Relocations=relocs, WholeSectionRecorded=True, SymbolExtentUnchanged=True, AppliedRelocationProof=False)
                owners[name] = row
        need(set(owners) == set(expected), "CM3 complete prelink owner inventory")
        self.report.update(PrelinkReferenceRoots=evidence, PrelinkReferenceOwners=owners, ClosedPrelinkBodies=3,
            PrelinkOwnObjectsOnly=True, PrelinkReferenceProtocolScope="THREE_REFERENCE_OWNING_OBJECT_ROOTS_ONLY_NOT_FINAL_RELOCATION_PROOF")
        self._prelink_verified = True

    def build(self):
        self.objects = []
        for index, source in enumerate(self.sources):
            obj = self.output / "objects" / ("%02d-" % index + source.stem + ".o")
            obj.parent.mkdir(parents=True, exist_ok=True)
            discovery, actual = obj.with_suffix(".discovery.d"), obj.with_suffix(".compile.d")
            flags = [*self.artifact["compile_flags"], "-" + self.mode, "-g0"] if source.suffix == ".S" else self.flags
            target = "pilot-source-" + str(index)
            self.command([self.tools["gcc"], *flags, "-M", "-MF", discovery, "-MT", target, source], "discover " + source.name)
            dependencies = self.dependencies(discovery, capture_system=True)
            require_dependency_roles([Path(row["Path"]) for row in dependencies], source, self.fixture_copy, self.kernel)
            row = dict(Source=str(source), SourceSha256=sha(source.read_bytes()), Object=str(obj), ObjectSha256=None,
                Dependencies=dependencies, DiscoveryDependencyFile=str(discovery), CompileDependencyFile=str(actual),
                CompileFlags=list(flags), CompileDependenciesVerified=False)
            self.report["Sources"].append(row)
            self.command([self.tools["gcc"], *flags, "-MD", "-MF", actual, "-MT", target, "-c", source, "-o", obj], "compile " + source.name)
            row["ObjectSha256"] = sha(regular(obj).read_bytes())
            compiled = self.dependencies(actual)
            native.require_compile_dependencies(dependencies, compiled)
            require_dependency_roles([Path(item["Path"]) for item in compiled], source, self.fixture_copy, self.kernel)
            row.update(ActualCompileDependencies=compiled, CompileDependenciesVerified=True)
            self.objects.append(obj)
            self.inspect(obj)
        self.freeze_objects()
        self.verify_objects("before-prelink")
        try:
            self.prelink()
        finally:
            self.verify_objects("after-prelink")
        base = [*self.artifact["compile_flags"], "-" + self.mode, "-nostdlib",
            "-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack",
            "-T", self.fixture_copy / "link.ld", *self.objects]
        self.report["Links"] = []
        finals = []
        for name, extra in (("ordinary", []), ("emit-relocs", ["-Wl,--emit-relocs"])):
            path, link_map = self.output / (name + ".elf"), self.output / (name + ".map")
            self.link_twin(name, [self.tools["gcc"], *base, *extra, "-Wl,-Map=" + str(link_map), "-o", path])
            self.inspect(path)
            self.admission.require_attributes(path.with_suffix(".attributes").read_text())
            self.audit_final(path)
            self.report["Links"].append(dict(Kind=name, Path=str(path), Sha256=sha(path.read_bytes()), Map=str(link_map), MapSha256=sha(regular(link_map).read_bytes())))
            finals.append(path)
        comparison = self.structural.compare_load_images(*finals)
        need(comparison["Identical"] is True, "CM3 twin load mismatch")
        save(self.output / "load-image.json", comparison)
        self.report.update(ReferenceBuilt=True, TwinLoadImageIdentical=True, TwinAllocatedSectionsIdentical=True,
            TranslationUnits=4, FinalExecutableLinks=2, PrelinkRelAuthority=[str(obj) for obj in self.objects],
            FrozenObjectHashes=dict(self.object_hashes), LoadImageSha256=sha(json.dumps(comparison, sort_keys=True).encode("ascii")))
        self._twins_verified = self._built = True

    def audit_final(self, path):
        image = self.structural._ELF(path, "ET_EXEC")
        native.require_final_float_flags(image.elf.header.e_flags, "CM3")
        need(not any(row["name"] and row["section"] == "SHN_UNDEF" for row in image.symbols), "CM3 undefined reference symbol")
        names = ("reference_reset_handler", "vPortSVCHandler", "xPortPendSVHandler", "xPortSysTickHandler",
                 "pxPortInitialiseStack", "xPortStartScheduler", "vTaskSwitchContext", "xTaskIncrementTick")
        symbols = {name: image.symbol(name, "STT_FUNC", root=True) for name in names}
        first = local_start(image)
        vector = image.elf.get_section_by_name(".isr_vector")
        need(vector is not None and vector.header.sh_addr == 0 and vector.header.sh_size == 1024 and vector.header.sh_flags & 7 == 2, "CM3 reference vector geometry")
        words = struct.unpack("<256I", vector.data())
        need(words[0] == 0x20010000 and image.elf.header.e_entry == symbols["reference_reset_handler"]["value"], "CM3 entry/MSP")
        for slot, name in ((1, "reference_reset_handler"), (11, "vPortSVCHandler"), (14, "xPortPendSVHandler"), (15, "xPortSysTickHandler")):
            need(words[slot] == symbols[name]["value"] and words[slot] & 1, "CM3 strong vector: " + name)
        current = image.symbol("pxCurrentTCB", "STT_OBJECT")
        need(current["size"] == 4 and current["value"] % 4 == 0 and image.sections[current["section"]].header.sh_type == "SHT_NOBITS", "CM3 current-TCB BSS")
        roots, facts = image.elf.get_section_by_name(".reference_roots"), image.elf.get_section_by_name(".reference_contract")
        need(roots is not None and roots.header.sh_flags & 7 == 2 and roots.header.sh_size == 8 and
             struct.unpack("<2I", roots.data()) == tuple(symbols[name]["value"] for name in ("pxPortInitialiseStack", "xPortStartScheduler")), "CM3 typed constructor/scheduler roots")
        need(facts is not None and facts.header.sh_flags & 7 == 2 and facts.header.sh_size == 40, "CM3 facts section")
        require_header_facts(facts.data())
        need(not any(row["name"].startswith(("fiber_", "ctxrt_")) for row in image.symbols), "CM3 native code in reference image")
        self.report.setdefault("FinalStructuralChecks", []).append(dict(Path=str(path), LocalFirstStartBinding=first["binding"],
            LocalFirstStartSize=first["size"], FinalRootRelocationProof=False))

    def finish(self, error):
        self.report["Verdict"] = "FAIL"
        drift = []
        def close(label, action):
            try:
                action()
            except Exception as failure:
                drift.append(label + ": " + type(failure).__name__ + ": " + str(failure))
        if self._reference_opened:
            def identity():
                self.reference_identity()
                self._reference_closed = True
            close("reference identity", identity)
        if hasattr(self, "object_hashes"):
            close("objects", lambda: self.verify_objects("closing"))
        for directory, before in self.full_memberships:
            close(str(directory), lambda directory=directory, before=before: need(file_membership(directory) == before, "membership drift"))
        for row in self.inputs.values():
            for path in (row["Original"], row["Captured"]):
                close(path, lambda path=path, digest=row["Sha256"]: need(sha(Path(path).read_bytes()) == digest, "input drift"))
        for path, digest in self.generated.items():
            close(path, lambda path=path, digest=digest: need(sha(Path(path).read_bytes()) == digest, "generated input drift"))
        if hasattr(self, "bundle"):
            close("inventory", self.bundle.verify)
        modules = {}
        def packages():
            for name, module in tuple(sys.modules.items()):
                if name == "elftools" or name.startswith("elftools."):
                    path = Path(module.__file__).resolve(strict=True)
                    need(path.is_relative_to(self.output / "python/elftools"), "module outside capture")
                    modules[name] = dict(Path=str(path), Sha256=sha(path.read_bytes()))
        close("package modules", packages)
        complete = (self._prepared and self._built and self._prelink_verified and self._twins_verified and self._reference_closed
            and len(self.report["Sources"]) == 4 and len(self.report.get("Links", [])) == 2
            and [row["Name"] for row in self.report.get("PrelinkReferenceRoots", [])] == list(ROOTS)
            and bool(self.commands) and all(row.get("CompileDependenciesVerified") is True for row in self.report["Sources"])
            and [row["Stage"] for row in self.report.get("ObjectChecks", [])] == list(CHECKPOINTS)
            and all(row["Status"] == "PASS" for row in self.report.get("ObjectChecks", []))
            and all(row["Status"] == "PASS" for row in self.commands))
        self.report.update(Error=error if error is not None else None if complete else "incomplete CM3 reference build stages",
            InputDrift=drift, Commands=self.commands, ImportedPackageModules=modules,
            ReferenceClosingIdentityVerified=self._reference_closed, ArtifactSealVerified=False)
        try:
            save(self.output / "inputs.json", dict(Files=list(self.inputs.values()), Generated=self.generated))
            save(self.output / "results.json", self.report)
            common.seal_artifacts(self.output)
            self.report["ArtifactSealVerified"] = True
            if error is None and not drift and complete:
                self.report["Verdict"] = PASS
            save(self.output / "results.json", self.report)
            common.seal_artifacts(self.output)
        except Exception as failure:
            previous = self.report.get("Error")
            self.report.update(Verdict="FAIL", ArtifactSealVerified=False,
                Error=(previous + "; " if previous else "") + "artifact closure: " + type(failure).__name__ + ": " + str(failure))
            save(self.output / "results.json", self.report)
            try:
                common.seal_artifacts(self.output)
            except Exception as recovery:
                self.report["Error"] += "; failure reseal: " + type(recovery).__name__ + ": " + str(recovery)
                save(self.output / "results.json", self.report)
                save(self.output / "artifacts.json", dict(Artifacts=common.artifact_inventory(self.output)))
            return False
        return self.report["Verdict"] == PASS


def main(argv=None):
    need(not sys.flags.optimize, "optimized Python unsupported")
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("gcc", "git", "freertos", "inventory", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--profile", choices=("CM3",), default="CM3")
    parser.add_argument("--mode", choices=MODES, default="O2")
    parser.add_argument("--python-modules", default=str(Path(os.environ.get("TEMP", ".")) / "fiber-classic-audit-python"))
    args = parser.parse_args(argv)
    pilot, error = Reference(args), None
    try:
        pilot.prepare()
        pilot.build()
    except Exception as failure:
        error = type(failure).__name__ + ": " + str(failure)
        print(error, file=sys.stderr)
    passed = pilot.finish(error)
    print(pilot.report["Verdict"] + " " + str(pilot.output), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
