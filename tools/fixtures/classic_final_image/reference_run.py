"""Opt-in pinned CM4 O2 reference twins; link-only, never scheduler execution."""
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
NATIVE_BYTES = (HERE / "run.py").read_bytes()
SPEC = importlib.util.spec_from_file_location("reference_final_native_envelope", HERE / "run.py")
native = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native
exec(compile(NATIVE_BYTES, str(HERE / "run.py"), "exec"), native.__dict__)
need, sha, save, regular, load = native.need, native.sha, native.save, native.regular, native.load

PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
COHORT = "cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default"
PORT = "portable/GCC/ARM_CM4F/port.c"
PORTMACRO = "portable/GCC/ARM_CM4F/portmacro.h"
ROOTS = ("prvPortStartFirstTask", "vPortSVCHandler", "xPortPendSVHandler")
FIXTURE_FILES = ("reference.h", "providers.c", "consumer.c", "startup.S", "link.ld")
HELPERS = ("tools/freeze_classic_fp_mechanisms.py", "tools/freeze_cm3_mechanisms.py",
           "tools/freeze_cohorts.py", "tools/fixtures/freeze_cohorts/reference_recipe.py",
           "tools/fixtures/freeze_cohorts/process_runner.py", "tools/fixtures/cm55_tfm_parity/elf.py",
           "tools/fixtures/cm4_cm7_freeze_parity/check.py")
CHECKPOINTS = ("before-prelink", "after-prelink", "before-link-ordinary", "after-link-ordinary",
               "before-link-emit-relocs", "after-link-emit-relocs", "closing")
PASS = "REFERENCE-CM4-FINAL-TWIN-BUILD-PASS"


def selection(profile, mode):
    need(type(profile) is str and profile == "CM4" and type(mode) is str and mode == "O2",
         "reference pilot admits only CM4 O2")
    return COHORT


def scope_report():
    return dict(Verdict="FAIL", Error=None, ProofScope="PINNED_REFERENCE_CM4_O2_DIRECT_TWIN_BUILD_ONLY",
        Profile="CM4", Mode="O2", Cohort=COHORT, ReferenceCommit=PIN, Linkage="direct", LTO=False,
        ReferenceBuilt=False, NativeBuilt=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
        FinalElfProof=False, FinalRootRelocationProof=False, FinalReferenceParity=False,
        CompleteObjectProof=False, PolicyEquivalence=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, SchedulerSemanticsProven=False, ReferenceKernelAvailable=False,
        FPCCRPolicy=dict(DeclaredNativePolicy="eager", ReferencePolicy="upstream-lazy",
            ReferenceASPEN=1, ReferenceLSPEN=1, ReferenceBits=0xC0000000,
            DifferenceId="FAP-FP-SETUP-POLICY", PolicyEquivalenceProven=False, HardwareEffectsProven=False),
        InputDrift=[], Sources=[], Commands=[])


def require_artifact(manifest, admission):
    artifact = native.require_manifest_selection(manifest, "CM4", "O2", admission)
    need(artifact["upstream_sources"] == [PORT] and artifact["upstream_defines"] ==
         dict(FIBER_FREERTOS_PARITY_ENABLE_MPU="0", FIBER_FREERTOS_PARITY_ENABLE_FPU="1",
              FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE="0"), "exact reference source/defines")
    return artifact


def match_reference_protocols(image, checker):
    protocols = checker._REFERENCE["CM4"]
    need(tuple(protocols) == ROOTS, "exact reference protocol roots")
    evidence = [checker._match(image, "Reference", name, protocols[name]) for name in ROOTS]
    need(len(evidence) == 3 and all(type(row["TailNops"]) is int and row["TailNops"] == 0 for row in evidence),
         "reference O2 complete protocols/tail layout")
    return evidence


def require_dependency_roles(paths, source, fixture, kernel):
    paths = set(paths)
    need(source in paths, "source missing from dependencies")
    if source.suffix == ".c":
        expected = {kernel / PORTMACRO, fixture / "FreeRTOSConfig.h", fixture / "freeze_base_FreeRTOSConfig.h"}
        actual = {p for p in paths if p.name in ("portmacro.h", "FreeRTOSConfig.h", "freeze_base_FreeRTOSConfig.h")}
        need(actual == expected, "exact reference config/portmacro providers")


def artifact_inventory(output):
    return {path.relative_to(output).as_posix(): sha(path.read_bytes()) for path in output.rglob("*")
            if path.is_file() and path != output / "artifacts.json"}


def seal_artifacts(output):
    expected = artifact_inventory(output)
    manifest = dict(Artifacts=expected)
    save(output / "artifacts.json", manifest)
    need(artifact_inventory(output) == expected, "reference artifact seal path/hash drift")
    need(json.loads((output / "artifacts.json").read_bytes()) == manifest, "reference artifact manifest drift")


class Reference(native.Pilot):
    def __init__(self, args):
        selection(getattr(args, "profile", "CM4"), getattr(args, "mode", "O2"))
        reference = Path(args.freertos).resolve(strict=True)
        output = Path(os.path.abspath(args.output_dir)).resolve(strict=False)
        need(reference.is_dir() and not output.is_relative_to(reference) and not reference.is_relative_to(output),
             "reference/output overlap")
        super().__init__(args)
        self.reference, self.report = reference, scope_report()
        self.fixture = HERE / "reference"
        self.fixture_copy = self.root / "tools/fixtures/classic_final_image/reference"
        self.kernel = self.output / "freertos"
        self.reference_bindings = {}
        self._reference_opened = self._reference_closed = False

    def git_bytes(self, *arguments):
        return self.command([self.git, "--no-optional-locks", "-c", "core.fsmonitor=false",
                             "-C", self.reference, *arguments], "reference git " + arguments[0], timeout=30).stdout

    def reference_identity(self):
        need(self.git_bytes("rev-parse", "HEAD").decode("ascii").strip() == PIN, "actual reference pin")
        need(not self.git_bytes("status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"),
             "reference worktree drift")

    def capture_reference(self, relative):
        need(relative in (PORT, PORTMACRO) or re.fullmatch(r"include/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+[.]h", relative),
             "reference input outside CM4 provider/include set")
        source = regular(self.reference / relative)
        data = source.read_bytes()
        blob = self.git_bytes("show", PIN + ":" + relative)
        comparison = self.admission.shared.inventory.reference_bytes_match(data, blob)
        captured = self.capture(source, self.kernel / relative, expected=sha(data))
        blob_path = self.generated_file(self.output / "reference-blobs" / relative, blob)
        self.reference_bindings[relative] = dict(Path=relative, Original=str(source), Captured=str(captured),
            WorktreeSha256=sha(data), GitBlobSha256=sha(blob), GitBlob=str(blob_path), ByteComparison=comparison)

    def prepare(self):
        self.capture(HERE / "run.py", self.root / "tools/fixtures/classic_final_image/run.py", expected=sha(NATIVE_BYTES))
        self.capture(Path(__file__), self.root / "tools/fixtures/classic_final_image/reference_run.py", expected=sha(SELF_BYTES))
        self.capture(HERE / "test_reference_run.py", self.root / "tools/fixtures/classic_final_image/test_reference_run.py")
        self.capture(HERE / "elf.py", self.root / "tools/fixtures/classic_final_image/elf.py")
        for relative in HELPERS:
            self.capture(self.repo / relative, self.root / relative)
        for name in FIXTURE_FILES:
            self.capture(self.fixture / name, self.fixture_copy / name)
        self.process = load("reference_final_process", self.root / HELPERS[4])
        self.recipe = load("reference_final_recipe", self.root / HELPERS[3])
        self.admission = load("reference_final_admission", self.root / HELPERS[0])
        need(self.admission.shared.inventory.PIN == PIN, "inventory reference pin")
        inventory = Path(self.args.inventory).resolve(strict=True)
        manifest_path = regular(inventory / "artifacts.json")
        manifest_bytes = manifest_path.read_bytes()
        self.capture(manifest_path, expected=sha(manifest_bytes))
        for relative, digest in json.loads(manifest_bytes)["Artifacts"].items():
            need(not Path(relative).is_absolute() and ".." not in Path(relative).parts, "inventory path")
            self.capture(inventory / relative, expected=digest)
        self.bundle = self.admission.shared.Bundle(inventory)
        self.artifact = require_artifact(self.admission.shared.captured_inventory(self.bundle), self.admission)
        self.report.update(SourceInventorySha256=self.bundle.result["SourceInventorySha256"],
                           SourceInventoryReceipt=str(inventory), CohortArtifact=self.artifact)
        self.git = regular(self.args.git)
        need(not self.git.is_relative_to(self.reference), "Git executable inside kernel")
        self.capture(self.git)
        self.command([self.git, "--version"], "git version")
        self.reference_identity()
        self._reference_opened = True
        for directory, recursive in ((self.reference / "include", True), (self.reference / "portable/GCC/ARM_CM4F", False),
                                      (self.fixture, False)):
            self.memberships.append((directory, recursive, native.membership(directory, recursive)))
        names = [p.relative_to(self.reference).as_posix() for p in sorted((self.reference / "include").rglob("*.h"))]
        need(names, "empty reference headers")
        for relative in (*names, PORT, PORTMACRO):
            self.capture_reference(relative)
        self.capture(self.repo / "tools/fixtures/classic_fp_context_runtime/reference/FreeRTOSConfig.h",
                     self.fixture_copy / "freeze_base_FreeRTOSConfig.h")
        binding = self.recipe.reference_recipe(self.artifact, "O2", self.fixture_copy, self.kernel)
        need(binding["PortmacroProvider"] == PORTMACRO and binding["ExtraIncludes"] == []
             and binding["ExactTargetRecipe"] is True and binding["WitnessKind"] == "none", "exact reference recipe")
        self.generated_file(self.fixture_copy / "FreeRTOSConfig.h", binding["ConfigText"].encode("ascii"))
        self.flags = binding["Flags"]
        need(self.flags[:5] == [*self.artifact["compile_flags"], "-O2"] and
             not any(flag in ("-include", "-flto", "-flto=auto") for flag in self.flags), "reference flag envelope")
        self.report.update(CompileFlags=self.flags, RecipeDifferences=binding["Differences"],
                           PortmacroProvider=PORTMACRO, ReferenceFileBindings=list(self.reference_bindings.values()))
        self.report["Interpreter"] = dict(ReportedExecutable=sys.executable, ModulePath=str(native.interpreter_path()))
        self.capture(native.interpreter_path())
        gcc = regular(self.args.gcc)
        self.capture(gcc)
        self.tools["gcc"] = gcc
        for key in ("objdump", "readelf", "nm"):
            tool = regular(gcc.with_name("arm-none-eabi-" + key + ".exe"))
            self.capture(tool)
            self.tools[key] = tool
        save(self.output / "environment.json", self.environment)
        need(self.command([gcc, "-dumpfullversion"], "compiler version").stdout.strip() == b"14.3.1", "compiler baseline")
        need(self.command([gcc, "-dumpmachine"], "compiler target").stdout.strip() == b"arm-none-eabi", "compiler machine")
        self.command([gcc, "-dumpspecs"], "compiler specs")
        for key in ("cc1", "collect2", "as", "ld", "lto1", "lto-wrapper"):
            path = self.command([gcc, "-print-prog-name=" + key], "resolve " + key).stdout.decode("utf-8").strip()
            self.capture(regular(path))
        for directory in {Path(row["Original"]).parent for row in self.inputs.values() if row["Original"].endswith(".exe")}:
            if directory.is_relative_to(gcc.parent.parent):
                for path in directory.glob("*.dll"):
                    self.capture(path)
        package = Path(self.args.python_modules).resolve(strict=True) / "elftools"
        self.memberships.append((package, True, native.membership(package, True)))
        for path in sorted(package.rglob("*.py")):
            self.capture(path, self.output / "python/elftools" / path.relative_to(package))
        need(not any(name == "elftools" or name.startswith("elftools.") for name in sys.modules), "ambient pyelftools module")
        sys.path.insert(0, str(self.output / "python"))
        self.final_reader = load("reference_final_structural_reader", self.root / "tools/fixtures/classic_final_image/elf.py")
        need(sys.modules["elftools"].__version__ == "0.33", "pyelftools version")
        self.sources = [self.kernel / PORT, *(self.fixture_copy / name for name in ("providers.c", "consumer.c", "startup.S"))]
        self.copy_memberships = [(directory, native.membership(directory, True)) for directory in
                                  (self.root, self.kernel, self.output / "python")]
        self._prepared = True

    def dependencies(self, path, *, capture_system=False):
        rows = []
        for dependency in native.read_dependencies(path):
            key = str(dependency)
            if dependency.is_relative_to(self.output):
                expected = self.generated.get(key)
                if expected is None:
                    matches = [row for row in self.inputs.values() if row["Captured"] == key]
                    need(len(matches) == 1, "unbound reference copy dependency")
                    expected = matches[0]["Sha256"]
            else:
                need(not dependency.is_relative_to(self.repo) and not dependency.is_relative_to(self.reference),
                     "live project/kernel dependency")
                if capture_system:
                    self.capture(dependency)
                need(key in self.inputs, "unbound compiler system dependency")
                expected = self.inputs[key]["Sha256"]
            digest = sha(dependency.read_bytes())
            need(digest == expected, "reference compile dependency drift")
            rows.append(dict(Path=key, Sha256=digest))
        return rows

    def freeze_objects(self):
        rows = self.report["Sources"]
        need(not hasattr(self, "object_hashes"), "objects already frozen")
        need(len(rows) == len(self.objects) == len(set(self.objects)) == 4 and
             [row["Object"] for row in rows] == [str(path) for path in self.objects], "exact four-object inventory")
        need(all(row["CompileDependenciesVerified"] is True for row in rows), "unverified compilation dependencies")
        self.object_hashes = tuple((row["Object"], row["ObjectSha256"]) for row in rows)

    def prelink(self):
        decoder = load("reference_final_prelink_decoder", self.root / HELPERS[5])
        checker = load("reference_final_prelink_protocol", self.root / HELPERS[6])
        port = self.objects[0]
        self.admission.require_attributes(port.with_suffix(".attributes").read_text(), "CM4")
        evidence = match_reference_protocols(decoder.Object(port, port.with_suffix(".dis")), checker)
        owners = {}
        expected = {name: (0, "STT_FUNC", "STB_GLOBAL") for name in
                    ("vPortSVCHandler", "xPortPendSVHandler", "xPortSysTickHandler", "pxPortInitialiseStack", "xPortStartScheduler")}
        expected["prvPortStartFirstTask"] = (0, "STT_FUNC", "STB_LOCAL")
        expected.update({name: (1, "STT_FUNC", "STB_GLOBAL") for name in
                         ("vTaskSwitchContext", "xTaskIncrementTick", "reference_assert_failed", "reference_fail_stop")})
        expected["pxCurrentTCB"] = (1, "STT_OBJECT", "STB_GLOBAL")
        for index, obj in enumerate(self.objects):
            parsed = self.final_reader._ELF(obj, "ET_REL")
            for symbol in parsed.symbols:
                name = symbol["name"]
                if name not in expected or symbol["section"] == "SHN_UNDEF":
                    continue
                owner, kind, binding = expected[name]
                need(index == owner and symbol["kind"] == kind and symbol["binding"] == binding
                     and type(symbol["section"]) is int and symbol["size"] > 0 and name not in owners,
                     "reference prelink definition owner: " + name)
                section = parsed.sections[symbol["section"]]
                offset = symbol["value"] & ~1 if kind == "STT_FUNC" else symbol["value"]
                need(0 <= offset < offset + symbol["size"] <= section.header.sh_size, "reference prelink extent")
                if name == "pxCurrentTCB":
                    need(symbol["size"] == 4 and offset % 4 == 0 and section.header.sh_type == "SHT_NOBITS"
                         and section.header.sh_flags & 7 == 3, "opaque null current-TCB storage")
                owners[name] = dict(Source=str(self.sources[index]), SourceSha256=self.report["Sources"][index]["SourceSha256"],
                    Object=str(obj), ObjectSha256=dict(self.object_hashes)[str(obj)], Section=section.name,
                    Offset=offset, Size=symbol["size"], Binding=binding, Kind=kind)
        need(set(owners) == set(expected), "complete reference prelink owner inventory")
        self.report.update(PrelinkReferenceRoots=evidence, PrelinkReferenceOwners=owners,
            PrelinkReferenceProtocolScope="THREE_REFERENCE_ROOTS_ONLY_NOT_FINAL_RELOCATION_PROOF")
        self._prelink_verified = True

    def build(self):
        self.objects = []
        for index, source in enumerate(self.sources):
            obj = self.output / "objects" / ("%02d-" % index + source.stem + ".o")
            obj.parent.mkdir(parents=True, exist_ok=True)
            discovery, actual = obj.with_suffix(".discovery.d"), obj.with_suffix(".compile.d")
            flags = [*self.artifact["compile_flags"], "-O2", "-g0"] if source.suffix == ".S" else self.flags
            target = "pilot-source-" + str(index)
            self.command([self.tools["gcc"], *flags, "-M", "-MF", discovery, "-MT", target, source], "discover " + source.name)
            dependencies = self.dependencies(discovery, capture_system=True)
            require_dependency_roles([Path(row["Path"]) for row in dependencies], source, self.fixture_copy, self.kernel)
            row = dict(Source=str(source), SourceSha256=sha(source.read_bytes()), Object=str(obj), ObjectSha256=None,
                Dependencies=dependencies, DiscoveryDependencyFile=str(discovery), CompileDependencyFile=str(actual),
                CompileFlags=list(flags), CompileDependenciesVerified=False)
            self.report["Sources"].append(row)
            self.command([self.tools["gcc"], *flags, "-MD", "-MF", actual, "-MT", target, "-c", source, "-o", obj],
                         "compile " + source.name)
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
        base = [*self.artifact["compile_flags"], "-O2", "-nostdlib",
                "-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack",
                "-T", self.fixture_copy / "link.ld", *self.objects]
        self.report["Links"] = []
        finals = []
        for name, extra in (("ordinary", []), ("emit-relocs", ["-Wl,--emit-relocs"])):
            path, link_map = self.output / (name + ".elf"), self.output / (name + ".map")
            self.link_twin(name, [self.tools["gcc"], *base, *extra, "-Wl,-Map=" + str(link_map), "-o", path])
            self.inspect(path)
            self.admission.require_attributes(path.with_suffix(".attributes").read_text(), "CM4")
            self.audit_final(path)
            self.report["Links"].append(dict(Kind=name, Path=str(path), Sha256=sha(path.read_bytes()),
                Map=str(link_map), MapSha256=sha(regular(link_map).read_bytes())))
            finals.append(path)
        comparison = self.final_reader.compare_load_images(*finals)
        need(comparison["Identical"] is True, "reference twin load mismatch")
        save(self.output / "load-image.json", comparison)
        self.report.update(ReferenceBuilt=True, TwinLoadImageIdentical=True, TwinAllocatedSectionsIdentical=True,
            TranslationUnits=4, FinalExecutableLinks=2, PrelinkRelAuthority=[str(obj) for obj in self.objects],
            FrozenObjectHashes=dict(self.object_hashes), LoadImageSha256=sha(json.dumps(comparison, sort_keys=True).encode("ascii")))
        self._twins_verified = self._built = True

    def audit_final(self, path):
        image = self.final_reader._ELF(path, "ET_EXEC")
        native.require_final_float_flags(image.elf.header.e_flags, "CM4")
        need(not any(row["name"] and row["section"] == "SHN_UNDEF" for row in image.symbols), "undefined reference symbol")
        names = ("reference_reset_handler", "vPortSVCHandler", "xPortPendSVHandler", "xPortSysTickHandler",
                 "pxPortInitialiseStack", "xPortStartScheduler", "vTaskSwitchContext", "xTaskIncrementTick")
        symbols = {name: image.symbol(name, "STT_FUNC", root=True) for name in names}
        vector = image.elf.get_section_by_name(".isr_vector")
        need(vector is not None and vector.header.sh_addr == 0 and vector.header.sh_size == 1024
             and vector.header.sh_flags & 7 == 2, "reference vector geometry")
        words = struct.unpack("<256I", vector.data())
        need(words[0] == 0x20010000 and image.elf.header.e_entry == symbols["reference_reset_handler"]["value"], "reference entry/MSP")
        for slot, name in ((1, "reference_reset_handler"), (11, "vPortSVCHandler"), (14, "xPortPendSVHandler"),
                           (15, "xPortSysTickHandler")):
            need(words[slot] == symbols[name]["value"] and words[slot] & 1, "reference strong vector: " + name)
        current = image.symbol("pxCurrentTCB", "STT_OBJECT")
        need(current["size"] == 4 and current["value"] % 4 == 0 and
             image.sections[current["section"]].header.sh_type == "SHT_NOBITS", "reference current-TCB BSS")
        roots = image.elf.get_section_by_name(".reference_roots")
        facts = image.elf.get_section_by_name(".reference_contract")
        need(roots is not None and roots.header.sh_flags & 7 == 2 and roots.header.sh_size == 8 and
             struct.unpack("<2I", roots.data()) == tuple(symbols[name]["value"] for name in
               ("pxPortInitialiseStack", "xPortStartScheduler")), "typed reference constructor/scheduler roots")
        need(facts is not None and facts.header.sh_flags & 7 == 2 and facts.header.sh_size == 40 and
             struct.unpack("<10I", facts.data()) == (1, 4, 4, 4, 8, 4, 1, 16, 16, 4), "reference header facts")
        need(not any(row["name"].startswith(("fiber_", "ctxrt_")) for row in image.symbols), "native code in reference image")

    def finish(self, error):
        drift = []
        self.report["Verdict"] = "FAIL"
        if self._reference_opened:
            try:
                self.reference_identity()
                self._reference_closed = True
            except Exception as failure:
                drift.append("closing reference identity: " + str(failure))
        if hasattr(self, "object_hashes"):
            try:
                self.verify_objects("closing")
            except Exception as failure:
                drift.append(str(failure))
        for directory, recursive, before in self.memberships:
            if native.membership(directory, recursive) != before:
                drift.append("membership: " + str(directory))
        for directory, before in getattr(self, "copy_memberships", []):
            if native.membership(directory, True) != before:
                drift.append("copied membership: " + str(directory))
        for row in self.inputs.values():
            for path in (row["Original"], row["Captured"]):
                if not Path(path).is_file() or sha(Path(path).read_bytes()) != row["Sha256"]:
                    drift.append(path)
        for path, digest in self.generated.items():
            if not Path(path).is_file() or sha(Path(path).read_bytes()) != digest:
                drift.append(path)
        try:
            if hasattr(self, "bundle"):
                self.bundle.verify()
        except Exception as failure:
            drift.append(str(failure))
        modules = {}
        for name, module in tuple(sys.modules.items()):
            if name == "elftools" or name.startswith("elftools."):
                path = Path(module.__file__).resolve(strict=True)
                if not path.is_relative_to(self.output / "python/elftools"):
                    drift.append("module outside capture: " + name)
                modules[name] = dict(Path=str(path), Sha256=sha(path.read_bytes()))
        complete = (self._prepared and self._built and self._prelink_verified and self._twins_verified and self._reference_closed
            and len(self.report["Sources"]) == 4 and len(self.report.get("Links", [])) == 2
            and len(self.report.get("PrelinkReferenceRoots", [])) == 3 and self.commands
            and all(row.get("CompileDependenciesVerified") is True for row in self.report["Sources"])
            and [row["Stage"] for row in self.report.get("ObjectChecks", [])] == list(CHECKPOINTS)
            and all(row["Status"] == "PASS" for row in self.report.get("ObjectChecks", []))
            and all(row["Status"] == "PASS" for row in self.commands))
        self.report.update(Error=error if error is not None else None if complete else "incomplete reference build stages",
            InputDrift=drift, Commands=self.commands, ImportedPackageModules=modules,
            ReferenceClosingIdentityVerified=self._reference_closed)
        self.report["ArtifactSealVerified"] = False
        try:
            save(self.output / "inputs.json", dict(Files=list(self.inputs.values()), Generated=self.generated))
            save(self.output / "results.json", self.report)
            seal_artifacts(self.output)
            self.report["ArtifactSealVerified"] = True
            if error is None and not drift and complete:
                self.report["Verdict"] = PASS
            save(self.output / "results.json", self.report)
            # The final verdict changes the inventory too; seal it separately.
            seal_artifacts(self.output)
        except Exception as failure:
            detail = type(failure).__name__ + ": " + str(failure)
            previous = self.report.get("Error")
            self.report.update(Verdict="FAIL", ArtifactSealVerified=False,
                               Error=(previous + "; " if previous else "") + "artifact closure: " + detail)
            save(self.output / "results.json", self.report)
            try:
                seal_artifacts(self.output)
            except Exception as recovery:
                self.report["Error"] += "; failure reseal: " + type(recovery).__name__ + ": " + str(recovery)
                save(self.output / "results.json", self.report)
                save(self.output / "artifacts.json", dict(Artifacts=artifact_inventory(self.output)))
            return False
        return self.report["Verdict"] == PASS


def main(argv=None):
    need(not sys.flags.optimize, "optimized Python unsupported")
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("gcc", "git", "freertos", "inventory", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--profile", choices=("CM4",), default="CM4")
    parser.add_argument("--mode", choices=("O2",), default="O2")
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
