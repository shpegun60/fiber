"""Admit the fixed ordinary CM3 reference seed; never build or execute tools.

The caller supplies the authenticated, unchanged native transport utilities.
This class only reads and closes evidence and loads authenticated helper bytes.
"""
import os
import json
from pathlib import Path
import re
from unittest.mock import patch


SEED = Path("C:/fzfinal-cm3-reference-grid-20261104-e1/CM3-O2")
RECEIPT_SHA256 = "9B605CEC54DE39C55662B6AAA2FAC260647C54F63AC903890FB9717EE3C3C2EC"
ARTIFACTS_SHA256 = "A762CF954D7D9956A2F8D83DC3EC3B3A2620A3BF7759C27BDAACF399F5EDD6FC"
PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
CLASSIC = "tools/fixtures/classic_final_image/"
FIXTURE = "tools/fixtures/cm3_final_image/reference/"
REFERENCE = "tools/fixtures/cm3_final_image/reference_run.py"
RECIPE = "tools/fixtures/freeze_cohorts/reference_recipe.py"
MODEL = "tools/fixtures/cm3_final_image/admission.py"
PROCESS = "tools/fixtures/freeze_cohorts/process_runner.py"
INVENTORY = "tools/freeze_cm3_mechanisms.py"
LOADER = "tools/fixtures/cm3_final_roots/reference_witness.py"
LOADER_SHA256 = "AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C"
PORT = "portable/GCC/ARM_CM3/port.c"
PORTMACRO = "portable/GCC/ARM_CM3/portmacro.h"
BASE_CONFIG = "tools/fixtures/freertos_asm_parity/FreeRTOSConfig.h"
SOURCES = ("freertos/" + PORT, *("source/" + FIXTURE + name for name in ("providers.c", "consumer.c", "startup.S")))
ROOTS = ("prvPortStartFirstTask", "vPortSVCHandler", "xPortPendSVHandler")
CHECKPOINTS = ("before-prelink", "after-prelink", "before-link-ordinary", "after-link-ordinary",
               "before-link-emit-relocs", "after-link-emit-relocs", "closing")
WORKERS = ("cc1", "collect2", "as", "ld", "lto1", "lto-wrapper")


def stable_path(path):
    return Path(os.path.abspath(os.fspath(path)))


class Seed:
    def __init__(self, api, args):
        self.api, self.args = api, args
        self.closure = api.Closure()
        self.root = api.checked_path(args.reference_build)
        api.need(self.root == api.checked_path(SEED), "fixed qualified reference seed required")
        api.same([api.digest_text(args.reference_receipt_sha256), api.digest_text(args.reference_artifacts_sha256)],
                 [RECEIPT_SHA256, ARTIFACTS_SHA256], "fixed reference seed receipt hashes")
        self.result = self.closure.structured(self.root / "results.json", RECEIPT_SHA256)
        manifest = self.closure.structured(self.root / "artifacts.json", ARTIFACTS_SHA256)
        self.artifacts = manifest["Artifacts"]
        api.need(type(self.artifacts) is dict and self.artifacts, "nonempty reference seed artifacts required")
        for name, value in self.artifacts.items():
            api.portable_name(name)
            api.digest_text(value)
        api.same(self.artifacts.get("results.json"), RECEIPT_SHA256, "reference receipt/manifest binding")
        self.closure.tree(self.root, dict(self.artifacts, **{"artifacts.json": ARTIFACTS_SHA256}))
        self.inputs = self.closure.structured(self.root / "inputs.json", self.artifacts["inputs.json"])
        self.originals, self.captures = {}, {}
        rows, self.generated = self.inputs["Files"], self.inputs["Generated"]
        api.need(type(rows) is list and rows and type(self.generated) is dict and self.generated,
                 "complete reference input and generated-file records required")
        for row in rows:
            original, captured = api.regular(row["Original"]), api.regular(row["Captured"])
            api.need(original not in self.originals and captured.is_relative_to(self.root), "unique reference input identity")
            value = api.digest_text(row["Sha256"])
            self.member(captured, value)
            self.closure.read(original, value)
            self.originals[original] = row
            if captured in self.captures:
                api.same(self.captures[captured]["Sha256"], value, "shared reference capture bytes")
            self.captures[captured] = row
        for path, value in self.generated.items():
            self.member(path, api.digest_text(value))
        self.inventory = api.checked_path(self.result["SourceInventoryReceipt"])
        inventory_manifest = self.inventory / "artifacts.json"
        api.need(inventory_manifest in self.originals, "captured complete source inventory required")
        inventory_hash = self.originals[inventory_manifest]["Sha256"]
        inventory_files = self.closure.structured(inventory_manifest, inventory_hash)["Artifacts"]
        api.need(type(inventory_files) is dict and inventory_files, "nonempty source inventory closure")
        for name, value in inventory_files.items():
            path = api.regular(self.inventory / api.portable_name(name))
            api.need(path.is_relative_to(self.inventory) and path in self.originals, "omitted reference inventory input")
            api.same(self.originals[path]["Sha256"], api.digest_text(value), "reference inventory member hash")
        self.closure.tree(self.inventory, dict(inventory_files, **{"artifacts.json": inventory_hash}))
        self.output = api.checked_path(args.output_dir, must_exist=False)
        self.deny_output({api.REPO, self.root, self.inventory,
                          *(path.parent for path in self.originals), *(path.parent for path in self.captures),
                          *(api.regular(path).parent for path in self.generated)})
        self.validate_scope()
        self.buffers = {path: self.closure.read(path, row["Sha256"]) for path, row in self.captures.items()
                        if path.suffix == ".py"}
        loader_path = api.regular(api.REPO / LOADER)
        loader_data = self.closure.read(loader_path, LOADER_SHA256)
        self.buffers[loader_path] = loader_data
        loader = api.load_buffer("cm3_reference_lto_immutable_loader", loader_path, loader_data)
        self.frozen = loader.FrozenSources(self.buffers)
        self.loader_evidence = dict(Path=str(loader_path), Sha256=api.sha(loader_data))
        self.native = self.module(CLASSIC + "run.py")
        self.recipe, self.model = self.module(RECIPE), self.module(MODEL)
        self.process, self.reference_recipe = self.module(PROCESS), self.module(REFERENCE)
        self.validate_inventory()
        self.validate_commands()
        self.validate_reference()
        self.validate_recipe()
        self.validate_sources()
        self.validate_links()
        self.validate_prelink()
        self.closure.read(Path(__file__))
        self.closure.read(api.__file__)
        self.interpreter = api.regular(self.native.interpreter_path())
        self.closure.read(self.interpreter)
        self.deny_output({self.tool_root, self.interpreter.parent, self.reference_root, loader_path.parent,
                          api.regular(api.__file__).parent, api.regular(__file__).parent})
        self.closure.close()

    def deny_output(self, roots):
        self.api.need(not self.output.exists() and all(not self.output.is_relative_to(root)
            and not root.is_relative_to(self.output) for root in roots), "fresh output overlaps authenticated reference inputs")

    def member(self, path, expected=None):
        api = self.api
        path = api.regular(path)
        api.need(path.is_relative_to(self.root), "reference seed artifact escaped root")
        value = self.artifacts[path.relative_to(self.root).as_posix()]
        api.digest_text(value)
        if expected is not None:
            api.same(value, api.digest_text(expected), "reference artifact/row binding")
        return self.closure.read(path, value)

    def distinct(self, paths, message):
        paths = [self.api.regular(path) for path in paths]
        self.api.need(len(set(paths)) == len(paths) and all(not path.samefile(other)
            for index, path in enumerate(paths) for other in paths[:index]), message)

    def module(self, relative):
        api = self.api
        api.portable_name(relative)
        path = api.regular(self.root / "source" / relative)
        api.need(path in self.captures and api.regular(self.captures[path]["Original"]) == api.regular(api.REPO / relative),
                 "executed reference helper original identity")
        immutable = {stable_path(selected): data for selected, data in self.buffers.items()}

        def buffer_read(selected):
            key = stable_path(selected)
            api.need(key in immutable, "helper read outside authenticated immutable buffers")
            return immutable[key]

        with self.frozen.active(), patch.object(Path, "read_bytes", buffer_read):
            return self.frozen.load("cm3_reference_lto_seed_" + api.sha(relative.encode("ascii"))[:16], path)

    def validate_scope(self):
        api, r = self.api, self.result
        api.same([r.get(key) for key in ("Verdict", "Profile", "Mode", "Cohort", "SourceGroup", "ReferenceCommit", "Linkage", "ProofScope")],
            ["REFERENCE-CM3-FINAL-TWIN-BUILD-PASS", "CM3", "O2", COHORT, "CM3", PIN, "direct",
             "PINNED_REFERENCE_CM3_THREE_OWNING_PRELINK_ROOTS_AND_DIRECT_TWINS_ONLY"], "exact ordinary reference seed scope")
        api.need(r.get("Error") is None, "reference seed error")
        for key in ("ArtifactSealVerified", "ReferenceBuilt", "ReferenceClosingIdentityVerified", "PrelinkOwnObjectsOnly",
                    "TwinLoadImageIdentical", "TwinAllocatedSectionsIdentical", "DeclaredVTOR"):
            api.need(r.get(key) is True, "literal true reference seed fact: " + key)
        for key in ("LTO", "NativeBuilt", "RequiredCellSatisfied", "FinalElfProof", "FinalRootRelocationProof",
                    "FinalReferenceParity", "CompleteObjectProof", "PolicyEquivalence", "CpuExecution", "BoardExecution",
                    "GlobalFreezeQualified", "SchedulerSemanticsProven", "CSourceSemanticProof", "ReferenceKernelAvailable",
                    "HandlerRoutingProven", "UnreachabilityProven"):
            api.need(r.get(key) is False, "literal false reference seed scope: " + key)
        api.same([r["TranslationUnits"], r["FinalExecutableLinks"], r["RequiredCellsSatisfied"], r["ClosedPrelinkBodies"],
                  r["SchedulerThreshold"], r["FixtureHandlerInstallationCheck"], r["RecipeVersion"], r["InputDrift"], r["FPPolicy"]],
                 [4, 2, 0, 3, 16, 1, 1, [], "NOT-APPLICABLE-NO-FPU"], "exact reference seed counters/configuration")
        api.same([row["Stage"] for row in r["ObjectChecks"]], list(CHECKPOINTS), "seven ordered reference object checkpoints")
        api.need(all(row["Status"] == "PASS" and row["Error"] is None for row in r["ObjectChecks"]), "reference object checkpoint failure")
        api.digest_text(r["SourceInventorySha256"])

    def validate_inventory(self):
        api = self.api
        gate = self.module(INVENTORY)
        bundle = gate.Bundle(self.inventory)
        manifest = gate.captured_inventory(bundle)
        api.same(bundle.result["SourceInventorySha256"], self.result["SourceInventorySha256"], "reference source inventory fingerprint")
        self.artifact = self.result["CohortArtifact"]
        self.model.require_cohort(self.artifact, COHORT)
        selected = self.native.require_manifest_selection(manifest, "CM3", "O2", self.model)
        api.same(self.artifact, selected, "reference artifact must be the unique captured inventory artifact")
        self.inventory_gate = gate

    def expect(self, label, argvs):
        selected = [(index, command) for index, command in enumerate(self.commands) if command["Label"] == label]
        self.api.same([command["Argv"] for _, command in selected], argvs, "exact reference seed command: " + label)
        self.validated_commands.update(index for index, _ in selected)
        return selected

    def stdout(self, index):
        return self.member(self.root / ("command-%04d.stdout" % index))

    def validate_commands(self):
        api = self.api
        self.commands, self.validated_commands, self.workers = self.result["Commands"], set(), {}
        api.need(type(self.commands) is list and len(self.commands) == 71, "exact 71 reference seed commands required")
        self.sources = self.result["Sources"]
        api.need(type(self.sources) is list and len(self.sources) == 4, "four reference source records required")
        api.same([row["Source"] for row in self.sources], [str(self.root / name) for name in SOURCES], "four ordered reference sources")
        compilers = set()
        for index, command in enumerate(self.commands):
            api.need(command["Status"] == "PASS" and type(command["Exit"]) is int and command["Exit"] == 0
                and command["TimedOut"] is False and command["Error"] is None and command["Cwd"] == str(self.root)
                and type(command["Label"]) is str and command["Label"] and type(command["Argv"]) is list
                and command["Argv"] and all(type(value) is str and value for value in command["Argv"]),
                "successful complete reference command record required")
            api.same(self.closure.structured(self.root / ("command-%04d.json" % index)), command, "saved reference command record")
            self.stdout(index)
            self.member(self.root / ("command-%04d.stderr" % index))
            api.need(api.regular(command["Argv"][0]) in self.originals, "reference command executable capture required")
            if "-c" in command["Argv"] and any(row["Source"] in command["Argv"] for row in self.sources):
                compilers.add(api.regular(command["Argv"][0]))
        api.need(len(compilers) == 1, "one source-bound reference compiler required")
        self.gcc = next(iter(compilers))
        self.tool_root = self.gcc.parent.parent
        api.need(sum(command["Argv"][0] == str(self.gcc) and "-c" in command["Argv"] for command in self.commands) == 4,
                 "exact four actual compiler invocations; Git config is not compilation")
        for name in WORKERS:
            selected = self.expect("resolve " + name, [[str(self.gcc), "-print-prog-name=" + name]])
            path = api.regular(self.stdout(selected[0][0]).decode("utf-8").strip())
            api.need(path in self.originals and path.is_relative_to(self.tool_root), "captured toolchain worker required")
            self.workers[name] = path
        for label, flags, expected in (("compiler version", ["-dumpfullversion"], b"14.3.1"),
                                       ("compiler target", ["-dumpmachine"], b"arm-none-eabi"),
                                       ("compiler specs", ["-dumpspecs"], None)):
            selected = self.expect(label, [[str(self.gcc), *flags]])
            output = self.stdout(selected[0][0])
            api.need(output.strip() == expected if expected is not None else bool(output), "exact compiler identity: " + label)
        plugins = [path for path in self.originals if path.is_relative_to(self.tool_root)
                   and re.fullmatch(r"liblto_plugin(?:-[0-9]+)?\.dll", path.name, re.IGNORECASE)]
        api.need(len(plugins) == 1, "one captured reference LTO plugin required")
        self.plugin = plugins[0]
        for directory in {path.parent for path in self.originals if path.suffix.lower() == ".exe" and path.is_relative_to(self.tool_root)}:
            api.need({api.regular(path) for path in directory.glob("*.dll")} <= set(self.originals), "complete tool DLL input coverage")
        api.need(api.regular(self.result["Interpreter"]["ModulePath"]) in self.originals, "recorded reference interpreter capture")
        parser = {self.root / name for name in self.artifacts if name.startswith("python/elftools/")}
        api.need(parser and parser <= set(self.captures), "complete captured reference parser inputs")

    def validate_reference(self):
        api, r = self.api, self.result
        bindings = r["ReferenceFileBindings"]
        api.need(type(bindings) is list and len(bindings) == 23 and len({row["Path"] for row in bindings}) == 23,
                 "exact 23 unique pinned reference file bindings")
        revs = [(index, command) for index, command in enumerate(self.commands) if command["Label"] == "reference git rev-parse"]
        api.need(len(revs) == 2 and len(revs[0][1]["Argv"]) == 8 and revs[0][1]["Argv"][4] == "-C", "opening/closing Git identity commands")
        self.reference_root = api.checked_path(revs[0][1]["Argv"][5])
        git = api.regular(revs[0][1]["Argv"][0])
        api.need(git in self.originals and not git.is_relative_to(self.reference_root), "captured external Git executable")
        prefix = [str(git), "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(self.reference_root)]
        self.expect("git version", [[str(git), "--version"]])
        for label, tail, expected in (("reference git rev-parse", ["rev-parse", "HEAD"], PIN.encode("ascii")),
                                       ("reference git status", ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"], b"")):
            for index, _ in self.expect(label, [[*prefix, *tail], [*prefix, *tail]]):
                api.need(self.stdout(index).strip() == expected, "opening/closing pinned clean reference identity")
        self.expect("reference git show", [[*prefix, "show", PIN + ":" + row["Path"]] for row in bindings])
        show_rows = [index for index, command in enumerate(self.commands) if command["Label"] == "reference git show"]
        paths = set()
        for row, command_index in zip(bindings, show_rows):
            relative = row["Path"]
            api.portable_name(relative)
            api.need(relative in (PORT, PORTMACRO) or re.fullmatch(r"include/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+[.]h", relative),
                     "bounded reference source/header path")
            original, captured, blob = (api.regular(row[key]) for key in ("Original", "Captured", "GitBlob"))
            api.need(original == self.reference_root / relative and captured == self.root / "freertos" / relative
                     and blob == self.root / "reference-blobs" / relative and captured in self.captures
                     and original in self.originals and self.captures[captured]["Original"] == str(original), "exact reference path roles")
            api.same(self.originals[original]["Sha256"], row["WorktreeSha256"], "worktree/reference input binding")
            actual = self.closure.read(original, api.digest_text(row["WorktreeSha256"]))
            api.need(self.member(captured, row["WorktreeSha256"]) == actual, "reference worktree/captured bytes differ")
            raw = self.member(blob, api.digest_text(row["GitBlobSha256"]))
            api.need(self.stdout(command_index) == raw, "pinned Git show stdout/blob binding")
            comparison = self.inventory_gate.inventory.reference_bytes_match(actual, raw)
            api.same(comparison, row["ByteComparison"], "exact or documented LF/CRLF byte comparison")
            api.same(self.generated[str(blob)], row["GitBlobSha256"], "generated raw reference blob binding")
            paths.add(relative)
        api.need({PORT, PORTMACRO} <= paths and set(api.files_under(self.root / "freertos")) == paths,
                 "complete selected reference source/header membership")

    def validate_recipe(self):
        api, r = self.api, self.result
        self.fixture = self.root / "source" / FIXTURE
        self.script = api.regular(self.fixture / "link.ld")
        binding = self.recipe.reference_recipe(self.artifact, "O2", self.fixture, self.root / "freertos")
        api.same([binding["PortmacroProvider"], binding["ExtraIncludes"], binding["WitnessKind"], binding["ExactTargetRecipe"]],
                 [PORTMACRO, [], "none", True], "exact no-FP reference recipe")
        self.flags = binding["Flags"]
        config = self.reference_recipe.configuration_text(binding["ConfigText"])
        api.same([r["CompileFlags"], r["ConfigText"], r["BaseConfig"], r["PortmacroProvider"], r["RecipeDifferences"]],
                 [self.flags, config, BASE_CONFIG, PORTMACRO, binding["Differences"]], "bound generated reference recipe")
        config_path, base = self.fixture / "FreeRTOSConfig.h", self.fixture / "freeze_base_FreeRTOSConfig.h"
        api.need(self.member(config_path) == config.encode("ascii") and str(config_path) in self.generated,
                 "exact generated threshold/assertion/handler-installation configuration")
        api.need(base in self.captures and self.captures[base]["Original"] == str(api.REPO / BASE_CONFIG), "copied base config original identity")
        base_bytes = self.member(base, self.captures[base]["Sha256"])
        assertions = re.findall(rb"(?m)^#define configASSERT\(x\) (.+)\r?$", base_bytes)
        api.need(len(assertions) == 1 and assertions[0].rstrip(b"\r") == b"do { if (!(x)) { for (;;) { } } } while (0)",
                 "unchanged inline fail-stop configASSERT required")
        fixture_names = {"reference.h", "providers.c", "consumer.c", "startup.S", "link.ld", "FreeRTOSConfig.h", "freeze_base_FreeRTOSConfig.h"}
        api.need(set(api.files_under(self.fixture)) == fixture_names, "exact reference fixture/header members")
        for name in ("reference.h", "providers.c", "consumer.c", "startup.S", "link.ld"):
            path = self.fixture / name
            api.need(path in self.captures and self.captures[path]["Original"] == str(api.REPO / FIXTURE / name), "reference fixture capture identity")
            self.member(path, self.captures[path]["Sha256"])
        generated = {str(config_path), *(row["GitBlob"] for row in r["ReferenceFileBindings"])}
        api.need(set(self.generated) == generated, "exact generated raw-blob/config inventory")

    def dependencies(self, path, index):
        text = self.member(path).decode("utf-8").replace("\\\r\n", "").replace("\\\n", "")
        target, separator, prerequisites = text.partition(": ")
        self.api.need(separator and target == "pilot-source-" + str(index), "bound reference dependency target")
        tokens = re.findall(r"(?:\\[ \t#]|[^\s])+", prerequisites)
        self.api.need(tokens, "nonempty actual reference dependencies")
        return {self.api.regular(re.sub(r"\\([ \t#])", r"\1", token)) for token in tokens}

    def inspect(self, path):
        for tool, flags, suffix in (("objdump", ["-drwC", "-Mreg-names-std"], ".dis"),
                                    ("readelf", ["-hASsrW", "-lW"], ".readelf"),
                                    ("readelf", ["-A"], ".attributes"),
                                    ("nm", ["-P", "-S", "--defined-only"], ".nm")):
            executable = self.api.regular(self.gcc.with_name("arm-none-eabi-" + tool + ".exe"))
            self.api.need(executable in self.originals, "captured reference inspector")
            selected = self.expect("inspect " + path.name + suffix, [[str(executable), *flags, str(path)]])
            data = self.member(path.with_suffix(suffix))
            self.api.need(data == self.stdout(selected[0][0]), "inspector stdout/sidecar binding")
            if suffix == ".attributes":
                self.model.require_attributes(data.decode("utf-8"))

    def validate_sources(self):
        api = self.api
        sources, objects = [], []
        for index, row in enumerate(self.sources):
            source = api.regular(row["Source"])
            obj = self.root / "objects" / ("%02d-" % index + source.stem + ".o")
            api.same(row["Object"], str(obj), "fixed reference object role")
            api.need(source in self.captures and row["CompileDependenciesVerified"] is True, "reference source/dependency capture")
            flags = [*self.artifact["compile_flags"], "-O2", "-g0"] if index == 3 else self.flags
            api.same(row["CompileFlags"], flags, "exact per-source reference flags")
            dependencies = row["Dependencies"]
            api.need(type(dependencies) is list and dependencies, "nonempty reference dependency metadata")
            api.same(row["ActualCompileDependencies"], dependencies, "reference actual/discovery dependency equality")
            expected = set()
            for dependency in dependencies:
                api.need(type(dependency) is dict and set(dependency) == {"Path", "Sha256"}, "exact dependency row")
                path, value = api.regular(dependency["Path"]), api.digest_text(dependency["Sha256"])
                api.need(path not in expected and (path in self.captures or path in self.originals or str(path) in self.generated),
                         "unique fully captured reference dependency")
                expected.add(path)
                self.closure.read(path, value)
            self.reference_recipe.require_dependency_roles(expected, source, self.fixture, self.root / "freertos")
            discovery, actual = obj.with_suffix(".discovery.d"), obj.with_suffix(".compile.d")
            api.same([row["DiscoveryDependencyFile"], row["CompileDependencyFile"]], [str(discovery), str(actual)], "fixed raw dependency file roles")
            api.need(self.dependencies(discovery, index) == self.dependencies(actual, index) == expected,
                     "raw discovery/actual files must reproduce complete declared physical dependency membership")
            self.expect("discover " + source.name, [[str(self.gcc), *flags, "-M", "-MF", str(discovery),
                "-MT", "pilot-source-" + str(index), str(source)]])
            self.expect("compile " + source.name, [[str(self.gcc), *flags, "-MD", "-MF", str(actual),
                "-MT", "pilot-source-" + str(index), "-c", str(source), "-o", str(obj)]])
            self.member(source, row["SourceSha256"])
            self.member(obj, row["ObjectSha256"])
            self.inspect(obj)
            sources.append(source)
            objects.append(obj)
        self.distinct([*sources, *objects], "eight physically distinct reference source/object roles")
        api.same(self.result["FrozenObjectHashes"], {str(path): row["ObjectSha256"] for path, row in zip(objects, self.sources)},
                 "all four frozen reference object hashes")

    def validate_links(self):
        api, r = self.api, self.result
        api.same([row["Kind"] for row in r["Links"]], ["ordinary", "emit-relocs"], "two ordered ordinary reference twins")
        roles = [self.script, *(row["Source"] for row in self.sources), *(row["Object"] for row in self.sources)]
        for link in r["Links"]:
            kind = link["Kind"]
            api.same([link["Path"], link["Map"]], [str(self.root / (kind + ".elf")), str(self.root / (kind + ".map"))], "fixed reference ELF/map roles")
            flags = [str(self.gcc), *self.artifact["compile_flags"], "-O2", "-nostdlib", api.LINK_OPTIONS,
                     "-T", str(self.script), *(row["Object"] for row in self.sources)]
            if kind == "emit-relocs":
                flags.append("-Wl,--emit-relocs")
            flags.extend(("-Wl,-Map=" + link["Map"], "-o", link["Path"]))
            self.expect("link " + kind, [flags])
            self.member(link["Path"], link["Sha256"])
            self.member(link["Map"], link["MapSha256"])
            self.inspect(Path(link["Path"]))
            roles.extend((link["Path"], link["Map"]))
        self.distinct(roles, "physically distinct reference providers, script, final twins and maps")
        api.same(r["FinalStructuralChecks"], [dict(Path=row["Path"], LocalFirstStartBinding="STB_LOCAL",
            LocalFirstStartSize=32, FinalRootRelocationProof=False) for row in r["Links"]], "bounded reference final structural records")
        labels = ["git version", "reference git rev-parse", "reference git status", *(["reference git show"] * 23),
                  "compiler version", "compiler target", "compiler specs", *("resolve " + name for name in WORKERS)]
        for row in self.sources:
            source, obj = Path(row["Source"]), Path(row["Object"])
            labels.extend(("discover " + source.name, "compile " + source.name))
            labels.extend("inspect " + obj.name + suffix for suffix in (".dis", ".readelf", ".attributes", ".nm"))
        for row in r["Links"]:
            labels.append("link " + row["Kind"])
            labels.extend("inspect " + Path(row["Path"]).name + suffix for suffix in (".dis", ".readelf", ".attributes", ".nm"))
        labels.extend(("reference git rev-parse", "reference git status"))
        api.same([row["Label"] for row in self.commands], labels, "all 71 ordered reference commands")
        api.need(self.validated_commands == set(range(len(self.commands))), "every reference command must have an exact argv contract")

    def validate_prelink(self):
        api, r = self.api, self.result
        checker = self.module("tools/fixtures/cm3_freeze_parity/check.py")
        api.same(tuple(checker._REFERENCE), ROOTS, "fixed source-transcribed reference protocol roots")
        expected = [dict(Side="Reference", Name=name, Tokens=len(checker._REFERENCE[name]), LiteralIslands=1, TailNops=0,
            BodySha256=api.sha(json.dumps(checker._REFERENCE[name], separators=(",", ":")).encode("ascii"))) for name in ROOTS]
        api.same(r["PrelinkReferenceRoots"], expected, "three recorded complete reference O2 protocols")
        api.same(r["PrelinkReferenceProtocolScope"], "THREE_REFERENCE_OWNING_OBJECT_ROOTS_ONLY_NOT_FINAL_RELOCATION_PROOF", "reference prelink scope")
        api.same(r["PrelinkRelAuthority"], [row["Object"] for row in self.sources], "four actual prelink providers")
        for name, size, binding in ((ROOTS[0], 32, "STB_LOCAL"), (ROOTS[1], 36, "STB_GLOBAL"), (ROOTS[2], 68, "STB_GLOBAL")):
            owner, source = r["PrelinkReferenceOwners"][name], self.sources[0]
            api.same([owner[key] for key in ("Source", "SourceSha256", "Object", "ObjectSha256", "Kind", "Binding", "Offset", "Size", "Section")],
                [source["Source"], source["SourceSha256"], source["Object"], source["ObjectSha256"], "STT_FUNC", binding, 0, size, ".text." + name],
                "actual port.c owns each reference prelink root")
            section = owner["OwningSection"]
            api.same([section[key] for key in ("Name", "Size", "RootOffset", "RootSize", "WholeSectionRecorded", "SymbolExtentUnchanged", "AppliedRelocationProof")],
                     [owner["Section"], size, 0, size, True, True, False], "complete ordinary owning-section record")
            api.digest_text(section["Sha256"])
            api.same(section["RootRawBytesSha256"], section["Sha256"], "exact zero-offset whole-section/root raw hash")
