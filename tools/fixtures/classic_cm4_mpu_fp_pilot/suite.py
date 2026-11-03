"""Actual protected FP pilot builds, execution, and FAIL-first closing."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import struct

from cm4_mpu_basic_engine import COHORT, pilot, fp, common, need, save, digest, load
from cm4_mpu_basic_suite import BasicGrid
import cm4_mpu_fp_checks as checks
from cm4_mpu_fp_contracts import MUTATIONS, parse_actual, validate, control_tests

HERE = Path(__file__).resolve().parent
BASIC = HERE.parent / "classic_cm4_mpu_basic_grid"
PORT = "fiber/port/ARM_CM4_MPU"
EXPECTED_CODEGEN = {"omit-high-save": "FP_HIGH_SAVE", "omit-high-restore": "FP_HIGH_RESTORE",
                    "omit-low-save": "FP_LOW_SAVE", "omit-low-restore": "FP_LOW_RESTORE",
                    "corrupt-fpscr-save": None}


class FpPilot(BasicGrid):
    def __init__(self, args):
        super().__init__(args)
        self.fixture = HERE
        self.references, self.associations, self.controls = [], [], []
        self.workers, self.plugin = {}, None
        self.report = dict(Verdict="FAIL", Error=None, CompleteSuite=False, RequestedInventoryComplete=False,
                           Scope="CM4/AN386 MPU8 O2 direct hard-FP eager/lazy FP-active pilot only",
                           Execution="NOT_RUN", CompileOnly=not args.execute_pilot, Rows=self.rows,
                           Controls=self.controls, References=self.references, Associations=self.associations,
                           Commands=self.commands, Repository=str(self.repo), BuildRoot=str(self.build),
                           ReferenceExecuted=False, NewFinalReferenceParity=False,
                           ArtifactsVerifiedBeforePass=False, CaptureManifest=args.capture_manifest,
                           PreSaveLspactObserved=False)

    def preflight(self):
        common.Suite.preflight(self)
        gcc = self.tools["gcc"]
        self.plugin = Path(self.command([gcc, "-print-file-name=liblto_plugin.dll"],
                                        "resolve explicit plugin")["Stdout"].strip()).resolve(strict=True)
        self.enroll(self.plugin, "ExplicitLTOPlugin")
        for name in ("nm", "ar"):
            self.tools[name] = (gcc.parent / ("arm-none-eabi-" + name + ".exe")).resolve(strict=True)
            self.enroll(self.tools[name], "ActualNativeInspectionTool")
            self.command([self.tools[name], "--version"], "explicit native " + name)
        for name in ("cc1", "as", "collect2", "ld", "lto1", "lto-wrapper"):
            value = self.command([gcc, "-print-prog-name=" + name], "resolve compiler delegate " + name)["Stdout"].strip()
            need(Path(value).is_absolute(), "Absolute compiler delegate required")
            path = Path(value).resolve(strict=True)
            self.enroll(path, "ActualCompilerDelegate")
            self.workers[name] = dict(Path=str(path), Sha256=digest(path))
        self.report["ExplicitTools"] = dict(CompilerWorkers=self.workers,
            NativeNM=dict(Path=str(self.tools["nm"]), Sha256=digest(self.tools["nm"])),
            NativeAR=dict(Path=str(self.tools["ar"]), Sha256=digest(self.tools["ar"])),
            Plugin=dict(Path=str(self.plugin), Sha256=digest(self.plugin)))
        self.report["CheckerControls"] = checks.self_controls()
        self.report["ContractControls"] = control_tests()
        save(self.build / "inputs.before.json", list(self.inputs.values()))

    def flags_for(self, consumer, lazy, model=False):
        values = pilot.Pilot.flags(self, consumer, 0, model)
        need(values.count("-DFIBER_FPU_LAZY=0") == 1, "Inherited policy flag changed")
        return ["-DFIBER_FPU_LAZY=" + str(int(lazy)) if value == "-DFIBER_FPU_LAZY=0" else value
                for value in values] + ["-DPILOT_LAZY=" + str(int(lazy))]

    def mutate(self, original, mutation, directory):
        text = original.read_text()
        anchor = "void PendSV_Handler(void)"
        need(text.count(anchor) == 1, "Exact subject handler mutation boundary")
        head, body = text.split(anchor)
        replacements = {
            "omit-high-save": ("vstmiaeq r1!, {s16-s31}", "addeq.w r1, r1, #64"),
            "omit-high-restore": ("vldmdbeq r1!, {s16-s31}", "subeq.w r1, r1, #64"),
            "omit-low-save": ("vstmiaeq r1!, {s0-s16}", "addeq.w r1, r1, #68"),
            "omit-low-restore": ("vstmiaeq r0!, {s0-s16}", "addeq.w r0, r0, #68"),
        }
        if mutation in replacements:
            before, after = replacements[mutation]
            need(body.count(before) == 1, "Exact FP omission instruction")
            body = body.replace(before, after)
        else:
            need(mutation == "corrupt-fpscr-save", "Unknown mutation")
            pattern = r'("vstmiaeq r1!, \{s0-s16\}\s+\\n")'
            append = '\n"movw r12, #0 \\n"\n"movt r12, #128 \\n"\n"it eq \\n"\n"streq r12, [r1, #-4] \\n"'
            body, count = re.subn(pattern, lambda m: m.group(1) + append, body)
            need(count == 1, "Exact saved-FPSCR corruption site")
        target = directory / "mutant-fiber_port.c"
        target.write_text(head + anchor + body, encoding="ascii", newline="\n")
        self.generated[str(target.resolve())] = dict(Path=str(target.resolve()), Sha256=digest(target),
                                                   Role="CompiledProtectedFpMutation")
        save(directory / "mutation.json", dict(Name=mutation, Original=str(original), OriginalSha256=digest(original),
             Mutated=str(target), MutatedSha256=digest(target), PreservesCursorGeometry=True,
             Scope="Actual copied backend instruction omission/corruption; not an executed reference"))
        return target

    def compile_subject(self, sources, providers, directory, flags, mutation):
        objects, maps = [], []
        for index, original in enumerate(sources):
            need(str(original.resolve()) in self.inputs, "Source must be captured before compile")
            source = self.mutate(original, mutation, directory) if mutation and original == providers[0] else original
            obj = directory / ("%02d-" % index + original.stem + ".o")
            dep = obj.with_suffix(".d")
            command = self.command([self.tools["gcc"], *flags, "-I" + str(original.parent), "-MD", "-MF", dep,
                                    "-c", source, "-o", obj], "compile actual FP pilot source")
            need("warning:" not in command["Stderr"], "Compiler warning in FP pilot")
            self.dependency_check(dep)
            role = "port" if original in providers else "fixture" if original.parent in (HERE, BASIC) else "common"
            if original.name == "fiber_port_context_cohort_expectation.c":
                role = "expectation"
            maps.append(dict(Original=str(original), Compiled=str(source), SourceSha256=digest(source),
                             Object=str(obj), ObjectSha256=digest(obj), Role=role, Command=command["Record"]))
            objects.append(obj)
        save(directory / "source-object-map.json", maps)
        return objects, maps

    def audit_subject(self, image, consumer, proof, model):
        words = struct.unpack("<256I", image.sections[".isr_vector"]["Data"])
        need(image.sections[".boot_vectors"]["Address"] == 0 and image.sections[".boot_vectors"]["Size"] == 8 and
             image.sections[".isr_vector"]["Address"] == 0x400 and image.sections[".isr_vector"]["Size"] == 1024 and
             image.sections[".privileged_code"]["Address"] == 0x800 and
             struct.unpack("<2I", image.sections[".boot_vectors"]["Data"]) == words[:2] and
             words[0] == 0x20010000 and words[1] == image.symbol("Reset_Handler", "STT_FUNC")["Address"],
             "Exact FP pilot bootstrap/vector geometry")
        need(fp.capability_matches(fp.CM4, image.path.with_suffix(".readelf.txt").read_text(), pilot.CPU),
             "Exact CM4 hard-FP capability")
        if model:
            return dict(ModelProbe=True, RuntimeProviders=False)
        for name in (*common.PUBLIC, *common.FORWARD, "SVC_Handler", "PendSV_Handler"):
            image.symbol(name, "STT_FUNC")
        need(words[11] == image.symbol("SVC_Handler")["Address"] and words[14] == image.symbol("PendSV_Handler")["Address"]
             and words[11] & words[14] & 1, "Actual strong Thumb vectors")
        for name, role in ((common.SLOT, "state"), (common.REVERSE, "state"),
                           (common.CONFIG_ANCHOR, "optional_configuration")):
            if name == common.CONFIG_ANCHOR and consumer == "context":
                need(name not in image.symbols, "Context acquired configuration provider")
                continue
            symbol = image.symbol(name, "STT_OBJECT")
            need(symbol["Size"] > 0 and name in proof and
                 proof[name]["Source"] == str(self.reader.get_runtime_source_paths(self.repo, (role,))[0]),
                 "Actual common-private prelink owner")
        slot = image.symbol(common.SLOT, "STT_OBJECT")
        need(slot["Address"] == 0x20000000 and slot["Size"] == 4 and
             image.sections[".current_slot"]["Size"] == 32, "Exact privileged current aperture")
        cohorts = [name for name in image.symbols if name.startswith("fiber_port_context_cohort_arm")]
        need(cohorts == [COHORT], "Exact MPU8 FP context cohort")
        image.symbol(pilot.STORAGE, "STT_OBJECT")
        expectation = image.sections[".fiber_port_context_cohort_expectation"]
        count = 3 if consumer == "fiber" else 2
        need(expectation["Size"] == count * 4 and not expectation["Flags"] & 5 and
             Counter(struct.unpack("<" + str(count) + "I", expectation["Data"])) ==
             Counter({image.symbol(COHORT)["Address"]: 1, image.symbol(pilot.STORAGE)["Address"]: count - 1}),
             "Exact readonly context/storage expectations")
        roots = image.symbol("fixture_public_api_roots", "STT_OBJECT")
        names = (("fiber_v1_init", "fiber_v1_current", "fiber_v1_set_scheduler", "fiber_v1_start", "fiber_v1_yield")
                 if consumer == "fiber" else common.PUBLIC)
        need(roots["Size"] == 20 and not image.sections[roots["Section"]]["Flags"] & 1 and
             struct.unpack("<5I", image.bytes(roots)) == tuple(image.symbol(n, "STT_FUNC")["Address"] for n in names),
             "Actual five-operation public roots")
        need(not set(common.LEGACY) & set(image.symbols), "Legacy provider substitution")
        if consumer == "context":
            need(not any(n.startswith("fiber_v1_") for n in image.symbols), "Context acquired Fiber")
        workers = image.symbol("workers", "STT_OBJECT", local=True)
        need(0x20008000 <= workers["Address"] < workers["Address"] + workers["Size"] <= 0x2000e000,
             "Context metadata must remain privileged")
        for index, address in enumerate((0x20002000, 0x20004000, 0x20006000)):
            section = image.sections[".stack" + str(index)]
            need(section["Address"] == address and section["Size"] == 4096, "Three disjoint user stacks")
        schedule = [i for i in image.body("fiber_port_runtime_schedule") if not image.is_data(i, "fiber_port_runtime_schedule")]
        need(len(schedule) == 2 and schedule[0]["Mnemonic"] == "svc" and
             re.fullmatch(r"#?(?:71|0x0*47)", schedule[0]["Operands"].split("@", 1)[0].strip()) and
             schedule[1]["Mnemonic"] == "bx" and schedule[1]["Operands"].strip() == "lr", "Real naked SVC71 primitive")
        probe_symbol = image.symbol("fixture_fp_probe", "STT_FUNC")
        probe = [i for i in image.body("fixture_fp_probe") if not image.is_data(i, "fixture_fp_probe")]
        need(0x10000 <= (probe_symbol["Address"] & ~1) < 0x20000 and
             all(0x10000 <= i["Address"] < 0x20000 for i in probe), "User-executable assembly oracle")
        for site, target in (("fixture_fp_public_call", "fixture_task_yield"),
                             ("fixture_fp_direct_call", "fiber_port_runtime_schedule")):
            address = image.symbol(site)["Address"] & ~1
            call = next((i for i in probe if i["Address"] == address), None)
            need(call is not None and call["Mnemonic"] == "bl" and
                 re.fullmatch(r"(?:0x)?[0-9a-f]+\s+<" + target + r">", call["Operands"]) is not None and
                 int(call["Operands"].split()[0], 16) == image.symbol(target)["Address"] & ~1,
                 "Actual assembly oracle call target: " + site)
        for name, values in (("fixture_gpr_seeds", tuple(0xa4000000 + w * 0x01000000 + r * 0x1111
                for w in range(3) for r in range(4, 12))),
                ("fixture_fp_seeds", tuple(v for w in range(2) for v in
                 [*(0x3f000000 + w * 0x01000000 + r * 0x00010101 for r in range(32)), w * 0x00400000]))):
            symbol = image.symbol(name, "STT_OBJECT")
            need(symbol["Size"] == len(values) * 4 and 0x10000 <= symbol["Address"] and
                 symbol["Address"] + symbol["Size"] <= 0x20000 and
                 not image.sections[symbol["Section"]]["Flags"] & 1 and
                 struct.unpack("<" + str(len(values)) + "I", image.bytes(symbol)) == values,
                 "Actual readonly distinct oracle payload: " + name)
        return dict(ActualProviders=True, ExactVectors=True, ContextCohort=COHORT,
                    ReturnPC=image.symbol("fiber_port_svc_return_return_site")["Address"],
                    PrivateOwners=proof, ThreePrivilegedContexts=True, LegacyAbsent=True,
                    OraclePayloadAndCallTargets=True)

    def build_subject(self, consumer, lazy, mutation=None, model=False):
        name = "model" if model else consumer + ("-lazy" if lazy else "-eager") + ("-" + mutation if mutation else "")
        directory = self.build / name
        directory.mkdir()
        providers = [self.repo / PORT / name for name in ("fiber_port.c", "fiber_port_boot.c")]
        roles = ("engine", "state", "panic") + (("optional_configuration",) if consumer == "fiber" else ())
        sources = [] if model else list(self.reader.get_runtime_source_paths(self.repo, roles))
        if consumer == "fiber" and not model:
            sources.append(self.repo / "fiber/lifecycle/fiber_v1.c")
        if not model:
            sources += providers + [self.repo / "fiber/port/fiber_port_context_cohort_expectation.c",
                                     HERE / "application.c", HERE / "fp_probe.S", BASIC / "api_roots.S"]
        sources += [BASIC / name for name in ("startup.S", "transport.c")]
        if model:
            sources.append(BASIC / "model.c")
        objects, maps = self.compile_subject(sources, providers, directory, self.flags_for(consumer, lazy, model), mutation)
        proof = {}
        if not model:
            state = str(self.reader.get_runtime_source_paths(self.repo, ("state",))[0])
            configuration = str(self.reader.get_runtime_source_paths(self.repo, ("optional_configuration",))[0])
            proof = self.audit_common_private(maps, {common.SLOT: state, common.REVERSE: state,
                     common.CONFIG_ANCHOR: configuration if consumer == "fiber" else None}, directory)
            self.audit_provider([Path(m["Object"]) for m in maps if m["Role"] == "port"], directory)
        elf = directory / "runtime.elf"
        self.command([self.tools["gcc"], *pilot.CPU, "-O2", "-nostdlib",
            "-Wl,--gc-sections,--no-undefined,--fatal-warnings,-z,noexecstack", "-Wl,-Map=" + str(directory / "runtime.map"),
            "-T", HERE / "link.ld", *objects, "-o", elf], "link actual protected FP pilot")
        self.dump(elf)
        image = fp.Image(elf, self.ELFFile)
        audit = self.audit_subject(image, consumer, proof, model)
        mechanism, rejection = None, None
        if not model:
            try:
                mechanism = checks.check_subject(image)
            except RuntimeError as failure:
                rejection = str(failure)
            need(rejection == EXPECTED_CODEGEN.get(mutation), "Wrong FP codegen discriminator: " + repr((mutation, rejection)))
        row = dict(Name=name, Consumer=consumer, Lazy=lazy, Mutation=mutation, Model=model,
                   Optimization="O2", LTO=False, Archive=False, Case=0, Elf=str(elf), ElfSha256=digest(elf),
                   Audit=audit, Mechanism=mechanism, CodegenRejection=rejection, Status="COMPILED", Executed=False)
        save(directory / "codegen-audit.json", row)
        print("COMPILED " + name, flush=True)
        return row

    def execute(self, row):
        need(self.a.execute_pilot and digest(row["Elf"]) == row["ElfSha256"], "Request/ELF execution identity")
        actual = self.command(["wsl.exe", "-d", self.a.wsl_distro, "--", "bash",
            self.wsl_path(self.repo / "tools/fixtures/arm_control/qemu.sh"), "run", self.a.qemu_root,
            self.wsl_path(Path(row["Elf"]).parent), "mps2-an386", self.wsl_path(row["Elf"]), "12"],
            "actual protected FP pilot " + row["Name"], timeout=25, expected=None)
        observed = parse_actual(actual, row)
        row.update(Actual=actual, Observed=observed, Executed=True,
                   Status="EXPECTED_FP_MISMATCH" if row["Mutation"] else "PASS")
        save(Path(row["Elf"]).parent / "execution.json", row)
        print(row["Status"] + " " + row["Name"], flush=True)

    def run(self):
        self.preflight()
        reference = self.build_reference("O2", False, False)
        reference_image = fp.Image(reference["Elf"], self.ELFFile)
        reference["FpMechanisms"] = checks.check_reference(reference_image)
        self.references.append(reference)
        self.report["ModelProbe"] = self.build_subject("context", False, model=True)
        for consumer in ("context", "fiber"):
            for lazy in (False, True):
                row = self.build_subject(consumer, lazy)
                self.rows.append(row)
                path = Path(row["Elf"]).parent / "reference-association.json"
                paired = self.pair(row, reference, path)
                self.associations.append(dict(Consumer=consumer, Lazy=lazy, SubjectElf=row["Elf"],
                    SubjectSha256=row["ElfSha256"], ReferenceElf=reference["Elf"], ReferenceSha256=reference["ElfSha256"],
                    Evidence=str(path), EvidenceSha256=digest(path), NamedMechanismResults=len(paired["Checks"]),
                    SubjectFp=row["Mechanism"], ReferenceFp=reference["FpMechanisms"], Executed=False))
        for lazy in (False, True):
            for mutation in MUTATIONS:
                self.controls.append(self.build_subject("context", lazy, mutation))
        if self.a.execute_pilot:
            for row in [self.report["ModelProbe"], *self.rows, *self.controls]:
                self.execute(row)

    def bind_artifacts(self):
        manifest = json.loads((self.build / "artifacts.json").read_text())
        rows = [self.report["ModelProbe"], *self.rows, *self.controls, *self.references]
        need(len(rows) == 16 and len({r["Elf"] for r in rows}) == 16, "Sixteen distinct ELF bindings")
        for row in rows:
            path = Path(row["Elf"]).resolve(strict=True)
            need(str(path) == row["Elf"] and path.is_relative_to(self.build) and path.is_file() and
                 digest(path) == row["ElfSha256"] == manifest["Artifacts"].get(path.relative_to(self.build).as_posix()),
                 "Actual ELF bytes/manifest binding")
        model = self.report["ModelProbe"]
        need(Path(model["Elf"]) == self.build / "model/runtime.elf", "Exact model artifact path")
        self.report["ModelArtifactBinding"] = dict(Verified=True, ArtifactRelative="model/runtime.elf",
            Elf=model["Elf"], ElfSha256=model["ElfSha256"], ManifestEntrySha256=model["ElfSha256"])
        for row in self.associations:
            path = Path(row["Evidence"]).resolve(strict=True)
            need(path.is_relative_to(self.build) and digest(path) == row["EvidenceSha256"] ==
                 manifest["Artifacts"].get(path.relative_to(self.build).as_posix()), "Association artifact drift")

    def finish(self, error):
        self.report.update(Error=error, Verdict="FAIL", RequestedInventoryComplete=False,
                           ArtifactsVerifiedBeforePass=False, InputCount=len(self.inputs))
        try:
            save(self.build / "results.json", self.report)
            if error is not None:
                raise RuntimeError("Prior failure: " + repr(error))
            self.close_identity()
            self.report["InputDrift"] = self.input_drift()
            need(not self.report["InputDrift"], "Input drift")
            save(self.build / "inputs.after.json", [dict(Path=p, Sha256=digest(p)) for p in self.inputs])
            save(self.build / "dependencies.json", self.dependencies)
            save(self.build / "generated-inputs.json", list(self.generated.values()))
            save(self.build / "results.json", self.report)
            self.artifact_manifest(verify=True)
            self.bind_artifacts()
            candidate = dict(self.report, Verdict="FP-PILOT-PASS" if self.a.execute_pilot else "COMPILE-PREFLIGHT-PASS",
                             Execution="FP_ACTIVE_PILOT" if self.a.execute_pilot else "NOT_RUN",
                             RequestedInventoryComplete=True, ArtifactsVerifiedBeforePass=True)
            validate(candidate, self.a.execute_pilot)
            self.report.update(candidate)
            save(self.build / "results.json", self.report)
            self.artifact_manifest(verify=True)
            self.bind_artifacts()
            need(not self.input_drift(), "Late input drift")
            return True
        except Exception as failure:
            self.report.update(Verdict="FAIL", RequestedInventoryComplete=False, ArtifactsVerifiedBeforePass=False,
                               Error=error if error is not None else "finalizer: " + type(failure).__name__ + ": " + str(failure))
            save(self.build / "results.json", self.report)
            try:
                self.artifact_manifest(verify=False)
            except Exception as manifest_failure:
                self.report["FailureManifestError"] = str(manifest_failure)
                save(self.build / "results.json", self.report)
            return False
