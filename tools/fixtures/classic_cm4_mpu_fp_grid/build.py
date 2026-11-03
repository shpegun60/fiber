"""Actual subject builds for the separate protected CM4 FP grid."""
from pathlib import Path

from cm4_mpu_basic_engine import COHORT, common, digest, fp, need, pilot, save
from cm4_mpu_fp_suite import BASIC, EXPECTED_CODEGEN, HERE, PORT, FpPilot
import cm4_mpu_fp_checks as fpchecks


class ProvenPrivateLtoImage:
    """Reuse the established private-object policy without widening public ABI."""
    def __init__(self, image, lto, proof):
        self.image, self.lto, self.proof = image, lto, proof

    def __getattr__(self, name):
        return getattr(self.image, name)

    def symbol(self, name, kind=None, local=False):
        if name in common.COMMON_PRIVATE_OBJECTS:
            value = self.image.symbol(name, kind, local=True)
            need(value["Kind"] == "STT_OBJECT" and value["Size"] > 0 and name in self.proof and
                 common.binding_admitted(name, value["Kind"], value["Binding"], self.lto, self.proof),
                 "Prelink-owned private object required before final-LTO LOCAL admission")
            return value
        return self.image.symbol(name, kind, local=local)


class GridBuilds(FpPilot):
    def flags_for(self, consumer, lazy, opt, lto, model=False):
        need(opt in ("O2", "Os") and type(lto) is bool, "Supported FP grid compiler mode")
        flags = super().flags_for(consumer, lazy, model)
        need([flag for flag in flags if flag.startswith("-O")] == ["-O2"] and
             "-flto" not in flags and flags.count("-mgeneral-regs-only") == 1,
             "Inherited FP compiler optimization/GRO flags changed")
        return ["-" + opt if flag == "-O2" else flag for flag in flags] + (["-flto"] if lto else [])

    def build_subject(self, consumer, lazy, opt, lto, archive, mutation=None, model=False):
        need(consumer in ("context", "fiber") and type(lazy) is bool and
             opt in ("O2", "Os") and type(lto) is bool and type(archive) is bool and
             type(model) is bool and (mutation is None or mutation in EXPECTED_CODEGEN),
             "Supported FP grid subject key")
        need(not model or (consumer == "context" and lazy is False and opt == "O2" and
                           lto is False and archive is False and mutation is None),
             "One unchanged O2 native direct model image")
        name = ("model" if model else consumer + ("-lazy" if lazy else "-eager") + "-" + opt +
                ("-lto" if lto else "-native") + ("-archive" if archive else "-direct") +
                ("-" + mutation if mutation else ""))
        directory = self.build / name
        directory.mkdir()
        providers = [self.repo / PORT / filename for filename in ("fiber_port.c", "fiber_port_boot.c")]
        roles = ("engine", "state", "panic") + (("optional_configuration",) if consumer == "fiber" else ())
        sources = [] if model else list(self.reader.get_runtime_source_paths(self.repo, roles))
        if consumer == "fiber" and not model:
            sources.append(self.repo / "fiber/lifecycle/fiber_v1.c")
        if not model:
            sources += providers + [self.repo / "fiber/port/fiber_port_context_cohort_expectation.c",
                                     HERE / "application.c", HERE / "fp_probe.S", BASIC / "api_roots.S"]
        sources += [BASIC / filename for filename in ("startup.S", "transport.c")]
        if model:
            sources.append(BASIC / "model.c")
        flags = self.flags_for(consumer, lazy, opt, lto, model)
        objects, maps = self.compile_subject(sources, providers, directory, flags, mutation)
        proof = {}
        port_maps = [record for record in maps if record["Role"] == "port"]
        if not model:
            need([record["Original"] for record in port_maps] == [str(path) for path in providers],
                 "Exactly the two actual port provider inputs")
            state = str(self.reader.get_runtime_source_paths(self.repo, ("state",))[0])
            configuration = str(self.reader.get_runtime_source_paths(self.repo, ("optional_configuration",))[0])
            proof = self.audit_common_private(maps, {common.SLOT: state, common.REVERSE: state,
                     common.CONFIG_ANCHOR: configuration if consumer == "fiber" else None}, directory)
            self.audit_provider([Path(record["Object"]) for record in port_maps], directory)
        else:
            need(not port_maps, "Model must not acquire runtime providers")

        port_objects = [Path(record["Object"]) for record in port_maps]
        library, members = None, None
        if archive:
            need(len(port_objects) == 2 and len(set(port_objects)) == 2 and self.plugin is not None,
                 "Two distinct port objects and enrolled native AR plugin required")
            library = directory / "libactual-port.a"
            self.command([self.tools["ar"], "rcs", library, *port_objects],
                         "archive only actual FP port providers with explicit plugin")
            members = self.command([self.tools["ar"], "t", library],
                                   "verify exact native FP port archive members")["Stdout"].splitlines()
            need(members == [path.name for path in port_objects], "Exact ordered two-member FP port archive")
            linked = [obj for obj in objects if obj not in port_objects] + [library]
        else:
            linked = objects

        elf = directory / "runtime.elf"
        map_path = directory / "runtime.map"
        self.command([self.tools["gcc"], *pilot.CPU, "-" + opt, "-nostdlib", *(["-flto"] if lto else []),
            "-Wl,--gc-sections,--no-undefined,--fatal-warnings,-z,noexecstack", "-Wl,-Map=" + str(map_path),
            "-T", HERE / "link.ld", *linked, "-o", elf], "link actual protected FP grid subject")
        if archive:
            map_text = map_path.read_text()
            included = map_text.split("Discarded input sections", 1)[0]
            entries = [library.name + "(" + member + ")" for member in members]
            need("Archive member included to satisfy reference by file (symbol)" in included and
                 all(entry in included for entry in entries), "Both real port archive members extracted by final link")
            save(directory / "archive-proof.json", dict(Archive=str(library), ArchiveSha256=digest(library),
                ExpectedMembers=[path.name for path in port_objects], ActualMembers=members,
                ProviderInputs=port_maps, DirectInputs=[str(obj) for obj in objects if obj not in port_objects],
                FinalMap=str(map_path), FinalMapSha256=digest(map_path), ExtractedEntries=entries,
                LTO=lto, OnlyPortProvidersArchived=True))
        self.dump(elf)
        image = fp.Image(elf, self.ELFFile)
        audit = self.audit_subject(ProvenPrivateLtoImage(image, lto, proof), consumer, proof, model)
        if not model:
            need(audit["ContextCohort"] == COHORT, "Inherited FP context cohort audit")
            audit["FinalPrivateBindings"] = {name: image.symbol(name, "STT_OBJECT", local=True)["Binding"] for name in proof}
        mechanism, rejection = None, None
        if not model:
            try:
                mechanism = fpchecks.check_subject(image)
            except RuntimeError as failure:
                rejection = str(failure)
            need(rejection == EXPECTED_CODEGEN.get(mutation),
                 "Wrong FP codegen discriminator: " + repr((mutation, rejection)))
        row = dict(Name=name, Consumer=consumer, Lazy=lazy, Mutation=mutation, Model=model,
                   Optimization=opt, LTO=lto, Archive=archive, Case=0, Elf=str(elf), ElfSha256=digest(elf),
                   Audit=audit, Mechanism=mechanism, CodegenRejection=rejection, Status="COMPILED", Executed=False)
        save(directory / "codegen-audit.json", row)
        print("COMPILED " + name, flush=True)
        return row
