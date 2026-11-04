"""Native classic direct-link witnesses; no target execution or parity promotion."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys


PROFILES = {
    "CM4": ("cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default", "ARM_CM4", "arm_cm4"),
    "CM7": ("cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default", "ARM_CM7/r0p1", "arm_cm7_r0p1"),
    "CM0": ("cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default", "ARM_CM0", "arm_cm0"),
    "CM0PLUS": ("cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default", "ARM_CM0", "arm_cm0"),
    "CM0PLUSVTOR": ("cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default", "ARM_CM0", "arm_cm0"),
}
CM0_PROFILES = frozenset(("CM0", "CM0PLUS", "CM0PLUSVTOR"))
MODES = ("O0", "Og", "O2", "Os", "O3")
COMMON_SOURCES = ("context/context_core.c", "context/context_runtime_state.c", "context/context_panic.c")
FIXTURE_FILES = ("run.py", "application.c", "startup.S", "link.ld", "README.md", "CONTRACT.md", "elf.py", "test_run.py")
HELPERS = ("tools/freeze_classic_fp_mechanisms.py", "tools/freeze_cm3_mechanisms.py",
           "tools/freeze_cohorts.py", "tools/runtime_sources.py", "tools/runtime_sources.ps1",
           "tools/fixtures/freeze_cohorts/build_recipe.py",
           "tools/fixtures/freeze_cohorts/process_runner.py",
           "tools/fixtures/cm55_tfm_parity/elf.py", "tools/fixtures/cm4_cm7_freeze_parity/check.py")
CM0_HELPERS = ("tools/freeze_cm0_mechanisms.py", "tools/fixtures/cm0_freeze_parity/closed_roots.py")


def selection(profile, mode):
    need(type(profile) is str and profile in PROFILES, "unsupported native profile")
    need(type(mode) is str and mode in MODES, "unsupported native mode")
    cohort, directory, storage = PROFILES[profile]
    sources = tuple("fiber/port/" + directory + "/" + name for name in
                    ("fiber_port.c", "fiber_port_boot.c", "fiber_port_exception.c"))
    return cohort, directory, storage, sources


def scope_report(profile="CM4", mode="O2"):
    cohort, _, _, _ = selection(profile, mode)
    scope = "NATIVE_CM0_DIRECT_TWIN_BUILD_ONLY" if profile in CM0_PROFILES else "NATIVE_CLASSIC_FP_DIRECT_TWIN_BUILD_ONLY"
    return dict(Verdict="FAIL", Error=None, ProofScope=scope,
                Profile=profile, Cohort=cohort, Mode=mode, Linkage="direct", LTO=False, ReferenceBuilt=False,
                RequiredCellSatisfied=False, RequiredCellsSatisfied=0, FinalElfProof=False,
                FinalRootRelocationProof=False, CompleteObjectProof=False,
                PolicyEquivalence=False, CpuExecution=False, BoardExecution=False,
                GlobalFreezeQualified=False, InputDrift=[], Sources=[], Commands=[])


def need(ok, message):
    if not ok:
        raise RuntimeError("classic-final-build: " + message)


def require_manifest_selection(manifest, profile, mode, admission):
    identity, _, _, sources = selection(profile, mode)
    group = "CM0" if profile in CM0_PROFILES else profile
    cohorts = [row for row in manifest["cohorts"] if row["id"] == identity]
    need(len(cohorts) == 1 and len(cohorts[0]["artifacts"]) == 1, "unique cohort")
    artifact = cohorts[0]["artifacts"][0]
    admission.require_cohort(artifact, identity if profile in CM0_PROFILES else profile)
    defines = (dict(FIBER_PORT_ARMV6M="1", FIBER_PORT_BUILD_SELECTED="1") if profile in CM0_PROFILES else
               dict(FIBER_FPU_LAZY="0", FIBER_PORT_ARMV7EM="1",
                    FIBER_PORT_BUILD_SELECTED="1", FIBER_SCHEDULER_BASEPRI="16"))
    need(artifact["defines"] == defines, "exact defines")
    groups = [row for row in manifest["source_groups"] if row["id"] == group]
    need(len(groups) == 1 and tuple(groups[0]["sources"]) == sources, "exact source group")
    return artifact


def startup_flags(artifact, mode):
    need(type(mode) is str and mode in MODES, "unsupported native mode")
    vtor = artifact["target"]["vtor"]
    need(type(vtor) is bool, "literal startup VTOR trait")
    return [*artifact["compile_flags"], "-" + mode, "-g0", "-DPILOT_HAS_VTOR=" + str(int(vtor))]


def require_final_float_flags(flags, profile):
    selection(profile, "O2")
    expected = 0x200 if profile in CM0_PROFILES else 0x400
    need(type(flags) is int and flags & 0x600 == expected, "exact final float-ABI flags")


def startup_literal_guard(image, vtor):
    need(type(vtor) is bool, "literal startup VTOR trait")
    symbol = image.symbol("Reset_Handler", "STT_FUNC", root=True)
    start = symbol["value"] & ~1
    body = image.section_read(symbol["section"], start, symbol["size"])
    need(type(body) is bytes and len(body) == symbol["size"], "complete startup body bytes")
    offsets = [offset for offset in range((-start) % 4, len(body) - 3, 4)
               if struct.unpack_from("<I", body, offset)[0] == 0xE000ED08]
    need(len(offsets) == int(vtor), "startup VTOR aligned-literal count")
    return dict(Name="Reset_Handler", Size=len(body), BodySha256=sha(body),
                Scope="STARTUP_VTOR_ALIGNED_LITERAL_SOURCE_BACKED_ONLY", LiteralValue=0xE000ED08,
                LiteralOffsets=offsets, ExpectedLiteralCount=int(vtor), ObservedLiteralCount=len(offsets),
                LiteralPredicateSatisfied=True, FullMMIOProof=False)


def match_native_protocols(image, profile, mode, checker):
    selection(profile, mode)
    protocols = checker._protocols(mode)["Native"] if profile in CM0_PROFILES else checker._NATIVE[profile]
    need(tuple(protocols) == ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler"),
         "exact native protocol roots")
    evidence = [checker._match(image, "Native", name, expected) for name, expected in protocols.items()]
    need(len(evidence) == 3 and all(type(row["TailNops"]) is int and
         row["TailNops"] == (1 if mode == "O0" else 0) for row in evidence),
         "native complete protocols/tail layout")
    return evidence


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")


def regular(path):
    path = Path(os.path.abspath(path))
    need(not any(part.lower() in ("cm33f_secure_transfer_reference", "m55_secure_closed_parity")
                 or part.lower() in ("test_cm33f_secure_transfer_reference.ps1",
                                     "test_m55_secure_closed_parity.ps1") for part in path.parts),
         "protected input")
    for parent in (path, *path.parents):
        info = parent.lstat()
        need(not parent.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400,
             "symlink/reparse input: " + str(parent))
    need(path.is_file(), "not a file: " + str(path))
    return path.resolve(strict=True)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def process_environment(source):
    rejected = {"GCC_EXEC_PREFIX", "COMPILER_PATH", "LIBRARY_PATH", "CPATH", "C_INCLUDE_PATH",
                "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "DEPENDENCIES_OUTPUT", "SUNPRO_DEPENDENCIES",
                "GCC_SPECS", "LD_PRELOAD"}
    need(not any(value and key.upper() in rejected for key, value in source.items()), "ambient compiler override")
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC", "PATHEXT", "SYSTEMDRIVE",
               "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER",
               "PROCESSOR_LEVEL", "PROCESSOR_REVISION"}
    return {key: value for key, value in source.items() if key.upper() in allowed}


def membership(directory, recursive=False):
    paths = directory.rglob("*") if recursive else directory.iterdir()
    return sorted(str(path) for path in paths if path.is_file() and path.suffix.lower() in (".c", ".h", ".py"))


def read_dependencies(path):
    text = regular(path).read_text(encoding="utf-8").replace("\\\r\n", "").replace("\\\n", "")
    target, separator, prerequisites = text.partition(": ")
    need(separator and re.fullmatch(r"pilot-source-[0-8]", target), "dependency grammar")
    tokens = re.findall(r"(?:\\[ \t#]|[^\s])+", prerequisites)
    paths = [regular(re.sub(r"\\([ \t#])", r"\1", token)) for token in tokens]
    need(paths, "empty dependency inventory")
    # GCC can repeat a header verbatim or through relative include spellings.
    # Compare physical membership; the complete raw .d remains an artifact.
    return tuple(sorted(set(paths)))


def require_compile_dependencies(discovered, actual):
    need(type(discovered) is list and discovered and type(actual) is list and actual,
         "empty actual/discovery dependency inventory")
    need(discovered == actual, "actual compilation dependencies differ from discovery")


def interpreter_path():
    if os.name != "nt":
        return regular(sys.executable)
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    api = ctypes.WinDLL("kernel32", use_last_error=True).GetModuleFileNameW
    api.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32)
    api.restype = ctypes.c_uint32
    length = api(None, buffer, len(buffer))
    need(0 < length < len(buffer), "interpreter module identity")
    return regular(buffer.value)


class Pilot:
    def __init__(self, args):
        self.repo = Path(__file__).resolve().parents[3]
        self.fixture = self.repo / "tools/fixtures/classic_final_image"
        self.profile, self.mode = getattr(args, "profile", "CM4"), getattr(args, "mode", "O2")
        self.cohort, self.port_directory, self.storage, self.port_sources = selection(self.profile, self.mode)
        lexical = Path(os.path.abspath(args.output_dir))
        for path in (lexical, *lexical.parents):
            if path.exists() or path.is_symlink():
                info = path.lstat()
                need(not path.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400,
                     "output symlink/reparse ancestor")
        self.output = lexical.resolve(strict=False)
        need(not self.output.exists() and not self.output.is_relative_to(self.repo)
             and not self.repo.is_relative_to(self.output), "fresh external output required")
        self.output.mkdir(parents=True)
        self.output = self.output.resolve(strict=True)
        need(not self.output.is_relative_to(self.repo) and not self.repo.is_relative_to(self.output), "output aliases repository")
        self.args, self.report = args, scope_report(self.profile, self.mode)
        self.inputs, self.generated, self.tools, self.commands = {}, {}, {}, []
        self.root = self.output / "source"
        self.environment = process_environment(os.environ)
        self.memberships = []
        self._prepared = self._built = self._prelink_verified = self._twins_verified = False

    def capture(self, original, target=None, expected=None):
        original = regular(original)
        data = original.read_bytes()
        digest = sha(data)
        need(expected is None or digest == expected, "input authority mismatch: " + str(original))
        key = str(original)
        if key in self.inputs:
            need(self.inputs[key]["Sha256"] == digest, "input changed: " + key)
        if target is None:
            target = self.output / "input-bytes" / (digest + "-" + original.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        self.inputs[key] = dict(Original=key, Captured=str(target), Sha256=digest)
        return target

    def generated_file(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.generated[str(path)] = sha(data)
        return path

    def command(self, argv, label, timeout=60):
        argv = [str(arg) for arg in argv]
        index = len(self.commands)
        record = dict(Label=label, Argv=argv, Cwd=str(self.output), Status="ATTEMPT",
                      Exit=None, TimedOut=None, Error=None)
        self.commands.append(record)
        path = self.output / ("command-%04d.json" % index)
        save(path, record)
        result = None
        try:
            executable = regular(argv[0])
            need(str(executable) in self.inputs, "untracked executable")
            need(sha(executable.read_bytes()) == self.inputs[str(executable)]["Sha256"], "tool drift before launch")
            result = self.process.run(argv, cwd=str(self.output), env=self.environment, timeout=timeout)
            record.update(Exit=result.returncode, TimedOut=result.timed_out, Seconds=result.elapsed)
            (self.output / ("command-%04d.stdout" % index)).write_bytes(result.stdout)
            (self.output / ("command-%04d.stderr" % index)).write_bytes(result.stderr)
            need(type(result.returncode) is int and result.returncode == 0 and result.timed_out is False,
                 "tool failed/timeout: " + label)
            record["Status"] = "PASS"
            return result
        except BaseException as error:
            record.update(Status="FAIL", Error=type(error).__name__ + ": " + str(error))
            raise
        finally:
            save(path, record)
            save(self.output / "commands.json", self.commands)

    def prepare(self):
        for relative in (*HELPERS, *(CM0_HELPERS if self.profile in CM0_PROFILES else ())):
            self.capture(self.repo / relative, self.root / relative)
        for name in FIXTURE_FILES:
            self.capture(self.fixture / name, self.root / "tools/fixtures/classic_final_image" / name)
        self.process = load("classic_final_process", self.root / HELPERS[6])
        self.recipe = load("classic_final_recipe", self.root / HELPERS[5])
        self.classic = load("classic_final_admission", self.root / HELPERS[0])
        self.admission = (load("classic_final_cm0_admission", self.root / CM0_HELPERS[0])
                          if self.profile in CM0_PROFILES else self.classic)
        inventory_root = Path(self.args.inventory).resolve(strict=True)
        manifest_path = regular(inventory_root / "artifacts.json")
        inventory_files = json.loads(manifest_path.read_bytes())["Artifacts"]
        self.capture(manifest_path)
        for relative, digest in inventory_files.items():
            need(not Path(relative).is_absolute() and ".." not in Path(relative).parts, "inventory path")
            self.capture(inventory_root / relative, expected=digest)
        self.bundle = self.classic.shared.Bundle(inventory_root)
        manifest = self.classic.shared.captured_inventory(self.bundle)
        self.artifact = require_manifest_selection(manifest, self.profile, self.mode, self.admission)
        self.report.update(SourceInventorySha256=self.bundle.result["SourceInventorySha256"],
                           CohortArtifact=self.artifact, SourceInventoryReceipt=str(inventory_root))
        directories = (self.repo, self.repo / "context", self.repo / "fiber", self.repo / "fiber/port",
                       self.repo / "fiber/port" / self.port_directory)
        for directory in directories:
            self.memberships.append((directory, False, membership(directory)))
            for path in sorted(directory.glob("*.h")):
                self.capture(path, self.root / path.relative_to(self.repo))
        runtime_path = self.capture(self.repo / "tools/runtime_sources.json", self.root / "tools/runtime_sources.json")
        runtime = json.loads(runtime_path.read_bytes())
        runtime_paths = list(runtime["providers"].values())
        runtime_paths += [p for paths in runtime["compatibility"].values() for p in paths]
        for relative in (*runtime_paths, *self.port_sources, "fiber/port/fiber_port_context_cohort_expectation.c"):
            need(re.fullmatch(r"(?:context|fiber)/[A-Za-z0-9_./-]+\.c", relative) and ".." not in Path(relative).parts,
                 "runtime path")
            self.capture(self.repo / relative, self.root / relative)
        reader = load("classic_final_runtime_sources", self.root / "tools/runtime_sources.py")
        selected = reader.get_runtime_source_paths(self.root, ("engine", "state", "panic"))
        need(tuple(p.relative_to(self.root).as_posix() for p in selected) == COMMON_SOURCES, "Context provider ownership")
        cmsis = Path(self.args.cmsis).resolve(strict=True)
        self.memberships.append((cmsis, True, membership(cmsis, True)))
        for path in sorted(cmsis.rglob("*.h")):
            self.capture(path, self.output / "cmsis" / path.relative_to(cmsis))
        self.fixture_copy = self.root / "tools/fixtures/classic_final_image"
        main = self.generated_file(self.fixture_copy / "main.h", self.recipe.cmsis_main(self.artifact["target"]).encode("ascii"))
        self.flags = self.recipe.native_flags(self.artifact, self.mode, self.fixture_copy,
                        self.root / "fiber/port" / self.port_directory, self.root, self.output / "cmsis")
        prefix = [*self.artifact["compile_flags"], "-" + self.mode]
        need(self.flags[:len(prefix)] == prefix and str(main) == self.flags[-1], "exact recipe flags")
        self.report["CompileFlags"] = self.flags
        self.report["Interpreter"] = dict(ReportedExecutable=sys.executable, ModulePath=str(interpreter_path()))
        self.capture(interpreter_path())
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
        for directory in {Path(r["Original"]).parent for r in list(self.inputs.values()) if r["Original"].endswith(".exe")}:
            if directory.is_relative_to(gcc.parent.parent):
                for path in directory.glob("*.dll"):
                    self.capture(path)
        self.sources = [self.root / p for p in (*COMMON_SOURCES, *self.port_sources,
                         "fiber/port/fiber_port_context_cohort_expectation.c")]
        self.sources += [self.fixture_copy / "application.c", self.fixture_copy / "startup.S"]
        need(len(self.sources) == 9, "nine translation units")
        modules = Path(self.args.python_modules).resolve(strict=True)
        package = modules / "elftools"
        self.memberships.append((package, True, membership(package, True)))
        for path in sorted(package.rglob("*.py")):
            self.capture(path, self.output / "python/elftools" / path.relative_to(package))
        need(not any(name == "elftools" or name.startswith("elftools.") for name in sys.modules), "ambient pyelftools module")
        sys.path.insert(0, str(self.output / "python"))
        self.final_reader = load("classic_final_structural_reader", self.fixture_copy / "elf.py")
        need(sys.modules["elftools"].__version__ == "0.33", "pyelftools version")
        self.copy_memberships = [(self.root, membership(self.root, True)),
                                 (self.output / "cmsis", membership(self.output / "cmsis", True)),
                                 (self.output / "python", membership(self.output / "python", True))]
        self._prepared = True

    def dependencies(self, path, *, capture_system=False):
        result = []
        for dependency in read_dependencies(path):
            key = str(dependency)
            if dependency.is_relative_to(self.output):
                expected = self.generated.get(key)
                if expected is None:
                    matches = [r for r in self.inputs.values() if r["Captured"] == key]
                    need(len(matches) == 1, "unbound copied dependency: " + key)
                    expected = matches[0]["Sha256"]
            else:
                need(not dependency.is_relative_to(self.repo)
                     and not dependency.is_relative_to(Path(self.args.cmsis).resolve()),
                     "live project/CMSIS dependency")
                if capture_system:
                    self.capture(dependency)
                need(key in self.inputs, "unbound actual compiler dependency: " + key)
                expected = self.inputs[key]["Sha256"]
            digest = sha(dependency.read_bytes())
            need(digest == expected, "compiler dependency drift: " + key)
            result.append(dict(Path=key, Sha256=digest))
        return result

    def freeze_objects(self):
        need(not hasattr(self, "object_hashes"), "objects already frozen")
        rows = self.report["Sources"]
        need(len(rows) == len(self.objects) == len(set(self.objects)) == 9,
             "exact nine-object freeze inventory")
        need(all(row.get("CompileDependenciesVerified") is True for row in rows),
             "unverified actual compilation dependencies")
        need([row["Object"] for row in rows] == [str(path) for path in self.objects], "object/source identity")
        self.object_hashes = tuple((row["Object"], row["ObjectSha256"]) for row in rows)

    def verify_objects(self, stage):
        check = dict(Stage=stage, Status="ATTEMPT", Error=None)
        self.report.setdefault("ObjectChecks", []).append(check)
        try:
            frozen = getattr(self, "object_hashes", ())
            need(frozen and tuple(str(path) for path in self.objects) == tuple(path for path, _ in frozen),
                 "frozen object membership: " + stage)
            for path, expected in frozen:
                need(type(expected) is str and re.fullmatch(r"[0-9A-F]{64}", expected) is not None
                     and sha(regular(path).read_bytes()) == expected,
                     "frozen object drift: " + stage + ": " + path)
            check["Status"] = "PASS"
        except BaseException as error:
            check.update(Status="FAIL", Error=type(error).__name__ + ": " + str(error))
            raise
        finally:
            save(self.output / "object-checks.json", self.report["ObjectChecks"])

    def link_twin(self, name, argv):
        need(name in ("ordinary", "emit-relocs"), "twin identity")
        self.verify_objects("before-link-" + name)
        try:
            return self.command(argv, "link " + name)
        finally:
            self.verify_objects("after-link-" + name)

    def build(self):
        self.objects = []
        for index, source in enumerate(self.sources):
            obj = self.output / "objects" / ("%02d-" % index + source.stem + ".o")
            obj.parent.mkdir(parents=True, exist_ok=True)
            dep = obj.with_suffix(".discovery.d")
            actual_dep = obj.with_suffix(".compile.d")
            target = "pilot-source-" + str(index)
            flags = (startup_flags(self.artifact, self.mode) if source.suffix == ".S"
                     else [*self.flags, "-I" + str(source.parent)])
            self.command([self.tools["gcc"], *flags, "-M", "-MF", dep, "-MT", target, source],
                         "discover dependencies " + source.name)
            discovered = self.dependencies(dep, capture_system=True)
            row = dict(Source=str(source), SourceSha256=sha(source.read_bytes()), Object=str(obj),
                       ObjectSha256=None, Dependencies=discovered, DiscoveryDependencyFile=str(dep),
                       CompileDependencyFile=str(actual_dep), CompileFlags=flags, CompileDependenciesVerified=False)
            self.report["Sources"].append(row)
            self.command([self.tools["gcc"], *flags, "-MD", "-MF", actual_dep, "-MT", target,
                          "-c", source, "-o", obj], "compile " + source.name)
            row["ObjectSha256"] = sha(regular(obj).read_bytes())
            actual = self.dependencies(actual_dep)
            row["ActualCompileDependencies"] = actual
            require_compile_dependencies(discovered, actual)
            row["CompileDependenciesVerified"] = True
            self.objects.append(obj)
            self.inspect(obj)
        self.freeze_objects()
        self.verify_objects("before-prelink")
        try:
            self.prelink()
        finally:
            self.verify_objects("after-prelink")
        script = self.fixture_copy / "link.ld"
        base = [*self.artifact["compile_flags"], "-" + self.mode, "-nostdlib",
                "-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack", "-T", script,
                *self.objects]
        self.report["Links"] = []
        finals = []
        for name, extra in (("ordinary", []), ("emit-relocs", ["-Wl,--emit-relocs"])):
            elf = self.output / (name + ".elf")
            link_map = self.output / (name + ".map")
            self.link_twin(name, [self.tools["gcc"], *base, *extra, "-Wl,-Map=" + str(link_map), "-o", elf])
            self.inspect(elf)
            self.require_attributes(elf)
            self.audit_final(elf)
            finals.append(elf)
            self.report["Links"].append(dict(Kind=name, Path=str(elf), Sha256=sha(elf.read_bytes()),
                Map=str(link_map), MapSha256=sha(regular(link_map).read_bytes())))
        comparison = self.final_reader.compare_load_images(*finals)
        need(comparison["Identical"] is True, "twin PT_LOAD/allocated-section mismatch")
        save(self.output / "load-image.json", comparison)
        self._twins_verified = True
        self.report.update(TwinLoadImageIdentical=True, TwinAllocatedSectionsIdentical=True,
                           LoadImageSha256=sha(json.dumps(comparison, sort_keys=True).encode("ascii")),
                           TranslationUnits=9, FinalExecutableLinks=2, PrelinkRelAuthority=[str(o) for o in self.objects])
        self.report["FrozenObjectHashes"] = dict(self.object_hashes)
        self._built = True

    def inspect(self, path):
        for tool, options, suffix in (("objdump", ["-drwC", "-Mreg-names-std"], ".dis"),
                                      ("readelf", ["-hASsrW", "-lW"], ".readelf"),
                                      ("readelf", ["-A"], ".attributes"),
                                      ("nm", ["-P", "-S", "--defined-only"], ".nm")):
            result = self.command([self.tools[tool], *options, path], "inspect " + path.name + suffix)
            path.with_suffix(suffix).write_bytes(result.stdout)

    def require_attributes(self, path):
        attributes = path.with_suffix(".attributes").read_text()
        if self.profile in CM0_PROFILES:
            self.admission.require_attributes(attributes)
        else:
            self.admission.require_attributes(attributes, self.profile)

    def prelink(self):
        startup = self.objects[8]
        need(self.sources[8] == self.fixture_copy / "startup.S", "startup source binding")
        startup_evidence = startup_literal_guard(self.final_reader._ELF(startup, "ET_REL"),
                                                self.artifact["target"]["vtor"])
        startup_evidence.update(Source=str(self.sources[8]), SourceSha256=self.report["Sources"][8]["SourceSha256"],
                                Object=str(startup), ObjectSha256=dict(self.object_hashes)[str(startup)])
        self.report["PrelinkStartupLiteralGuard"] = startup_evidence
        decoder = load("classic_final_prelink_decoder", self.root / HELPERS[7])
        checker_path = CM0_HELPERS[1] if self.profile in CM0_PROFILES else HELPERS[8]
        checker = load("classic_final_prelink_protocol", self.root / checker_path)
        port = self.objects[3]
        self.require_attributes(port)
        image = decoder.Object(port, port.with_suffix(".dis"))
        evidence = match_native_protocols(image, self.profile, self.mode, checker)
        self.report["PrelinkNativeRoots"] = evidence
        self.report["PrelinkNativeProtocolScope"] = "THREE_NATIVE_ROOTS_ONLY_NOT_FINAL_RELOCATION_PROOF"
        definitions = {}
        callee_owners = {"fiber_panic": (2, "STB_WEAK"),
                         "fiber_port_context_validate_restore": (4, "STB_GLOBAL"),
                         "fiber_port_context_validate_save_current": (4, "STB_GLOBAL"),
                         "fiber_port_scheduler_pick_next_from_pendsv": (3, "STB_GLOBAL")}
        callees = {}
        slot_name = "fiber_internal_runtime_current_context_slot"
        slot_provider = None
        for source, obj in zip(self.sources, self.objects):
            parsed = self.final_reader._ELF(obj, "ET_REL")
            for symbol in parsed.symbols:
                if symbol["section"] != "SHN_UNDEF" and symbol["binding"] == "STB_GLOBAL":
                    definitions.setdefault(symbol["name"], []).append((str(source), str(obj), symbol["kind"]))
                if symbol["name"] in callee_owners and symbol["section"] != "SHN_UNDEF":
                    name = symbol["name"]
                    owner, binding = callee_owners[name]
                    need(source == self.sources[owner] and symbol["binding"] == binding
                         and symbol["kind"] == "STT_FUNC" and type(symbol["section"]) is int
                         and symbol["size"] > 0 and name not in callees, "prelink callee owner: " + name)
                    section = parsed.sections[symbol["section"]]
                    offset = symbol["value"] & ~1
                    need(0 <= offset < offset + symbol["size"] <= section.header.sh_size,
                         "prelink callee extent: " + name)
                    callees[name] = dict(Source=str(source), SourceSha256=self.report["Sources"][owner]["SourceSha256"],
                        Object=str(obj), ObjectSha256=dict(self.object_hashes)[str(obj)], Binding=binding,
                        Section=section.name, SectionIndex=symbol["section"], Offset=offset, Size=symbol["size"])
                if symbol["name"] == slot_name and symbol["section"] != "SHN_UNDEF":
                    need(source == self.sources[1] and slot_provider is None and symbol["kind"] == "STT_OBJECT"
                         and symbol["binding"] == "STB_GLOBAL" and symbol["size"] == 4
                         and type(symbol["section"]) is int, "prelink slot source authority")
                    section = parsed.sections[symbol["section"]]
                    offset = symbol["value"]
                    need(section.name == ".bss.fiber_runtime_current_context_slot"
                         and section.header.sh_type == "SHT_NOBITS" and section.header.sh_flags & 7 == 3
                         and offset % 4 == 0 and 0 <= offset < offset + 4 <= section.header.sh_size,
                         "prelink slot zero-fill extent")
                    slot_provider = dict(Source=str(source), SourceSha256=self.report["Sources"][1]["SourceSha256"],
                        Object=str(obj), ObjectSha256=dict(self.object_hashes)[str(obj)], Binding="STB_GLOBAL",
                        Section=section.name, SectionIndex=symbol["section"], Offset=offset, Size=4,
                        SectionType="SHT_NOBITS", SectionFlags=section.header.sh_flags)
        forward = ("fiber_port_context_init", "fiber_port_runtime_memory_barrier", "fiber_port_panic_wait",
                   "fiber_port_require_scheduler_configuration_environment", "fiber_port_runtime_prepare_start",
                   "fiber_port_runtime_select_first", "fiber_port_runtime_start_first", "fiber_port_runtime_schedule")
        for name in forward:
            found = definitions.get(name, [])
            need(len(found) == 1 and found[0][0] in {str(p) for p in self.sources[3:6]}
                 and found[0][2] == "STT_FUNC", "actual eight-operation owner: " + name)
        for name in ("fiber_internal_runtime_current_context_slot", "fiber_internal_runtime_port_abi_v1_anchor"):
            found = definitions.get(name, [])
            need(len(found) == 1 and found[0][0] == str(self.sources[1]) and found[0][2] == "STT_OBJECT",
                 "actual common-state owner: " + name)
        self.report["PrelinkOwners"] = {name: definitions[name] for name in (*forward,
            "fiber_internal_runtime_current_context_slot", "fiber_internal_runtime_port_abi_v1_anchor")}
        need(set(callees) == set(callee_owners), "complete prelink callee source authority")
        self.report["PrelinkCalleeProviders"] = callees
        need(slot_provider is not None, "missing prelink slot placement authority")
        self.report["PrelinkSlotProvider"] = slot_provider
        self._prelink_verified = True

    def audit_final(self, path):
        image = self.final_reader._ELF(path, "ET_EXEC")
        require_final_float_flags(image.elf.header.e_flags, self.profile)
        need(not any(s["name"] and s["section"] == "SHN_UNDEF" for s in image.symbols), "undefined final symbol")
        functions = ("Reset_Handler", "SVC_Handler", "PendSV_Handler", "ctxrt_v1_init", "ctxrt_v1_current",
                     "ctxrt_v1_set_dispatcher", "ctxrt_v1_start", "ctxrt_v1_yield")
        symbols = {name: image.symbol(name, "STT_FUNC", root=True) for name in functions}
        vector = image.elf.get_section_by_name(".isr_vector")
        need(vector is not None and vector.header.sh_addr == 0 and vector.header.sh_size == 1024
             and vector.header.sh_flags & 2 and not vector.header.sh_flags & 1, "vector geometry")
        words = struct.unpack("<256I", vector.data())
        need(words[0] == 0x20010000 and image.elf.header.e_entry == symbols["Reset_Handler"]["value"], "entry/MSP")
        for slot, name in ((1, "Reset_Handler"), (11, "SVC_Handler"), (14, "PendSV_Handler")):
            need(words[slot] == symbols[name]["value"] and words[slot] & 1, "strong vector: " + name)
        slot = image.symbol("fiber_internal_runtime_current_context_slot", "STT_OBJECT")
        need(slot["size"] == 4 and image.sections[slot["section"]].header.sh_type == "SHT_NOBITS", "current slot")
        def readonly_object(name):
            matches = [s for s in image.symbols if s["name"] == name and s["section"] != "SHN_UNDEF"]
            need(len(matches) == 1, "unique read-only object: " + name)
            item = matches[0]
            need(item["kind"] == "STT_OBJECT" and item["binding"] == "STB_GLOBAL" and item["size"] == 1
                 and type(item["section"]) is int, "read-only object definition: " + name)
            section = image.sections[item["section"]].header
            need(section.sh_flags & 2 and not section.sh_flags & 5 and section.sh_type == "SHT_PROGBITS"
                 and section.sh_addr <= item["value"] < section.sh_addr + section.sh_size
                 and image.read(item["value"], 1) == b"\x01", "read-only object contents: " + name)
            return item
        readonly_object("fiber_internal_runtime_port_abi_v1_anchor")
        names = {s["name"] for s in image.symbols}
        optional = {"fiber_internal_runtime_context_configuration_abi_v1_anchor",
                    "fiber_internal_runtime_require_context_configuration_open"}
        need(not {"fiber_init", "fiber_current", "fiber_start", "fiber_schedule", "fiber_scheduler_set_pick_next"} & names
             and not optional & names and not any(n.startswith("fiber_v1_") for n in names),
             "legacy/Fiber/optional configuration in pure Context image")
        providers = [n for n in names if n.startswith("fiber_port_context_cohort_arm")]
        storage = [n for n in names if n.startswith("fiber_port_storage_cohort_" + self.storage + "_")]
        need(len(providers) == len(storage) == 1, "unique private/storage providers")
        expected = [readonly_object(n)["value"] for n in providers + storage]
        section = image.elf.get_section_by_name(".fiber_port_context_cohort_expectation")
        need(section is not None and not section.header.sh_flags & 1 and section.header.sh_flags & 2
             and section.header.sh_size == 8 and sorted(struct.unpack("<2I", section.data())) == sorted(expected),
             "exact private/storage expectation pointers")

    def finish(self, error):
        self.report["Verdict"] = "FAIL"
        drift = []
        if hasattr(self, "object_hashes"):
            try:
                self.verify_objects("closing")
            except Exception as closing:
                drift.append(str(closing))
        for directory, recursive, before in getattr(self, "memberships", []):
            if membership(directory, recursive) != before:
                drift.append("membership: " + str(directory))
        for directory, before in getattr(self, "copy_memberships", []):
            if membership(directory, True) != before:
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
        except Exception as closing:
            drift.append(str(closing))
        self.report.update(Error=error, InputDrift=drift, Commands=self.commands)
        complete = (getattr(self, "_prepared", False) and getattr(self, "_built", False)
                    and getattr(self, "_prelink_verified", False) and getattr(self, "_twins_verified", False)
                    and len(self.report["Sources"]) == 9 and len(self.report.get("Links", [])) == 2
                    and len(self.report.get("PrelinkNativeRoots", [])) == 3 and self.commands
                    and self.report.get("PrelinkStartupLiteralGuard", {}).get("LiteralPredicateSatisfied") is True
                    and all(row.get("CompileDependenciesVerified") is True for row in self.report["Sources"])
                    and [check["Stage"] for check in self.report.get("ObjectChecks", [])] ==
                        ["before-prelink", "after-prelink", "before-link-ordinary", "after-link-ordinary",
                         "before-link-emit-relocs", "after-link-emit-relocs", "closing"]
                    and all(check["Status"] == "PASS" for check in self.report.get("ObjectChecks", []))
                    and all(c["Status"] == "PASS" for c in self.commands))
        modules = {}
        for name, module in tuple(sys.modules.items()):
            if name == "elftools" or name.startswith("elftools."):
                path = Path(module.__file__).resolve(strict=True)
                if not path.is_relative_to(self.output / "python/elftools"):
                    drift.append("module outside capture: " + name)
                modules[name] = dict(Path=str(path), Sha256=sha(path.read_bytes()))
        self.report["ImportedPackageModules"] = modules
        if error is None and not complete:
            self.report["Error"] = "incomplete build stages"
        if error is None and not drift and complete:
            self.report["Verdict"] = "NATIVE-FINAL-TWIN-BUILD-PASS"
        save(self.output / "inputs.json", dict(Files=list(self.inputs.values()), Generated=self.generated))
        save(self.output / "results.json", self.report)
        files = {p.relative_to(self.output).as_posix(): sha(p.read_bytes()) for p in self.output.rglob("*")
                 if p.is_file() and p != self.output / "artifacts.json"}
        save(self.output / "artifacts.json", dict(Artifacts=files))
        need(all(sha((self.output / p).read_bytes()) == digest for p, digest in files.items()), "artifact drift")
        return self.report["Verdict"] == "NATIVE-FINAL-TWIN-BUILD-PASS"


def main(argv=None):
    need(not sys.flags.optimize, "optimized Python unsupported")
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("gcc", "cmsis", "inventory", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--profile", choices=tuple(PROFILES), default="CM4")
    parser.add_argument("--mode", choices=MODES, default="O2")
    parser.add_argument("--python-modules", default=str(Path(os.environ.get("TEMP", ".")) / "fiber-classic-audit-python"))
    args = parser.parse_args(argv)
    pilot = Pilot(args)
    error = None
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
