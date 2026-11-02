"""Bounded lifecycle integration: real common/bridge; fake forward CPU only."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON_OPTIMIZATION")

MIXED_ROLES = ("engine", "state", "panic", "optional_configuration", "legacy_compat", "facade_bridge")
PURE_ROLES = ("engine", "state", "panic", "optional_configuration", "facade_bridge")
LIFECYCLE = "fiber/lifecycle/fiber_v1.c"
API = ["fiber_v1_init", "fiber_v1_set_scheduler", "fiber_v1_current",
       "fiber_v1_start", "fiber_v1_yield"]
COLD_API = {"fiber_v1_init", "fiber_v1_set_scheduler"}
CONTEXT_API = ["ctxrt_v1_init", "ctxrt_v1_current", "ctxrt_v1_set_dispatcher", "ctxrt_v1_start", "ctxrt_v1_yield"]
LEGACY_API = ["fiber_init", "fiber_current", "fiber_scheduler_set_pick_next", "fiber_start", "fiber_schedule"]
LIFECYCLE_FILES = frozenset({"fiber_v1.c", "fiber_v1.h", "fiber_v1_decl.h", "fiber_v1_privileged.h", "README.md"})
PROFILES = [
    ("CM0", "ARM_CM0", "cortex-m0", "ARMV6M", 0, 0, 0, []),
    ("CM0PLUS-NOVTOR", "ARM_CM0", "cortex-m0plus", "ARMV6M", 1, 0, 0, []),
    ("CM0PLUS-VTOR", "ARM_CM0", "cortex-m0plus", "ARMV6M", 1, 0, 1, []),
    ("CM4F", "ARM_CM4", "cortex-m4", "ARMV7EM", 4, 1, 1,
     ["-mfpu=fpv4-sp-d16", "-mfloat-abi=hard"]),
    ("CM7", "ARM_CM7/r0p1", "cortex-m7", "ARMV7EM", 7, 1, 1,
     ["-mfpu=fpv5-d16", "-mfloat-abi=hard"]),
]
MODES = [("O2", ["-O2"]), ("Os", ["-Os"]),
         ("O2LTO", ["-O2", "-flto"]), ("OsLTO", ["-Os", "-flto"])]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def runtime_reader(root):
    spec = importlib.util.spec_from_file_location("lifecycle_runtime_sources", Path(root) / "tools/runtime_sources.py")
    require(spec is not None and spec.loader is not None, "Cannot load actual runtime source reader")
    module = importlib.util.module_from_spec(spec)
    # Receipt capture imports readers from their real paths without adding cache files.
    old = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = old
    return module


def runtime_source_roles(root, use_legacy):
    root = Path(root)
    reader = runtime_reader(root)
    roles = MIXED_ROLES if use_legacy else PURE_ROLES
    ordered = reader.get_runtime_source_paths(root, roles)
    result = {}
    for role in roles:
        for source in reader.get_runtime_source_paths(root, (role,)):
            relative = source.relative_to(root).as_posix()
            require(relative not in result, "Duplicate compiled source: " + relative)
            result[relative] = role
    require(tuple(root / path for path in result) == ordered, "Runtime source role order mismatch")
    return result


def ownership_phase(root):
    root = Path(root)
    reader = runtime_reader(root)
    providers = {}
    for role in ("engine", "state", "panic", "optional_configuration"):
        paths = reader.get_runtime_source_paths(root, (role,))
        require(len(paths) == 1, "Expected one provider for " + role)
        providers[role] = paths[0].relative_to(root).as_posix()
    bridge = reader.get_runtime_source_paths(root, ("facade_bridge",))
    legacy = reader.get_runtime_source_paths(root, ("legacy_compat",))
    if all(path.startswith("fiber/") for path in providers.values()) and len(bridge) == 1 and not legacy:
        return "OLD_OWNER_ADDITIVE_BRIDGE", (True,)
    if all(path.startswith("context/") for path in providers.values()) and not bridge and legacy:
        return "CONTEXT_OWNER", (True, False)
    raise RuntimeError("Unsupported partial runtime ownership mapping")


def cohort_name(use_legacy):
    return "mixed-legacy" if use_legacy else "context-fiber-only"


def assert_lifecycle_packaging(root):
    directory = Path(root) / "fiber/lifecycle"
    files = set()
    for entry in directory.rglob("*"):
        require(not entry.is_symlink() and
                not getattr(entry.lstat(), "st_file_attributes", 0) & 0x400, "LIFECYCLE_PACKAGING")
        if entry.is_dir():
            continue
        require(entry.is_file(), "LIFECYCLE_PACKAGING")
        files.add(entry.relative_to(directory).as_posix())
    require(files == LIFECYCLE_FILES, "LIFECYCLE_PACKAGING")


class Runner:
    def __init__(self, args):
        self.repo = Path(args.repo).resolve()
        self.build = Path(args.build).resolve()
        self.build.mkdir(parents=True, exist_ok=False)
        self.root = self.build / "source"
        self.cmsis_live = Path(args.cmsis).resolve()
        self.cmsis = self.build / "cmsis"
        self.tools = {"arm": Path(args.arm).resolve(), "host": Path(args.host).resolve()}
        for name, base, suffix in [("cxx", "arm", "g++"), ("nm", "arm", "nm"),
                                    ("dump", "arm", "objdump"), ("readelf", "arm", "readelf"),
                                    ("hostcxx", "host", "g++"), ("hostnm", "host", "nm")]:
            prefix = "arm-none-eabi-" if base == "arm" else ""
            self.tools[name] = self.tools[base].with_name(prefix + suffix + ".exe")
        for path in self.tools.values():
            require(path.is_file(), "Missing required tool: " + str(path))
        self.inputs = {}
        self.dependencies = set()
        self.result = {"Status": "INCOMPLETE", "Scope": "host fake forward8; actual classic link/placement only",
                       "Host": [], "Mutants": [], "TargetLinks": [], "Public": [], "Attributes": [], "Controls": [], "ObjectMaps": [], "LifecycleObjects": []}
        self.index = 0

    def remember(self, path, copy=None):
        path = Path(path).resolve()
        if str(path) in self.inputs:
            require(digest(path) == self.inputs[str(path)]["SHA256"], "Input changed during capture: " + str(path))
            return
        data = path.read_bytes()
        row = {"Source": str(path), "SHA256": hashlib.sha256(data).hexdigest().upper()}
        if copy:
            copy = Path(copy)
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_bytes(data)
            row["Copy"] = str(copy)
        self.inputs[str(path)] = row
        (self.build / "inputs.json").write_text(json.dumps(sorted(self.inputs.values(), key=lambda r: r["Source"]), indent=2), encoding="utf-8")

    def run(self, tool, args, failure=False, env=None):
        command = [str(self.tools.get(tool, tool))] + [str(x) for x in args]
        self.index += 1
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                errors="strict", env=env, timeout=120)
        stem = self.build / ("command-%05d" % self.index)
        stem.with_suffix(".json").write_text(json.dumps({"Argv": command, "Exit": result.returncode}, indent=2), encoding="utf-8")
        stem.with_suffix(".stdout").write_text(result.stdout, encoding="utf-8")
        stem.with_suffix(".stderr").write_text(result.stderr, encoding="utf-8")
        if not failure:
            require(result.returncode == 0, "Command failed: " + str(stem) + "\n" + result.stderr)
            # Known intentional CM0 no-VTOR warning, and native-LTO serial notice
            # are the only diagnostics admitted in successful commands.
            warning = "[fiber] Selected ARMv6-M port has no SCB->VTOR; falling back to base table at 0x00000000."
            allowed = [r"In file included from .+:\d+(?::\d+)?[:,]",
                       r"\s+from .+:\d+(?::\d+)?[:,]",
                       r".+:\d+:\d+: warning: " + re.escape(warning),
                       r'\s*\d+ \| FIBER_DIAG_WARN\("' + re.escape(warning) + r'"\)',
                       r"\s*\|\s+\^~+",
                       r"lto-wrapper.exe: warning: using serial compilation of [1-9][0-9]* LTRANS jobs",
                       r"lto-wrapper.exe: note: see the '-flto' option documentation for more information"]
            for line in result.stderr.splitlines():
                require(any(re.fullmatch(pattern, line) for pattern in allowed),
                        "Unexpected diagnostic: " + str(stem) + "\n" + result.stderr)
        return result

    def snapshot(self):
        # Bounded production inventory; no mutable root ledgers or other agents' tests.
        assert_lifecycle_packaging(self.repo)
        paths = list((self.repo / "context").glob("*.h"))
        paths += list((self.repo / "fiber").glob("*.h"))
        phase, self.cohorts = ownership_phase(self.repo)
        before_roles = runtime_source_roles(self.repo, True)
        paths += runtime_reader(self.repo).get_runtime_source_inputs(self.repo, MIXED_ROLES)
        paths += [self.repo / "fiber/lifecycle" / x for x in LIFECYCLE_FILES]
        paths += list((self.repo / "fiber/port").glob("*.h"))
        paths += [self.repo / "fiber/port/fiber_port_context_cohort_expectation.c"]
        for _, directory, *_ in PROFILES:
            paths += [p for p in (self.repo / "fiber/port" / directory).rglob("*") if p.suffix in (".h", ".c")]
        paths += list((self.repo / "tools/fixtures/fiber_lifecycle").glob("*"))
        paths += [self.repo / "tools/test_fiber_lifecycle.ps1"]
        for path in sorted(set(paths)):
            if path.is_file():
                self.remember(path, self.root / path.relative_to(self.repo))
        require(ownership_phase(self.root) == (phase, self.cohorts), "Ownership mapping changed during snapshot")
        assert_lifecycle_packaging(self.root)
        require(runtime_source_roles(self.root, True) == before_roles, "Source role mapping changed during snapshot")
        self.result["RuntimeSourceSelection"] = {
            "OwnershipPhase": phase,
            "Cohorts": {cohort_name(use): runtime_source_roles(self.root, use) for use in self.cohorts},
            "PureContextStatus": "ENABLED_REQUIRES_SYMBOL_ABSENCE" if False in self.cohorts else "NOT_ADMISSIBLE_BEFORE_OWNERSHIP_ACTIVATION",
        }
        self.result["LifecyclePackaging"] = {"Files": sorted(LIFECYCLE_FILES), "Status": "PASS"}
        for path in self.cmsis_live.rglob("*.h"):
            self.remember(path, self.cmsis / path.relative_to(self.cmsis_live))
        for path in set(self.tools.values()):
            self.remember(path)
        self.result["Tools"] = {k: self.run(k, ["--version"]).stdout for k in ["arm", "host", "cxx", "hostcxx"]}
        for compiler in ["arm", "host"]:
            for component in ["cc1", "cc1plus", "as", "ld", "lto1", "lto-wrapper"]:
                path = Path(self.run(compiler, ["-print-prog-name=" + component]).stdout.strip())
                if not path.is_absolute():
                    path = self.tools[compiler].parent / path
                self.remember(path)
            probe_result = self.run(compiler, ["-###", "-flto", "-nostdlib", "-r", "-x", "c", str(self.root / LIFECYCLE)], failure=True)
            require(probe_result.returncode == 0, "Compiler driver probe failed")
            probe = probe_result.stderr
            matches = re.findall(r'(?:^|\s)-plugin\s+(?:"([^"]+)"|(\S+))', probe)
            require(len(matches) == 1, "Expected one driver LTO plugin: " + compiler)
            self.remember(Path(next(part for part in matches[0] if part)))
        executable = Path(sys.executable).resolve()
        if not executable.is_file() or executable.stat().st_size == 0:
            executable = Path(sys.base_prefix) / "python.exe"
        self.remember(executable)
        self.result["Python"] = {"Executable": str(executable), "Version": sys.version}
        self.fixture = self.root / "tools/fixtures/fiber_lifecycle"
        print("Captured lifecycle inputs: " + str(self.build), flush=True)

    def python_controls(self):
        cases = [("dash-O", ["-O", str(self.fixture / "run.py")], None),
                 ("dash-OO", ["-OO", str(self.fixture / "run.py")], None),
                 ("environment", [str(self.fixture / "run.py")], dict(os.environ, PYTHONOPTIMIZE="1")),
                 ("compiled-import", ["-c", "from pathlib import Path; p=" + repr(str(self.fixture / "run.py")) +
                  "; exec(compile(Path(p).read_text(),p,'exec',optimize=1),{'__name__':'test_import'})"], None)]
        for name, args, env in cases:
            result = self.run(sys.executable, args, failure=True, env=env)
            require(result.returncode == 1 and result.stdout == "" and result.stderr == "REJECT:PYTHON_OPTIMIZATION\n", "Python guard protocol changed: " + name)
            self.result["Controls"].append({"Name": name, "Diagnostic": "REJECT:PYTHON_OPTIMIZATION"})

    def packaging_controls(self):
        root = self.build / "packaging-controls/empty-directories"
        shutil.copytree(self.root / "fiber/lifecycle", root / "fiber/lifecycle")
        (root / "fiber/lifecycle/tests/fixtures/context").mkdir(parents=True)
        assert_lifecycle_packaging(root)
        self.result["Controls"].append({"Name": "production-packaging-empty-directories", "Result": "ACCEPT"})
        for name in ("tests/straytest.c", "hostfixture.c", "hostfixture.cpp"):
            root = self.build / "packaging-controls" / name.replace("/", "-")
            directory = root / "fiber/lifecycle"
            shutil.copytree(self.root / "fiber/lifecycle", directory)
            (directory / name).parent.mkdir(parents=True, exist_ok=True)
            (directory / name).write_text("/* Fixture-only forbidden production test source. */\n", encoding="ascii")
            self.expected_rejection(lambda: assert_lifecycle_packaging(root), "LIFECYCLE_PACKAGING")
            self.result["Controls"].append({"Name": "production-packaging-" + name, "Diagnostic": "LIFECYCLE_PACKAGING"})

    def flags(self, profile=None, root=None, use_legacy=True):
        root = root or self.root
        directory, arch = (profile[1], profile[3]) if profile else ("ARM_CM0", "ARMV6M")
        flags = ["-Wall", "-Wextra", "-Werror", "-Wundef", "-ffunction-sections", "-fdata-sections", "-fno-common",
                 "-I" + str(root), "-I" + str(root / "fiber"), "-I" + str(root / "fiber/port"),
                 "-I" + str(root / "fiber/port" / directory),
                 "-I" + str(root / "tools/fixtures/fiber_lifecycle"),
                 "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_" + arch + "=1", "-DUSE_LEGACY=" + str(int(use_legacy))]
        if profile:
            flags += ["-mthumb", "-mcpu=" + profile[2], "-ffreestanding", "-fno-builtin",
                      "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
                      "-DLIFECYCLE_CORE=" + str(profile[4]), "-DLIFECYCLE_FPU=" + str(profile[5]),
                      "-DLIFECYCLE_VTOR=" + str(profile[6])] + (profile[7] or ["-mfloat-abi=soft"])
            if not profile[6]:
                flags.remove("-Werror")
        return flags

    def compile(self, source, output, flags, cxx=False, cmsis=False):
        target = "-mthumb" in flags
        compiler = ("cxx" if cxx else "arm") if target else ("hostcxx" if cxx else "host")
        opts = list(flags) + (["-I" + str(self.cmsis)] if cmsis else [])
        opts += ["-std=c++17" if cxx else "-std=c11", "-x", "c++" if cxx else "c"]
        if cxx:
            opts += ["-fno-exceptions", "-fno-rtti"]
        dep = output.with_suffix(".d")
        self.run(compiler, opts + ["-M", "-MF", dep, source])
        text = dep.read_text(encoding="utf-8").replace("\\\n", " ")
        for token in re.findall(r"(?:\\ |[^\s])+", text.split(": ", 1)[1]):
            path = Path(token.replace("\\ ", " ")).resolve()
            require(path.is_file(), "Unresolved dependency " + str(path))
            self.dependencies.add(str(path))
            if not path.is_relative_to(self.build):
                self.remember(path)
        self.run(compiler, opts + ["-MD", "-MF", dep, "-c", source, "-o", output])
        return output

    def nm(self, path, host=False, options=None):
        text = self.run("hostnm" if host else "nm", (options or ["-S", "--defined-only"]) + [path]).stdout
        return text

    def single_engine(self, binary, host=False, use_legacy=True):
        rows = self.nm(binary, host)
        for name in API + CONTEXT_API + ["fiber_internal_runtime_current_context_slot"] + (LEGACY_API if use_legacy else []):
            matches = [line for line in rows.splitlines() if line.split()[-1] == name and line.split()[-2] != "A"]
            # Cold init/install are deliberately not noipa: LTO may inline them.
            require(len(matches) <= 1 if name in COLD_API else len(matches) == 1,
                    "Single engine/symbol failure: " + name)
        if not use_legacy:
            all_symbols = self.nm(binary, host, ["-a"])
            present = {line.split()[-1] for line in all_symbols.splitlines() if line.split()}
            require(not present.intersection(LEGACY_API), "PURE_CONTEXT_LEGACY_SYMBOLS:" + repr(sorted(present.intersection(LEGACY_API))))

    def compile_sources(self, root, directory, sources, flags, cmsis=False):
        objects = {}
        records = []
        for relative, role in sources.items():
            source = root / relative
            output = directory / "objects" / Path(relative).with_suffix(".o")
            output.parent.mkdir(parents=True, exist_ok=True)
            require(output not in objects.values(), "Object path collision: " + relative)
            objects[relative] = self.compile(source, output, flags, cmsis=cmsis)
            records.append({"RelativeSource": relative, "Role": role, "Source": str(source),
                            "SourceSHA256": digest(source), "Object": str(output), "ObjectSHA256": digest(output)})
        mapping = directory / "objects.json"
        mapping.write_text(json.dumps(records, indent=2), encoding="utf-8")
        self.result["ObjectMaps"].append(str(mapping))
        return objects

    def host_build(self, root, directory, options, use_legacy=True):
        directory.mkdir(parents=True)
        flags = self.flags(root=root, use_legacy=use_legacy) + options
        sources = runtime_source_roles(root, use_legacy)
        sources.update({LIFECYCLE: "lifecycle", "tools/fixtures/fiber_lifecycle/host.c": "host-fake-forward8"})
        objects = self.compile_sources(root, directory, sources, flags)
        binary = directory / "host.exe"
        self.run("host", flags + list(objects.values()) + ["-o", binary])
        return binary

    def host_tests(self, use_legacy):
        cohort = cohort_name(use_legacy)
        for mode, options in [("O0", ["-O0"])] + MODES:
            binary = self.host_build(self.root, self.build / cohort / ("host-" + mode), options, use_legacy)
            self.single_engine(binary, True, use_legacy)
            for scenario in range(31):
                result = self.run(str(binary), [scenario])
                match = re.fullmatch(r"PASS host-mock scenario=%d checks=(\d+)\n" % scenario, result.stdout)
                require(match is not None and not result.stderr, "Host result protocol mismatch")
                self.result["Host"].append({"Cohort": cohort, "Mode": mode, "Scenario": scenario, "Checks": int(match[1])})
            print("PASS " + cohort + " host " + mode + " (31 fresh-process scenarios)", flush=True)

    def mutants(self, use_legacy):
        cohort = cohort_name(use_legacy)
        source = (self.root / LIFECYCLE).read_text(encoding="utf-8")
        changes = [
            ("whole-fiber-overlap", "object_begin < raw_end && raw_begin < object_end", "object_begin < raw_end && raw_begin < object_end - sizeof(*fiber) + sizeof(CtxrtContextV1)", 6, "TAIL_NO_WRITE"),
            ("object-overflow", "object_begin > UINTPTR_MAX - sizeof(*fiber)", "0", 5, "OVERFLOW_DEREFERENCE"),
            ("optional-configuration", "    fiber_internal_runtime_require_context_configuration_open(&fiber->private_context);", "    /* guard removed by fixture mutation */", 19, "FAILED_START_CONFIG_CLOSED"),
            ("state-after-construction", "    ctxrt_v1_init(&fiber->private_context, stack_begin, stack_end, entry, arg);\n    fiber->private_state = FIBER_V1_INITIALIZED;", "    fiber->private_state = FIBER_V1_INITIALIZED;\n    ctxrt_v1_init(&fiber->private_context, stack_begin, stack_end, entry, arg);", 9, "FAILED_INIT_EMPTY"),
            ("policy-commit-order", "    ctxrt_v1_set_dispatcher(select != NULL ? fiber_v1_dispatch : NULL, runtime);", "    runtime->private_user = user;\n    runtime->private_select = select;\n    ctxrt_v1_set_dispatcher(select != NULL ? fiber_v1_dispatch : NULL, runtime);", 18, "HOTSWAP_UNCHANGED"),
            ("outgoing-state", "previous != NULL && previous->private_state != FIBER_V1_STARTED", "previous != NULL && 0", 23, "EVENT"),
            ("next-state", "next->private_state != FIBER_V1_STARTED", "0", 21, "EVENT"),
            ("mark-selected", "        next->private_state = FIBER_V1_STARTED;", "        /* selected state removed */", 16, "SELECTED_NOT_ENTERED"),
            ("entry-identity", "stack_begin, stack_end, entry, arg);", "stack_begin, stack_end, entry, (arg != NULL ? NULL : arg));", 0, "DIRECT_ENTRY"),
            ("current-identity", "return (FiberV1 *)(void *)ctxrt_v1_current();", "return NULL;", 16, "ONE_CURRENT"),
            ("yield-forwarding", "    ctxrt_v1_yield();", "    /* request removed */", 24, "YIELD_REQUEST_ONLY"),
        ]
        for name, old, new, scenario, diagnostic in changes:
            require(source.count(old) == 1, "Mutation anchor not unique: " + name)
            root = self.build / cohort / "mutant-source" / name
            shutil.copytree(self.root, root)
            (root / LIFECYCLE).write_text(source.replace(old, new), encoding="utf-8")
            for mode, options in MODES[:2]:
                binary = self.host_build(root, self.build / cohort / ("mutant-" + name + "-" + mode), options, use_legacy)
                result = self.run(str(binary), [scenario], failure=True)
                require(result.returncode == 90 and result.stdout == "" and result.stderr == "FAIL:" + diagnostic + "\n",
                        "Compiled mutant wrong rejection: " + name + " " + result.stderr)
                self.result["Mutants"].append({"Cohort": cohort, "Name": name, "Mode": mode, "Scenario": scenario, "Diagnostic": diagnostic})
        print("PASS " + cohort + " compiled lifecycle mutants", flush=True)

    def sections(self, binary):
        text = self.run("dump", ["-t", binary]).stdout
        result = {}
        for line in text.splitlines():
            words = line.split()
            if len(words) >= 5 and re.fullmatch(r"[0-9a-fA-F]+", words[0]):
                result.setdefault(words[-1], []).append((words[0], next((w for w in words[1:-1] if w.startswith(".")), "")))
        return result

    def placement(self, binary, use_legacy=True):
        symbols = self.sections(binary)
        thread_names = ["fiber_v1_current", "fiber_v1_yield", "ctxrt_v1_current", "ctxrt_v1_yield", "fiber_internal_runtime_load_current_context"]
        if use_legacy:
            thread_names += ["fiber_current", "fiber_schedule"]
        for name in thread_names:
            require(len(symbols.get(name, [])) == 1 and symbols[name][0][1] == ".thread_functions", "THREAD_PLACEMENT:" + name)
        for name in ["fiber_v1_dispatch", "fiber_v1_start", "policy"]:
            require(len(symbols.get(name, [])) == 1 and symbols[name][0][1] == ".privileged_text", "PRIVILEGED_PLACEMENT:" + name)
        for name in COLD_API:
            if name in symbols:
                require(len(symbols[name]) == 1 and symbols[name][0][1] == ".privileged_text", "PRIVILEGED_PLACEMENT:" + name)

    def body(self, disasm, function):
        match = re.search(r"^[0-9a-f]+ <" + function + r">:\n(.*?)(?=\n\n|\Z)", disasm, re.S | re.M)
        require(match is not None, "Missing function: " + function)
        return match[1]

    def instructions(self, body):
        return re.findall(r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{4,8}\s+)+([a-z][a-z0-9.]*)\s*([^\n]*)", body, re.M)

    def identity_wrappers(self, disasm):
        for name, target in [("fiber_v1_current", "ctxrt_v1_current"), ("fiber_v1_yield", "ctxrt_v1_yield")]:
            body = self.body(disasm, name)
            instructions = self.instructions(body)
            require(instructions and all(m in {"push", "pop", "bx", "bl", "b.w", "b.n", "nop", "nop.n"} for m, _ in instructions), "IDENTITY_WRAPPER:" + name)
            calls = [operands for m, operands in instructions if m in {"bl", "b.w", "b.n"}]
            require(len(calls) == 1 and re.fullmatch(r"[0-9a-f]+ <" + target + ">", calls[0]), "IDENTITY_TARGET:" + name)

    def public(self, profile, directory, use_legacy):
        for cxx in [False, True]:
            obj = self.compile(self.fixture / "consumer.c", directory / ("public-cxx.o" if cxx else "public-c.o"), self.flags(profile, use_legacy=use_legacy) + ["-O2"], cxx)
            deps = obj.with_suffix(".d").read_text(encoding="utf-8")
            require(not re.search(r"(?:core_cm\w+|fiber_port_private|fiber_runtime_state)\.h", deps), "Public consumer imports private/CPU headers")
            identities = re.findall(r"\bU\s+(fiber_port_storage_cohort_\w+)", self.nm(obj, options=["-u"]))
            require(len(identities) == 1, "Public consumer must retain exactly selected storage cohort")
            undefined = set(re.findall(r"\bU\s+(\w+)", self.nm(obj, options=["-u"])))
            expected = set(API) | set(identities) | (set(LEGACY_API) if use_legacy else set())
            require(undefined == expected, "Public C/C++ callable linkage changed: " + repr(undefined))
            self.result["Public"].append({"Cohort": cohort_name(use_legacy), "Profile": profile[0], "Language": "C++17" if cxx else "C11", "Storage": identities[0]})

    def lifecycle_object(self, obj):
        # Literal public ABI/local-adapter oracle, independent of role manifest.
        symbols = {}
        for line in self.nm(obj).splitlines():
            match = re.fullmatch(r"[0-9a-fA-F]+\s+(?:[0-9a-fA-F]+\s+)?([A-Za-z])\s+(\S+)", line)
            require(match is not None, "Unexpected lifecycle symbol row: " + line)
            kind, name = match.groups()
            require(name not in symbols, "Duplicate lifecycle definition: " + name)
            symbols[name] = kind
        require(not any(kind in "BbDdCcGgSs" for kind in symbols.values()), "LIFECYCLE_WRITABLE_STATE")
        functions = {name: kind for name, kind in symbols.items() if kind in "TtWw"}
        expected = {name: "T" for name in API}
        expected["fiber_v1_dispatch"] = "t"
        require(functions == expected, "LIFECYCLE_FUNCTION_DEFINITIONS")
        public = {name for name, kind in symbols.items() if kind.isupper()}
        require(public == set(API), "LIFECYCLE_PUBLIC_DEFINITIONS")
        return functions

    def target(self, use_legacy):
        cohort = cohort_name(use_legacy)
        for profile in PROFILES:
            directory = self.build / cohort / profile[0]
            directory.mkdir(parents=True)
            self.public(profile, directory, use_legacy)
            for mode, options in MODES:
                folder = directory / mode
                folder.mkdir()
                flags = self.flags(profile, use_legacy=use_legacy) + options
                sources = runtime_source_roles(self.root, use_legacy)
                sources.update({LIFECYCLE: "lifecycle", "tools/fixtures/fiber_lifecycle/target.c": "target-integration",
                                "fiber/port/fiber_port_context_cohort_expectation.c": "build-owned-expectation"})
                sources.update({"fiber/port/" + profile[1] + "/fiber_port" + suffix + ".c": "actual-selected-port" for suffix in ["", "_boot", "_exception"]})
                objects = self.compile_sources(self.root, folder, sources, flags, cmsis=True)
                binary = folder / "target.elf"
                library = Path(self.run("arm", flags + ["-print-libgcc-file-name"]).stdout.strip())
                self.remember(library)
                self.run("arm", flags + ["-nostdlib", "-Wl,--gc-sections", "-Wl,--fatal-warnings",
                         "-Wl,-Map=" + str(folder / "target.map"), "-T", self.fixture / "link.ld"] + list(objects.values()) + ["-lgcc", "-o", binary])
                self.single_engine(binary, use_legacy=use_legacy)
                self.placement(binary, use_legacy)
                require(not self.nm(binary, options=["-u"]).strip(), "Target ELF has unresolved dependencies")
                disasm = self.run("dump", ["-drwC", binary]).stdout
                self.identity_wrappers(disasm)
                (folder / "target.disasm").write_text(disasm, encoding="utf-8")
                self.run("readelf", ["-A", "-S", "-s", binary])
                if "-flto" not in options:
                    functions = self.lifecycle_object(objects[LIFECYCLE])
                    self.result["LifecycleObjects"].append({"Cohort": cohort, "Profile": profile[0], "Mode": mode,
                                                           "Object": str(objects[LIFECYCLE]), "Functions": functions})
                    undefined = set(re.findall(r"\bU\s+(\w+)", self.nm(objects[LIFECYCLE], options=["-u"])))
                    expected = {"ctxrt_v1_init", "ctxrt_v1_current", "ctxrt_v1_set_dispatcher", "ctxrt_v1_start", "ctxrt_v1_yield", "fiber_panic",
                                "fiber_internal_runtime_context_configuration_abi_v1_anchor", "fiber_internal_runtime_require_context_configuration_open",
                                "fiber_port_storage_cohort_" + ("arm_cm7_r0p1" if profile[4] == 7 else "arm_cm4" if profile[4] == 4 else "arm_cm0") + "_v1_r0"}
                    require(undefined == expected, "Lifecycle exact object dependencies changed: " + repr(undefined ^ expected))
                self.result["TargetLinks"].append({"Cohort": cohort, "Profile": profile[0], "Mode": mode, "ELF": str(binary), "SHA256": digest(binary)})
                if profile[0] == "CM4F" and mode in ("O2", "Os"):
                    self.target_controls(profile, folder, objects, flags, use_legacy)
                    if not use_legacy:
                        self.pure_legacy_control(profile, folder, objects, flags)
            self.attribute_checks(profile, directory, use_legacy)
            print("PASS " + cohort + " classic links/placement " + profile[0], flush=True)

    def attribute_checks(self, profile, directory, use_legacy):
        # Direct production consumer functions only, not user-policy transitive closure.
        for name, extra in [("instrument", ["-finstrument-functions"]),
                            ("stack", ["-fstack-protector-all"]),
                            ("coverage", ["--coverage"]),
                            ("sanitize", ["-fsanitize=undefined", "-fsanitize-coverage=trace-pc"]),
                            ("profile", ["-pg"])]:
            obj = self.compile(self.root / LIFECYCLE, directory / ("attributes-" + name + ".o"),
                               self.flags(profile, use_legacy=use_legacy) + ["-O2"] + extra)
            undefined = self.nm(obj, options=["-u"])
            # Cold init/set_scheduler are intentionally NOT advertised sensitive.
            disasm = self.run("dump", ["-drwC", obj]).stdout
            for function in ["fiber_v1_dispatch", "fiber_v1_current", "fiber_v1_yield", "fiber_v1_start"]:
                self.sensitive_root(disasm, function)
            self.result["Attributes"].append({"Cohort": cohort_name(use_legacy), "Profile": profile[0], "Flags": extra, "Object": str(obj), "Undefined": undefined})

    def sensitive_root(self, disasm, function):
        body = self.body(disasm, function)
        require(not re.search(r"__cyg_profile|__stack_chk|__gcov|__ubsan|__sanitizer|mcount", body), "SENSITIVE_INSTRUMENTED:" + function)
        require(not any(m.startswith("v") for m, _ in self.instructions(body)), "SENSITIVE_FP:" + function)

    def pure_legacy_control(self, profile, folder, objects, flags):
        directory = folder / "legacy-presence-control"
        directory.mkdir()
        sources = {path: "negative-only-legacy-compat" for path, role in runtime_source_roles(self.root, True).items()
                   if role == "legacy_compat"}
        require(sources, "Pure symbol control requires actual production legacy shim")
        fixture = "tools/fixtures/fiber_lifecycle/target.c"
        sources[fixture] = "negative-public-legacy-consumer"
        options = self.flags(profile, use_legacy=True) + ["-Os" if "-Os" in flags else "-O2"]
        extra = self.compile_sources(self.root, directory, sources, options, cmsis=True)
        replaced = dict(objects)
        for relative, obj in extra.items():
            require(relative == fixture or relative not in replaced, "Unexpected pure-control object collision")
            replaced[relative] = obj
        binary = directory / "with-legacy.elf"
        self.run("arm", flags + ["-nostdlib", "-Wl,--gc-sections", "-Wl,--fatal-warnings", "-T", self.fixture / "link.ld"] +
                 list(replaced.values()) + ["-lgcc", "-o", binary])
        diagnostic = "PURE_CONTEXT_LEGACY_SYMBOLS:" + repr(sorted(LEGACY_API))
        self.expected_rejection(lambda: self.single_engine(binary, use_legacy=False), diagnostic)
        records = [row for row in json.loads((folder / "objects.json").read_text(encoding="utf-8"))
                   if row["RelativeSource"] not in extra]
        records += json.loads((directory / "objects.json").read_text(encoding="utf-8"))
        mapping = directory / "image.objects.json"
        mapping.write_text(json.dumps(records, indent=2), encoding="utf-8")
        self.result["ObjectMaps"].append(str(mapping))
        self.result["Controls"].append({"Cohort": "context-fiber-only", "Name": "actual-legacy-shim-presence",
                                        "Profile": profile[0], "Mode": "Os" if "-Os" in flags else "O2", "Diagnostic": diagnostic,
                                        "ELF": str(binary), "SHA256": digest(binary)})

    def expected_rejection(self, action, diagnostic):
        try:
            action()
        except RuntimeError as error:
            require(str(error) == diagnostic, "Control rejected for wrong reason: " + str(error))
        else:
            raise RuntimeError("Control falsely accepted: " + diagnostic)

    def target_controls(self, profile, folder, objects, flags, use_legacy):
        changes = [
            ("thread-section", {LIFECYCLE: (" CTXRT_API_THREAD_FUNCTION", ""),
                                "fiber/lifecycle/fiber_v1_decl.h": (" CTXRT_API_THREAD_FUNCTION", "")},
             "THREAD_PLACEMENT:fiber_v1_current"),
            ("metadata-read", {LIFECYCLE: ("    return (FiberV1 *)(void *)ctxrt_v1_current();",
              "    FiberV1 *current = (FiberV1 *)(void *)ctxrt_v1_current();\n    if (current != NULL) (void)*(volatile uint32_t *)&current->private_state;\n    return current;")},
             "IDENTITY_WRAPPER:fiber_v1_current"),
            ("adapter-attributes", {LIFECYCLE: ("static CTXRT_DISPATCH_ATTR", "static __attribute__((noinline, noclone, used))")},
             "SENSITIVE_INSTRUMENTED:fiber_v1_dispatch"),
            ("extra-public-function", {LIFECYCLE: ('#include "fiber_v1.h"', '#include "fiber_v1.h"\nvoid fiber_v1_fixture_extra(void) {}')},
             "LIFECYCLE_FUNCTION_DEFINITIONS"),
            ("public-adapter", {LIFECYCLE: ("static CTXRT_DISPATCH_ATTR", "CTXRT_DISPATCH_ATTR")},
             "LIFECYCLE_FUNCTION_DEFINITIONS"),
            ("owned-current", {LIFECYCLE: ('#include "fiber_v1.h"', '#include "fiber_v1.h"\nFiberV1 *fiber_v1_fixture_illegal_current;')},
             "LIFECYCLE_WRITABLE_STATE"),
        ]
        for name, edits, diagnostic in changes:
            root = folder / ("source-" + name)
            shutil.copytree(self.root, root)
            for relative, (old, new) in edits.items():
                path = root / relative
                source = path.read_text(encoding="utf-8")
                require(source.count(old) == (2 if name == "thread-section" else 1), "Target control anchor changed: " + name)
                path.write_text(source.replace(old, new), encoding="utf-8")
            options = self.flags(profile, root, use_legacy) + ["-Os" if "-Os" in flags else "-O2"]
            if name == "adapter-attributes":
                obj = self.compile(root / LIFECYCLE, folder / (name + ".o"), options + ["-finstrument-functions"])
                disasm = self.run("dump", ["-drwC", obj]).stdout
                self.expected_rejection(lambda: self.sensitive_root(disasm, "fiber_v1_dispatch"), diagnostic)
            elif name in {"extra-public-function", "public-adapter", "owned-current"}:
                obj = self.compile(root / LIFECYCLE, folder / (name + ".o"), options)
                self.expected_rejection(lambda: self.lifecycle_object(obj), diagnostic)
            else:
                obj = self.compile(root / LIFECYCLE, folder / (name + ".o"), options)
                binary = folder / (name + ".elf")
                replaced = dict(objects)
                require(LIFECYCLE in replaced, "Missing lifecycle object replacement target")
                replaced[LIFECYCLE] = obj
                self.run("arm", options + ["-nostdlib", "-Wl,--gc-sections", "-Wl,--fatal-warnings", "-T", self.fixture / "link.ld"] + list(replaced.values()) + ["-lgcc", "-o", binary])
                if name == "thread-section":
                    self.expected_rejection(lambda: self.placement(binary, use_legacy), diagnostic)
                else:
                    disasm = self.run("dump", ["-drwC", binary]).stdout
                    self.expected_rejection(lambda: self.identity_wrappers(disasm), diagnostic)
            records = json.loads((folder / "objects.json").read_text(encoding="utf-8"))
            (record,) = [row for row in records if row["RelativeSource"] == LIFECYCLE]
            record.update({"Source": str(root / LIFECYCLE), "SourceSHA256": digest(root / LIFECYCLE),
                           "Object": str(obj), "ObjectSHA256": digest(obj)})
            if name in {"adapter-attributes", "extra-public-function", "public-adapter", "owned-current"}:
                records = [record]
            mapping = folder / (name + ".objects.json")
            mapping.write_text(json.dumps(records, indent=2), encoding="utf-8")
            self.result["ObjectMaps"].append(str(mapping))
            self.result["Controls"].append({"Cohort": cohort_name(use_legacy), "Name": name, "Profile": profile[0], "Mode": "Os" if "-Os" in flags else "O2", "Diagnostic": diagnostic})

    def finish(self):
        assert_lifecycle_packaging(self.repo)
        assert_lifecycle_packaging(self.root)
        for row in self.inputs.values():
            require(digest(row["Source"]) == row["SHA256"], "Live input drift: " + row["Source"])
            if "Copy" in row:
                require(digest(row["Copy"]) == row["SHA256"], "Archived input drift: " + row["Copy"])
        manifest = sorted(self.inputs.values(), key=lambda row: row["Source"])
        (self.build / "inputs.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        (self.build / "dependencies.json").write_text(json.dumps(sorted(self.dependencies), indent=2), encoding="utf-8")
        self.result["Status"] = "PASS"
        self.result["InputManifestSHA256"] = digest(self.build / "inputs.json")
        self.result["HostChecks"] = sum(row["Checks"] for row in self.result["Host"])
        (self.build / "results.json").write_text(json.dumps(self.result, indent=2), encoding="utf-8")
        artifacts = [{"Path": str(p), "SHA256": digest(p)} for p in sorted(self.build.rglob("*")) if p.is_file() and p.name != "artifacts.json"]
        (self.build / "artifacts.json").write_text(json.dumps(artifacts, indent=2), encoding="utf-8")
        print("PASS scenarios=%d checks=%d compiled-mutants=%d target-ELFs=%d public=%d attributes=%d" %
              (len(self.result["Host"]), self.result["HostChecks"], len(self.result["Mutants"]), len(self.result["TargetLinks"]),
               len(self.result["Public"]), len(self.result["Attributes"])), flush=True)
        print("Receipt: " + str(self.build / "results.json"), flush=True)


def main():
    parser = argparse.ArgumentParser()
    for option in ["repo", "arm", "host", "cmsis", "build"]:
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args()
    runner = Runner(args)
    runner.snapshot()
    runner.python_controls()
    runner.packaging_controls()
    for use_legacy in runner.cohorts:
        runner.host_tests(use_legacy)
        runner.mutants(use_legacy)
        runner.target(use_legacy)
    runner.finish()


if __name__ == "__main__":
    main()
