"""Finite mixed/pure Context qualification; no packages or target execution."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

COMMON_ROLES = ("engine", "state", "panic", "optional_configuration", "legacy_compat", "facade_bridge")
PURE_PROVIDERS = (("engine", "context/context_core.c"),
                  ("state", "context/context_runtime_state.c"),
                  ("panic", "context/context_panic.c"))
OPTIONAL_SYMBOLS = {"fiber_internal_runtime_context_configuration_abi_v1_anchor",
                    "fiber_internal_runtime_require_context_configuration_open"}
API = ["ctxrt_v1_init", "ctxrt_v1_current", "ctxrt_v1_set_dispatcher",
       "ctxrt_v1_start", "ctxrt_v1_yield"]
LEGACY = ["fiber_init", "fiber_current", "fiber_scheduler_set_pick_next",
          "fiber_start", "fiber_schedule"]
PROFILES = [("CM0", "ARM_CM0", "cortex-m0", "ARMV6M", 0, 0, [], 0),
            ("CM0PLUS-NOVTOR", "ARM_CM0", "cortex-m0plus", "ARMV6M", 1, 0, [], 0),
            ("CM0PLUS-VTOR", "ARM_CM0", "cortex-m0plus", "ARMV6M", 1, 0, [], 1),
            ("CM4", "ARM_CM4", "cortex-m4", "ARMV7EM", 4, 1,
             ["-mfpu=fpv4-sp-d16", "-mfloat-abi=hard"], 1),
            ("CM7", "ARM_CM7/r0p1", "cortex-m7", "ARMV7EM", 7, 1,
             ["-mfpu=fpv5-d16", "-mfloat-abi=hard"], 1)]
MODES = [("O2", ["-O2"]), ("Os", ["-Os"]),
         ("O2LTO", ["-O2", "-flto"]), ("OsLTO", ["-Os", "-flto"])]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def runtime_reader(repo):
    spec = importlib.util.spec_from_file_location("facade_runtime_sources", Path(repo) / "tools/runtime_sources.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def role_owner(repo, role):
    sources = runtime_reader(repo).get_runtime_source_paths(repo, (role,))
    require(len(sources) == 1, "Expected one actual facade test role owner: " + role)
    return sources[0]


def api_owner(repo):
    bridge = runtime_reader(repo).get_runtime_source_paths(repo, ("facade_bridge",))
    require(len(bridge) <= 1, "Facade bridge must have at most one API owner")
    return bridge[0] if bridge else role_owner(repo, "engine")


class StaleLinkDiagnosticError(RuntimeError):
    pass


class ClassifierControlFailure(RuntimeError):
    pass


def classify_unresolved(result, expected, linker):
    """Closed GNU-ld grammar, not a substring/blacklist error classifier."""
    def check(condition, message):
        if not condition:
            raise StaleLinkDiagnosticError(message)

    check(re.fullmatch(r"[A-Za-z_]\w*", expected), "invalid expected identity")
    check(result.returncode == 1, "stale link must exit exactly 1")
    check(result.stdout == "", "unexpected linker stdout")
    check(result.stderr.endswith("\n"), "unterminated linker diagnostics")
    lines = result.stderr[:-1].split("\n")
    trailer = "collect2.exe: error: ld returned 1 exit status"
    check(lines and lines[-1] == trailer, "missing exact collect2 trailer")
    # Object/source names and sections are the only variable context fields.
    # A drive colon is allowed; other colons cannot swallow another diagnostic.
    absolute = r"(?:[A-Za-z]:[\\/]|/)[^:\r\n\x00]+"
    obj = absolute + r"(?:\.o|\.a\([^():\r\n]+\.o\))"
    source = r"(?:[A-Za-z_][A-Za-z0-9_]*\.c|<artificial>)"
    section = r"\(\.[A-Za-z0-9_.$]+\+0x[0-9a-fA-F]+\)"
    reference = r": undefined reference to `" + re.escape(expected) + r"'"
    heading = re.compile(obj + r": in function `[A-Za-z_][A-Za-z0-9_.]*':")
    direct = re.compile(obj + ":" + section + reference)
    contextual = re.compile(source + ":" + section + reference)
    ld_prefix = re.compile(r"(?P<path>(?:[A-Za-z]:[\\/]|/)[^:\r\n\x00]*[\\/]" +
                           re.escape(Path(linker).name) + r"): (?P<body>.+)")
    serial = re.compile(r"lto-wrapper\.exe: warning: using serial compilation of [1-9][0-9]* LTRANS jobs")
    serial_note = "lto-wrapper.exe: note: see the '-flto' option documentation for more information"
    references = 0
    pending = False
    serial_seen = False
    index = 0
    while index < len(lines) - 1:
        line = lines[index]
        if not pending and references == 0 and not serial_seen and serial.fullmatch(line):
            check(index + 1 < len(lines) - 1 and lines[index + 1] == serial_note,
                  "incomplete native-LTO serial notice")
            serial_seen = True
            index += 2
            continue
        prefixed = ld_prefix.fullmatch(line)
        if pending:
            check(prefixed is None and contextual.fullmatch(line), "expected only the heading's relocation")
            pending = False
            references += 1
        else:
            check(prefixed is not None, "unexpected diagnostic line: " + line)
            check(Path(prefixed["path"]).resolve() == Path(linker).resolve(), "wrong linker diagnostic owner")
            body = prefixed["body"]
            if heading.fullmatch(body):
                pending = True
            else:
                check(direct.fullmatch(body), "unexpected linker diagnostic: " + body)
                references += 1
        index += 1
    check(not pending and references > 0, "missing expected relocation diagnostic")
    return expected


def exercise_classifier(classifier, good, expected, linker, counterexamples):
    try:
        answer = classifier(good, expected, linker)
    except StaleLinkDiagnosticError as error:
        raise ClassifierControlFailure("missing-only-rejected") from error
    if answer != expected:
        raise ClassifierControlFailure("missing-only-wrong-symbol")
    for name, counterfeit in counterexamples:
        try:
            classifier(counterfeit, expected, linker)
        except StaleLinkDiagnosticError:
            continue
        raise ClassifierControlFailure("counterfeit-accepted:" + name)


class Suite:
    def __init__(self, args):
        self.a = args
        self.build = Path(args.build).resolve()
        self.repo = Path(args.repo).resolve()
        self.snap = self.build / "inputs"
        self.root = self.snap / "repo"
        self.fixture = self.root / "tools/fixtures/context_facade"
        self.cmsis = self.snap / "cmsis"
        self.commands = []
        self.inputs = []
        self.dependencies = set()
        self.results = {"Status": "FAIL", "HostMock": [], "PublicCompiles": [],
                        "TargetLinks": [], "Attributes": [], "Controls": [], "DiagnosticControls": [],
                        "PureContextLinks": [], "PureContextControls": []}
        self.linker = None
        self.count = 0
        self.start = time.time()
        arm = Path(args.arm_gcc).resolve()
        host = Path(args.host_gcc).resolve()
        self.tools = {"arm": arm, "host": host}
        for name, suffix in [("cxx", "g++"), ("ar", "gcc-ar"), ("nm", "gcc-nm"),
                             ("dump", "objdump"), ("copy", "objcopy"), ("elf", "readelf")]:
            self.tools[name] = arm.with_name("arm-none-eabi-" + suffix + ".exe")
        self.tools["hostcxx"] = host.with_name("g++.exe")
        self.tools["hostnm"] = host.with_name("nm.exe")
        self.tools["hostdump"] = host.with_name("objdump.exe")
        for tool in self.tools.values():
            require(tool.is_file(), "Required tool missing: " + str(tool))

    def run(self, tool, arguments, failure=False):
        self.count += 1
        cmd = [str(self.tools.get(tool, tool))] + [str(x) for x in arguments]
        log = self.build / ("command-%05d.log" % self.count)
        result = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
        row = {"Index": self.count, "Command": cmd, "Exit": result.returncode,
               "Log": str(log.relative_to(self.build))}
        self.commands.append(row)
        with (self.build / "commands.jsonl").open("a", encoding="utf-8") as out:
            out.write(json.dumps(row) + "\n")
        if not failure:
            require(result.returncode == 0, "Command failed: %s\n%s\n%s" %
                    (cmd, result.stdout, result.stderr))
            for warning in re.findall(r"\bwarning: ([^\r\n]+)", result.stderr):
                require(warning == "[fiber] Selected ARMv6-M port has no SCB->VTOR; falling back to base table at 0x00000000." or
                        re.fullmatch(r"using serial compilation of \d+ LTRANS jobs", warning),
                        "Unexpected compiler/linker warning: " + warning)
        return result

    def capture(self, source, target, kind):
        source = Path(source).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        before = digest(source)
        shutil.copyfile(source, target)
        require(digest(target) == before and digest(source) == before,
                "Input changed during capture: " + str(source))
        self.inputs.append({"Source": str(source), "Copy": str(target.relative_to(self.build)),
                            "Before": before, "Kind": kind})

    def snapshot(self):
        paths = set((self.repo / "fiber").glob("*.h"))
        paths.update(runtime_reader(self.repo).get_runtime_source_inputs(self.repo, COMMON_ROLES))
        paths.update((self.repo / "fiber/port").glob("*.h"))
        paths.add(self.repo / "fiber/port/fiber_port_context_cohort_expectation.c")
        for _, directory, *_ in PROFILES:
            port = self.repo / "fiber/port" / directory
            paths.update(port.glob("*.h"))
            paths.update(port.glob("*.c"))
        paths.update((self.repo / "context").glob("*.h"))
        paths.update(p for p in (self.repo / "tools/fixtures/context_facade").glob("*") if p.is_file())
        paths.add(self.repo / "tools/test_context_facade.ps1")
        for source in sorted(paths):
            require(source.is_file(), "Required facade input missing: " + str(source))
            self.capture(source, self.root / source.relative_to(self.repo), "Source")
        for source in sorted(Path(self.a.cmsis).glob("*.h")):
            self.capture(source, self.cmsis / source.name, "CMSIS")
        for name, tool in self.tools.items():
            self.inputs.append({"Source": str(tool), "Before": digest(tool), "Kind": "Tool", "Name": name})
        # Hash the interpreter's real image, not a Windows execution alias.
        image = Path(sys.executable).resolve()
        try:
            digest(image)
        except OSError:
            image = Path(sys.base_prefix) / ("python.exe" if os.name == "nt" else "bin/python3")
        self.inputs.append({"Source": str(image), "Before": digest(image), "Kind": "Python"})
        self.results["Python"] = {"Executable": sys.executable, "Version": sys.version}
        for compiler in ["arm", "host", "cxx", "hostcxx"]:
            self.results[compiler + "Version"] = self.run(compiler, ["--version"]).stdout
        for compiler in ["arm", "host"]:
            for program in ["cc1", "cc1plus", "as", "ld", "lto1", "lto-wrapper"]:
                value = self.run(compiler, ["-print-prog-name=" + program]).stdout.strip()
                path = Path(value)
                if not path.is_absolute():
                    path = self.tools[compiler].parent / value
                path = path.resolve()
                require(path.is_file(), "Missing toolchain component: " + str(path))
                self.inputs.append({"Source": str(path), "Before": digest(path), "Kind": "Toolchain"})
                if compiler == "arm" and program == "ld":
                    self.linker = path
            probe = self.run(compiler, ["-###", "-flto", "-nostdlib", "-r", "-x", "c",
                                       str(api_owner(self.root))]).stderr
            matches = re.findall(r'(?:^|\s)-plugin\s+(?:"([^"]+)"|(\S+))', probe)
            require(len(matches) == 1, "Expected one driver-selected LTO plugin: " + compiler)
            used = Path(next(part for part in matches[0] if part)).resolve()
            queried = Path(self.run(compiler, ["-print-file-name=" + used.name]).stdout.strip()).resolve()
            require(used == queried and used.is_file(), "Driver/query LTO plugin path mismatch: " + compiler)
            self.inputs.append({"Source": str(used), "Before": digest(used), "Kind": "LTOPlugin"})
            self.run(compiler, ["-dumpspecs"])
        print("Captured immutable facade/common/classic inputs: " + str(self.build), flush=True)

    def flags(self, profile=None, root=None):
        root = root or self.root
        directory = profile[1] if profile else "ARM_CM0"
        arch = profile[3] if profile else "ARMV6M"
        flags = ["-Wall", "-Wextra", "-Werror", "-Wundef", "-ffunction-sections",
                 "-fdata-sections", "-fno-common", "-I" + str(root),
                 "-I" + str(root / "fiber"), "-I" + str(root / "context"), "-I" + str(root / "fiber/port"),
                 "-I" + str(root / "fiber/port" / directory),
                 "-I" + str(root / "tools/fixtures/context_facade"),
                 "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_" + arch + "=1"]
        if profile:
            if profile[4] <= 1 and profile[7] == 0:
                # GCC's pragma warning has no option-specific -Wno-error knob.
                # run() admits this exact no-VTOR warning and rejects all others.
                flags.remove("-Werror")
            flags += ["-mthumb", "-mcpu=" + profile[2],
                      "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
                      "-fno-asynchronous-unwind-tables", "-DFACADE_CORE=" + str(profile[4]),
                      "-DFACADE_FPU=" + str(profile[5]), "-DFACADE_VTOR=" + str(profile[7])] + (profile[6] or ["-mfloat-abi=soft"])
        return flags

    def compile(self, source, output, flags, cxx=False, cmsis=False):
        dep = output.with_suffix(".d")
        args = list(flags) + (["-I" + str(self.cmsis)] if cmsis else [])
        args += ["-std=c++17" if cxx else "-std=c11", "-x", "c++" if cxx else "c"]
        if cxx:
            args += ["-fno-exceptions", "-fno-rtti"]
        compiler = ("cxx" if cxx else "arm") if "-mthumb" in flags else ("hostcxx" if cxx else "host")
        self.run(compiler, args + ["-M", "-MF", str(dep), str(source)])
        text = dep.read_text(encoding="utf-8").replace("\\\n", " ")
        # Make escapes spaces; keep Windows drive colons/backslashes intact.
        for token in re.findall(r"(?:\\ |[^\s])+", text.split(": ", 1)[1]):
            path = Path(token.replace("\\ ", " ")).resolve()
            require(path.is_file(), "Dependency does not resolve: " + str(path))
            self.dependencies.add(str(path))
            if not path.is_relative_to(self.build) and not any(r["Source"] == str(path) for r in self.inputs):
                self.inputs.append({"Source": str(path), "Before": digest(path), "Kind": "SystemDependency"})
        self.run(compiler, args + ["-MD", "-MF", str(dep), "-c", str(source), "-o", str(output)])
        return output

    def symbols(self, path, host=False):
        text = self.run("hostnm" if host else "nm", ["-S", "--defined-only", str(path)]).stdout
        rows = []
        for line in text.splitlines():
            m = re.match(r"^([0-9a-fA-F]+)\s+(?:([0-9a-fA-F]+)\s+)?([A-Za-z])\s+(\S+)$", line)
            if m:
                rows.append((m[4], m[3], int(m[1], 16), int(m[2] or "0", 16)))
        return rows

    def state_identity(self, binary, host=False):
        rows = self.symbols(binary, host)
        for symbol in ["fiber_internal_runtime_current_context_slot",
                       "fiber_internal_runtime_port_abi_v1_anchor"] + API + LEGACY:
            # PE LTO leaves absolute zero-valued bookkeeping symbols beside
            # the real local/global definition. They are not allocated state.
            matches = [r for r in rows if r[0] == symbol and (not host or r[1] != "A")]
            require(len(matches) == 1, "Missing/duplicate exact runtime symbol: " + symbol)
        slot = [r for r in rows if r[0] == "fiber_internal_runtime_current_context_slot" and r[1] != "A"][0]
        if host:
            # PE nm omits sizes and classifies a named .bss subsection as D.
            require(slot[1] in "BbDd", "Host current slot storage changed")
        else:
            require(slot[1] in "Bb" and slot[3] == 4, "Current slot storage changed")

    def host_build(self, root, directory, mode, modern_cxx=False):
        directory.mkdir(parents=True)
        flags = self.flags(root=root) + mode
        sources = runtime_reader(root).get_runtime_source_paths(root, COMMON_ROLES)
        require(len({source.name for source in sources}) == len(sources), "Ambiguous common object basenames")
        objects = [self.compile(source, directory / (source.name + ".o"), flags) for source in sources]
        if "-flto" not in mode:
            sections = self.run("hostdump", ["-h", str(directory / (role_owner(root, "state").name + ".o"))]).stdout
            require(re.search(r"\.bss\.fiber_runtime_current_context_slot\s+00000008\b", sections),
                    "Host current slot object is not one 64-bit pointer")
        fixture = root / "tools/fixtures/context_facade"
        for modern in [0, 1]:
            cxx = bool(modern) == modern_cxx
            objects.append(self.compile(fixture / "consumer.c", directory / ("consumer%d.o" % modern),
                           flags + ["-DUSE_NEW=" + str(modern),
                                    "-DINCLUDE_ORDER=" + str(0 if modern else 1)], cxx))
        objects.append(self.compile(fixture / "host.c", directory / "mock.o", flags))
        binary = directory / "host.exe"
        self.run("host", flags + [str(x) for x in objects] + ["-o", str(binary)])
        return binary

    def host_tests(self):
        modes = [("O0", ["-O0"])] + MODES
        for index, (mode, flags) in enumerate(modes):
            binary = self.host_build(self.root, self.build / ("host-" + mode), flags, bool(index % 2))
            self.state_identity(binary, True)
            for scenario in range(38):
                result = self.run(str(binary), [str(scenario)])
                m = re.fullmatch(r"PASS host-mock scenario=%d checks=(\d+)\s*" % scenario, result.stdout)
                require(m is not None and not result.stderr, "Host result protocol mismatch")
                self.results["HostMock"].append({"Mode": mode, "Scenario": scenario, "Checks": int(m[1])})
            print("PASS host-mock " + mode + " (38 fresh-process scenarios)", flush=True)

    def mutation(self, name, relative, old, new):
        root = self.build / "mutants" / name
        shutil.copytree(self.root, root)
        path = root / relative
        body = path.read_text(encoding="utf-8")
        require(body.count(old) == 1, "Mutation anchor must match exactly once: " + name)
        path.write_text(body.replace(old, new), encoding="utf-8")
        return root

    def host_controls(self):
        engine = role_owner(self.root, "engine")
        state = role_owner(self.root, "state")
        api = api_owner(self.root)
        engine_relative, state_relative, api_relative = (p.relative_to(self.root) for p in (engine, state, api))
        text = engine.read_text()
        guards = re.findall(r"(FIBER_REQUIRE\(fiber_internal_scheduler_is_configured\(\) != 0u, 'K'\);)"
                            r"(\s+)(FIBER_REQUIRE\((?:fiber_current|ctxrt_v1_current)\(\) == 0, 'k'\);)", text)
        require(len(guards) == 1, "Actual engine start-precedence mutation anchor changed")
        first, whitespace, second = guards[0]
        api_text = api.read_text()
        current_calls = [call for call in ("return fiber_current();", "return fiber_internal_runtime_load_current_context();")
                         if call in api_text]
        set_calls = [call for call in ("fiber_scheduler_set_pick_next(dispatch, user);",
                                      "fiber_internal_scheduler_store_pick_next(dispatch, user);") if call in api_text]
        yield_calls = [call for call in ("fiber_schedule();", "fiber_port_runtime_schedule();") if call in api_text]
        require(len(current_calls) == len(set_calls) == len(yield_calls) == 1, "Actual Context API mutation owner changed")
        mutants = [
            ("start-precedence", engine_relative, first + whitespace + second,
             second + whitespace + first, 4,
             "test >= 0 && test < 19 && panic_code == expected[test]"),
            ("configuration-close", engine_relative,
             "fiber_internal_runtime_close_context_configuration();", "/* removed by control */", 8,
             "fiber_internal_runtime_context_configuration_is_open() == 0"),
            ("facade-current", api_relative, current_calls[0],
             "(void)" + current_calls[0][len("return "):] + " return 0;", 8,
             "modern_current() == ctx && legacy_current() == ctx"),
            ("facade-user", api_relative,
             set_calls[0], "(void)user; " + set_calls[0].replace("dispatch, user", "dispatch, 0"), 8,
             "current == expected_current && user == expected_user"),
            ("facade-yield", api_relative, yield_calls[0], "/* removed by control */", 21, "0"),
            ("task-return", engine_relative, "fiber_panic('R');", "fiber_panic('N');", 22,
             "test >= 0 && test < 19 && panic_code == expected[test]"),
            ("dispatcher-replacement", state_relative,
             "fiber_internal_runtime_scheduler_pick_next = pick_next;",
             "if (fiber_internal_runtime_scheduler_pick_next == 0) fiber_internal_runtime_scheduler_pick_next = pick_next;",
             36, "replacement_hook_count == 1"),
        ]
        for name, source, old, new, scenario, expression in mutants:
            root = self.mutation(name, source, old, new)
            binary = self.host_build(root, self.build / ("control-" + name), ["-O2"])
            result = self.run(str(binary), [str(scenario)], failure=True)
            require(result.returncode == 90 and re.fullmatch(
                    r"ASSERT line=\d+ expression=" + re.escape(expression) + r" trace=[A-Z]* panic=[A-Za-z-]\s*", result.stderr) and
                    not result.stdout, "Control not killed by maintained assertion: " + name)
            self.results["Controls"].append({"Name": name, "Scenario": scenario,
                                             "Exit": result.returncode, "Diagnostic": result.stderr.strip()})

    def public_and_targets(self):
        for profile in PROFILES:
            name = profile[0]
            flags = self.flags(profile)
            libgcc = Path(self.run("arm", flags + ["-print-libgcc-file-name"]).stdout.strip()).resolve()
            self.inputs.append({"Source": str(libgcc), "Before": digest(libgcc), "Kind": "TargetLibrary"})
            libgcov = Path(self.run("arm", flags + ["-print-file-name=libgcov.a"]).stdout.strip()).resolve()
            self.inputs.append({"Source": str(libgcov), "Before": digest(libgcov), "Kind": "TargetLibrary"})
            directory = self.build / name
            directory.mkdir()
            for cxx in [False, True]:
                for order in [0, 1, 2]:
                    obj = directory / ("public-%d-%d.o" % (cxx, order))
                    self.compile(self.fixture / "consumer.c", obj,
                                 flags + ["-O2", "-DUSE_NEW=1", "-DINCLUDE_ORDER=" + str(order)], cxx)
                    # Full public static allocation must bind the exact storage identity.
                    undefined = self.run("nm", ["-u", str(obj)]).stdout
                    identities = re.findall(r"\bU\s+(fiber_port_storage_cohort_\w+)", undefined)
                    require(len(identities) == 1, "Context-only consumer lost storage identity")
                    require("SVC_Handler" not in undefined and "ctxrt_v1_" in undefined,
                            "Public consumer unexpectedly depends on private handlers")
                    deps = obj.with_suffix(".d").read_text(encoding="utf-8")
                    require(not re.search(r"(?:core_cm\d+|fiber_port_private|fiber_runtime_state)\.h", deps),
                            "Public Context storage gained private/CMSIS dependencies")
                    if order == 0:
                        require("fiber_api_decl.h" not in deps and "fiber_core.h" not in deps,
                                "Context-only consumer imports legacy callable API")
                    self.results["PublicCompiles"].append({"Profile": name, "Language": "C++" if cxx else "C",
                                                           "Order": order, "Storage": identities[0]})
            for mode, opts in MODES:
                self.target_links(profile, mode, opts, directory)
                self.pure_context_links(profile, mode, opts, directory)
            self.attributes(profile, directory)
            print("PASS " + name + " public/ELF/attributes", flush=True)

    def link(self, profile, flags, directory, label, inputs, failure=False, script=None):
        binary = directory / (label + ".elf")
        result = self.run("arm", flags + ["-nostdlib", "-Wl,--gc-sections", "-Wl,--fatal-warnings",
                         "-Wl,-Map=" + str(binary.with_suffix(".map")),
                         "-T" + str(script or self.fixture / "link.ld"), "-Wl,--start-group"] +
                         [str(x) for x in inputs] + ["-Wl,--end-group", "-lgcc", "-o", str(binary)], failure)
        return binary, result

    def expected_missing(self, obj, prefix):
        text = self.run("nm", ["-u", str(obj)]).stdout
        symbols = []
        for line in text.splitlines():
            match = re.fullmatch(r"\s*U\s+([A-Za-z_]\w*)", line)
            require(match is not None, "Unexpected actual stale-input nm output: " + line)
            if match[1].startswith(prefix):
                symbols.append(match[1])
        require(len(symbols) == 1, "Expected one exact identity import in " + str(obj))
        return symbols[0]

    def require_unresolved(self, result, expected):
        return classify_unresolved(result, expected, self.linker)

    def diagnostic_controls(self, profile, mode, flags, directory, inputs, good, expected):
        _, mixed = self.link(profile, flags, directory, "missing-plus-overflow", inputs, True,
                             self.fixture / "overflow.ld")
        missing = set(re.findall(r"undefined reference to `([A-Za-z_]\w*)'", mixed.stderr))
        require(mixed.returncode == 1 and mixed.stdout == "" and missing == {expected} and
                re.search(r"region `RAM' overflowed by [1-9][0-9]* bytes", mixed.stderr),
                "Compiled mixed-failure control did not produce both expected missing identity and RAM overflow")

        def fake(text=None, code=1, stdout=""):
            return subprocess.CompletedProcess([], code, stdout, good.stderr if text is None else text)

        trailer = "collect2.exe: error: ld returned 1 exit status\n"
        before_trailer = good.stderr[:-len(trailer)]
        wrong = expected + "_counterfeit"
        cases = [
            ("real-missing-plus-overflow", mixed),
            ("same-prefix-wrong-name", fake(good.stderr.replace(expected, wrong))),
            ("unknown-linker-error", fake(before_trailer + str(self.linker) + ": error: unrelated failure\n" + trailer)),
            ("unknown-unprefixed-error", fake(before_trailer + "error: unrelated failure\n" + trailer)),
            ("error-after-trailer", fake(good.stderr + "error: unrelated failure\n")),
            ("ram-overflow-text", fake(before_trailer + str(self.linker) + ": region `RAM' overflowed by 16 bytes\n" + trailer)),
            ("multiple-definition", fake(before_trailer + str(self.linker) + ": multiple definition of `other'\n" + trailer)),
            ("offset-out-of-range", fake(before_trailer + str(self.linker) + ": offset out of range\n" + trailer)),
            ("unexpected-warning", fake(before_trailer + str(self.linker) + ": warning: unrelated warning\n" + trailer)),
            ("incomplete-heading", fake(before_trailer + str(self.linker) + ": C:/fixture.o: in function `entry':\n" + trailer)),
            ("blank-diagnostic", fake(before_trailer + "\n" + trailer)),
            ("missing-trailer", fake(before_trailer)),
            ("duplicate-trailer", fake(good.stderr + trailer)),
            ("missing-reference", fake(trailer)),
            ("unterminated-trailer", fake(good.stderr[:-1])),
            ("exit-zero", fake(code=0)),
            ("exit-two", fake(code=2)),
            ("stdout-contamination", fake(stdout="unrelated failure\n")),
        ]
        exercise_classifier(classify_unresolved, good, expected, self.linker, cases)
        for name, result in cases:
            self.results["DiagnosticControls"].append({"Name": name, "Profile": profile[0], "Mode": mode,
                "ExpectedMissing": expected, "Exit": result.returncode, "Stdout": result.stdout,
                "Stderr": result.stderr, "Result": "REJECT"})

        def prefix_only(result, name, linker):
            symbols = set(re.findall(r"undefined reference to [`']([^`']+)'", result.stderr))
            if result.returncode and len(symbols) == 1 and next(iter(symbols)).startswith(name):
                return next(iter(symbols))
            raise StaleLinkDiagnosticError("counterfeit prefix-only classifier")

        def ignore_exit(result, name, linker):
            return classify_unresolved(subprocess.CompletedProcess([], 1, result.stdout, result.stderr), name, linker)

        def ignore_stdout(result, name, linker):
            return classify_unresolved(subprocess.CompletedProcess([], result.returncode, "", result.stderr), name, linker)

        def infer_wrong_name(result, name, linker):
            symbols = set(re.findall(r"undefined reference to `([A-Za-z_]\w*)'", result.stderr))
            if len(symbols) != 1:
                raise StaleLinkDiagnosticError("counterfeit name inference")
            return classify_unresolved(result, next(iter(symbols)), linker)

        def always_reject(result, name, linker):
            raise StaleLinkDiagnosticError("counterfeit always-reject classifier")

        mutants = [("prefix-only", prefix_only, "counterfeit-accepted:real-missing-plus-overflow"),
                   ("ignore-exit", ignore_exit, "counterfeit-accepted:exit-zero"),
                   ("ignore-stdout", ignore_stdout, "counterfeit-accepted:stdout-contamination"),
                   ("infer-symbol-from-error", infer_wrong_name, "counterfeit-accepted:same-prefix-wrong-name"),
                   ("always-reject", always_reject, "missing-only-rejected")]
        for name, classifier, expected_failure in mutants:
            try:
                exercise_classifier(classifier, good, expected, self.linker, cases)
            except ClassifierControlFailure as error:
                require(str(error) == expected_failure, "Wrong counterfeit-classifier kill: " + name + ": " + str(error))
                self.results["DiagnosticControls"].append({"Name": "classifier-" + name, "Profile": profile[0],
                    "Mode": mode, "ExpectedMissing": expected, "Result": "KILLED", "Reason": str(error)})
            else:
                raise RuntimeError("Counterfeit classifier survived: " + name)

    def target_links(self, profile, mode, opts, parent):
        directory = parent / mode
        directory.mkdir()
        flags = self.flags(profile) + opts
        common_sources = runtime_reader(self.root).get_runtime_source_paths(self.root, COMMON_ROLES)
        require(len({source.name for source in common_sources}) == len(common_sources), "Ambiguous common object basenames")
        common_by_source = {source: self.compile(source, directory / (source.name + ".o"), flags) for source in common_sources}
        common = list(common_by_source.values())
        compat = self.symbols(common_by_source[api_owner(self.root)]) if "-flto" not in opts else []
        require(not any(r[1] in "bBdDgGsS" for r in compat), "Facade introduced writable state")
        ports = [self.compile(path, directory / (path.name + ".o"), flags, cmsis=True)
                 for path in sorted((self.root / "fiber/port" / profile[1]).glob("*.c"))]
        expectation = self.compile(self.root / "fiber/port/fiber_port_context_cohort_expectation.c",
                                   directory / "expectation.o", flags, cmsis=True)
        consumers = []
        for modern in [0, 1]:
            consumers.append(self.compile(self.fixture / "consumer.c", directory / ("consumer%d.o" % modern),
                             flags + ["-DUSE_NEW=" + str(modern), "-DINCLUDE_ORDER=" + str(0 if modern else 2)], not modern))
        driver = self.compile(self.fixture / "target.c", directory / "driver.o", flags, cmsis=True)
        archive = directory / "libengine.a"
        self.run("ar", ["rcs", str(archive)] + [str(x) for x in common + ports])
        for form in ["direct", "archive"]:
            engine = common + ports if form == "direct" else [archive]
            binary, _ = self.link(profile, flags, directory, form, [driver, expectation] + consumers + engine)
            self.state_identity(binary)
            rows = self.symbols(binary)
            cohorts = [r[0] for r in rows if r[0].startswith("fiber_port_context_cohort_armv")]
            require(len(cohorts) == 1 and ("_v%d_d" % profile[7]) in cohorts[0],
                    "Final private cohort has incorrect VTOR capability")
            for handler in ["SVC_Handler", "PendSV_Handler"]:
                require(len([r for r in rows if r[0] == handler and r[1] == "T"]) == 1,
                        "Strong vector lost: " + handler)
            vector = directory / (form + "-vectors.bin")
            self.run("copy", ["-O", "binary", "--only-section=.isr_vector", str(binary), str(vector)])
            words = struct.unpack("<48I", vector.read_bytes())
            for slot, handler in [(11, "SVC_Handler"), (14, "PendSV_Handler")]:
                address = [r[2] for r in rows if r[0] == handler][0]
                require(words[slot] == (address | 1), "Vector does not resolve to strong " + handler)
            require(not self.run("nm", ["-u", str(binary)]).stdout.strip(), "Final ELF has undefined symbols")
            attributes = self.run("elf", ["-A", str(binary)]).stdout
            if profile[5]:
                require("Tag_ABI_VFP_args: VFP registers" in attributes, "Hard FP ABI missing in final ELF")
            self.run("dump", ["-drwC", str(binary)])
            self.results["TargetLinks"].append({"Profile": profile[0], "Mode": mode, "Form": form,
                                                 "ELF": str(binary.relative_to(self.build)), "StrongVectors": True})
        # Real expectation compiled with a different priority geometry rejects a complete archive.
        stale = self.compile(self.root / "fiber/port/fiber_port_context_cohort_expectation.c",
                             directory / "stale-expectation.o", flags + ["-DFACADE_NVIC_BITS=3"], cmsis=True)
        expected = self.expected_missing(stale, "fiber_port_context_cohort_")
        _, result = self.link(profile, flags, directory, "stale-cohort", [driver, stale] + consumers + [archive], True)
        self.require_unresolved(result, expected)
        self.results["Controls"].append({"Name": "stale-private-cohort", "Profile": profile[0], "Mode": mode,
                                         "ExpectedMissing": expected, "StaleInput": str(stale.relative_to(self.build))})
        if profile[0] == "CM0" and mode in ("O2", "O2LTO"):
            self.diagnostic_controls(profile, mode, flags, directory, [driver, stale] + consumers + [archive], result, expected)
        if profile[4] == 1:
            opposite = list(profile)
            opposite[7] = 1 - profile[7]
            stale_vtor = self.compile(self.root / "fiber/port/fiber_port_context_cohort_expectation.c",
                                      directory / "stale-vtor.o", self.flags(opposite) + opts, cmsis=True)
            expected = self.expected_missing(stale_vtor, "fiber_port_context_cohort_")
            _, result = self.link(profile, flags, directory, "stale-vtor", [driver, stale_vtor] + consumers + [archive], True)
            missing = self.require_unresolved(result, expected)
            require(("_v%d_d" % opposite[7]) in missing, "Wrong stale VTOR diagnostic")
            self.results["Controls"].append({"Name": "cross-vtor-private-cohort", "Profile": profile[0], "Mode": mode,
                                             "ExpectedMissing": expected, "StaleInput": str(stale_vtor.relative_to(self.build))})
        # Alter only the caller's actual storage spelling; no provider stub is added.
        root = self.mutation(profile[0] + "-" + mode + "-storage", "fiber/port/" + profile[1] + "/fiber_port_types.h",
                             "#define FIBER_PORT_STORAGE_COHORT_REVISION 1", "#define FIBER_PORT_STORAGE_COHORT_REVISION 999")
        wrong = self.compile(root / "tools/fixtures/context_facade/consumer.c", directory / "stale-storage.o",
                             self.flags(profile, root) + opts + ["-DUSE_NEW=1", "-DINCLUDE_ORDER=0"])
        expected = self.expected_missing(wrong, "fiber_port_storage_cohort_")
        _, result = self.link(profile, flags, directory, "stale-storage", [driver, expectation, consumers[0], wrong, archive], True)
        missing = self.require_unresolved(result, expected)
        require("_v999_" in missing,
                "Context consumer stale storage accepted")
        self.results["Controls"].append({"Name": "stale-context-storage", "Profile": profile[0], "Mode": mode,
                                         "ExpectedMissing": expected, "StaleInput": str(wrong.relative_to(self.build))})
        # A real common anchor rename must fail with the old backend, even with
        # all component archives present and after LTO/section GC.
        state = role_owner(self.root, "state")
        relative = state.relative_to(self.root)
        root = self.mutation(profile[0] + "-" + mode + "-reverse", relative,
                             "const unsigned char fiber_internal_runtime_port_abi_v1_anchor =",
                             "const unsigned char fiber_internal_runtime_port_abi_v2_anchor =")
        wrong = self.compile(root / relative, directory / "stale-reverse.o",
                             self.flags(profile, root) + opts)
        # The real constructor is the old reverse-v1 consumer in this pair;
        # the mutated common object provides only v2 and imports no v1 itself.
        old_consumer = next(x for x in ports if x.name == "fiber_port_boot.c.o")
        expected = self.expected_missing(old_consumer, "fiber_internal_runtime_port_abi_")
        _, result = self.link(profile, flags, directory, "stale-reverse", [driver, expectation] + consumers +
                              [wrong] + [obj for source, obj in common_by_source.items() if source != state] + ports, True)
        require(self.require_unresolved(result, expected) ==
                "fiber_internal_runtime_port_abi_v1_anchor", "Stale reverse ABI accepted")
        self.results["Controls"].append({"Name": "stale-reverse-v1", "Profile": profile[0], "Mode": mode,
                                         "ExpectedMissing": expected, "StaleInput": str(old_consumer.relative_to(self.build))})

    def pure_context_links(self, profile, mode, opts, parent):
        directory = parent / ("pure-" + mode)
        directory.mkdir()
        flags = self.flags(profile) + opts
        reader = runtime_reader(self.root)
        # Independent expected owner paths: the manifest selects inputs, not the
        # oracle that those inputs are the canonical Context-only provider trio.
        sources = []
        for role, relative in PURE_PROVIDERS:
            selected = reader.get_runtime_source_paths(self.root, (role,))
            require(selected == (self.root / relative,), "Pure Context provider ownership changed: " + role)
            sources.extend(selected)
        common = {source: self.compile(source, directory / (source.name + ".o"), flags) for source in sources}
        for source, obj in common.items():
            defined = {row[0] for row in self.symbols(obj)}
            imported = set(re.findall(r"\bU\s+(\w+)", self.run("nm", ["-u", obj]).stdout))
            require(not (defined | imported).intersection(set(LEGACY) | OPTIONAL_SYMBOLS),
                    "Mandatory Context object acquired legacy/optional ownership or dependency: " + str(source))
        ports = [self.compile(path, directory / (path.name + ".o"), flags, cmsis=True)
                 for path in sorted((self.root / "fiber/port" / profile[1]).glob("*.c"))]
        expectation = self.compile(self.root / "fiber/port/fiber_port_context_cohort_expectation.c",
                                   directory / "expectation.o", flags, cmsis=True)
        driver = self.compile(self.fixture / "context_target.c", directory / "driver.o", flags, cmsis=True)
        archive = directory / "libcontext-port.a"
        self.run("ar", ["rcs", archive, *common.values(), *ports])
        consumers = {}
        for cxx in (False, True):
            language = "cpp" if cxx else "c"
            consumer = self.compile(self.fixture / "consumer.c", directory / (language + "-consumer.o"),
                                    flags + ["-DUSE_NEW=1", "-DINCLUDE_ORDER=0"], cxx)
            consumers[language] = consumer
            imports = set(re.findall(r"\bU\s+(\w+)", self.run("nm", ["-u", consumer]).stdout))
            storage = {name for name in imports if name.startswith("fiber_port_storage_cohort_")}
            require(len(storage) == 1 and imports == set(API) | storage,
                    "Pure allocating consumer must import only Context v1 and one storage identity")
            dependencies = consumer.with_suffix(".d").read_text(encoding="utf-8")
            require(not re.search(r"(?:fiber_core|fiber_api_decl|fiber_runtime_state|fiber_port_private|core_cm\w+)\.h", dependencies),
                    "Pure public consumer acquired a legacy/private/CMSIS dependency")
            for form in ("direct", "archive"):
                engine = [*common.values(), *ports] if form == "direct" else [archive]
                binary, _ = self.link(profile, flags, directory, language + "-" + form,
                                      [driver, expectation, consumer, *engine])
                rows = self.symbols(binary)
                names = {r[0] for r in rows}
                require(not names.intersection(LEGACY), "Pure Context ELF contains a legacy five-operation symbol")
                require(not names.intersection(OPTIONAL_SYMBOLS), "Pure Context ELF contains optional configuration")
                for name in API + ["fiber_internal_runtime_port_abi_v1_anchor",
                                   "fiber_internal_runtime_current_context_slot"]:
                    require(len([r for r in rows if r[0] == name]) == 1,
                            "Pure Context missing/duplicate runtime symbol: " + name)
                slot = next(r for r in rows if r[0] == "fiber_internal_runtime_current_context_slot")
                require(slot[1] in "Bb" and slot[3] == 4, "Pure Context acquired a second/invalid current slot")
                cohorts = [r[0] for r in rows if r[0].startswith("fiber_port_context_cohort_armv")]
                require(len(cohorts) == 1 and ("_v%d_d" % profile[7]) in cohorts[0],
                        "Pure Context private cohort/VTOR capability mismatch")
                require(storage <= names, "Pure Context storage provider lost")
                for name in ("SVC_Handler", "PendSV_Handler"):
                    require(len([r for r in rows if r[0] == name and r[1] == "T"]) == 1,
                            "Pure Context lost its actual strong vector: " + name)
                vector = binary.with_suffix(".vectors.bin")
                self.run("copy", ["-O", "binary", "--only-section=.isr_vector", binary, vector])
                words = struct.unpack("<48I", vector.read_bytes())
                for index, name in ((11, "SVC_Handler"), (14, "PendSV_Handler")):
                    require(words[index] == (next(r[2] for r in rows if r[0] == name) | 1),
                            "Pure Context vector does not resolve to actual backend: " + name)
                require(not self.run("nm", ["-u", binary]).stdout.strip(), "Pure Context has unresolved dependencies")
                attributes = self.run("elf", ["-A", binary]).stdout
                if profile[5]:
                    require("Tag_ABI_VFP_args: VFP registers" in attributes, "Pure Context lost hard-FP ABI")
                self.run("dump", ["-drwC", binary])
                self.results["PureContextLinks"].append(dict(Profile=profile[0], Mode=mode, Language=language,
                    Form=form, ELF=str(binary.relative_to(self.build)), Providers=[str(s.relative_to(self.root)) for s in sources],
                    LegacyFiveAbsent=True, OptionalConfigurationAbsent=True, StrongVectors=True))

        # Retain the same closed missing-name classifier. No shim or optional
        # provider is added to make either deliberate dependency link.
        engine = self.root / PURE_PROVIDERS[0][1]
        actual = engine.read_text(encoding="utf-8")
        calls = [call for call in ("fiber_port_context_init(context, stack_begin, stack_end, entry, arg);",
                                  "fiber_port_context_init(ctx, stack_begin, stack_end, entry, arg);") if call in actual]
        require(len(calls) == 1, "Pure optional-dependency mutant init anchor changed")
        parameter = "context" if calls[0].startswith("fiber_port_context_init(context,") else "ctx"
        mutants = (("legacy-dependency", "return fiber_internal_runtime_load_current_context();",
                    "extern CtxrtContextV1 *fiber_current(void); "
                    "CtxrtContextV1 *(*volatile dependency_call)(void) = fiber_current; "
                    "return dependency_call();", "fiber_current"),
                   ("optional-dependency", calls[0],
                    "extern void fiber_internal_runtime_require_context_configuration_open(const CtxrtContextV1 *); "
                    "void (*volatile dependency_call)(const CtxrtContextV1 *) = "
                    "fiber_internal_runtime_require_context_configuration_open; "
                    "dependency_call(" + parameter + "); " + calls[0],
                    "fiber_internal_runtime_require_context_configuration_open"))
        for label, old, new, missing in mutants:
            require(actual.count(old) == 1, "Pure dependency mutant anchor changed: " + label)
            changed = directory / (label.replace("-", "_") + ".c")
            changed.write_text(actual.replace(old, new), encoding="utf-8")
            obj = self.compile(changed, directory / (label + ".o"), flags)
            expected = self.expected_missing(obj, missing)
            require(expected == missing, "Pure dependency control does not import the exact intended symbol")
            _, result = self.link(profile, flags, directory, label,
                                  [driver, expectation, consumers["c"], obj] +
                                  [output for source, output in common.items() if source != engine] + ports, True)
            self.require_unresolved(result, missing)
            self.results["PureContextControls"].append(dict(Name=label, Profile=profile[0], Mode=mode,
                ExpectedMissing=missing, Mutant=str(changed.relative_to(self.build)),
                MutantSHA256=digest(changed), OptionalAndLegacyProvidersOmitted=True))

    def attribute_object(self, root, profile, directory, opts, label):
        directory.mkdir(parents=True, exist_ok=True)
        raw = ["-finstrument-functions", "-fstack-protector-all", "-fprofile-arcs", "-ftest-coverage",
               "-fsanitize=undefined", "-fsanitize-coverage=trace-pc"]
        flags = self.flags(profile, root) + opts + raw
        obj = self.compile(api_owner(root), directory / (label + ".o"), flags)
        if "-flto" in opts:
            lowered = directory / (label + "-native.o")
            self.run("arm", flags + ["-nostdlib", "-r", "-flinker-output=nolto-rel", str(obj), "-o", str(lowered)])
            obj = lowered
            sections = self.run("dump", ["-h", str(obj)]).stdout
            require(".gnu.lto_" not in sections, "Native LTO lowering retained IR/fat fallback")
        text = self.run("dump", ["-drwC", str(obj)]).stdout
        undefined = self.run("nm", ["-u", str(obj)]).stdout
        return text, undefined

    def attributes(self, profile, parent):
        forbidden = r"__cyg_profile|__stack_chk|__gcov|__ubsan|__sanitizer_cov|\bmcount\b|__gnu_mcount"
        modes = [(opt + ("LTO" if lto else ""), ["-" + opt] + (["-flto"] if lto else []))
                 for opt in ["O0", "Og", "O2", "Os", "O3"] for lto in [False, True]]
        macros = self.run("arm", self.flags(profile) + ["-dM", "-E", "-x", "c",
                          str(self.root / "context/context_api_attributes.h")]).stdout
        for alias, canonical in [("CTXRT_API_ATTR_SENSITIVE", "FIBER_API_ATTR_SENSITIVE"),
                                 ("CTXRT_GENERAL_REGS_ONLY", "FIBER_GENERAL_REGS_ONLY"),
                                 ("CTXRT_DISPATCH_ATTR", "FIBER_SCHEDULER_HOOK_ATTR"),
                                 ("CTXRT_API_THREAD_FUNCTION", "FIBER_API_THREAD_FUNCTION"),
                                 ("CTXRT_API_NORETURN", "FIBER_API_NORETURN")]:
            require(re.search(r"(?m)^#define " + alias + " " + canonical + r"$", macros),
                    "Context attribute alias changed: " + alias)
        require('target("general-regs-only")' in macros, "ARM GRO annotation is inactive")
        for mode, opts in modes:
            directory = parent / ("attributes-" + mode)
            text, undefined = self.attribute_object(self.root, profile, directory, opts, "positive")
            native = directory / ("positive-native.o" if "-flto" in opts else "positive.o")
            require(not any(r[1] in "bBdDgGsS" for r in self.symbols(native)), "Facade acquired writable state/counters")
            require(not re.search(forbidden, text + undefined), "Facade compiler protection failed: " + profile[0] + mode)
            instructions = []
            for line in text.splitlines():
                columns = line.split("\t")
                if len(columns) >= 3 and re.fullmatch(r"\s*[0-9a-f]+:", columns[0]):
                    instructions.append(columns[2].split()[0])
            require(instructions and not any(mnemonic.startswith("v") for mnemonic in instructions),
                    "Facade acquired FP/SIMD code")
            for symbol in API:
                require("<" + symbol + ">:" in text, "Native facade body not present: " + symbol)
            for symbol in ["ctxrt_v1_current", "ctxrt_v1_yield"]:
                table = self.run("dump", ["-t", str(native)]).stdout
                require(re.search(r"\.text\.fiber_runtime_thread_functions\s+[0-9a-f]+\s+" + symbol + r"\b", table),
                        "Context Thread placement lost: " + symbol)
            self.results["Attributes"].append({"Profile": profile[0], "Mode": mode,
                                                "RawFamilies": 6, "NativeLTO": "-flto" in opts})
            # Remove the actual canonical bundle on declarations AND definitions.
            root = self.build / "mutants" / (profile[0] + "-attrs-" + mode)
            shutil.copytree(self.root, root)
            for relative in [Path("context/context_api_decl.h"), api_owner(root).relative_to(root)]:
                path = root / relative
                body = path.read_text(encoding="utf-8")
                pattern = re.compile(r"((?:CTXRT_[A-Z_]+\s+)+)((?:void|CtxrtContextV1\s*\*)\s*"
                                     r"(ctxrt_v1_(?:init|current|set_dispatcher|start|yield))\s*\()")
                found = pattern.findall(body)
                require(len(found) == 5 and {item[2] for item in found} == set(API) and
                        all(item[0].split().count("CTXRT_API_ATTR_SENSITIVE") == 1 for item in found),
                        "Attribute mutation surface changed")
                mutated = pattern.sub(lambda match: match[1].replace("CTXRT_API_ATTR_SENSITIVE", "") + match[2], body)
                path.write_text(mutated, encoding="utf-8")
            badtext, badundefined = self.attribute_object(root, profile, directory / "control", opts, "unprotected")
            require("__cyg_profile_func_enter" in badtext + badundefined and
                    "__cyg_profile_func_exit" in badtext + badundefined,
                    "Annotation removal did not produce active instrumentation")
            self.results["Controls"].append({"Name": "actual-annotation-removal", "Profile": profile[0], "Mode": mode})

    def finish(self):
        drift = []
        for row in self.inputs:
            row["After"] = digest(row["Source"]) if Path(row["Source"]).is_file() else "MISSING"
            if row["After"] != row["Before"]:
                drift.append(row["Source"])
            if "Copy" in row:
                row["CopyAfter"] = digest(self.build / row["Copy"])
                if row["CopyAfter"] != row["Before"]:
                    drift.append(row["Copy"])
        self.results["Drift"] = drift
        self.results["Commands"] = self.count
        self.results["Seconds"] = round(time.time() - self.start, 2)
        (self.build / "inputs.json").write_text(json.dumps(self.inputs, indent=2), encoding="utf-8")
        (self.build / "dependencies.json").write_text(json.dumps(sorted(self.dependencies), indent=2), encoding="utf-8")
        if drift:
            self.results["Status"] = "FAIL"
        (self.build / "results.json").write_text(json.dumps(self.results, indent=2), encoding="utf-8")
        artifacts = [{"Path": str(p.relative_to(self.build)), "SHA256": digest(p)}
                     for p in sorted(self.build.rglob("*")) if p.is_file() and p.name != "artifacts.json"]
        (self.build / "artifacts.json").write_text(json.dumps(artifacts, indent=2), encoding="utf-8")
        require(not drift, "Source/tool input drift: " + str(drift))


def main():
    require(sys.flags.optimize == 0 and not os.environ.get("PYTHONOPTIMIZE"),
            "context-facade: optimized Python invocation is not supported")
    parser = argparse.ArgumentParser()
    for name in ["repo", "build", "arm-gcc", "host-gcc", "cmsis"]:
        parser.add_argument("--" + name, required=True)
    suite = Suite(parser.parse_args())
    try:
        suite.snapshot()
        suite.host_tests()
        suite.host_controls()
        suite.public_and_targets()
        suite.results["Status"] = "PASS"
    except Exception as error:
        suite.results["Error"] = str(error)
        raise
    finally:
        suite.finish()
    print("PASS context facade: %d host scenarios, %d public compiles, %d real-backend ELF links, %d controls; %s" %
          (len(suite.results["HostMock"]), len(suite.results["PublicCompiles"]),
           len(suite.results["TargetLinks"]), len(suite.results["Controls"]), suite.build), flush=True)
    print("PASS closed diagnostic controls: %d" % len(suite.results["DiagnosticControls"]), flush=True)
    print("PASS pure Context: %d real-backend ELF links, %d exact dependency controls" %
          (len(suite.results["PureContextLinks"]), len(suite.results["PureContextControls"])), flush=True)


if __name__ == "__main__":
    main()
