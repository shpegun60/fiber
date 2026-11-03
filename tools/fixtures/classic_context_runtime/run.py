"""Actual microbit/CM0 Context and Fiber consumer execution; never provisions tools."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
PASS = "PASS:CM0-CONTEXT-RUNTIME"
CHECK = "CHECK:CM0:CPUID=C20:SVC=11:PENDSV=14:FIRST=1:SELF=1:BIDIR=1:ROUNDS=16:REGS=R4-R11"
OPT_ERROR = "Disable PYTHONOPTIMIZE and do not use -O/-OO for classic Context runtime"
STOPPED = ("tools/fixtures/cm33f_secure_transfer_reference", "tools/fixtures/m55_secure_closed_parity",
           "tools/test_m55_secure_closed_parity.ps1", "tools/test_cm33f_secure_transfer_reference.ps1")
PUBLIC = ("ctxrt_v1_init", "ctxrt_v1_current", "ctxrt_v1_set_dispatcher", "ctxrt_v1_start", "ctxrt_v1_yield")
LEGACY = ("fiber_init", "fiber_current", "fiber_scheduler_set_pick_next", "fiber_start", "fiber_schedule")
FORWARD = ("fiber_port_context_init", "fiber_port_runtime_prepare_start", "fiber_port_runtime_select_first",
           "fiber_port_runtime_start_first", "fiber_port_runtime_schedule",
           "fiber_port_require_scheduler_configuration_environment", "fiber_port_runtime_memory_barrier",
           "fiber_port_panic_wait")
SLOT = "fiber_internal_runtime_current_context_slot"
REVERSE = "fiber_internal_runtime_port_abi_v1_anchor"
CONFIG = "fiber_internal_runtime_require_context_configuration_open"
CONFIG_ANCHOR = "fiber_internal_runtime_context_configuration_abi_v1_anchor"
COMMON_PRIVATE_OBJECTS = (SLOT, REVERSE, CONFIG_ANCHOR)
CASE_NAMES = {0: "POSITIVE", 1: "NO_DISPATCHER", 2: "NULL_FIRST", 3: "NULL_NEXT", 4: "ENTRY_RETURN",
              5: "FIBER_DOUBLE_INIT", 6: "FIBER_CLOSED_INIT", 7: "BAD_CANARY", 8: "BAD_EXC_RETURN",
              9: "UNHANDLED_FAULT", 10: "PRESTART_YIELD", 11: "MASKED_YIELD", 12: "CALLBACK_MASK",
              13: "FIBER_OVERLAP"}
# Each code is an exact production diagnostic, not an arbitrary nonzero exit.
PANICS = {1: "K", 2: "N", 3: "N", 4: "R", 5: "L", 6: "k", 7: "c", 8: "x",
          10: "G", 11: "p", 12: "r", 13: "C"}
EXTRA_CASES = {14: ("PRESTART_FOREIGN_SVC", "u"), 15: ("RUNNING_START_SVC", "l"),
               16: ("PRESTART_PENDSV", "j")}


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="ascii")


def terminal(result, expected):
    if result.get("TimedOut") or result["Exit"] != expected["Exit"]:
        return False
    # Both channels are retained separately. No substring/traceback matching.
    text = (result["Stdout"] + result["Stderr"]).replace("\r\n", "\n")
    return text == "\n".join(expected["Lines"]) + "\n"


def terminal_controls():
    positive = dict(Exit=0, Lines=[CHECK, PASS])
    panic = dict(Exit=64, Lines=["PANIC:K"])
    oracle = dict(Exit=66, Lines=["REASON:00000079", "FAIL:CM0-ORACLE"])
    def result(code, text, timeout=False):
        return dict(Exit=code, Stdout="", Stderr=text, TimedOut=timeout)
    tests = [("positive", result(0, CHECK+"\n"+PASS+"\n"), positive, True),
             ("panic", result(64, "PANIC:K\n"), panic, True),
             ("oracle", result(66, "REASON:00000079\nFAIL:CM0-ORACLE\n"), oracle, True),
             ("marker-wrong-exit", result(64, CHECK+"\n"+PASS+"\n"), positive, False),
             ("wrong-panic", result(64, "PANIC:N\n"), panic, False),
             ("panic-wrong-exit", result(1, "PANIC:K\n"), panic, False),
             ("timeout", result(64, "PANIC:K\n", True), panic, False),
             ("timeout-status", result(124, "PANIC:K\n"), panic, False),
             ("default-fault", result(65, "FAIL:CM0-FAULT\n"), panic, False),
             ("duplicate", result(64, "PANIC:K\nPANIC:K\n"), panic, False),
             ("malformed", result(64, "PANIC:KK\n"), panic, False),
             ("traceback", result(64, "RuntimeError: PANIC:K\n"), panic, False),
             ("missing-check", result(0, PASS+"\n"), positive, False),
             ("wrong-reason", result(66, "REASON:0000001F\nFAIL:CM0-ORACLE\n"), oracle, False),
             ("missing-reason", result(66, "FAIL:CM0-ORACLE\n"), oracle, False),
             ("extra-output", result(64, "debug\nPANIC:K\n"), panic, False)]
    for name, actual, expected, accepted in tests:
        need(terminal(actual, expected) == accepted, "Terminal classifier control failed: " + name)
    return [dict(Name=n, Accepted=v) for n, _, _, v in tests]


def binding_admitted(name, kind, binding, lto, proven_private):
    if binding == "STB_GLOBAL":
        return True
    return (binding == "STB_LOCAL" and lto and kind == "STT_OBJECT" and
            name in COMMON_PRIVATE_OBJECTS and name in proven_private)


def binding_controls():
    proven = set(COMMON_PRIVATE_OBJECTS)
    tests = [("normal-private-local", SLOT, "STT_OBJECT", "STB_LOCAL", False, proven, False),
             ("lto-private-local", SLOT, "STT_OBJECT", "STB_LOCAL", True, proven, True),
             ("lto-reverse-local", REVERSE, "STT_OBJECT", "STB_LOCAL", True, proven, True),
             ("lto-config-local", CONFIG_ANCHOR, "STT_OBJECT", "STB_LOCAL", True, proven, True),
             ("unproven-private-local", SLOT, "STT_OBJECT", "STB_LOCAL", True, set(), False),
             ("normal-private-weak", SLOT, "STT_OBJECT", "STB_WEAK", False, proven, False),
             ("lto-private-weak", SLOT, "STT_OBJECT", "STB_WEAK", True, proven, False),
             ("lto-local-handler", "PendSV_Handler", "STT_FUNC", "STB_LOCAL", True, proven, False),
             ("lto-local-svc", "SVC_Handler", "STT_FUNC", "STB_LOCAL", True, proven, False),
             ("lto-local-api", PUBLIC[0], "STT_FUNC", "STB_LOCAL", True, proven, False),
             ("lto-local-cohort", "fiber_port_context_cohort_armv6m_test", "STT_OBJECT", "STB_LOCAL", True, proven, False),
             ("lto-local-storage-provider", "fiber_port_storage_cohort_arm_cm0_v1_r0", "STT_OBJECT", "STB_LOCAL", True, proven, False),
             ("private-wrong-kind", SLOT, "STT_FUNC", "STB_LOCAL", True, proven, False),
             ("normal-private-global", SLOT, "STT_OBJECT", "STB_GLOBAL", False, proven, True),
             ("lto-global-api", PUBLIC[0], "STT_FUNC", "STB_GLOBAL", True, proven, True)]
    for name, symbol, kind, binding, lto, owners, accepted in tests:
        need(binding_admitted(symbol, kind, binding, lto, owners) == accepted,
             "Binding-policy control failed: " + name)
    return [dict(Name=n, Accepted=v) for n, _, _, _, _, _, v in tests]


def protected(relative):
    text = relative.replace("\\", "/").lower()
    return any(text == prefix or text.startswith(prefix + "/") for prefix in STOPPED)


def directory_files(root):
    """Only for closed exports or explicitly enrolled fixture/tool/header trees."""
    root = Path(root)
    for directory, folders, files in os.walk(root):
        folders[:] = sorted(p for p in folders if p not in (".git", "__pycache__"))
        for name in folders:
            candidate = Path(directory) / name
            relative = candidate.relative_to(root).as_posix()
            need(not protected(relative), "Protected stopped input present in export: " + relative)
            need(not candidate.is_symlink(), "Symlink directory in input inventory: " + str(candidate))
        for name in sorted(files):
            candidate = Path(directory) / name
            relative = candidate.relative_to(root).as_posix()
            need(not protected(relative), "Protected stopped input present in export: " + relative)
            if name.endswith((".pyc", ".pyo")):
                continue
            need(not candidate.is_symlink(), "Symlink file in input inventory: " + str(candidate))
            yield candidate.resolve()


class Suite:
    def __init__(self, args):
        self.a = args
        self.repo = Path(args.repo).resolve(strict=True)
        self.fixture = Path(__file__).resolve().parent
        need(self.fixture == self.repo / "tools/fixtures/classic_context_runtime", "Runner must belong to the selected repository/export")
        self.build = Path(args.build_root).resolve()
        need(not self.build.exists(), "Build root must be the exact absent output directory")
        need(not self.build.is_relative_to(self.repo), "Build root must be outside the repository")
        self.build.mkdir(parents=True)
        self.inputs, self.generated = {}, {}
        self.commands, self.dependencies = [], []
        self.rows, self.parity = [], []
        self.report = dict(Verdict="FAIL", CompleteSuite=not args.development_smoke,
                           Scope="Actual microbit Cortex-M0 (CPUID part C20), privileged PSP; no M0+, FP, MPU, TrustZone or board claim",
                           Rows=self.rows, ReferenceParity=self.parity, Commands=self.commands,
                           Repository=str(self.repo), BuildRoot=str(self.build))
        self.tools = {}

    def command(self, argv, label, timeout=120, expected=0, stdin=None):
        argv = list(map(str, argv))
        item = dict(Arguments=argv, Label=label, WorkingDirectory=str(self.repo), TimedOut=False)
        start = time.monotonic()
        try:
            p = subprocess.run(argv, cwd=self.repo, input=stdin, capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=timeout)
            item.update(Exit=p.returncode, Stdout=p.stdout, Stderr=p.stderr)
        except subprocess.TimeoutExpired as error:
            def text(value):
                return value.decode("utf-8", "replace") if isinstance(value, bytes) else value or ""
            item.update(Exit=None, Stdout=text(error.stdout), Stderr=text(error.stderr), TimedOut=True)
        item["Seconds"] = time.monotonic() - start
        path = self.build / "commands" / ("%05d.json" % len(self.commands))
        save(path, item)
        self.commands.append(str(path))
        item["Record"] = str(path)
        if expected is not None:
            need(not item["TimedOut"] and item["Exit"] == expected,
                 label + " failed; inspect " + str(path))
        return item

    def git(self, root, *args, expected=0, stdin=None):
        return self.command(["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                             "-c", "core.longpaths=true", "-C", root, *args],
                            "git " + " ".join(args), expected=expected, stdin=stdin)

    def enroll(self, path, role):
        path = Path(path).resolve(strict=True)
        need(path.is_file(), "Input is not a file: " + str(path))
        need(not path.is_relative_to(self.build), "Build output cannot be an original input")
        if path.is_relative_to(self.repo):
            need(not protected(path.relative_to(self.repo).as_posix()), "Stopped input cannot be enrolled")
        key = str(path)
        value = digest(path)
        if key in self.inputs:
            need(self.inputs[key]["Sha256"] == value, "Input changed while enrolling: " + key)
        else:
            self.inputs[key] = dict(Path=key, Sha256=value, Role=role)

    def repo_inventory(self):
        probe = self.git(self.repo, "rev-parse", "--show-toplevel", expected=None)
        exact = probe["Exit"] == 0 and Path(probe["Stdout"].strip()).resolve() == self.repo
        if exact:
            names = self.git(self.repo, "ls-files", "-z")["Stdout"].split("\0")
            paths = [self.repo / p for p in names if p]
            head = self.git(self.repo, "rev-parse", "HEAD")["Stdout"].strip()
            self.report["RepositoryIdentity"] = dict(Attribution="EXACT_GIT_ROOT", Head=head,
                TrackedStatus=self.git(self.repo, "status", "--porcelain=v1", "--untracked-files=no")["Stdout"],
                Claim="HEAD attribution plus measured tracked/explicit overlay bytes; not a clean-commit claim")
        else:
            paths = list(directory_files(self.repo))
            self.report["RepositoryIdentity"] = dict(Attribution="NO_GIT_ATTRIBUTION",
                Claim="Closed content-addressed export; no inferred parent repository HEAD")
        for path in paths:
            if "__pycache__" not in path.parts:
                self.enroll(path, "Repository")
        for path in directory_files(self.fixture):
            self.enroll(path, "OwnedFixture")
        for name in ("tools/test_classic_context_runtime.ps1", "tools/freertos_asm_parity.ps1",
                     "tools/runtime_sources.py", "tools/runtime_sources.ps1", "tools/runtime_sources.json"):
            self.enroll(self.repo / name, "ExplicitRunner")
        relative = {Path(k).relative_to(self.repo).as_posix(): v["Sha256"] for k, v in self.inputs.items()
                    if Path(k).is_relative_to(self.repo)}
        encoded = json.dumps(relative, sort_keys=True, separators=(",", ":")).encode("ascii")
        self.report["RepositoryIdentity"]["TreeSha256"] = hashlib.sha256(encoded).hexdigest().upper()
        self.repo_paths_before = set(relative)
        self.exact_git = exact

    def reference_identity(self, enroll=False):
        root = Path(self.a.freertos).resolve(strict=True)
        need(self.git(root, "rev-parse", "HEAD")["Stdout"].strip() == PIN, "FreeRTOS pin mismatch")
        status = self.git(root, "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching")["Stdout"]
        need(not status, "FreeRTOS reference has tracked/untracked/ignored changes")
        tree = self.git(root, "ls-tree", "-r", "HEAD")["Stdout"].splitlines()
        files = []
        for row in tree:
            match = re.fullmatch(r"100(?:644|755) blob ([0-9a-f]{40})\t(.+)", row)
            if match:
                files.append((match[2], match[1]))
            else:
                need(re.fullmatch(r"160000 commit [0-9a-f]{40}\t.+", row), "Unknown reference tree entry")
        need(bool(files), "Empty pinned reference tree")
        actual = self.git(root, "hash-object", "--stdin-paths", stdin="".join(p+"\n" for p, _ in files))["Stdout"].splitlines()
        need(actual == [h for _, h in files], "Pinned reference tracked content differs from HEAD")
        if enroll:
            for name, _ in files:
                self.enroll(root / name, "PinnedReference")
            self.report["ReferenceIdentity"] = dict(Commit=PIN, TrackedFiles=len(files), Clean=True)

    def preflight(self):
        need(__debug__ and not sys.flags.optimize, OPT_ERROR)
        need(importlib.metadata.version("pyelftools") == "0.33", "Requires pyelftools==0.33")
        from elftools.elf.elffile import ELFFile
        self.ELFFile = ELFFile
        self.report["TerminalControls"] = terminal_controls()
        self.report["BindingControls"] = binding_controls()
        self.repo_inventory()
        self.reference_identity(enroll=True)
        for path in Path(self.a.cmsis).resolve(strict=True).rglob("*.h"):
            self.enroll(path, "CMSIS")
        gcc = Path(self.a.gcc).resolve(strict=True)
        self.tools["gcc"] = gcc
        for name in ("ar", "nm", "objdump", "readelf"):
            stem = "arm-none-eabi-"+{"ar": "gcc-ar", "nm": "gcc-nm"}.get(name, name)+".exe"
            self.tools[name] = (gcc.parent / stem).resolve(strict=True)
        for path in self.tools.values():
            self.enroll(path, "Tool")
        for tool in ("cc1", "lto1", "as", "ld", "collect2"):
            path = self.command([gcc, "-print-prog-name="+tool], "identify "+tool)["Stdout"].strip()
            self.enroll(path, "CompilerSubprocess")
        plugin = self.command([gcc, "-print-file-name=liblto_plugin.dll"], "identify LTO plugin")["Stdout"].strip()
        self.enroll(plugin, "LTOPlugin")
        for path in gcc.parent.glob("*.dll"):
            self.enroll(path, "CompilerLibrary")
        include = self.command([gcc, "-print-file-name=include"], "identify compiler headers")["Stdout"].strip()
        for root in (Path(include), gcc.parent.parent / "arm-none-eabi/include"):
            need(root.is_dir(), "Missing toolchain include root: " + str(root))
            for path in root.rglob("*.h"):
                self.enroll(path, "ToolchainHeader")
        if os.name == "nt":
            buffer = ctypes.create_unicode_buffer(32768)
            need(0 < ctypes.windll.kernel32.GetModuleFileNameW(None, buffer, len(buffer)) < len(buffer),
                 "Cannot identify Python executable")
            python = Path(buffer.value)
        else:
            python = Path(sys.executable)
        self.enroll(python, "Python")
        import elftools
        for path in directory_files(Path(elftools.__file__).parent):
            self.enroll(path, "Pyelftools")
        powershell = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        self.tools["powershell"] = powershell.resolve(strict=True)
        self.enroll(powershell, "PowerShell")
        self.report["CompilerVersion"] = self.command([gcc, "--version"], "compiler version")["Stdout"]
        self.report["Python"] = dict(Executable=str(python), Version=sys.version, Pyelftools="0.33")
        save(self.build / "inputs.before.json", list(self.inputs.values()))
        self.qemu_before = self.inspect_qemu("qemu-before")
        self.report["PreflightComplete"] = True

    def wsl_path(self, path):
        path = str(Path(path).resolve())
        if re.match(r"^[A-Za-z]:[\\/]", path):
            return "/mnt/" + path[0].lower() + "/" + path[3:].replace("\\", "/")
        need(path.startswith("/"), "Unmappable WSL path: " + path)
        return path

    def inspect_qemu(self, name):
        directory = self.build / name
        directory.mkdir()
        self.command(["wsl.exe", "-d", self.a.wsl_distro, "--", "bash",
                      self.wsl_path(self.fixture / "qemu.sh"), "inspect", self.a.qemu_root,
                      self.wsl_path(directory)], "inspect isolated QEMU")
        required = ("qemu-version.txt", "qemu-machines.txt", "qemu-cpus.txt", "qemu-ldd.txt",
                    "qemu-sha256.txt", "qemu-libraries-sha256.txt", "wsl-tools-sha256.txt",
                    "wsl-user.txt", "wsl-system.txt", "wsl-os-release.txt", "deb-sha256.txt",
                    "deb-versions.txt", "qemu-root.txt")
        result = {}
        for item in required:
            path = directory / item
            need(path.is_file() and path.stat().st_size, "Missing QEMU provenance: " + item)
            if item != "qemu-ldd.txt":  # ASLR addresses in this diagnostic are nondeterministic.
                result[item] = digest(path)
        need(re.search(r"(?m)^microbit\s", (directory/"qemu-machines.txt").read_text()), "QEMU lacks microbit")
        return result

    def case_header(self):
        text = (self.fixture / "fixture.h").read_text()
        for value, name in CASE_NAMES.items():
            need(re.search(r"(?m)^#define FIXTURE_"+name+r" "+str(value)+r"\s*$", text),
                 "Fixture case contract changed: " + name)
        extras = list(EXTRA_CASES)
        self.extra_panics = {n: EXTRA_CASES[n][1] for n in extras}
        for n in extras:
            need(re.search(r"(?m)^#define FIXTURE_"+EXTRA_CASES[n][0]+r" "+str(n)+r"\s*$", text), "Origin case ID changed")
        self.report["FixtureCases"] = {str(k): v for k, v in CASE_NAMES.items()}
        self.report["FixtureCases"].update({str(k): EXTRA_CASES[k][0] for k in extras})

    def stage(self):
        self.case_header()
        rows = []
        def add(consumer, opt, lto, archive, policy, case=0, mutant=None, kind="Positive"):
            expected = dict(Exit=0, Lines=[CHECK, PASS])
            if kind == "Panic":
                expected = dict(Exit=64, Lines=["PANIC:"+PANICS.get(case, self.extra_panics.get(case))])
            elif kind == "FaultControl":
                expected = dict(Exit=65, Lines=["FAIL:CM0-FAULT"])
            elif mutant:
                expected = dict(Exit=66, Lines=["REASON:"+("0000001F" if mutant == "publication" else "00000079"), "FAIL:CM0-ORACLE"])
            name = "-".join((consumer, opt, "lto" if lto else "normal", "archive" if archive else "direct",
                             policy, str(case), mutant or kind.lower()))
            rows.append(dict(Name=name, Consumer=consumer, Optimization=opt, LTO=lto, Archive=archive,
                             Policy=policy, Case=case, Mutant=mutant, Kind=kind, Expected=expected, Status="STAGED"))
        if self.a.development_smoke:
            add("context", "O2", False, False, "primary")
            for case in (1, 4):
                add("context", "O2", False, False, "primary", case=case, kind="Panic")
            for mutant in ("pendsv-r9", "pendsv-r4", "publication"):
                add("context", "O2", False, False, "primary", mutant=mutant, kind="CompiledControl")
            add("context", "O2", False, False, "primary", case=9, kind="FaultControl")
        else:
            for consumer in ("context", "fiber"):
                for opt in ("O2", "Os"):
                    for lto in (False, True):
                        for archive in (False, True):
                            for policy in ("primary", "validation"):
                                add(consumer, opt, lto, archive, policy)
                            for case in sorted(set(PANICS) | set(self.extra_panics)):
                                if consumer == "context" and case in (5, 6, 13):
                                    continue
                                add(consumer, opt, lto, archive, "primary", case=case, kind="Panic")
                            for mutant in ("pendsv-r9", "pendsv-r4", "publication"):
                                add(consumer, opt, lto, archive, "primary", mutant=mutant, kind="CompiledControl")
                add(consumer, "O2", False, False, "primary", case=9, kind="FaultControl")
        need(len({r["Name"] for r in rows}) == len(rows), "Duplicate staged cases")
        need(set(PANICS) | set(self.extra_panics) == set(range(1, 17)) - {9}, "Exact required panic ID set changed")
        self.rows.extend(rows)
        self.report["ExpectedGrid"] = {kind: sum(r["Kind"] == kind for r in rows)
                                       for kind in ("Positive", "Panic", "CompiledControl", "FaultControl")}
        literal = dict(Positive=1, Panic=2, CompiledControl=3, FaultControl=1) if self.a.development_smoke else dict(
            Positive=32, Panic=216, CompiledControl=48, FaultControl=2)
        need(self.report["ExpectedGrid"] == literal and len(rows) == (7 if self.a.development_smoke else 298),
             "Literal required execution grid mismatch")
        save(self.build / "staged.json", rows)

    def dependency_check(self, path):
        text = path.read_text().replace("\\\n", " ").replace("\\\r\n", " ")
        need(": " in text, "Malformed GCC dependency file: " + str(path))
        words = re.findall(r"(?:\\.|[^\s])+", text.split(": ", 1)[1])
        records = []
        for word in words:
            name = re.sub(r"\\([ #:\\])", r"\1", word)
            source = Path(name).resolve(strict=True)
            enrolled = self.inputs.get(str(source)) or self.generated.get(str(source))
            need(enrolled is not None, "Unenrolled compiler dependency: " + str(source))
            need(digest(source) == enrolled["Sha256"], "Compiler dependency drift: " + str(source))
            records.append(dict(Path=str(source), Sha256=enrolled["Sha256"]))
        need(records, "Empty GCC dependency file")
        self.dependencies.append(dict(File=str(path), Dependencies=records))

    def mutate(self, path, name, directory):
        text = path.read_text()
        if name in ("pendsv-r9", "pendsv-r4"):
            anchor = "void PendSV_Handler(void)"
            need(text.count(anchor) == 1, "PendSV mutation anchor count")
            head, body = text.split(anchor)
            if name == "pendsv-r9":
                body, count = re.subn(r'"mov\s+r9,\s+r5\s+\\n"', lambda m: '"nop \\n"', body)
            else:
                body, count = re.subn(r'("ldmia\s+r0!,\s*\{r3-r7\}\s+\\n")',
                                      lambda m: m[0]+'\n\t\t\t"movs r4, #0 \\n"', body)
            need(count == 1, "PendSV-only restore mutation count")
            changed = head + anchor + body
            need(changed.split(anchor)[0] == head, "Mutation changed SVC/prefix")
        else:
            anchor = "fiber_internal_runtime_current_context_slot = next;"
            need(text.count(anchor) == 1, "Publication mutation anchor count")
            changed = text.replace(anchor, "if (fiber_internal_runtime_current_context_slot == 0) { "+anchor+" }")
        target = directory / ("mutant-"+path.name)
        target.write_text(changed, encoding="ascii", newline="\n")
        self.generated[str(target.resolve())] = dict(Path=str(target.resolve()), Sha256=digest(target), Role="CompiledMutation")
        save(directory / "mutation.json", dict(Name=name, Original=str(path), OriginalSha256=digest(path),
                                               Compiled=str(target), CompiledSha256=digest(target)))
        return target

    def build_case(self, row):
        directory = self.build / "cases" / row["Name"]
        directory.mkdir(parents=True)
        reader_path = self.repo / "tools/runtime_sources.py"
        spec = importlib.util.spec_from_file_location("classic_runtime_sources", reader_path)
        reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reader)
        roles = ("engine", "state", "panic") + (("optional_configuration",) if row["Consumer"] == "fiber" else ())
        common = list(reader.get_runtime_source_paths(self.repo, roles))
        port = self.repo / "fiber/port/ARM_CM0"
        provider = [port / n for n in ("fiber_port.c", "fiber_port_boot.c", "fiber_port_exception.c")]
        if row["Consumer"] == "fiber":
            common.append(self.repo / "fiber/lifecycle/fiber_v1.c")
        fixtures = [self.fixture / n for n in ("application.c", "startup.S", "probe.S")]
        expectation_source = self.repo / "fiber/port/fiber_port_context_cohort_expectation.c"
        fixtures.append(expectation_source)  # Application-owned expectation, never hidden in the port archive.
        flags = ["-mcpu=cortex-m0", "-mthumb", "-mfloat-abi=soft", "-std=gnu11", "-"+row["Optimization"],
                 "-ffreestanding", "-fno-builtin", "-fno-common", "-ffunction-sections", "-fdata-sections",
                 "-Wall", "-Wextra", "-Wundef", "-Werror=undef", "-Werror=implicit-function-declaration", "-Werror=return-type",
                 "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV6M=1",
                 "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH="+str(int(row["Policy"] == "validation")),
                 "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH="+str(int(row["Policy"] == "validation")),
                 "-DFIBER_STACK_CANARY=1", "-DFIBER_REWIND_MSP=1", "-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=0",
                 "-DFIXTURE_USE_FIBER="+str(int(row["Consumer"] == "fiber")), "-DFIXTURE_CASE="+str(row["Case"]),
                 "-I"+str(self.fixture), "-I"+str(port), "-I"+str(self.repo),
                 "-I"+str(self.repo / "fiber"), "-I"+self.a.cmsis]
        if row["LTO"]:
            flags.append("-flto")
        objects, port_objects, maps = [], [], []
        for index, source in enumerate(common + provider + fixtures):
            need(str(source.resolve()) in self.inputs, "Source not enrolled before compilation: " + str(source))
            original = source
            if (row["Mutant"] in ("pendsv-r9", "pendsv-r4") and source == provider[0]) or (
                    row["Mutant"] == "publication" and source.name == "context_runtime_state.c"):
                source = self.mutate(source, row["Mutant"], directory)
            obj = directory / ("%02d-" % index + original.stem + ".o")
            dep = obj.with_suffix(".d")
            command = self.command([self.tools["gcc"], *flags, "-I"+str(original.parent),
                                    "-MMD", "-MF", dep, "-c", source, "-o", obj], "compile "+row["Name"])
            diagnostics = command["Stderr"]
            for line in diagnostics.splitlines():
                if "warning:" in line:
                    need("Selected ARMv6-M port has no SCB->VTOR; falling back to base table at 0x00000000." in line
                         or (original.name == "fiber_port_exception.c" and "array subscript 0 is outside array bounds" in line),
                         "Unexpected compiler warning: " + command["Record"])
            self.dependency_check(dep)
            objects.append(obj)
            if original in provider:
                port_objects.append(obj)
            maps.append(dict(Original=str(original), Compiled=str(source), SourceSha256=digest(source),
                             Object=str(obj), ObjectSha256=digest(obj), Command=command["Record"], Role="expectation" if original == expectation_source else "port" if original in provider else "common" if original in common else "fixture"))
        save(directory / "source-object-map.json", maps)
        state_sources = reader.get_runtime_source_paths(self.repo, ("state",))
        config_sources = reader.get_runtime_source_paths(self.repo, ("optional_configuration",)) if row["Consumer"] == "fiber" else ()
        need(len(state_sources) == 1 and len(config_sources) == int(row["Consumer"] == "fiber"),
             "Exact common private owner recipe changed")
        owners = {SLOT: str(state_sources[0]), REVERSE: str(state_sources[0]),
                  CONFIG_ANCHOR: str(config_sources[0]) if config_sources else None}
        private_proof = self.audit_common_private(maps, owners, directory)
        row["CommonPrivateProviders"] = str(directory / "common-private-providers.json")
        self.audit_provider(port_objects, directory)
        if row["Archive"]:
            archive = directory / "libcm0.a"
            self.command([self.tools["ar"], "rcs", archive, *port_objects], "archive actual port")
            linked = [obj for obj in objects if obj not in port_objects] + [archive]
        else:
            linked = objects
        elf = directory / "runtime.elf"
        options = ["-mcpu=cortex-m0", "-mthumb", "-mfloat-abi=soft", "-"+row["Optimization"],
                   "-ffunction-sections", "-fdata-sections", "-nostdlib"] + (["-flto"] if row["LTO"] else [])
        self.command([self.tools["gcc"], *options, "-Wl,--gc-sections", "-Wl,--no-undefined", "-Wl,--fatal-warnings",
                      "-T", self.fixture / "link.ld", "-Wl,-Map="+str(directory/"runtime.map"), *linked, "-o", elf], "link actual runtime")
        for tool, args, filename in (("objdump", ["-drwC", "-Mreg-names-std"], "runtime.dis"),
                                     ("readelf", ["-hASsrW", "-A"], "runtime.readelf.txt"),
                                     ("nm", ["-a"], "runtime.nm.txt")):
            text = self.command([self.tools[tool], *args, elf], "inspect final ELF")["Stdout"]
            (directory / filename).write_text(text, encoding="ascii")
        audit = self.audit_elf(elf, row, private_proof)
        save(directory / "elf-audit.json", audit)
        row.update(Elf=str(elf), ElfSha256=digest(elf), SourceObjectMap=str(directory/"source-object-map.json"), ElfAudit=str(directory/"elf-audit.json"))
        result = self.command(["wsl.exe", "-d", self.a.wsl_distro, "--", "bash",
                               self.wsl_path(self.fixture / "qemu.sh"), "run", self.a.qemu_root,
                               self.wsl_path(directory), "microbit", self.wsl_path(elf), "15"],
                              "actual microbit "+row["Name"], timeout=30, expected=None)
        row["Actual"] = result
        need(terminal(result, row["Expected"]), "Wrong terminal outcome: "+row["Name"]+"; "+result["Record"])
        row["Status"] = "PASS"
        save(directory / "execution.json", row)
        print("PASS "+row["Name"], flush=True)

    def audit_provider(self, objects, directory):
        text = self.command([self.tools["nm"], "-g", "--defined-only", *objects], "actual eight-operation provider definitions")["Stdout"]
        (directory / "provider-definitions.txt").write_text(text, encoding="ascii")
        for symbol in FORWARD:
            need(len(re.findall(r"(?m)^[0-9a-fA-F]+ T "+symbol+r"$", text)) == 1,
                 "Actual port forward definition missing/duplicate/weak: "+symbol)

    def audit_common_private(self, maps, owners, directory):
        definitions = {name: [] for name in COMMON_PRIVATE_OBJECTS}
        for record in maps:
            result = self.command([self.tools["nm"], "-P", "--defined-only", record["Object"]],
                                  "prelink common-private ownership " + record["Object"])
            for line in result["Stdout"].splitlines():
                fields = line.split()
                if fields and fields[0] in definitions:
                    need(len(fields) >= 3, "Malformed prelink private symbol: " + line)
                    definitions[fields[0]].append(dict(Source=record["Original"], Object=record["Object"],
                        ObjectSha256=record["ObjectSha256"], Role=record["Role"], NmType=fields[1], Command=result["Record"]))
        for name, owner in owners.items():
            found = definitions[name]
            if owner is None:
                need(not found, "Pure Context has a prelink optional configuration anchor")
            else:
                # POSIX gcc-nm B/D/R are strong GLOBAL objects; b/d/r, W/V,
                # COMMON and definitions in any other TU are not admissible.
                need(len(found) == 1 and found[0]["NmType"] in ("B", "D", "R") and
                     found[0]["Role"] == "common" and found[0]["Source"] == owner,
                     "Prelink private object must have one GLOBAL actual common owner and no port/fixture definitions: " + name)
        proven = {name: found[0] for name, found in definitions.items() if found}
        save(directory / "common-private-providers.json", dict(Status="PASS", ExpectedOwners=owners, Definitions=proven))
        return proven

    def audit_elf(self, path, row, private_proof):
        with path.open("rb") as stream:
            elf = self.ELFFile(stream)
            need(elf.elfclass == 32 and elf.little_endian and elf["e_machine"] == "EM_ARM" and elf["e_type"] == "ET_EXEC", "Not final ARM ELF32 executable")
            table = elf.get_section_by_name(".symtab")
            need(table is not None, "Final ELF lacks symbol inventory")
            symbols = list(table.iter_symbols())
            undefined = [s.name for s in symbols if s.name and s["st_shndx"] == "SHN_UNDEF"]
            need(not undefined, "Final ELF unresolved symbols: "+str(undefined))
            defined = {s.name: s for s in symbols if s.name and s["st_shndx"] != "SHN_UNDEF"}
            def unique(name, kind=None):
                matches = [s for s in symbols if s.name == name and s["st_shndx"] != "SHN_UNDEF"]
                need(len(matches) == 1, "Final symbol missing/duplicate: "+name)
                s = matches[0]
                need(binding_admitted(name, kind, s["st_info"]["bind"], row["LTO"], private_proof),
                     "Final symbol binding not admitted: "+name)
                if kind:
                    need(s["st_info"]["type"] == kind and s["st_size"] > 0, "Final symbol kind/size: "+name)
                return s
            complete_api = row["Kind"] in ("Positive", "CompiledControl")
            required = PUBLIC if complete_api else ("ctxrt_v1_current",)
            for name in (*required, "SVC_Handler", "PendSV_Handler", SLOT):
                unique(name, "STT_OBJECT" if name in (SLOT, REVERSE) else "STT_FUNC")
            need(defined[SLOT]["st_size"] == 4, "Current slot geometry")
            if complete_api or REVERSE in defined:
                need(unique(REVERSE, "STT_OBJECT")["st_size"] == 1, "Reverse anchor geometry")
            need(not any(n in defined for n in LEGACY), "Legacy shim linked into pure/current Context consumer")
            if row["Consumer"] == "context":
                need(CONFIG not in defined and CONFIG_ANCHOR not in defined and
                     not any(n.startswith("fiber_v1_") for n in defined), "Pure Context acquired optional configuration/Fiber")
            elif complete_api or CONFIG in defined or CONFIG_ANCHOR in defined:
                unique(CONFIG, "STT_FUNC")
                unique(CONFIG_ANCHOR, "STT_OBJECT")
            runtime = [n for n in defined if n.startswith("fiber_port_context_cohort_arm")]
            storage = [n for n in defined if n.startswith("fiber_port_storage_cohort_") and "consumer_expectation" not in n]
            need(len(runtime) == len(storage) == 1 and runtime[0].startswith("fiber_port_context_cohort_armv6m_"), "Unique actual CM0 runtime/storage cohort required")
            for name in runtime + storage:
                s = unique(name, "STT_OBJECT")
                section = elf.get_section(s["st_shndx"])
                need(s["st_size"] == 1 and section.data()[s["st_value"]-section["sh_addr"]] == 1, "Cohort provider value/geometry")
            vector = elf.get_section_by_name(".isr_vector")
            need(vector is not None and vector["sh_addr"] == 0 and vector["sh_size"] == 192, "Exact 48-entry vector table missing")
            need(vector["sh_flags"] & 2 and not vector["sh_flags"] & 1, "Vector section must be ALLOC/read-only")
            words = struct.unpack("<48I", vector.data())
            need(words[0] == 0x20004000 and words[1] == (unique("Reset_Handler", "STT_FUNC")["st_value"] | 1), "Initial MSP/reset vector mismatch")
            for index, name in ((11, "SVC_Handler"), (14, "PendSV_Handler")):
                need(words[index] & 1 and words[index] == (defined[name]["st_value"] | 1), "Strong handler Thumb vector mismatch: "+name)
            expectation = elf.get_section_by_name(".fiber_port_context_cohort_expectation")
            need(expectation is not None and expectation["sh_size"] in (8, 12) and expectation["sh_size"] % 4 == 0, "Retained build/storage expectations missing")
            need(expectation["sh_flags"] & 2 and not expectation["sh_flags"] & 1, "Expectation section must be ALLOC/read-only")
            pointers = list(struct.unpack("<"+"I"*(expectation["sh_size"]//4), expectation.data()))
            need(pointers.count(defined[runtime[0]]["st_value"]) == 1 and
                 pointers.count(defined[storage[0]]["st_value"]) == (2 if row["Consumer"] == "fiber" else 1) and
                 len(pointers) == (3 if row["Consumer"] == "fiber" else 2), "Expectation pointers/count changed")
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_LOAD":
                    begin, end = segment["p_vaddr"], segment["p_vaddr"]+segment["p_memsz"]
                    need(0 <= begin <= end <= 0x40000 or 0x20000000 <= begin <= end <= 0x20004000, "ELF load outside microbit flash/RAM")
            need(not any(re.search(r"__cyg_profile|__stack_chk|__gcov|__ubsan|__asan|__sanitizer_cov|mcount|__gnu_mcount", n) for n in defined), "Compiler instrumentation in final runtime")
            attrs = path.with_name("runtime.readelf.txt").read_text()
            need(re.search(r"Tag_CPU_arch: v6S?-M\b", attrs) and "Tag_THUMB_ISA_use: Thumb-1" in attrs and
                 not re.search(r"Tag_(FP_arch|MVE_arch|Advanced_SIMD_arch|ABI_VFP_args|PAC_extension|BTI_extension):", attrs), "Wrong CM0 ISA/FP attributes")
            return dict(StrongHandlers=True, VectorSlots={"11": words[11], "14": words[14]}, InitialMSP=words[0],
                        RuntimeCohort=runtime[0], StorageCohort=storage[0], ExpectationPointers=pointers,
                        ForwardDefinitions="All eight checked in actual input objects; unreferenced panic-wait may be GCed",
                        LiveForward=[n for n in FORWARD if n in defined], NoUnresolved=True, NoLegacy=True,
                        LivePublicContext=[n for n in PUBLIC if n in defined], CompleteApiRequired=complete_api,
                        ConfigurationModule=CONFIG in defined,
                        CommonPrivateBindings={n: defined[n]["st_info"]["bind"] for n in COMMON_PRIVATE_OBJECTS if n in defined},
                        PrelinkCommonOwners=private_proof)

    def reference_parity(self):
        for opt in ("-O2", "-Os"):
            directory = self.build / ("reference-parity-"+opt[1:])
            row = dict(Optimization=opt, Status="STAGED", Directory=str(directory))
            self.parity.append(row)
            result = self.command([self.tools["powershell"], "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                                   self.repo / "tools/freertos_asm_parity.ps1", "-ArmGcc", self.a.gcc,
                                   "-CmsisCore", self.a.cmsis, "-FreeRtosKernel", self.a.freertos,
                                   "-Optimization", opt, "-BuildRoot", directory, "-Cm0Only", "-KeepBuild"],
                                  "mandatory actual pinned CM0 paired parity "+opt, timeout=300)
            need("CM0_FOCUSED_PARITY_PASS" in result["Stdout"], "Missing focused reference PASS")
            receipt = directory / "CM0-FOCUSED/artifacts.json"
            need(receipt.is_file(), "Paired reference artifacts not retained")
            row.update(Status="PASS", Receipt=str(receipt), Sha256=digest(receipt), Command=result["Record"])

    def input_drift(self):
        drift = []
        for record in self.inputs.values():
            path = Path(record["Path"])
            if not path.is_file() or digest(path) != record["Sha256"]:
                drift.append(str(path))
        for record in self.generated.values():
            path = Path(record["Path"])
            if not path.is_file() or digest(path) != record["Sha256"]:
                drift.append(str(path))
        return drift

    def check_repository_inventory(self):
        if self.exact_git:
            names = self.git(self.repo, "ls-files", "-z")["Stdout"].split("\0")
            paths = {str((self.repo / name).resolve()) for name in names if name and "__pycache__" not in Path(name).parts}
        else:
            paths = {str(path) for path in directory_files(self.repo)}
        paths.update(str(path) for path in directory_files(self.fixture))
        paths.update(str((self.repo / name).resolve()) for name in (
            "tools/test_classic_context_runtime.ps1", "tools/freertos_asm_parity.ps1",
            "tools/runtime_sources.py", "tools/runtime_sources.ps1", "tools/runtime_sources.json"))
        relative = {Path(p).relative_to(self.repo).as_posix() for p in paths}
        self.report["RepositoryInventoryDrift"] = sorted(relative ^ self.repo_paths_before)
        need(not self.report["RepositoryInventoryDrift"], "Repository/export file inventory changed")

    def artifact_manifest(self, verify=False):
        destination = self.build / "artifacts.json"
        artifacts = {p.relative_to(self.build).as_posix(): digest(p) for p in sorted(self.build.rglob("*"))
                     if p.is_file() and p != destination}
        if verify:
            changed = [name for name, value in artifacts.items() if digest(self.build / name) != value]
            need(not changed, "Artifacts changed during final hash verification: "+str(changed))
        save(destination, dict(Artifacts=artifacts, ResultsSha256=digest(self.build/"results.json")))

    def finish(self, error):
        self.report["Error"] = error
        if not error:
            after = self.inspect_qemu("qemu-after")
            self.report["QemuDrift"] = [k for k in self.qemu_before if self.qemu_before[k] != after.get(k)]
            need(not self.report["QemuDrift"], "QEMU/tool/library identity drift")
            self.reference_identity()
            self.check_repository_inventory()
            need(all(r["Status"] == "PASS" for r in self.rows) and len(self.parity) == 2 and
                 all(r["Status"] == "PASS" for r in self.parity), "Staged/actual coverage mismatch")
        drift = self.input_drift()
        self.report["InputDrift"] = drift
        if not (self.build / "inputs.before.json").is_file():
            save(self.build / "inputs.before.json", list(self.inputs.values()))
        save(self.build / "inputs.after.json", [dict(Path=p, Sha256=digest(p) if Path(p).is_file() else None) for p in self.inputs])
        save(self.build / "dependencies.json", self.dependencies)
        save(self.build / "generated-inputs.json", list(self.generated.values()))
        self.report["InputCount"] = len(self.inputs)
        save(self.build / "results.json", self.report)
        self.artifact_manifest(verify=True)
        if not error:
            need(not drift, "Enrolled source/tool inputs changed")
            need(not self.input_drift(), "Inputs changed while verifying artifact hashes")
            self.report["Verdict"] = "PASS"
            self.report["ArtifactsVerifiedBeforePass"] = True
            save(self.build / "results.json", self.report)
            self.artifact_manifest(verify=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "gcc", "cmsis", "freertos", "qemu-root", "wsl-distro", "build-root"):
        parser.add_argument("--"+name, required=True)
    parser.add_argument("--development-smoke", action="store_true")
    args = parser.parse_args()
    suite = Suite(args)
    print("Classic Context runtime evidence: "+str(suite.build), flush=True)
    error = None
    try:
        suite.stage()
        suite.preflight()
        for row in suite.rows:
            row["Status"] = "RUNNING"
            try:
                suite.build_case(row)
            except Exception as failure:
                row.update(Status="FAIL", Error=str(failure))
                raise
        suite.reference_parity()
    except Exception as failure:
        error = str(failure)
        suite.report["Traceback"] = traceback.format_exc()
    try:
        suite.finish(error)
    except Exception as failure:
        error = str(failure)
        suite.report.update(Verdict="FAIL", Error=error, FinalizationTraceback=traceback.format_exc())
        # Preserve even a failure inside drift/receipt verification.
        save(suite.build / "results.json", suite.report)
        suite.artifact_manifest()
    if error:
        raise SystemExit("FAIL classic Context runtime: "+error+"; "+str(suite.build))
    print("PASS classic Context runtime "+("development smoke " if args.development_smoke else "complete ")+str(suite.build), flush=True)


if __name__ == "__main__":
    main()
