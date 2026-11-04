"""Synthetic reference-adapter controls; never compiler, Git or CPU qualification."""
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import ModuleType, SimpleNamespace
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
TOOLS = HERE.parents[1]
TFM_WRAPPER = "portable/ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c"
PORTMACRO = "portable/GCC/ARM_CM4F/portmacro.h"
FALSE_FIELDS = ("GlobalFreezeQualified", "GeneratedAssemblyParity", "FinalElfProof",
                "CpuExecution", "BoardExecution", "TransitiveHostClosure")


def need(ok, message):
    if not ok:
        raise AssertionError(message)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    data = path.read_bytes()
    exec(compile(data, str(path), "exec"), module.__dict__)
    module.review_source = data
    return module


class SyntheticCompile:
    """Only filesystem capture and dependency callbacks, with inert object bytes."""

    def __init__(self, args, report):
        self.a, self.report = args, report
        self.repo, self.build = Path(args.repo), Path(args.build)
        self.gcc = Path(args.arm_gcc)
        self.inputs, self.commands, self.allowed = {}, [], set()
        self.compile_index, self.lower_calls, self.base_preflights = 0, [], 0

    def track(self, path):
        path = Path(path).resolve(strict=True)
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest().upper()
        old = self.inputs.get(str(path))
        if old is not None:
            self.inventory.need(old["Sha256"] == digest, "synthetic-input-drift")
            return
        copied = self.build / "synthetic-inputs" / (digest + "-" + path.name)
        copied.parent.mkdir(parents=True, exist_ok=True)
        copied.write_bytes(data)
        self.inputs[str(path)] = dict(Original=str(path), Captured=str(copied), Sha256=digest)

    def compile(self, source, target, flags):
        self.track(source)
        for path in self.dependency_plan(self.compile_index, target.parent):
            self.track(path)
        self.compile_index += 1
        target.write_bytes(b"Synthetic object bytes; not an ELF or native compilation.\n")

    def lower(self, profile, objects, target, flags, lto):
        need(lto is False, "Synthetic reference object control unexpectedly requested LTO")
        self.lower_calls.append((profile, list(objects)))
        target.write_bytes(b"Synthetic relocatable marker; not a native group.\n")

    def preflight(self):
        self.base_preflights += 1


def load_subject():
    inventory = load("reference_contract_inventory", TOOLS / "freeze_cohorts.py")
    native = ModuleType("freeze_compile")
    native.HERE, native.inventory = TOOLS, inventory
    native.need, native.regular = inventory.need, inventory.regular
    native.sha, native.save = inventory.sha, inventory.save
    native.Compile = SyntheticCompile
    SyntheticCompile.inventory = inventory
    recipe = SimpleNamespace(__file__=str(__file__))

    def recipe_loader(name, path):
        need(name == "freeze_reference_recipe", "Unexpected helper import")
        need(path == TOOLS / "fixtures/freeze_cohorts/reference_recipe.py", "Unexpected recipe path")
        return recipe

    native.load = recipe_loader
    native.closure = SimpleNamespace(Elf=lambda path: SimpleNamespace(native=lambda: None))
    with patch.dict(sys.modules, {"freeze_compile": native}), patch.object(sys, "path", list(sys.path)):
        subject = load("reference_compile_contract_subject", TOOLS / "freeze_reference_compile.py")
    need(subject.native is native, "Real native module was imported")
    return subject


class Fixture:
    def __init__(self, directory, subject):
        self.base, self.subject = directory.resolve(), subject
        self.repo, self.reference, self.build = (self.base / name for name in ("repo", "freertos", "output"))
        for path in (self.repo, self.reference, self.build):
            path.mkdir()
        self.git = self.put(self.base / "host/git.exe", b"Inert synthetic Git marker.\n")
        self.gcc = self.put(self.base / "host/gcc.exe", b"Inert synthetic GCC marker.\n")
        self.tools = self.repo / "tools"
        self.base_config = self.put(self.tools / "fixtures/freertos_asm_parity/FreeRTOSConfig.h",
                                    b"/* Synthetic base config, never compiled. */\n")
        subject.native.HERE = self.tools
        subject.recipe.__file__ = str(self.put(self.base / "recipe.py", b"# Synthetic recipe marker.\n"))
        self.include = self.base / "tfm/interface/include"
        self.tfm_bytes = {
            "interface/include/os_wrapper/mutex.h": b"/* synthetic mutex */\n#define SYNTHETIC_MUTEX 1\n",
            "interface/include/os_wrapper/common.h": b"/* synthetic common */\n#define SYNTHETIC_COMMON 1\n",
            "license.rst": b"Synthetic test license marker.\nNot a real upstream license.\n",
        }
        for name, data in self.tfm_bytes.items():
            self.put(self.base / "tfm" / name, data)
        self.tfm_hashes = {name: subject.sha(data) for name, data in self.tfm_bytes.items()}
        self.blobs, self.git_calls = {}, []
        self.head, self.status = (subject.inventory.PIN + "\n").encode(), b""
        for name in ("include/FreeRTOS.h", PORTMACRO, "portable/GCC/WRONG/portmacro.h"):
            self.upstream(name, ("/* Synthetic " + name + ". */\n").encode())
        self.artifact = dict(role="runtime", source_group_id="SYNTHETIC_CM4",
            target=dict(architecture="ARMV7EM"), compile_flags=[], defines={},
            upstream_sources=["portable/GCC/ARM_CM4F/port.c"])
        self.cohort = dict(id="synthetic-reference-contract", policy={}, artifacts=[self.artifact])
        self.set_sources(self.artifact["upstream_sources"])
        self.binding = dict(ConfigText="/* Synthetic generated adapter. */\n#define SYNTHETIC_CONFIG 1\n",
                            Flags=["-DSYNTHETIC_CONTRACT_ONLY=1"],
                            PortmacroProvider=PORTMACRO, Differences=[])
        subject.recipe.reference_recipe = lambda *args: deepcopy(self.binding)
        report = dict(Cells=[], RequiredCellsSatisfied=0, **{key: False for key in FALSE_FIELDS})
        args = SimpleNamespace(repo=str(self.repo), freertos=str(self.reference), build=str(self.build),
                               git=str(self.git), arm_gcc=str(self.gcc), tfm_include=str(self.include))
        self.audit = subject.Reference(args, report)
        self.audit.git_bytes = self.git_bytes
        self.audit.dependency_plan = self.dependencies

    @staticmethod
    def put(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path.resolve()

    def upstream(self, name, blob, worktree=None):
        self.blobs[name] = blob
        return self.put(self.reference / name, blob if worktree is None else worktree)

    def set_sources(self, names):
        self.artifact["upstream_sources"] = names
        for name in names:
            self.upstream(name, b"/* Synthetic translation unit, never compiled. */\n")

    def git_bytes(self, *arguments):
        self.git_calls.append(arguments)
        if arguments == ("rev-parse", "HEAD"):
            return self.head
        if arguments == ("status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"):
            return self.status
        if arguments[0] == "show":
            need(arguments[1].startswith(self.subject.inventory.PIN + ":"), "Non-pinned Git blob request")
            return self.blobs[arguments[1].split(":", 1)[1]]
        raise AssertionError("Unexpected synthetic Git request: " + repr(arguments))

    def dependencies(self, index, directory):
        name = self.artifact["upstream_sources"][index]
        paths = [self.reference / "include/FreeRTOS.h"]
        if not (self.artifact["role"] == "secure_companion" and Path(name).name == "secure_init.c"):
            paths.append(directory / "FreeRTOSConfig.h")
        if self.artifact["role"] == "runtime":
            paths.append(self.reference / PORTMACRO)
        if name == TFM_WRAPPER:
            paths.extend(self.include / "os_wrapper" / file for file in ("mutex.h", "common.h"))
        return paths

    def run_cell(self):
        with redirect_stdout(io.StringIO()):
            self.audit.build_cell(self.cohort, self.artifact, "O0")

    def no_promotion(self):
        need(all(self.audit.report[key] is False for key in FALSE_FIELDS), "Global proof promoted")
        need(type(self.audit.report["RequiredCellsSatisfied"]) is int and
             self.audit.report["RequiredCellsSatisfied"] == 0, "Required cells promoted")
        for row in self.audit.report["Cells"]:
            need(all(row[key] is False for key in
                     ("RequiredCellSatisfied", "GeneratedAssemblyParity", "FinalElfProof", "CpuExecution")),
                 "Reference cell promoted")


def main():
    records, failures = [], []
    forbidden = AssertionError("Subprocess/native execution is forbidden in reference contract tests")
    with ExitStack() as guards:
        process = guards.enter_context(patch.object(subprocess, "Popen", side_effect=forbidden))
        run = guards.enter_context(patch.object(subprocess, "run", side_effect=forbidden))
        guards.enter_context(patch.object(os, "system", side_effect=forbidden))
        guards.enter_context(patch.object(os, "execve", side_effect=forbidden))
        subject = load_subject()

        def control(name, action, rejection=None):
            with TemporaryDirectory(prefix="freeze-reference-contract-") as temporary:
                fixture = Fixture(Path(temporary), subject)
                error = None
                try:
                    action(fixture)
                except Exception as failure:
                    error = failure
                fixture.no_promotion()
                matched = (error is None if rejection is None else
                           isinstance(error, RuntimeError) and
                           (rejection is True or str(error) == "freeze-inventory: " + rejection))
                record = dict(Name=name, ExpectedRejection=rejection,
                              ActualError=None if error is None else type(error).__name__ + ": " + str(error),
                              Matched=matched)
                records.append(record)
                if not matched:
                    failures.append(record)

        def track_header(fixture, worktree, blob=b"first\nsecond\n"):
            path = fixture.upstream("include/synthetic_bound.h", blob, worktree)
            fixture.audit.track(path)
            binding = fixture.audit.bindings["include/synthetic_bound.h"]
            need(binding["WorktreeSha256"] == subject.sha(worktree), "Raw worktree hash lost")
            need(binding["GitBlobSha256"] == subject.sha(blob), "Git blob hash lost")
            need(Path(fixture.audit.inputs[str(path)]["Captured"]).read_bytes() == worktree, "Raw capture normalized")
            need((fixture.build / "reference-blobs/include/synthetic_bound.h").read_bytes() == blob,
                 "Pinned blob capture normalized")
            need(fixture.git_calls == [("show", subject.inventory.PIN + ":include/synthetic_bound.h")],
                 "Wrong blob identity requested")
            need(binding["ByteComparison"] == ("exact" if worktree == blob else "git-lf-worktree-crlf"),
                 "Wrong normalization label")

        control("upstream-exact-lf-and-both-raw-captures", lambda f: track_header(f, b"first\nsecond\n"))
        control("upstream-whole-crlf-expansion", lambda f: track_header(f, b"first\r\nsecond\r\n"))
        for name, data in (("altered", b"FIRST\nsecond\n"), ("mixed-newlines", b"first\r\nsecond\n"),
                           ("lone-cr", b"first\rsecond\n")):
            control("upstream-reject-" + name, lambda f, d=data: track_header(f, d), "reference-source-bytes")
        control("upstream-reject-reverse-normalization",
                lambda f: track_header(f, b"first\nsecond\n", b"first\r\nsecond\r\n"), "reference-source-bytes")

        def cached_drift(fixture):
            path = fixture.upstream("include/cached.h", b"original\n")
            fixture.audit.track(path)
            path.write_bytes(b"changed\n")
            fixture.audit.track(path)

        control("upstream-cached-binding-does-not-hide-drift", cached_drift, "synthetic-input-drift")
        control("exact-head-clean-worktree", lambda f: f.audit.reference_identity())
        control("wrong-head", lambda f: (setattr(f, "head", b"0" * 40 + b"\n"), f.audit.reference_identity()),
                "actual-reference-pin")
        for name, status in (("tracked", b" M include/FreeRTOS.h\n"), ("untracked", b"?? extra.h\n"),
                             ("ignored", b"!! ignored.h\n")):
            control("dirty-" + name, lambda f, s=status: (setattr(f, "status", s), f.audit.reference_identity()),
                    "reference-worktree-drift")

        def valid_cell(fixture):
            fixture.run_cell()
            directory = fixture.build / "cells" / fixture.cohort["id"] / fixture.artifact["role"] / "O0"
            for path in (fixture.base_config, directory / "FreeRTOSConfig.h",
                         directory / "freeze_base_FreeRTOSConfig.h"):
                need(str(path.resolve()) in fixture.audit.inputs, "Config input not tracked")
                need(Path(fixture.audit.inputs[str(path.resolve())]["Captured"]).read_bytes() == path.read_bytes(),
                     "Config capture changed")
            row = fixture.audit.report["Cells"][0]
            need(row["Status"] == "REFERENCE-COMPILE-PREFLIGHT-PASS" and len(row["Objects"]) ==
                 len(fixture.artifact["upstream_sources"]), "Synthetic cell did not complete")
            need(len(fixture.audit.lower_calls) == 1, "Unexpected synthetic lower count")
            for obj in row["Objects"]:
                need(obj["TrackedCompileInputs"], "Per-TU input set missing")

        control("runtime-sole-portmacro-and-generated-config-tracked", valid_cell)

        def dependencies(fixture, change):
            fixture.audit.dependency_plan = lambda index, directory: change(
                fixture, index, directory, fixture.dependencies(index, directory))
            fixture.run_cell()

        control("runtime-missing-portmacro", lambda f: dependencies(f, lambda f, i, d, p:
                [x for x in p if x.name != "portmacro.h"]), "actual-reference-portmacro-provider")
        control("runtime-wrong-portmacro", lambda f: dependencies(f, lambda f, i, d, p:
                [x for x in p if x.name != "portmacro.h"] + [f.reference / "portable/GCC/WRONG/portmacro.h"]),
                "actual-reference-portmacro-provider")
        control("runtime-extra-portmacro", lambda f: dependencies(f, lambda f, i, d, p:
                p + [f.reference / "portable/GCC/WRONG/portmacro.h"]), "actual-reference-portmacro-provider")
        control("runtime-missing-config", lambda f: dependencies(f, lambda f, i, d, p:
                [x for x in p if x.name != "FreeRTOSConfig.h"]), "actual-reference-config-provider")
        control("runtime-wrong-config", lambda f: dependencies(f, lambda f, i, d, p:
                [x for x in p if x.name != "FreeRTOSConfig.h"] +
                [f.put(f.base / "foreign/FreeRTOSConfig.h", b"foreign config\n")]), "actual-reference-config-provider")
        control("runtime-extra-config", lambda f: dependencies(f, lambda f, i, d, p:
                p + [f.put(f.base / "foreign/FreeRTOSConfig.h", b"foreign config\n")]),
                "actual-reference-config-provider")

        def second_tu(fixture):
            fixture.set_sources(["portable/GCC/ARM_CM4F/port.c", "portable/GCC/ARM_CM4F/portasm.c"])
            dependencies(fixture, lambda f, i, d, p: p if i == 0 else [x for x in p if x.name != "portmacro.h"])

        control("provider-set-reset-for-every-tu", second_tu, "actual-reference-portmacro-provider")

        def companion(fixture, name="secure_context.c", change=None):
            fixture.artifact["role"] = "secure_companion"
            fixture.set_sources(["portable/GCC/SYNTHETIC/secure/" + name])
            if change is None:
                valid_cell(fixture)
            else:
                dependencies(fixture, change)

        control("companion-no-portmacro", companion)
        control("companion-reject-portmacro", lambda f: companion(f, change=lambda f, i, d, p:
                p + [f.reference / PORTMACRO]), "actual-reference-portmacro-provider")
        control("companion-secure-init-without-config", lambda f: companion(f, "secure_init.c"))
        control("companion-other-tu-still-requires-config", lambda f: companion(f, change=lambda f, i, d, p:
                [x for x in p if x.name != "FreeRTOSConfig.h"]), "actual-reference-config-provider")

        def runtime_init(fixture):
            fixture.set_sources(["portable/GCC/SYNTHETIC/secure_init.c"])
            dependencies(fixture, lambda f, i, d, p: [x for x in p if x.name != "FreeRTOSConfig.h"])

        control("runtime-secure-init-does-not-get-companion-exception", runtime_init,
                "actual-reference-config-provider")

        def tfm(fixture, change=None):
            fixture.set_sources([TFM_WRAPPER])
            if change is None:
                valid_cell(fixture)
            else:
                dependencies(fixture, change)

        control("tfm-wrapper-exact-two-provider-headers", tfm)
        control("tfm-wrapper-missing-common", lambda f: tfm(f, lambda f, i, d, p:
                [x for x in p if x.name != "common.h"]), "actual-pinned-tfm-provider")
        control("tfm-wrapper-wrong-provider", lambda f: tfm(f, lambda f, i, d, p:
                [x for x in p if x.parent.name != "os_wrapper"] +
                [f.put(f.base / "wrong/os_wrapper" / name, b"wrong provider\n") for name in ("mutex.h", "common.h")]),
                "actual-pinned-tfm-provider")
        control("tfm-headers-forbidden-in-other-tu", lambda f: dependencies(f, lambda f, i, d, p:
                p + [f.include / "os_wrapper/mutex.h"]), "actual-pinned-tfm-provider")

        def tfm_constants(fixture):
            need(subject.TFM_COMMIT == "9ca8a5eb3c85eecee1303dffa262800ea0385584" and
                 re.fullmatch(r"[0-9a-f]{40}", subject.TFM_COMMIT), "TF-M commit constant changed")
            need(set(subject.TFM_FILES) == set(fixture.tfm_bytes), "Unexpected real TF-M path constants")
            need(all(re.fullmatch(r"[0-9A-F]{64}", value) for value in subject.TFM_FILES.values()),
                 "Malformed real TF-M SHA256 constants")

        control("real-tfm-constant-syntax-only-not-real-provider-qualification", tfm_constants)

        def provider(fixture, change=None, crlf=False):
            if crlf:
                for name, data in fixture.tfm_bytes.items():
                    (fixture.base / "tfm" / name).write_bytes(data.replace(b"\n", b"\r\n"))
            if change is not None:
                change(fixture)
            with patch.object(subject, "TFM_FILES", fixture.tfm_hashes):
                rows = subject.tfm_provider(fixture.include)
            need(len(rows) == 3, "Synthetic TF-M provider count changed")
            for row in rows:
                path = Path(row["Path"])
                name = path.relative_to(fixture.base / "tfm").as_posix()
                need(row["WorktreeSha256"] == subject.sha(path.read_bytes()) and
                     row["GitBlobSha256"] == fixture.tfm_hashes[name], "TF-M raw/canonical hashes lost")
                need(row["ByteComparison"] == ("git-lf-worktree-crlf" if crlf else "exact"),
                     "TF-M byte comparison label changed")

        control("synthetic-tfm-exact-lf", provider)
        control("synthetic-tfm-whole-crlf-expansion", lambda f: provider(f, crlf=True))
        for name, data in (("altered", b"altered\n"), ("mixed", b"/* synthetic mutex */\r\n#define SYNTHETIC_MUTEX 1\n"),
                           ("lone-cr", b"/* synthetic mutex */\r#define SYNTHETIC_MUTEX 1\n")):
            control("synthetic-tfm-reject-" + name, lambda f, data=data: provider(f, lambda f:
                    (f.include / "os_wrapper/mutex.h").write_bytes(data)), "tfm-pinned-provider-bytes")
        control("synthetic-tfm-missing-license", lambda f: provider(f, lambda f:
                (f.base / "tfm/license.rst").unlink()), "missing/reparse-input")

        def bad_layout(fixture):
            include = fixture.base / "tfm/not-interface/include"
            include.mkdir(parents=True)
            with patch.object(subject, "TFM_FILES", fixture.tfm_hashes):
                subject.tfm_provider(include)

        control("synthetic-tfm-wrong-layout", bad_layout, "tfm-provider-layout")

        def cli_scope_and_counters(fixture):
            tree = ast.parse(subject.review_source)
            main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
            assignment = next(node for node in main.body if isinstance(node, ast.Assign) and
                              any(isinstance(target, ast.Name) and target.id == "report" for target in node.targets))
            report = {item.arg: ast.literal_eval(item.value) for item in assignment.value.keywords}
            need(all(report[key] is False for key in FALSE_FIELDS) and report["RequiredCellsSatisfied"] == 0,
                 "CLI default proof scope promoted")
            need(report["ProofScope"] == "REFERENCE_COMPILE_PREFLIGHT_ONLY", "CLI proof scope changed")
            fixture.audit.commands = [dict(command=[str(fixture.git), "-c", "core.fsmonitor=false", "show"]),
                dict(command=[str(fixture.gcc), "-c", "synthetic.c"]),
                dict(command=[str(fixture.gcc), "-r", "synthetic.o"])]
            for key, expected in (("SourceCompileCommands", 1), ("RelocatableGroupCommands", 1)):
                expressions = [keyword.value for node in ast.walk(main) if isinstance(node, ast.Call)
                               for keyword in node.keywords if keyword.arg == key]
                need(len(expressions) == 1, "Missing or duplicate CLI counter expression")
                actual = eval(compile(ast.Expression(expressions[0]), "<synthetic-counter>", "eval"),
                              {"sum": sum, "str": str, "audit": fixture.audit})
                need(actual == expected, "Git -c or non-GCC command counted as source compilation")

        control("cli-no-promotion-and-git-c-not-a-source-compile", cli_scope_and_counters)

        def resolved_escape(fixture):
            lexical = fixture.upstream("include/synthetic_escape.h", b"synthetic alias placeholder\n")
            escaped = fixture.put(fixture.base / "outside/synthetic_escape.h", b"synthetic outside header\n")
            original_regular = subject.regular

            def simulated_resolution(path):
                return escaped if Path(path).absolute() == lexical else original_regular(path)

            # Simulate only resolution, not an OS reparse point or a real upstream escape.
            with patch.object(subject, "regular", simulated_resolution):
                fixture.audit.track(lexical)

        control("lexical-upstream-header-resolving-outside-reference", resolved_escape, True)
        need(process.call_count == 0 and run.call_count == 0, "A subprocess call was attempted")

    positive = sum(row["ExpectedRejection"] is None for row in records)
    print(json.dumps(dict(Verdict="SYNTHETIC-REFERENCE-CONTRACT-FAIL" if failures else
        "SYNTHETIC-REFERENCE-CONTRACT-PASS", PositiveControls=positive,
        NegativeControls=len(records) - positive, Controls=records, Failures=failures,
        CompilerInvocations=0, SubprocessInvocations=0, TargetExecutions=0, GlobalFreezeQualified=False,
        SubjectSha256=hashlib.sha256(subject.review_source).hexdigest().upper(),
        Scope="SYNTHETIC_ADAPTER_ONLY_NOT_REAL_FREERTOS_TFM_OR_CPU_QUALIFICATION"), indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
