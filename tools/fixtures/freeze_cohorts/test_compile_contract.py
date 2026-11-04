"""Synthetic verify_inventory tamper controls; not 27-port or CPU qualification."""
from copy import deepcopy
from contextlib import ExitStack, chdir, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
TOOLS = HERE.parents[1]
REGISTRY_NAME = "tools/fixtures/sensitive_port_closure/run.py"
REGISTRY_BYTES = b"# Synthetic one-CM4 registry marker; never a real port registry.\n"
IMPORT_BASE = b"SYNTHETIC_IMPORT_ONLY = True\nclass Audit:\n    pass\n"
CORE_INPUTS = (
    "tools/freeze_cohorts.py", "tools/freeze_cohorts.json",
    "tools/runtime_sources.py", "tools/runtime_sources.ps1", "tools/runtime_sources.json",
    REGISTRY_NAME,
)
RUNTIME_MANIFEST = dict(schema_version=1,
    providers=dict(engine="context/engine.c", state="context/state.c", panic="fiber/panic.c",
                   optional_configuration="context/config.c"),
    compatibility=dict(legacy_compat=["fiber/legacy.c"], facade_bridge=["context/facade.c"]))
HEADERS = ("basic_types.h", "mcu_core.h", "context/shared_api.h", "fiber/shared_fiber.h",
           "fiber/port/shared_port.h", "fiber/port/ARM_CM4/fiber_port_private.h",
           "fiber/port/ARM_CM4/fiber_portmacro.h")
INPUT_HELPER = TOOLS / "fixtures/freeze_cohorts/inventory_inputs.py"


def need(ok, message):
    if not ok:
        raise AssertionError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("ascii"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None, "Missing synthetic-test import loader")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_subject():
    need((HERE / "build_recipe.py").is_file(), "build_recipe.py must exist before importing freeze_compile")
    original_read = Path.read_bytes
    closure_path = TOOLS / "fixtures/sensitive_port_closure/run.py"

    def import_bytes(path):
        if path == closure_path:
            return IMPORT_BASE
        return original_read(path)

    # Compile's inherited native implementation is outside verify_inventory's contract.
    with patch.object(Path, "read_bytes", import_bytes):
        subject = load("freeze_compile_contract_subject", TOOLS / "freeze_compile.py")
    need(subject.closure.SYNTHETIC_IMPORT_ONLY is True, "Native runner import was not isolated")
    return subject


class Fixture:
    def __init__(self, directory, subject, sample):
        self.base = directory.resolve()
        self.repo = self.base / "repo"
        self.freertos = self.base / "freertos"
        self.root = self.base / "receipt"
        self.subject = subject
        self.manifest, self.registry = sample()
        self.manifest["scope_backlog"] = [dict(id="synthetic-backlog", status="Pending",
            description="Synthetic fixture only", refs=["docs/synthetic_backlog.md"])]
        self.rows = []
        self.registry_calls = 0
        providers = {
            name: b"/* Generated synthetic provider bytes; never compiled. */\n"
            for name in CORE_INPUTS if name != "tools/freeze_cohorts.json"
        }
        providers[REGISTRY_NAME] = REGISTRY_BYTES
        providers["tools/runtime_sources.py"] = (TOOLS / "runtime_sources.py").read_bytes()
        providers["tools/runtime_sources.json"] = encoded(RUNTIME_MANIFEST) + b"\n"
        for name in (*RUNTIME_MANIFEST["providers"].values(),
                     *(name for paths in RUNTIME_MANIFEST["compatibility"].values() for name in paths),
                     *HEADERS):
            providers[name] = b"/* Synthetic declared input; never compiled. */\n"
        providers["fiber/port/ARM_CM4/fiber_portmacro.h"] = b"#define FIBER_PORT_RUNTIME_SELECTABLE 1\n"
        for cohort in self.manifest["cohorts"]:
            for reference in cohort["claim_refs"]:
                providers[reference["path"]] = b"Synthetic claim fixture, not proof.\n"
        for row in self.manifest["scope_backlog"]:
            for name in row["refs"]:
                providers[name] = b"Synthetic backlog fixture, not proof.\n"
        providers["tools/freeze_cohorts.json"] = encoded(self.manifest) + b"\n"
        for group in self.manifest["source_groups"]:
            for name in group["sources"]:
                providers[name] = b"/* Synthetic CM4 source; no executable code. */\n"
        upstream = sorted({name for cohort in self.manifest["cohorts"]
                           for artifact in cohort["artifacts"] for name in artifact["upstream_sources"]})
        for name in upstream:
            providers["pinned-reference/" + name] = b"/* Synthetic upstream source; not pinned FreeRTOS bytes. */\n"
        for name, data in providers.items():
            original = (self.freertos / name[len("pinned-reference/"):]
                        if name.startswith("pinned-reference/") else self.repo / name)
            self.add_input(name, data, original)
        self.required = subject.inventory.plan(self.manifest)
        write_json(self.root / "required-cells.json", self.required)
        write_json(self.root / "commands.json", [])
        bindings = []
        for name in upstream:
            data = (self.root / "inputs/pinned-reference" / name).read_bytes()
            blob = self.root / "reference-blobs" / name
            blob.parent.mkdir(parents=True, exist_ok=True)
            blob.write_bytes(data)
            bindings.append(dict(Path=name, WorktreeSha256=sha(data), GitBlobSha256=sha(data), ByteComparison="exact"))
        self.result = dict(Verdict="INVENTORY-PLAN-PASS", Error=None, GlobalFreezeQualified=False,
            ReferenceIdentityVerified=True, ReferenceCommit=subject.inventory.PIN,
            CompilerInvocations=0, TargetExecutions=0, CompilerDependenciesCaptured=False,
            ProofScope="DECLARED_INVENTORY_AND_PLAN_ONLY", InputDrift=[], ReferenceFileBindings=bindings)
        self.refresh_capture()
        self.seal()

    def add_input(self, name, data, original):
        copied = self.root / "inputs" / name
        for path in (original, copied):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.rows.append(dict(Original=str(original), Captured=str(copied), Sha256=sha(data)))

    def refresh_capture(self):
        write_json(self.root / "capture.json", dict(Files=self.rows))
        names = {Path(row["Captured"]).relative_to(self.root / "inputs").as_posix(): row["Sha256"]
                 for row in self.rows if Path(row["Captured"]).is_relative_to(self.root / "inputs")}
        self.result["SourceInventorySha256"] = sha(encoded(names))
        self.result["ManifestSha256"] = sha((self.root / "inputs/tools/freeze_cohorts.json").read_bytes())
        self.result["RequiredCellsSha256"] = sha((self.root / "required-cells.json").read_bytes())
        self.write_result()

    def write_result(self):
        write_json(self.root / "results.json", self.result)

    def seal(self):
        artifacts = {path.relative_to(self.root).as_posix(): sha(path.read_bytes())
                     for path in sorted(self.root.rglob("*"))
                     if path.is_file() and path != self.root / "artifacts.json"}
        write_json(self.root / "artifacts.json", dict(Artifacts=artifacts))

    def artifact_map(self):
        return json.loads((self.root / "artifacts.json").read_bytes())["Artifacts"]

    def capture_row(self, name):
        copied = self.root / "inputs" / name
        return next(row for row in self.rows if Path(row["Captured"]) == copied)

    def verify(self):
        original_read = Path.read_bytes

        def generated_only(path):
            need(path == INPUT_HELPER or path.resolve().is_relative_to(self.base),
                 "verify_inventory read outside generated fixture/helper: " + str(path))
            return original_read(path)

        def synthetic_registry(data):
            need(data == REGISTRY_BYTES, "Registry stub requires exact generated fixture bytes")
            self.registry_calls += 1
            return deepcopy(self.registry)

        with patch.object(self.subject.inventory, "read_registry", synthetic_registry), \
                patch.object(Path, "read_bytes", generated_only):
            return self.subject.verify_inventory(self.root, self.repo, self.freertos)


def main():
    records = []
    failures = []
    forbidden = AssertionError("Process execution is forbidden in compile receipt controls")
    with ExitStack() as guards:
        popen = guards.enter_context(patch.object(subprocess, "Popen", side_effect=forbidden))
        guards.enter_context(patch("os.system", side_effect=forbidden))
        guards.enter_context(patch("os.execve", side_effect=forbidden))
        subject = load_subject()
        sample = load("freeze_compile_contract_sample", HERE / "test_contract.py").sample

        def control(name, mutation=None, reason=None):
            with TemporaryDirectory(prefix="freeze-compile-contract-") as temporary:
                fixture = Fixture(Path(temporary), subject, sample)
                if mutation is not None:
                    mutation(fixture)
                try:
                    result, manifest, groups = fixture.verify()
                except RuntimeError as failure:
                    error = str(failure)
                    accepted = False
                else:
                    error = None
                    if reason is None:
                        need(manifest == fixture.manifest and groups == {"CM4": fixture.manifest["source_groups"][0]},
                             name + " changed returned manifest or groups")
                        need(result == fixture.result and fixture.registry_calls == 1, name + " lost result/registry binding")
                        need(result["GlobalFreezeQualified"] is False and fixture.required["RequiredCellCount"] == 19,
                             name + " expanded synthetic scope")
                        need(subject.LOADED[str(INPUT_HELPER.resolve())] == sha(INPUT_HELPER.read_bytes()),
                             name + " did not register executed input helper for preflight capture")
                        reader = fixture.repo / "tools/runtime_sources.py"
                        need(subject.LOADED[str(reader)] == sha(reader.read_bytes()),
                             name + " did not register the bound canonical runtime reader")
                    accepted = True
                matched = (accepted if reason is None else not accepted and error == "freeze-inventory: " + reason)
                if not matched:
                    failures.append(dict(Name=name, ExpectedRejection=reason, ActualRejection=error))
                records.append(dict(Name=name, Accepted=accepted, ExpectedRejection=reason, Matched=matched))

        control("valid-generated-cm4-receipt")

        def reordered_capture(fixture):
            fixture.rows.reverse()
            fixture.refresh_capture()
            fixture.seal()

        control("valid-reordered-capture", reordered_capture)

        def host_git_capture(fixture):
            fixture.add_input("host-git/git.exe", b"Synthetic inert host-file bytes; never executed.\n",
                              fixture.base / "host/git.exe")
            fixture.refresh_capture()
            fixture.seal()

        control("valid-inert-host-git-capture", host_git_capture)

        def artifact_key(fixture, foreign):
            artifacts = fixture.artifact_map()
            if foreign:
                artifacts["foreign.bin"] = sha(b"not present")
            else:
                artifacts.pop("results.json")
            write_json(fixture.root / "artifacts.json", dict(Artifacts=artifacts))

        control("missing-artifact-key", lambda f: artifact_key(f, False), "inventory-artifact-set")
        control("foreign-artifact-key", lambda f: artifact_key(f, True), "inventory-artifact-set")
        control("missing-artifact-file", lambda f: (f.root / "commands.json").unlink(), "inventory-artifact-set")
        control("unlisted-artifact-file", lambda f: (f.root / "foreign.bin").write_bytes(b"foreign"), "inventory-artifact-set")
        port_name = "fiber/port/ARM_CM4/fiber_port.c"
        control("mutated-captured-bytes", lambda f: (f.root / "inputs" / port_name).write_bytes(b"tampered"),
                "inventory-artifact-bytes")

        def resealed_copy(fixture):
            (fixture.root / "inputs" / port_name).write_bytes(b"tampered")
            fixture.seal()

        control("mutated-copy-resealed-artifacts", resealed_copy, "inventory-capture-binding")

        def wrong_fingerprint(fixture):
            fixture.result["SourceInventorySha256"] = "0" * 64
            fixture.write_result()
            fixture.seal()

        control("wrong-source-fingerprint", wrong_fingerprint, "inventory-source-fingerprint")
        control("original-source-drift", lambda f: (f.repo / port_name).write_bytes(b"original drift"),
                "inventory-original-source-drift")
        upstream_name = "portable/GCC/ARM_CM4F/port.c"
        control("original-upstream-drift", lambda f: (f.freertos / upstream_name).write_bytes(b"upstream drift"),
                "inventory-original-source-drift")

        def wrong_original(fixture):
            row = fixture.capture_row(port_name)
            foreign = fixture.base / "foreign-source.c"
            foreign.write_bytes(Path(row["Original"]).read_bytes())
            row["Original"] = str(foreign)
            fixture.refresh_capture()
            fixture.seal()

        control("same-bytes-wrong-original-path", wrong_original, "inventory-original-source-drift")

        def receipt_field(fixture, key, value):
            fixture.result[key] = value
            fixture.write_result()
            fixture.seal()

        for name, key, value in (
            ("bad-receipt-status", "Verdict", "FAIL"),
            ("forged-global-scope", "GlobalFreezeQualified", True),
            ("numeric-global-scope", "GlobalFreezeQualified", 0),
            ("unverified-reference", "ReferenceIdentityVerified", False),
            ("numeric-reference-identity", "ReferenceIdentityVerified", 1),
            ("wrong-reference-pin", "ReferenceCommit", "0" * 40),
            ("wrong-declared-proof-scope", "ProofScope", "CPU_PROOF"),
            ("nonzero-compiler-invocations", "CompilerInvocations", 1),
            ("bool-compiler-invocations", "CompilerInvocations", False),
            ("nonzero-target-executions", "TargetExecutions", 1),
            ("bool-target-executions", "TargetExecutions", False),
            ("forged-compiler-dependencies", "CompilerDependenciesCaptured", True),
            ("receipt-error", "Error", "unresolved failure"),
            ("receipt-drift", "InputDrift", ["changed-input"]),
        ):
            control(name, lambda f, k=key, v=value: receipt_field(f, k, v), "inventory-receipt-scope")

        def reduced_plan(fixture, empty):
            fixture.required["RequiredCells"] = [] if empty else fixture.required["RequiredCells"][:-1]
            fixture.required["RequiredCellCount"] = len(fixture.required["RequiredCells"])
            write_json(fixture.root / "required-cells.json", fixture.required)
            fixture.refresh_capture()
            fixture.seal()

        control("self-consistent-reduced-plan", lambda f: reduced_plan(f, False), "inventory-required-plan-binding")
        control("self-consistent-empty-plan", lambda f: reduced_plan(f, True), "inventory-required-plan-binding")

        def duplicate_capture(fixture):
            fixture.rows.append(deepcopy(fixture.rows[0]))
            fixture.refresh_capture()
            fixture.seal()

        control("duplicate-capture", duplicate_capture, "inventory-capture-binding")

        def outside_capture(fixture, sibling):
            row = fixture.capture_row(port_name)
            foreign = (fixture.root / "inputs-neighbor/source.c" if sibling else fixture.base / "outside-source.c")
            foreign.parent.mkdir(parents=True, exist_ok=True)
            foreign.write_bytes(Path(row["Captured"]).read_bytes())
            row["Captured"] = str(foreign)
            fixture.refresh_capture()
            fixture.seal()

        control("capture-outside-receipt", lambda f: outside_capture(f, False), "inventory-capture-containment")
        control("capture-inputs-prefix-lookalike", lambda f: outside_capture(f, True), "inventory-capture-containment")

        def omitted_capture(fixture, name):
            fixture.rows.remove(fixture.capture_row(name))
            fixture.refresh_capture()
            fixture.seal()

        for name in (*CORE_INPUTS, port_name, "pinned-reference/" + upstream_name):
            control("missing-declared-capture:" + name, lambda f, n=name: omitted_capture(f, n),
                    "inventory-declared-source-coverage")

        for name in (*HEADERS, "context/engine.c", "fiber/legacy.c", "context/facade.c",
                     "tools/compile_matrix.ps1", "docs/synthetic_backlog.md"):
            control("missing-complete-capture:" + name, lambda f, n=name: omitted_capture(f, n),
                    "inventory-complete-source-coverage")

        def omitted_header_drift(fixture, remove_copy):
            name = "fiber/port/ARM_CM4/fiber_port_private.h"
            row = fixture.capture_row(name)
            fixture.rows.remove(row)
            Path(row["Original"]).write_bytes(b"Unrecorded header drift\n")
            if remove_copy:
                Path(row["Captured"]).unlink()
            fixture.result["ExpectedInputs"] = [Path(row["Captured"]).relative_to(fixture.root / "inputs").as_posix()
                                                for row in fixture.rows]
            fixture.refresh_capture()
            fixture.seal()

        control("omitted-header-drift-resealed-with-copy", lambda f: omitted_header_drift(f, False),
                "inventory-complete-source-coverage")
        control("omitted-header-drift-resealed-without-copy", lambda f: omitted_header_drift(f, True),
                "inventory-complete-source-coverage")

        def current_header(fixture, name):
            path = fixture.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"New current header, not in the old receipt.\n")

        for name in ("new_root.h", "context/new_shared.h", "fiber/new_shared.h", "fiber/port/new_shared.h",
                     "fiber/port/ARM_CM4/new_private.h"):
            control("new-current-header-invalidates-old-receipt:" + name,
                    lambda f, n=name: current_header(f, n), "inventory-complete-source-coverage")
        control("unselected-port-header-not-in-declared-closure",
                lambda f: current_header(f, "fiber/port/UNSELECTED/not_selected.h"))

        def replaced_runtime_provider(fixture):
            runtime = deepcopy(RUNTIME_MANIFEST)
            runtime["providers"]["engine"] = "context/replaced_engine.c"
            (fixture.repo / "context/replaced_engine.c").write_bytes(b"New current provider, not captured.\n")
            row = fixture.capture_row("tools/runtime_sources.json")
            data = encoded(runtime)
            for key in ("Original", "Captured"):
                Path(row[key]).write_bytes(data)
            row["Sha256"] = sha(data)
            fixture.refresh_capture()
            fixture.seal()

        control("resealed-provider-membership-cannot-omit-current-provider", replaced_runtime_provider,
                "inventory-complete-source-coverage")

        def foreign_capture(fixture):
            fixture.add_input("foreign.txt", b"Not a declared input\n", fixture.repo / "foreign.txt")
            fixture.result["ExpectedInputs"] = ["foreign.txt"]
            fixture.refresh_capture()
            fixture.seal()

        control("claimed-expected-inputs-cannot-add-foreign-capture", foreign_capture,
                "inventory-complete-source-coverage")

        def unlisted_copy(fixture):
            (fixture.root / "inputs/unlisted.bin").write_bytes(b"Not covered by a capture row\n")
            fixture.seal()

        control("every-input-copy-needs-a-capture-row", unlisted_copy, "inventory-capture-file-set")

        def cmsis_cli(fixture, relative):
            cmsis = fixture.base / relative
            cmsis.mkdir()
            compiler = fixture.base / "host/arm-none-eabi-gcc.exe"
            compiler.parent.mkdir(exist_ok=True)
            compiler.write_bytes(b"Inert compiler marker; never executed.\n")
            out = fixture.base / "cli-output"
            received = []

            class NoCompiler:
                def __init__(self, args, report):
                    received.append(args.cmsis_core)
                    self.inputs, self.commands, self.gcc = {}, [], compiler
                    self.report = report

                def preflight(self):
                    pass

                def build_cell(self, cohort, artifact, group, mode):
                    self.report["Cells"].append(dict(Status="COMPILE-PREFLIGHT-PASS"))

            argv = [str(TOOLS / "freeze_compile.py"), "--repo", str(fixture.repo),
                    "--inventory", str(fixture.root), "--freertos", str(fixture.freertos),
                    "--arm-gcc", str(compiler), "--cmsis-core", relative,
                    "--output-dir", str(out), "--all-cohorts", "--mode", "O0"]
            with patch.object(subject, "Compile", NoCompiler), \
                    patch.object(subject, "verify_inventory", return_value=(fixture.result, fixture.manifest,
                        {"CM4": fixture.manifest["source_groups"][0]})), \
                    patch.object(sys, "argv", argv), chdir(fixture.base), redirect_stdout(io.StringIO()):
                need(subject.main() == 0, "CMSIS-only CLI stub failed")
            need(received == [str(cmsis.resolve())] and Path(received[0]).is_absolute(),
                 "Compile did not receive the canonical absolute CMSIS argument")
            report = json.loads((out / "results.json").read_bytes())
            need(report["GlobalFreezeQualified"] is False and report["RequiredCellsSatisfied"] == 0,
                 "CMSIS argument regression promoted proof scope")

        for name, relative in (("relative-cmsis-normalized-before-compile", "cmsis-relative"),
                               ("relative-cmsis-weird-whitespace-is-literal", "CMSIS  [literal] headers")):
            with TemporaryDirectory(prefix="freeze-compile-cmsis-contract-") as temporary:
                fixture = Fixture(Path(temporary), subject, sample)
                cmsis_cli(fixture, relative)
            records.append(dict(Name=name, Accepted=True, ExpectedRejection=None, Matched=True))
        need(popen.call_count == 0, "Unexpected attempt to execute a process")
    positive = sum(row["ExpectedRejection"] is None for row in records)
    print(json.dumps(dict(Verdict="SYNTHETIC-COMPILE-CONTRACT-FAIL" if failures else "SYNTHETIC-COMPILE-CONTRACT-PASS",
        PositiveControls=positive, NegativeControls=len(records) - positive, Controls=records, Failures=failures,
        CompilerInvocations=0, TargetExecutions=0,
        Scope="GENERATED_ONE_CM4_RECEIPT_ONLY_NOT_27_SOURCE_GROUP_QUALIFICATION", GlobalFreezeQualified=False), indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
