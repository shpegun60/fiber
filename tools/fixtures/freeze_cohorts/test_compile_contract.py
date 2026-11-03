"""Synthetic verify_inventory tamper controls; not 27-port or CPU qualification."""
from copy import deepcopy
from contextlib import ExitStack
import hashlib
import importlib.util
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
        self.rows = []
        self.registry_calls = 0
        providers = {
            name: b"/* Generated synthetic provider bytes; never compiled. */\n"
            for name in CORE_INPUTS if name != "tools/freeze_cohorts.json"
        }
        providers[REGISTRY_NAME] = REGISTRY_BYTES
        providers["tools/runtime_sources.json"] = b'{"synthetic": true}\n'
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
            need(path.resolve().is_relative_to(self.base), "verify_inventory read outside generated fixture: " + str(path))
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
