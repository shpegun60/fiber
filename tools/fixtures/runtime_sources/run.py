"""Shared reader corpus. All mutations are generated under the evidence root."""

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
PROVIDERS = ("engine", "state", "panic", "optional_configuration")
COMPATIBILITY = ("legacy_compat", "facade_bridge")
ROLES = PROVIDERS + COMPATIBILITY
CURRENT = {
    "schema_version": 1,
    "providers": dict(zip(PROVIDERS, (
        "fiber/fiber_core.c", "fiber/fiber_runtime_state.c", "fiber/fiber_panic.c",
        "fiber/fiber_runtime_context_configuration.c"))),
    "compatibility": {"legacy_compat": [], "facade_bridge": ["fiber/fiber_context_compat.c"]},
}
INVERTED = {
    "schema_version": 1,
    "providers": dict(zip(PROVIDERS, (
        "context/context_core.c", "context/context_runtime_state.c", "context/context_panic.c",
        "context/context_configuration.c"))),
    "compatibility": {"legacy_compat": ["fiber/fiber_core.c"], "facade_bridge": []},
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def load_reader(root):
    path = root / "tools/runtime_sources.py"
    spec = importlib.util.spec_from_file_location("inventory_case_reader", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_names(manifest):
    return [manifest["providers"][role] for role in PROVIDERS] + sum(
        (manifest["compatibility"][role] for role in COMPATIBILITY), [])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--powershell", required=True, type=Path)
    args = parser.parse_args()
    repo, build = args.repo.resolve(), args.build.resolve()
    fixture = Path(__file__).resolve().parent
    helpers = [repo / ("tools/runtime_sources" + suffix) for suffix in (".json", ".ps1", ".py")]
    live = json.loads(helpers[0].read_text(encoding="utf-8-sig"))
    python_binary = Path(sys.executable).resolve()
    try:
        digest(python_binary)
    except OSError:
        # Windows Store launch aliases execute but cannot be read as binaries.
        python_binary = Path(sys.base_prefix) / python_binary.name
    inputs = sorted(set(helpers + [repo / p for p in source_names(live)] + [
        repo / "tools/test_runtime_sources.ps1", Path(__file__).resolve(),
        fixture / "readers.ps1", fixture / "cases.json", fixture / "README.md",
        python_binary, args.powershell.resolve()]), key=str)
    before = {str(path): digest(path) for path in inputs}
    write_json(build / "inputs-before.json", before)
    commands, completed, plan, drift_controls = [], [], [], []
    status, error = "FAIL", None

    def command(arguments, name):
        result = subprocess.run(list(map(str, arguments)), capture_output=True)
        (build / (name + ".stdout")).write_bytes(result.stdout)
        (build / (name + ".stderr")).write_bytes(result.stderr)
        commands.append(dict(arguments=list(map(str, arguments)), exit_code=result.returncode))
        write_json(build / "commands.json", commands)
        require(result.returncode == 0, f"command failed: {name}; see retained stdout/stderr")

    def prepare(case):
        root = build / "exports" / case["name"]
        (root / "tools").mkdir(parents=True)
        manifest = copy.deepcopy(INVERTED if case.get("layout") == "inverted" else CURRENT)
        action = case.get("filesystem", {})
        for helper in helpers[1:]:
            relative = "tools/" + helper.name
            if action.get("kind") != "missing" or action.get("path") != relative:
                shutil.copyfile(helper, root / relative)
        for relative in source_names(manifest):
            if action.get("kind") == "missing" and action.get("path") == relative:
                continue
            destination = root / relative
            if action.get("kind") == "reparse" and relative.startswith("fiber/"):
                destination = build / "reparse-target" / case["name"] / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if action.get("kind") == "directory" and action.get("path") == relative:
                destination.mkdir()
            else:
                destination.write_text("/* Inventory-only fixture; no executable runtime body. */\n", encoding="ascii")
        if "set" in case or "remove" in case:
            keys = case.get("set", case.get("remove"))
            target = manifest
            for key in keys[:-1]:
                target = target[key]
            if "set" in case:
                target[keys[-1]] = case["value"]
            else:
                del target[keys[-1]]
        text = json.dumps(manifest, separators=(",", ":"))
        if "replace" in case:
            old, new = case["replace"]
            require(text.count(old) == 1, "exact JSON mutation drift: " + case["name"])
            text = text.replace(old, new)
        text += case.get("suffix", "")
        data = text.encode("utf-8")
        if case.get("encoding") == "bom":
            data = b"\xef\xbb\xbf" + data
        elif case.get("encoding") == "invalid":
            data = b"\xff" + data
        elif case.get("encoding", "").startswith(("utf-16", "utf-32")):
            data = text.encode(case["encoding"])
        if action.get("kind") != "missing" or action.get("path") != "tools/runtime_sources.json":
            (root / "tools/runtime_sources.json").write_bytes(data)
        if action.get("kind") == "reparse":
            target = build / "reparse-target" / case["name"] / "fiber"
            script = ("$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path '" +
                      str(root / "fiber").replace("'", "''") + "' -Target '" +
                      str(target).replace("'", "''") + "' | Out-Null")
            command([args.powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], "reparse")
        require(not (root / ".git").exists(), "fixture unexpectedly depends on Git metadata")
        return root

    def query(case):
        try:
            module = load_reader(Path(case["root"]))
        except Exception as failure:
            return dict(name=case["name"], apis={
                api: dict(accepted=False, error=str(failure)) for api in ("paths", "inputs")})
        results = {}
        for api, function in (("paths", module.get_runtime_source_paths),
                              ("inputs", module.get_runtime_source_inputs)):
            try:
                arguments = [case["root"]] if case["omit_roles"] else [case["root"], case["roles"]]
                results[api] = dict(accepted=True, value=list(map(str, function(*arguments))))
            except Exception as failure:
                results[api] = dict(accepted=False, error=str(failure))
        return dict(name=case["name"], apis=results)

    def add_case(case, root):
        entry = dict(name=case["name"], root=str(root), roles=case.get("roles", list(PROVIDERS[:3]) + ["legacy_compat"]),
                     accept=case["accept"], expected=case.get("expected", []), omit_roles=case.get("omit_roles", False),
                     api_acceptance=case.get("api_acceptance", {}))
        plan.append(entry)
        return entry

    try:
        corpus = json.loads((fixture / "cases.json").read_text(encoding="utf-8"))
        require(len({c["name"] for c in corpus}) == len(corpus), "duplicate corpus case name")
        live_roles = list(ROLES)
        add_case(dict(name="live-inventory", accept=True, roles=live_roles, expected=source_names(live)), repo)
        for case in corpus:
            add_case(case, prepare(case))
        selected = source_names(CURRENT)
        for relative in ["tools/runtime_sources.json", "tools/runtime_sources.ps1", "tools/runtime_sources.py", *selected]:
            name = "drift-" + relative.replace("/", "-").replace(".", "-")
            case = dict(name=name, accept=True, roles=list(ROLES), expected=selected)
            root = prepare(case)
            module = load_reader(root)
            tracked = module.get_runtime_source_inputs(root, ROLES)
            first = {str(path): digest(path) for path in tracked}
            path = root / relative
            suffix = b"\n" if path.suffix == ".json" else b"\n# drift\n" if path.suffix in (".ps1", ".py") else b"\n/* drift */\n"
            with path.open("ab") as output:
                output.write(suffix)
            second = {str(p): digest(p) for p in module.get_runtime_source_inputs(root, ROLES)}
            changed = [p for p in first if first[p] != second.get(p)]
            require(changed == [str(path)], "receipt input mutation was not causally detected: " + relative)
            drift_controls.append(dict(path=relative, before=first[str(path)], after=second[str(path)]))
            add_case(case, root)
        write_json(build / "case-plan.json", plan)
        python_results = [query(case) for case in plan]
        write_json(build / "python-results.json", python_results)
        ps_output = build / "powershell-results.json"
        command([args.powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", fixture / "readers.ps1",
                 "-CaseList", build / "case-plan.json", "-OutputPath", ps_output], "powershell-readers")
        ps_results = json.loads(ps_output.read_text(encoding="utf-8-sig"))
        require(len(ps_results) == len(plan), "PowerShell case census mismatch")
        for case, py, ps in zip(plan, python_results, ps_results):
            require(py["name"] == ps["name"] == case["name"], "cross-language case order mismatch")
            root = Path(case["root"])
            expected = list(map(str, (root / p for p in case["expected"])))
            metadata = [str(root / ("tools/runtime_sources" + suffix)) for suffix in (".json", ".ps1", ".py")]
            for language, result in (("python", py), ("powershell", ps)):
                acceptance = case["api_acceptance"].get(language, {})
                for api in ("paths", "inputs"):
                    verdict = acceptance.get(api, case["accept"])
                    observed = result["apis"][api]
                    require(observed["accepted"] == verdict,
                            f"reader acceptance mismatch: {case['name']}/{language}/{api}; {observed}")
                    if verdict:
                        value = expected if api == "paths" else metadata + expected
                        require(observed["value"] == value,
                                f"selection/receipt changed: {case['name']}/{language}/{api}")
            completed.append(dict(name=case["name"], accepted=case["accept"], both_readers=True))
        status = "PASS"
    except Exception as failure:
        error = str(failure)
    finally:
        after = {str(path): digest(path) if path.is_file() else None for path in inputs}
        drift = [path for path in before if before[path] != after[path]]
        write_json(build / "inputs-after.json", after)
        if drift:
            status, error = "FAIL", "live input drift"
        result = dict(Status=status, Scope="Shared source-inventory readers only; no C compilation, ABI/runtime/CPU qualification",
                      SharedCases=len(plan), CompletedCases=len(completed), ReaderDecisions=2 * len(completed),
                      ApiDecisions=4 * len(completed),
                      PositiveCases=sum(c["accepted"] for c in completed),
                      NegativeCases=sum(not c["accepted"] for c in completed),
                      ByteDriftControls=drift_controls, InputCount=len(before), InputDrift=drift,
                      Cases=completed, Error=error)
        write_json(build / "results.json", result)
        artifacts = {str(path): digest(path) for path in sorted(build.rglob("*")) if path.is_file()}
        write_json(build / "artifact-hashes.json", artifacts)
    print(f"{status} runtime source inventory: {len(completed)} shared cases, {2 * len(completed)} reader decisions; {build}")
    if error:
        print(error)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
