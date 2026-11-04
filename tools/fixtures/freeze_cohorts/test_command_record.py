"""Exercise actual command-record method ASTs with inert process results."""
import ast
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace


TOOLS = Path(__file__).resolve().parents[2]


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="ascii")


def sha(value):
    return hashlib.sha256(value).hexdigest().upper()


def method(path, class_name, function, namespace):
    source = path.read_bytes()
    tree = ast.parse(source)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
    node = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == function)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
    return namespace[function], sha(source)


def main():
    controls, subjects = [], {}
    for kind in ("native", "reference"):
        with TemporaryDirectory(prefix="freeze-record-controls-") as temporary:
            root = Path(temporary)
            process = SimpleNamespace(run=None)
            namespace = dict(need=need, save=save, sha=sha, time=time, process_runner=process,
                             native=SimpleNamespace(process_runner=process))
            path = TOOLS / ("freeze_compile.py" if kind == "native" else "freeze_reference_compile.py")
            call, fingerprint = method(path, "Compile" if kind == "native" else "Reference",
                                       "run" if kind == "native" else "git_bytes", namespace)
            subjects[path.name] = fingerprint
            for case in ("success", "failure", "timeout", "zero-exit-timeout", "setup-error", "interrupt"):
                output = root / case
                output.mkdir()
                fixture = SimpleNamespace(build=output, commands=[], allowed={"inert-tool"},
                    track=lambda path: None, environment={}, git=Path("inert-tool"), reference=Path("inert-reference"))
                invoked = []

                def run(argv, **kwargs):
                    pending = json.loads((output / "command-00000.json").read_bytes())
                    need(len(fixture.commands) == 1 and pending["exit"] is None and pending["seconds"] is None,
                         "attempt-not-retained-before-process")
                    need(kwargs["cwd"] == output and kwargs["env"] == {}, "process-context")
                    invoked.append(argv)
                    if case == "setup-error":
                        raise OSError("synthetic setup failure")
                    if case == "interrupt":
                        raise KeyboardInterrupt("synthetic interruption")
                    return SimpleNamespace(returncode=0 if case in ("success", "zero-exit-timeout") else 124,
                        stdout=b"synthetic partial stdout\n", stderr=b"synthetic stderr\n",
                        timed_out=case in ("timeout", "zero-exit-timeout"))

                process.run = run
                failure, answer = None, None
                try:
                    if kind == "native":
                        answer = call(fixture, ["inert-tool", "-dumpfullversion"], "synthetic", timeout=0.1)
                    else:
                        answer = call(fixture, "rev-parse", "HEAD")
                except BaseException as error:
                    failure = error
                need(bool(failure) == (case != "success") and len(invoked) == 1, "wrong-command-result")
                record = json.loads((output / "command-00000.json").read_bytes())
                need(record == fixture.commands[0] and record["seconds"] is not None, "final-record-not-retained")
                if case in ("setup-error", "interrupt"):
                    need(record["exit"] is None and record["Error"].startswith(type(failure).__name__ + ":"),
                         "exception-record-lost")
                else:
                    need(record["Error"] is None and record["timed_out"] == ("timeout" in case), "completion-record")
                    if kind == "native":
                        need(record["stdout"] == "synthetic partial stdout\n" and record["stderr"] == "synthetic stderr\n",
                             "partial-text-lost")
                    else:
                        need(record["stdout_sha256"] == sha(b"synthetic partial stdout\n"), "partial-git-hash-lost")
                if case == "success":
                    need(answer == ("synthetic partial stdout\n" if kind == "native" else b"synthetic partial stdout\n"),
                         "returned-output")
                controls.append(kind + ":" + case)
    print(json.dumps(dict(Verdict="SYNTHETIC-COMMAND-RECORD-PASS", Controls=controls, Subjects=subjects,
        CompilerInvocations=0, SubprocessInvocations=0, TargetExecutions=0,
        GlobalFreezeQualified=False, Scope="METHOD_AST_WITH_INERT_PROCESS_ONLY_NOT_TREE_CLEANUP_PROOF"), indent=2))


if __name__ == "__main__":
    main()
