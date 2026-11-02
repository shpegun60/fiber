"""Bounded native-ELF regression for interior data callback reachability."""
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import inspect as introspect
import json
from pathlib import Path
import struct
import subprocess
import textwrap
import traceback


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "arm-gcc", "build"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    repo, gcc, build = Path(args.repo).resolve(), Path(args.arm_gcc).resolve(), Path(args.build).resolve()
    build.mkdir(parents=True, exist_ok=True)
    classifier_path = repo / "tools/fixtures/sensitive_port_closure/run.py"
    fixture = Path(__file__).resolve().parent / "interior_callback.c"
    inputs = [classifier_path, fixture, Path(__file__).resolve(), repo / "fiber/fiber_api_attributes.h",
              repo / "tools/test_sensitive_data_reachability.ps1",
              gcc, gcc.with_name("arm-none-eabi-objdump.exe")]
    before = {str(p): sha(p) for p in inputs}
    write(build / "inputs.before.json", before)
    spec = importlib.util.spec_from_file_location("data_reachability_classifier", classifier_path)
    classifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(classifier)
    original = classifier.Elf.targets
    source = textwrap.dedent(introspect.getsource(original))
    anchor = 's["value"] <= value < s["value"] + s["size"]'
    require(source.count(anchor) == 1, "Exact containing-object resolver mutation anchor changed")
    scope = {"struct": struct}
    exec(compile(source.replace(anchor, "False"), "<exact-start-only-resolver-control>", "exec"), scope)
    old_resolver = scope["targets"]
    commands, cases = [], []

    def command(parts, name):
        parts = list(map(str, parts))
        result = subprocess.run(parts, capture_output=True, text=True, timeout=120)
        record = dict(Command=parts, ExitCode=result.returncode, Output=result.stdout + result.stderr)
        commands.append(record)
        write(build / ("command-%03d.json" % (len(commands) - 1)), record)
        require(result.returncode == 0, name + ": " + record["Output"])
        return record["Output"]

    try:
        for opt in ("-O2", "-Os"):
            for layout in ("normal", "lto-sectioned", "lto-unsectioned"):
                for padding in (0, 1024):
                    for protected in (False, True):
                        label = "%s-%s-%d-%s" % (opt[1:], layout, padding, "protected" if protected else "ordinary")
                        directory = build / label
                        directory.mkdir()
                        flags = ["-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=soft", opt, "-std=gnu11",
                                 "-ffreestanding", "-fno-builtin", "-fdata-sections", "-finstrument-functions",
                                 "-Werror", "-I" + str(repo / "fiber"),
                                 "-DREADINESS_CALLBACK_PADDING_WORDS=" + str(padding)]
                        flags += ["-fno-function-sections" if layout == "lto-unsectioned" else "-ffunction-sections"]
                        if protected:
                            flags += ["-DREADINESS_PROTECTED_HELPER=1"]
                        if layout != "normal":
                            flags += ["-flto", "-fno-fat-lto-objects"]
                        obj = directory / "input.o"
                        command([gcc, *flags, "-c", fixture, "-o", obj], "compile")
                        native = obj
                        if layout != "normal":
                            native = directory / "native.o"
                            command([gcc, *flags, "-nostdlib", "-r", "-flinker-output=nolto-rel",
                                     obj, "-o", native], "native LTO lowering")
                        dis = command([gcc.with_name("arm-none-eabi-objdump.exe"), "-drwC", native], "objdump")
                        (directory / "native.dis").write_text(dis, encoding="ascii")
                        reports = {}
                        for root in ("readiness_indirect_root", "readiness_direct_root"):
                            report = classifier.inspect(native, dis, roots={root}, common=True,
                                                        allowed_cold={"readiness_ordinary_helper"})
                            write(directory / (root + ".json"), report)
                            require("readiness_ordinary_helper" in report["reachable"], "Lost helper edge: " + label)
                            hooks = [d for d in report["defects"] if d["kind"] == "function-hook" and
                                     d["family"] == "instrument" and d["function"] == "readiness_ordinary_helper"]
                            require(not report["defects"] if protected else bool(hooks),
                                    "Wrong exact helper classification: " + label + "/" + root)
                            reports[root] = dict(Defects=len(report["defects"]), HelperHooks=len(hooks))
                        if padding and not protected:
                            classifier.Elf.targets = old_resolver
                            try:
                                missed = classifier.inspect(native, dis, roots={"readiness_indirect_root"}, common=True,
                                                            allowed_cold={"readiness_ordinary_helper"})
                            finally:
                                classifier.Elf.targets = original
                            write(directory / "old-resolver-control.json", missed)
                            require(not missed["defects"] and "readiness_ordinary_helper" not in missed["reachable"],
                                    "Old resolver did not reproduce the specific missing data edge: " + label)
                        cases.append(dict(Name=label, ELF=str(native), SHA256=sha(native), Roots=reports,
                                          OldResolverControl=bool(padding and not protected)))
        after = {str(p): sha(p) for p in inputs}
        require(after == before, "Consumed input drift")
        write(build / "inputs.after.json", after)
        write(build / "results.json", dict(Status="PASS", Cases=cases, Commands=len(commands),
              NativeObjects=len(cases), RootChecks=2 * len(cases), OldResolverControls=6,
              Boundary="Compiled native ELF reachability only, not production-path, CPU execution or global closure"))
        artifacts = {str(p.relative_to(build)): sha(p) for p in build.rglob("*") if p.is_file()}
        write(build / "artifacts.json", artifacts)
        print("PASS sensitive data reachability: 24 native objects, 48 root checks, 6 causal controls; " + str(build))
    except Exception as error:
        write(build / "results.json", dict(Status="FAIL", Cases=cases, Error=str(error), Traceback=traceback.format_exc()))
        raise


if __name__ == "__main__":
    main()
