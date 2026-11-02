"""Additional raw-flag freeze gate, not a replacement for documented counterflags."""
import sys

OPT_ERROR = "Disable PYTHONOPTIMIZE and do not use -O/-OO for sensitive port closure"
if not __debug__ or sys.flags.optimize:
    raise SystemExit(OPT_ERROR)

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time
import traceback

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

FAMILIES = {
    "instrument": ("-finstrument-functions",),
    "ssp": ("-fstack-protector-all",),
    "coverage": ("-fprofile-arcs", "-ftest-coverage"),
    "ubsan": ("-fsanitize=undefined",),
    "tracepc": ("-fsanitize-coverage=trace-pc",),
    "pg": ("-pg",),
}
BUNDLES = dict(FAMILIES, baseline=(), raw=tuple(f for flags in FAMILIES.values() for f in flags))
FORWARD = set("fiber_port_context_init fiber_port_runtime_memory_barrier fiber_port_panic_wait "
              "fiber_port_require_scheduler_configuration_environment fiber_port_runtime_prepare_start "
              "fiber_port_runtime_select_first fiber_port_runtime_start_first fiber_port_runtime_schedule".split())
PUBLIC_HOT = {"fiber_current", "fiber_start", "fiber_schedule"}
COMMON_COLD = {"fiber_init", "fiber_scheduler_set_pick_next", "fiber_internal_scheduler_store_pick_next"}
COMMON_SOURCES = ("fiber_core.c", "fiber_runtime_state.c", "fiber_runtime_context_configuration.c", "fiber_panic.c")
ANNOTATION_REMOVAL = (
    "-DFIBER_API_ATTR_SENSITIVE=FIBER_API_NOINLINE FIBER_API_NOIPA FIBER_API_NOCLONE FIBER_API_NOICF FIBER_API_USED",
    "-DFIBER_API_ATTR_INLINE_SENSITIVE=",
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="ascii")


def family(name):
    if name in ("__cyg_profile_func_enter", "__cyg_profile_func_exit"):
        return "instrument"
    if name in ("__stack_chk_guard", "__stack_chk_fail", "__stack_chk_fail_local"):
        return "ssp"
    if name.startswith(("__gcov", "__llvm_gcov", "__llvm_profile", "__profc_", "__profd_")):
        return "coverage"
    if name.startswith("__ubsan_"):
        return "ubsan"
    if name.startswith("__sanitizer_cov_"):
        return "tracepc"
    if name in ("__gnu_mcount_nc", "mcount", "_mcount", "__fentry__"):
        return "pg"
    return None


def cold_name(name, allowed=COMMON_COLD):
    return any(name == n or name.startswith(n + ".") for n in allowed)


class Elf:
    """Strict ELF32-LE ARM section/symbol/REL parser, without Python packages."""
    def __init__(self, path):
        self.path, self.data = Path(path), Path(path).read_bytes()
        require(self.data[:7] == b"\x7fELF\x01\x01\x01", "Expected ELF32 little-endian: " + str(path))
        h = struct.unpack_from("<16sHHIIIIIHHHHHH", self.data)
        require(h[1] == 1 and h[2] == 40 and h[11] == 40, "Expected native relocatable ARM ELF")
        self.sections = []
        for index in range(h[12]):
            row = struct.unpack_from("<10I", self.data, h[6] + index * h[11])
            self.sections.append(dict(zip(("name", "type", "flags", "address", "offset", "size",
                                           "link", "info", "alignment", "entsize"), row), index=index))
        names = self.payload(self.sections[h[13]])
        for section in self.sections:
            section["name"] = self.string(names, section["name"])
        self.tables, self.symbols = {}, []
        for section in self.sections:
            if section["type"] != 2:
                continue
            require(section["entsize"] == 16, "Unexpected ELF symbol geometry")
            strings = self.payload(self.sections[section["link"]])
            table = []
            for offset in range(section["offset"], section["offset"] + section["size"], 16):
                name, value, size, info, other, target = struct.unpack_from("<IIIBBH", self.data, offset)
                symbol = dict(name=self.string(strings, name), value=value, size=size,
                              type=info & 15, bind=info >> 4, section=target, other=other)
                table.append(symbol)
                self.symbols.append(symbol)
            self.tables[section["index"]] = table
        self.functions = [s for s in self.symbols if s["type"] == 2 and 0 < s["section"] < 0xFF00 and s["size"]]
        self.objects = [s for s in self.symbols if s["type"] == 1 and 0 < s["section"] < 0xFF00 and s["size"]]
        for function in self.functions:
            section = self.sections[function["section"]]
            require(section["flags"] & 4 and (function["value"] & ~1) + function["size"] <= section["size"],
                    "Function extent exceeds its executable section: " + function["name"])
        self.relocations = []
        for section in self.sections:
            require(section["type"] != 4, "Unexpected RELA relocations; parser qualification required")
            if section["type"] != 9:
                continue
            require(section["entsize"] == 8 and section["link"] in self.tables, "Invalid REL geometry")
            for offset in range(section["offset"], section["offset"] + section["size"], 8):
                address, info = struct.unpack_from("<II", self.data, offset)
                symbol = self.tables[section["link"]][info >> 8]
                self.relocations.append(dict(section=section["info"], offset=address,
                                             type=info & 255, symbol=symbol))

    @staticmethod
    def string(data, offset):
        return data[offset:data.index(b"\0", offset)].decode("ascii")

    def payload(self, section):
        if section["type"] == 8:
            return b""
        return self.data[section["offset"]:section["offset"] + section["size"]]

    def functions_at(self, section, offset):
        return [f for f in self.functions if f["section"] == section and
                (f["value"] & ~1) <= offset < (f["value"] & ~1) + f["size"]]

    def objects_at(self, section, offset):
        return [s for s in self.objects if s["section"] == section and
                s["value"] <= offset < s["value"] + s["size"]]

    def targets(self, rel):
        target = rel["symbol"]
        if target["type"] != 3:
            return [target["name"]] if target["name"] else []
        # ABS32 section relocations occur in GCC literal pools, gcov and init arrays.
        # A data addend can select an interior callback field; only functions
        # use Thumb-bit normalization and exact entry-address matching.
        if rel["type"] == 2:
            source = self.sections[rel["section"]]
            value = struct.unpack_from("<I", self.payload(source), rel["offset"])[0]
            return [s["name"] for s in self.symbols if s["name"] and s["type"] in (1, 2)
                    and s["section"] == target["section"] and
                    ((s["type"] == 2 and (s["value"] & ~1) == (value & ~1)) or
                     (s["type"] == 1 and (s["value"] == value or
                                          s["value"] <= value < s["value"] + s["size"])))]
        if rel["type"] in (10, 30, 51, 102):
            source = self.payload(self.sections[rel["section"]])
            if rel["type"] == 102:
                upper = struct.unpack_from("<H", source, rel["offset"])[0]
                value, bits = (upper & 0x7FF) << 1, 12
            else:
                upper, lower = struct.unpack_from("<HH", source, rel["offset"])
                sign = (upper >> 10) & 1
                j1, j2 = (lower >> 13) & 1, (lower >> 11) & 1
                if rel["type"] == 51:
                    value, bits = (sign << 20) | (j2 << 19) | (j1 << 18) | ((upper & 0x3F) << 12) | ((lower & 0x7FF) << 1), 21
                else:
                    value, bits = (sign << 24) | ((1 ^ j1 ^ sign) << 23) | ((1 ^ j2 ^ sign) << 22) | ((upper & 0x3FF) << 12) | ((lower & 0x7FF) << 1), 25
            addend = value - (1 << bits) if value & (1 << (bits - 1)) else value
            return [f["name"] for f in self.functions_at(target["section"], target["value"] + addend + 4)]
        return []

    def native(self):
        require(not any(s["name"].startswith(".gnu.lto_") for s in self.sections),
                "LTO IR is not native lowering: " + str(self.path))
        require(self.functions, "No native function bodies: " + str(self.path))


def inspect(path, disassembly, roots=None, common=False, allowed_cold=COMMON_COLD):
    elf = Elf(path)
    elf.native()
    names = {f["name"] for f in elf.functions}
    undefined = {s["name"] for s in elf.symbols if s["name"] and s["section"] == 0}
    normal_refs = {n: set() for n in names}
    edges, hits, unattributed = {n: set() for n in names}, [], []
    object_names = {s["name"] for s in elf.objects}
    data_refs = {n: set() for n in object_names}
    function_data = {n: set() for n in names}
    for rel in elf.relocations:
        source_section = elf.sections[rel["section"]]
        if not source_section["flags"] & 2:
            continue
        owners = elf.functions_at(rel["section"], rel["offset"])
        targets = elf.targets(rel)
        for owner in elf.objects_at(rel["section"], rel["offset"]):
            data_refs[owner["name"]].update(targets)
        require(not (owners and source_section["flags"] & 4 and rel["symbol"]["type"] == 3 and
                     rel["type"] in (10, 30, 51, 102) and not targets),
                "Unresolved section-relative branch in native function extent")
        for target in targets:
            for owner in owners:
                if target in names:
                    edges[owner["name"]].add(target)
                if target in object_names:
                    function_data[owner["name"]].add(target)
                category = family(target)
                if target in undefined and not category:
                    normal_refs[owner["name"]].add(target)
                if category:
                    hits.append(dict(function=owner["name"], family=category, target=target,
                                     section=source_section["name"], offset=rel["offset"], relocation=rel["type"]))
            if family(target) and not owners and source_section["flags"] & 4:
                unattributed.append(dict(target=target, section=source_section["name"], offset=rel["offset"]))
    # Same-section direct branches may be assembler-resolved without relocations.
    relocated = {(r["section"], r["offset"]) for r in elf.relocations}
    section = None
    for line in disassembly.splitlines():
        header = re.match(r"Disassembly of section (.+):$", line)
        if header:
            found = [s["index"] for s in elf.sections if s["name"] == header[1]]
            require(len(found) == 1, "Ambiguous disassembly section")
            section = found[0]
        instruction = re.match(r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{4}\s+){1,2}\s*(?:blx?|b(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)?(?:\.w|\.n)?)\s+[^<]*<([^>+]+)(?:\+[^>]*)?>", line)
        if (instruction and section is not None and instruction[2] in names and
                (section, int(instruction[1], 16)) not in relocated):
            for owner in elf.functions_at(section, int(instruction[1], 16)):
                if owner["name"] != instruction[2]:
                    edges[owner["name"]].add(instruction[2])
    # A local initialized callback can reach a cold helper without a direct BL.
    # Keep these conservative data paths separate from compiler registration calls.
    data_edges = {n: set() for n in names}
    data_imports = {n: set() for n in names}
    for name, initial in function_data.items():
        pending, seen = list(initial), set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            if target in names:
                data_edges[name].add(target)
            elif target in data_refs:
                pending.extend(data_refs[target])
            elif target in undefined:
                category = family(target)
                if category:
                    hits.append(dict(function=name, family=category, target=target, via_data=True))
                else:
                    data_imports[name].add(target)
    roots = set(names if roots is None else roots)
    require(roots <= names, "Missing exact protected roots: " + repr(sorted(roots - names)))
    reachable, work = set(roots), list(roots)
    while work:
        source = work.pop()
        for target in edges[source] | data_edges[source]:
            if target not in reachable:
                reachable.add(target)
                work.append(target)
    defects = [dict(kind="function-hook", **h) for h in hits if h["function"] in reachable]
    counters = []
    for symbol in elf.symbols:
        if symbol["section"] == 0 or family(symbol["name"]) != "coverage" or symbol["type"] != 1:
            continue
        match = re.match(r"__gcov(?:0\.|_\.)(.+)", symbol["name"])
        owner = match[1] if match else None
        allowed = common and owner is not None and cold_name(owner, allowed_cold) and owner not in reachable
        counters.append(dict(symbol=symbol["name"], owner=owner, allowed_cold=allowed))
        if not allowed:
            defects.append(dict(kind="counter-object", family="coverage", target=symbol["name"], function=owner))
    initializers = [dict(section=s["name"], bytes=s["size"], index=s["index"]) for s in elf.sections
                    if s["size"] and (s["name"].startswith((".init_array", ".fini_array", ".ctors", ".dtors")))]
    if initializers and not common:
        defects += [dict(kind="initializer-section", **s) for s in initializers]
    if initializers and common:
        if not counters or any(not c["allowed_cold"] for c in counters):
            defects += [dict(kind="initializer-with-sensitive-counter", **s) for s in initializers]
        for init in initializers:
            rels = [r for r in elf.relocations if r["section"] == init["index"]]
            targets = [name for r in rels for name in elf.targets(r)]
            expected_prefix = "_sub_I_" if init["section"].startswith(".init_array") else "_sub_D_"
            expected_hook = "__gcov_init" if expected_prefix == "_sub_I_" else "__gcov_exit"
            def registration_ok(name, ancestors):
                if name not in names or not name.startswith(expected_prefix) or name in ancestors:
                    return False
                coverage_calls = {h["target"] for h in hits if h["function"] == name and h["family"] == "coverage" and not h.get("via_data")}
                children = edges.get(name, set())
                # LTO may aggregate multiple registration-only leaf stubs.
                # Raw trace/SSP in this cold chain is allowed. Empty/foreign
                # constructors, other imports and cycles are not registration.
                return (not normal_refs[name] and coverage_calls <= {expected_hook} and
                        bool(coverage_calls or children) and
                        all(registration_ok(child, ancestors | {name}) for child in children))
            registration_valid = all(registration_ok(name, set()) for name in targets)
            if (init["bytes"] % 4 or len(rels) * 4 != init["bytes"] or len(targets) != len(rels)
                    or any(not n.startswith(expected_prefix) for n in targets) or not registration_valid):
                defects.append(dict(kind="unclassified-common-initializer", targets=targets, **init))
    defects += [dict(kind="unattributed-executable-hook", **h) for h in unattributed]
    outside = [h for h in hits if h["function"] not in reachable]
    if common:
        illegal = [h for h in outside if not cold_name(h["function"], allowed_cold) and
                   not h["function"].startswith(("_sub_I_", "_sub_D_"))]
        defects += [dict(kind="unclassified-common-hook", **h) for h in illegal]
    protected_imports = set().union(*(normal_refs[name] | data_imports[name] for name in reachable))
    return dict(path=str(path), functions=sorted(names), roots=sorted(roots), reachable=sorted(reachable),
                edges={k: sorted(v) for k, v in edges.items() if v},
                data_edges={k: sorted(v) for k, v in data_edges.items() if v}, hooks=hits,
                cold_hooks=outside, counters=counters, initializers=initializers,
                undefined=sorted(undefined), protected_normal_imports=sorted(protected_imports),
                defects=defects)


def profiles():
    # Explicit complete groups. In-progress ARM_CM33F Secure companion is not admitted.
    rows = (
        ("C5TF", "ARM_CM55_TFM/non_secure", 55, "ARMV81M_MAINLINE", 0, 0, "cortex-m55", "soft", "", "tfm"),
        ("C3FP", "ARM_CM33F_MPU/non_secure", 33, "ARMV8M_MAINLINE", 1, 1, "cortex-m33", "hard", "fpv5-sp-d16", "fpmpu"),
        ("CM7", "ARM_CM7/r0p1", 7, "ARMV7EM", 0, 1, "cortex-m7", "soft", "", "classic"),
        ("CM0", "ARM_CM0", 0, "ARMV6M", 0, 0, "cortex-m0", "soft", "", "classic"),
        ("CM3", "ARM_CM3", 3, "ARMV7M", 0, 0, "cortex-m3", "soft", "", "classic"),
        ("CM4", "ARM_CM4", 4, "ARMV7EM", 0, 1, "cortex-m4", "hard", "fpv4-sp-d16", "classic"),
        ("CM0MPU", "ARM_CM0_MPU", 0, "ARMV6M", 1, 0, "cortex-m0plus", "soft", "", "mpu"),
        ("CM3MPU", "ARM_CM3_MPU", 3, "ARMV7M", 1, 0, "cortex-m3", "soft", "", "mpu"),
        ("CM4MPU", "ARM_CM4_MPU", 4, "ARMV7EM", 1, 1, "cortex-m4", "hard", "fpv4-sp-d16", "mpu"),
        ("CM23NTZ", "ARM_CM23_NTZ/non_secure", 23, "ARMV8M_BASELINE", 0, 0, "cortex-m23", "soft", "", "ntz"),
        ("CM33NTZ", "ARM_CM33_NTZ/non_secure", 33, "ARMV8M_MAINLINE", 0, 0, "cortex-m33", "soft", "", "ntz"),
        ("CM33FNTZ", "ARM_CM33F_NTZ/non_secure", 33, "ARMV8M_MAINLINE", 0, 1, "cortex-m33", "hard", "fpv5-sp-d16", "ntz"),
        ("CM55NTZ", "ARM_CM55_NTZ/non_secure", 55, "ARMV81M_MAINLINE", 0, 0, "cortex-m55", "soft", "", "ntz"),
        ("CM55FNTZ", "ARM_CM55F_NTZ/non_secure", 55, "ARMV81M_MAINLINE", 0, 1, "cortex-m55+nomve", "hard", "fpv5-d16", "fpsvc"),
        ("CM55MVEFNTZ", "ARM_CM55_MVEF_NTZ/non_secure", 55, "ARMV81M_MAINLINE", 0, 1, "cortex-m55", "hard", "", "fpsvc"),
        ("CM33TFM", "ARM_CM33_TFM/non_secure", 33, "ARMV8M_MAINLINE", 0, 0, "cortex-m33", "soft", "", "tfm"),
        ("CM33FTFM", "ARM_CM33F_TFM/non_secure", 33, "ARMV8M_MAINLINE", 0, 1, "cortex-m33", "hard", "fpv5-sp-d16", "tfm"),
        ("CM33MPU", "ARM_CM33_MPU/non_secure", 33, "ARMV8M_MAINLINE", 1, 0, "cortex-m33", "soft", "", "mpu"),
        ("CM55MPU", "ARM_CM55_MPU/non_secure", 55, "ARMV81M_MAINLINE", 1, 0, "cortex-m55", "soft", "", "mpu"),
        ("CM55FMPU", "ARM_CM55F_MPU/non_secure", 55, "ARMV81M_MAINLINE", 1, 1, "cortex-m55+nomve", "hard", "fpv5-d16", "fpmpu"),
        ("CM55MVEFMPU", "ARM_CM55_MVEF_MPU/non_secure", 55, "ARMV81M_MAINLINE", 1, 1, "cortex-m55", "hard", "", "fpmpu"),
        ("C33S", "ARM_CM33/non_secure", 33, "ARMV8M_MAINLINE", 0, 0, "cortex-m33", "soft", "", "paired"),
        ("C55S", "ARM_CM55/non_secure", 55, "ARMV81M_MAINLINE", 0, 0, "cortex-m55", "soft", "", "paired-staged"),
        ("C3SO", "ARM_CM33_SECURE_ONLY/secure", 33, "ARMV8M_MAINLINE", 0, 0, "cortex-m33", "soft", "", "secure-only"),
        ("C5SO", "ARM_CM55_SECURE_ONLY/secure", 55, "ARMV81M_MAINLINE", 0, 0, "cortex-m55", "soft", "", "secure-only"),
        ("TRANSITIONAL", "transitional_v8m", 33, "ARMV8M_MAINLINE", 0, 0, "cortex-m33", "soft", "", "transitional"),
        ("C33S_GATEWAY", "ARM_CM33/secure", 33, "ARMV8M_MAINLINE", 0, 0, "cortex-m33", "soft", "", "companion"),
        ("C55S_GATEWAY", "ARM_CM55/secure", 55, "ARMV81M_MAINLINE", 0, 0, "cortex-m55", "soft", "", "companion"),
    )
    result = []
    for name, directory, core, arch, mpu, fpu, cpu, abi, fp, kind in rows:
        sources = ["fiber_port.c", "fiber_port_boot.c"]
        if kind == "classic":
            sources += ["fiber_port_exception.c"]
        elif kind == "tfm":
            sources += ["fiber_port_tfm.c", "fiber_port_tfm_os_wrapper.c"]
        elif kind == "fpmpu":
            sources = ["fiber_port_boot.c", "fiber_port_svc.c", "fiber_port_pendsv.c"]
        elif kind == "fpsvc":
            sources += ["fiber_port_svc.c"]
        elif kind in ("paired", "paired-staged"):
            sources += ["fiber_port_secure_context.c", "fiber_port_svc.c"]
            if kind == "paired-staged":
                sources += ["fiber_port_runtime.c", "fiber_port_pendsv.c"]
        elif kind == "transitional":
            sources = ["fiber_port_boot.c", "fiber_port_exception.c", "fiber_port_transitional_v8m.c"]
        elif kind == "companion":
            sources = ["fiber_secure_gateway.c", "fiber_secure_context_gateway.c", "fiber_secure_context_pool.c"]
        region_macro = {"C3FP": "CM33F", "CM33MPU": "CM33", "CM55MPU": "CM55", "CM55FMPU": "CM55F",
                        "CM55MVEFMPU": "CM55_MVEF", "CM4MPU": "CM4"}.get(name)
        result.append(dict(name=name, directory=directory, core=core, architecture=arch,
                           mpu=mpu, fpu=fpu, cpu=cpu, abi=abi, fp=fp, kind=kind,
                           sources=sorted(sources), defines=(["FIBER_PORT_" + region_macro + "_MPU_TOTAL_REGIONS=8"] if region_macro else [])))
        if kind == "companion":
            result[-1]["defines"] += ["FIBER_ARM_CM%d_SECURE_CONTEXT_MAX_COUNT=3" % core,
                                      "FIBER_ARM_CM%d_SECURE_CONTEXT_MAX_STACK_BYTES=1024" % core]
    return result


class Audit:
    def __init__(self, args):
        self.a, self.repo, self.build = args, Path(args.repo).resolve(), Path(args.build).resolve()
        self.fixture = Path(__file__).resolve().parent
        self.gcc = Path(args.arm_gcc).resolve()
        self.tools = {n: self.gcc.with_name("arm-none-eabi-" + n + ".exe") for n in ("objdump", "readelf", "gcc-nm")}
        self.commands, self.inputs, self.cases, self.controls, self.errors = [], {}, [], [], []
        self.baselines = {}
        self.preflight_checks = 0
        self.input_copies = {}
        self.planned_cells = 0
        self.snapshot = None

    def track(self, path):
        path = Path(path).resolve()
        require(path.is_file(), "Missing proof input: " + str(path))
        value = digest(path)
        previous = self.inputs.setdefault(str(path), value)
        require(previous == value, "Input changed during proof: " + str(path))
        if path.suffix.lower() in (".c", ".h", ".s", ".ld", ".inc", ".py", ".ps1", ".md") and str(path) not in self.input_copies:
            target = self.build / "input-bytes" / (value + path.suffix.lower())
            target.parent.mkdir(exist_ok=True)
            data = path.read_bytes()
            require(hashlib.sha256(data).hexdigest().upper() == value, "Source changed during byte capture")
            target.write_bytes(data)
            self.input_copies[str(path)] = str(target)

    def run(self, argv, label, timeout=120):
        argv = [str(a) for a in argv]
        require(not any(a.startswith("-fno-") and a != "-fno-function-sections" for a in argv),
                "Excluded compiler counterflag in proof command")
        start = time.monotonic()
        result = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout, cwd=self.build)
        row = dict(label=label, command=argv, exit=result.returncode, stdout=result.stdout,
                   stderr=result.stderr, seconds=round(time.monotonic() - start, 3))
        index = len(self.commands)
        write_json(self.build / ("command-%05d.json" % index), row)
        self.commands.append(row)
        require(result.returncode == 0, "Command failed: %s (command-%05d.json)\n%s" % (label, index, result.stderr[-2500:]))
        return result.stdout

    def flags(self, p, opt, lto, bundle):
        result = ["-mcpu=" + p["cpu"], "-mthumb", "-mfloat-abi=" + p["abi"], "-" + opt,
                  "-std=gnu11", "-ffreestanding", "-ffunction-sections", "-fdata-sections", "-g",
                  "-Wall", "-Wextra", "-Werror=implicit-function-declaration", "-Werror=attributes", "-Werror=ignored-attributes"]
        if p["fp"]:
            result += ["-mfpu=" + p["fp"]]
        if p["kind"] in ("secure-only", "companion"):
            result += ["-mcmse"]
        result += ["-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_" + p["architecture"] + "=1",
                   "-DCLOSURE_CORE=" + str(p["core"]), "-DCLOSURE_MPU=" + str(p["mpu"]),
                   "-DCLOSURE_FPU=" + str(p["fpu"]), "-DCLOSURE_VTOR=" + str(p.get("vtor", int(p["core"] != 0)))]
        result += ["-D" + d for d in p["defines"]]
        if lto:
            result += ["-flto"]
        result += list(BUNDLES[bundle])
        directory = self.repo / "fiber/port" / p["directory"]
        if p["name"] == "CM7" and self.a.cm7_prefix_root:
            result += ["-I" + str(Path(self.a.cm7_prefix_root).resolve())]
        for path in (self.fixture, directory, self.repo / "fiber/port", self.repo / "fiber", self.repo, Path(self.a.cmsis_core)):
            result += ["-I" + str(path)]
        return result + ["-include", self.fixture / "main.h"]

    def source_paths(self, p):
        directory = self.repo / "fiber/port" / p["directory"]
        if p["name"] == "CM7" and self.a.cm7_prefix_root:
            directory = Path(self.a.cm7_prefix_root).resolve()
        actual = sorted(f.name for f in directory.glob("*.c"))
        require(actual == p["sources"], "Exact port C inventory changed: " + p["name"] + repr(actual))
        if p["kind"] == "companion":
            return [directory / n for n in p["sources"]], []
        common = [self.repo / "fiber" / n for n in COMMON_SOURCES]
        # C55S has a private staged cohort, not the complete generic storage ABI.
        if p["kind"] != "paired-staged":
            common += [self.repo / "fiber/port/fiber_port_context_cohort_expectation.c"]
        return [directory / n for n in p["sources"]], common

    def dependencies(self, source, flags, target):
        dep = target.with_suffix(".dependencies")
        self.run([self.gcc, *flags, "-M", "-MT", "closure", "-MF", dep, source], "dependencies " + str(source))
        text = dep.read_text().replace("\\\n", " ")
        require(text.startswith("closure:"), "Unexpected make dependency target")
        paths = re.split(r"(?<!\\)\s+", text[len("closure:"):].strip())
        for path in paths:
            self.track(path.replace("\\ ", " ").replace("\\#", "#"))

    def compile(self, source, target, flags, extra=()):
        self.dependencies(source, [*flags, *extra], target)
        try:
            self.run([self.gcc, *flags, *extra, "-c", source, "-o", target], "compile " + str(target))
        except RuntimeError:
            diagnostic = self.commands[-1]["stderr"]
            if "Assembler messages:" in diagnostic:
                reproduction = target.parent / (target.stem + "-failed-assembly")
                reproduction.mkdir()
                try:
                    self.run([self.gcc, *flags, *extra, "-save-temps=obj", "-c", source, "-o", reproduction / target.name],
                             "capture failed assembly " + str(target))
                except RuntimeError:
                    pass
            raise
        if "-flto" in flags:
            elf = Elf(target)
            require(any(s["name"].startswith(".gnu.lto_") for s in elf.sections) and
                    not any(s["flags"] & 4 and s["size"] for s in elf.sections),
                    "LTO input must contain slim IR and no executable fat-object fallback")
        return target

    def lower(self, p, objects, target, flags, lto, section_mode="sectioned"):
        # Arcs/counters already exist in each TU's native body or slim LTO IR.
        # Repeating these two driver options adds libgcov even for -nostdlib -r.
        # All late instrumentation options remain enabled. The lowered active
        # control must still exhibit every requested family, including gcov.
        lowering = [f for f in flags if f not in FAMILIES["coverage"]]
        if lto and section_mode == "unsectioned":
            lowering = [f for f in lowering if f != "-ffunction-sections"] + ["-fno-function-sections"]
        self.run([self.gcc, *lowering, "-nostdlib", "-r", *(["-save-temps=obj"] if lto else []),
                  *(["-flinker-output=nolto-rel"] if lto else []), *objects, "-o", target], "native group " + str(target))
        elf = Elf(target)
        elf.native()
        dis = self.run([self.tools["objdump"], "-drwC", target], "native disassembly " + str(target))
        target.with_suffix(".dis").write_text(dis, encoding="ascii")
        attrs = self.run([self.tools["readelf"], "-A", target], "native CPU attributes " + str(target))
        target.with_suffix(".attributes").write_text(attrs, encoding="ascii")
        architecture = {"ARMV6M": "v6S-M", "ARMV7M": "v7", "ARMV7EM": "v7E-M",
                        "ARMV8M_BASELINE": "v8-M.baseline", "ARMV8M_MAINLINE": "v8-M.mainline",
                        "ARMV81M_MAINLINE": "v8.1-M.mainline"}[p["architecture"]]
        require(re.search(r"Tag_CPU_arch: " + re.escape(architecture) + r"\s*$", attrs, re.M),
                "Wrong actual ARM architecture target")
        return dis

    def preflight(self):
        if self.a.input_snapshot:
            self.track(self.a.input_snapshot)
            self.snapshot = json.loads(Path(self.a.input_snapshot).read_text(encoding="ascii"))
            require(all(Path(row["copy"]).is_file() and digest(row["copy"]) == row["sha256"]
                        for row in self.snapshot["files"]), "Immutable input copy differs from its construction manifest")
        for path in (self.gcc, *self.tools.values(), *self.fixture.glob("*"), self.fixture.parents[1] / "test_sensitive_port_closure.ps1"):
            if path.is_file():
                self.track(path)
        for program in ("cc1", "lto1", "lto-wrapper", "as", "ld", "liblto_plugin.dll"):
            located = self.run([self.gcc, "-print-prog-name=" + program], "locate compiler tool " + program).strip()
            path = Path(located)
            if not path.is_file():
                located = self.run([self.gcc, "-print-file-name=" + program], "locate compiler file " + program).strip()
                path = Path(located)
            require(path.is_file(), "Could not hash compiler tool " + program + ": " + located)
            self.track(path)
        for flag in ("-O", "-OO"):
            for code in (None,
                         "import runpy; runpy.run_path(%r,run_name='import_fixture')" % str(Path(__file__).resolve()),
                         "import importlib.util; s=importlib.util.spec_from_file_location('closure',%r); "
                         "m=importlib.util.module_from_spec(s); s.loader.exec_module(m)" % str(Path(__file__).resolve())):
                args = [sys.executable, flag, "-B", __file__] if code is None else [sys.executable, flag, "-B", "-c", code]
                result = subprocess.run(args, capture_output=True, text=True, timeout=20)
                require(result.returncode == 1 and result.stdout == "" and result.stderr.splitlines() == [OPT_ERROR],
                        "Optimized direct/import guard did not fail exactly")
                self.preflight_checks += 1
        fake = subprocess.run([sys.executable, "-c", "raise RuntimeError(%r)" % OPT_ERROR], capture_output=True, text=True)
        require(not (fake.returncode == 1 and fake.stdout == "" and fake.stderr.splitlines() == [OPT_ERROR]),
                "Counterfeit exception diagnostic accepted")
        require(family("__cyg_profile_func_enter_fake") is None and family("__stack_chk_fail_fake") is None,
                "Hook classifier accepts similar but distinct symbols")
        self.preflight_checks += 2

    def literal_range_failure(self, target, thumb1=False):
        command = self.commands[-1]
        stderr = command["stderr"]
        diagnostics = re.findall(r"^(.+\.s):(\d+): Error: (.+)$", stderr, re.M)
        message_pattern = r"offset out of range|invalid offset, value too big \(0x[0-9A-Fa-f]+\)" if thumb1 else r"offset out of range"
        require(command["exit"] != 0 and diagnostics and
                all(re.fullmatch(message_pattern, message) for _, _, message in diagnostics),
                "Pool control did not fail with exact literal-range diagnostics")
        for line in stderr.splitlines():
            if re.search(r"\b(?:fatal error|error|Error):", line):
                require(re.match(r"^.+\.s:\d+: Error: (?:" + message_pattern + r")$", line) or
                        re.match(r"^lto-wrapper\.exe: fatal error: .+ returned 1 exit status$", line) or
                        line.endswith(": error: lto-wrapper failed") or
                        line == "collect2.exe: error: ld returned 1 exit status",
                        "Unrelated compiler/linker failure in pool control: " + line)
        evidence = []
        for filename, lineno, _ in diagnostics:
            assembly = Path(filename)
            require(assembly.parent == target.parent and assembly.name.startswith(target.name + ".ltrans") and
                    assembly.is_file(), "Pool diagnostic lacks its exact saved native LTO assembly")
            lines = assembly.read_text(encoding="ascii").splitlines()
            index = int(lineno) - 1
            require(0 <= index < len(lines) and
                    re.match(r"\s*ldr(?:\.[wn])?\s+r(?:[0-9]|1[0-5])\s*,\s*=\S", lines[index]),
                    "Pool range diagnostic does not identify an actual literal-load instruction")
            evidence.append(dict(assembly=str(assembly), line=int(lineno), instruction=lines[index].strip()))
        return dict(command="command-%05d.json" % (len(self.commands) - 1), diagnostics=evidence)

    def classic_pool_controls(self, p, directory, flags, port_objects, port_sources):
        source = next(s for s in port_sources if s.name == "fiber_port.c")
        port_name = p["name"]
        pool_count = 4 if port_name == "CM0MPU" else 3
        preprocessed = self.run([self.gcc, *flags, "-E", source], "actual " + port_name + " pool-control preprocessing")
        pool = re.compile(r'"\.ltorg[^"\r\n]*"')
        require(len(pool.findall(preprocessed)) == pool_count, "Actual " + port_name + " terminal-pool inventory changed")
        natural, count = pool.subn('""', preprocessed)
        require(count == pool_count, "Natural pool-removal inventory changed")
        pressured, count = pool.subn(lambda match: match[0] + ' ".space 8192\\n"', preprocessed)
        require(count == pool_count, "Pressure-positive inventory changed")
        pressured_bad, count = pool.subn('""', pressured)
        require(count == pool_count and pressured_bad.count('".space 8192\\n"') == pool_count,
                "Pressure-negative must change only the actual pool directives")
        index = next(i for i, s in enumerate(port_sources) if s == source)
        outcomes = {}
        for name, text, must_fail in (("natural-pool-removal", natural, False),
                                      ("pressure-pools-retained", pressured, False),
                                      ("pressure-pools-removed", pressured_bad, True)):
            case = directory / name
            case.mkdir()
            mutant = case / ("actual-" + port_name.lower() + ".i")
            mutant.write_text(text, encoding="ascii")
            obj = case / "actual-port.o"
            self.run([self.gcc, *flags, "-c", mutant, "-o", obj], "compile actual pool control " + name)
            elf = Elf(obj)
            require(any(s["name"].startswith(".gnu.lto_") for s in elf.sections) and
                    not any(s["flags"] & 4 and s["size"] for s in elf.sections),
                    "CM3 control must use actual slim IR, not native fallback")
            objects = list(port_objects)
            objects[index] = obj
            target = case / "port-native.o"
            try:
                self.lower(p, objects, target, flags, True, "unsectioned")
            except RuntimeError:
                require(must_fail or name == "natural-pool-removal", "Pressure-positive failed to assemble")
                outcomes[name] = dict(status="literal-range-failure", **self.literal_range_failure(target, p["core"] == 0))
            else:
                require(not must_fail, "Pressure pool-removal control unexpectedly assembled")
                outcomes[name] = dict(status="PASS", native_sha256=digest(target))
        row = dict(case=directory.name, kind="actual-" + p["name"].lower() + "-matched-unreachable-pool-pressure", source=str(source),
                   source_sha256=digest(source), pressure_bytes_per_naked_tail=8192,
                   semantics="Synthetic unreachable layout pressure only; natural pool removal is not required to fail",
                   outcomes=outcomes)
        write_json(directory / (p["name"].lower() + "-pool-controls.json"), row)
        self.controls.append(row)

    def case(self, p, opt, lto, bundle, section_mode="sectioned"):
        profile_label = p["name"] + ("-vtor1" if p["core"] == 0 and p.get("vtor") == 1 else "")
        label = "%s-%s-%s-%s" % (profile_label, opt, "native-lto-" + section_mode if lto else "normal", bundle)
        directory = self.build / label
        directory.mkdir()
        flags = self.flags(p, opt, lto, bundle)
        port_sources, common_sources = self.source_paths(p)
        port_objects = [self.compile(s, directory / ("port-" + s.stem + ".o"), flags) for s in port_sources]
        common_objects = [self.compile(s, directory / ("common-" + s.stem + ".o"), flags) for s in common_sources]
        groups = {}
        selections = [("port", port_objects)]
        if common_objects:
            selections += [("common", common_objects), ("whole", port_objects + common_objects)]
        for group, objects in selections:
            target = directory / (group + "-native.o")
            dis = self.lower(p, objects, target, flags, lto, section_mode)
            if group == "port":
                roots, common = None, False
            elif group == "common":
                roots, common = PUBLIC_HOT | {"fiber_panic", "fiber_internal_task_return"}, True
            else:
                common = True
                # No guessed namespace exemption for CMSIS/local helpers after LTO.
                present = {f["name"] for f in Elf(target).functions}
                roots = {n for n in present if not cold_name(n) and not n.startswith(("_sub_I_", "_sub_D_"))}
            groups[group] = inspect(target, dis, roots, common)
            if group == "port" and p["kind"] not in ("companion", "paired-staged"):
                require(FORWARD <= set(groups[group]["functions"]), "Actual forward ABI functions missing")
            write_json(directory / (group + "-classification.json"), groups[group])
        if p["name"] in ("CM0", "CM0MPU", "CM3") and opt == "O2" and lto and section_mode == "unsectioned" and bundle == "baseline":
            self.classic_pool_controls(p, directory, flags, port_objects, port_sources)
        expected = set(FAMILIES) if bundle == "raw" else {bundle} if bundle in FAMILIES else set()
        active = self.compile(self.fixture / "active_control.c", directory / "active.o", flags)
        dis = self.lower(p, [active], directory / "active-native.o", flags, lto, section_mode)
        control_cold = {"closure_unannotated_control"}
        control = inspect(directory / "active-native.o", dis, {"closure_sensitive_control"}, True, control_cold)
        observed = {h["family"] for h in control["hooks"] if h["function"] == "closure_unannotated_control"}
        require(expected <= observed, "Raw flags inactive on compiled unannotated control: " + repr(sorted(expected - observed)))
        if expected:
            require(any(d.get("function") == "closure_unannotated_control" and d.get("family") in expected
                        for d in control["defects"]), "Transitive classifier missed actual helper")
        require(not any(h["function"] == "closure_sensitive_control" for h in control["hooks"]),
                "Canonical sensitive control itself acquired hooks")
        indirect = inspect(directory / "active-native.o", dis, {"closure_indirect_control"}, True, control_cold)
        require("closure_unannotated_control" in indirect["data_edges"].get("closure_indirect_control", []) and
                "closure_unannotated_control" not in indirect["edges"].get("closure_indirect_control", []),
                "Compiled callback control did not retain its initialized data-pointer path")
        if expected:
            require(any(d.get("function") == "closure_unannotated_control" and d.get("family") in expected
                        for d in indirect["defects"]), "Transitive classifier missed initialized callback helper")
        require(not any(h["function"] == "closure_indirect_control" for h in indirect["hooks"]),
                "Canonical indirect control itself acquired hooks")
        write_json(directory / "direct-control-classification.json", control)
        write_json(directory / "indirect-control-classification.json", indirect)
        isolated = inspect(directory / "active-native.o", dis, {"closure_isolated_control"}, True, control_cold)
        require(not isolated["defects"] and isolated["reachable"] == ["closure_isolated_control"],
                "Isolated cold/startup closure control failed: " + json.dumps(isolated["defects"]))
        self.controls.append(dict(case=label, kind="active-unannotated-and-transitive", expected=sorted(expected), observed=sorted(observed)))
        self.controls.append(dict(case=label, kind="initialized-local-callback-transitive", expected=sorted(expected)))
        self.controls.append(dict(case=label, kind="isolated-cold-hooks-and-unresolved-branch", expected_defects=0))
        if bundle == "baseline":
            initializer = self.compile(self.fixture / "initializer_control.c", directory / "initializer-control.o", flags)
            dis = self.lower(p, [initializer], directory / "initializer-control-native.o", flags, lto, section_mode)
            bad_init = inspect(directory / "initializer-control-native.o", dis, {"closure_initializer_root"}, True)
            require(any(d["kind"] == "unclassified-common-initializer" and
                        d.get("targets") == ["closure_illegal_initializer"] for d in bad_init["defects"]),
                    "Unknown initializer inherited cold common registration allowance")
            self.controls.append(dict(case=label, kind="compiled-unknown-initializer", expected="unclassified-common-initializer"))
        if bundle == "raw":
            fake = self.compile(self.fixture / "initializer_control.c", directory / "fake-registration.o", flags,
                                ["-DCLOSURE_COUNTERFEIT_REGISTRATION=1"])
            dis = self.lower(p, [active, fake], directory / "fake-registration-native.o", flags, lto, section_mode)
            counterfeit = inspect(directory / "fake-registration-native.o", dis, {"closure_isolated_control"}, True, control_cold)
            require(any(d["kind"] == "unclassified-common-initializer" and
                        "_sub_I_closure_counterfeit" in d.get("targets", []) for d in counterfeit["defects"]),
                    "Counterfeit gcov-shaped initializer inherited cold registration allowance")
            self.controls.append(dict(case=label, kind="compiled-counterfeit-registration", expected="unclassified-common-initializer"))
        if bundle == "raw":
            mutation_source = (next(s for s in port_sources if s.name == "fiber_secure_context_pool.c")
                               if p["kind"] == "companion" else self.repo / "fiber/fiber_core.c")
            mutation_root = "fiber_secure_context_pool_boot_initialize" if p["kind"] == "companion" else "fiber_current"
            mutant = self.compile(mutation_source, directory / "removed-annotations.o", flags, ANNOTATION_REMOVAL)
            dis = self.lower(p, [mutant], directory / "removed-annotations-native.o", flags, lto, section_mode)
            mutation = inspect(directory / "removed-annotations-native.o", dis, {mutation_root}, True)
            removal_families = {h["family"] for h in mutation["hooks"] if h["function"] == mutation_root}
            needed = set(FAMILIES) - {"ubsan"} if p["kind"] != "companion" else {"instrument"}
            require(needed <= removal_families,
                    "Actual annotation-removal control missed hooks at " + mutation_root + ": " + repr(needed - removal_families))
            write_json(directory / "annotation-removal-classification.json", mutation)
            self.controls.append(dict(case=label, kind="actual-canonical-bundle-removal", function=mutation_root,
                                      expected=sorted(needed), observed=sorted(removal_families)))
            if p["kind"] != "companion":
                boot_source = next(s for s in port_sources if s.name == "fiber_port_boot.c")
                mutant_boot = self.compile(boot_source, directory / "removed-port-annotations.o", flags, ANNOTATION_REMOVAL)
                dis = self.lower(p, [mutant_boot], directory / "removed-port-annotations-native.o", flags, lto, section_mode)
                boot_mutation = inspect(directory / "removed-port-annotations-native.o", dis)
                require(any(h["family"] == "ubsan" for h in boot_mutation["hooks"]),
                        "Actual port annotation-removal control did not expose UBSan")
                require(any(h["family"] == "instrument" and h["function"] == "fiber_port_context_init"
                            for h in boot_mutation["hooks"]), "Actual port constructor annotation-removal did not expose exact entry instrumentation")
                write_json(directory / "port-annotation-removal-classification.json", boot_mutation)
                self.controls.append(dict(case=label, kind="actual-port-bundle-removal", expected=["instrument", "ubsan"],
                                          observed=sorted({h["family"] for h in boot_mutation["hooks"]})))
            # At O0, GCC can reject this deliberately mixed inline policy before lowering.
            # O2/Os require a compiled instrumentation leak, never an arbitrary build failure.
            if p["name"] in ("CM0", "CM0MPU", "CM3", "CM3MPU") and opt in ("O2", "Os"):
                copied = directory / "inline-bundle-removal"
                copied.mkdir()
                port_directory = port_sources[0].parent
                header = port_directory / "fiber_portmacro.h"
                original_header = header.read_bytes()
                removed_header, removed = re.subn(rb"\bFIBER_API_ATTR_INLINE_SENSITIVE\b", b"", original_header)
                require(removed > 0 and removed_header.count(b"FIBER_GENERAL_REGS_ONLY") ==
                        original_header.count(b"FIBER_GENERAL_REGS_ONLY") and
                        removed_header.count(b"FIBER_API_ATTR_SENSITIVE") == original_header.count(b"FIBER_API_ATTR_SENSITIVE"),
                        "Inline-only annotation control must retain GRO and every non-inline annotation")
                for source in port_directory.iterdir():
                    if source.is_file() and source.suffix in (".c", ".h"):
                        (copied / source.name).write_bytes(removed_header if source == header else source.read_bytes())
                mutated_objects = [self.compile(copied / source.name, copied / (source.stem + ".o"), flags)
                                   for source in port_sources]
                target = copied / "port-native.o"
                dis = self.lower(p, mutated_objects, target, flags, lto, section_mode)
                result = inspect(target, dis)
                require(any(d["kind"] == "function-hook" and d["family"] == "instrument" for d in result["defects"]),
                        "Actual inline-only annotation removal did not expose transitive function instrumentation")
                write_json(copied / "classification.json", result)
                self.controls.append(dict(case=label, kind="actual-inline-bundle-only-removal", annotations_removed=removed,
                                          source_header=str(header), source_header_sha256=digest(header),
                                          mutant_header_sha256=digest(copied / header.name),
                                          expected="function-hook:instrument", gro_retained=True))
        baseline_key = (p["name"], p.get("vtor"), opt, lto, section_mode)
        if bundle == "baseline":
            self.baselines[baseline_key] = {name: result["protected_normal_imports"] for name, result in groups.items()}
        else:
            require(baseline_key in self.baselines, "Exact baseline imports not qualified before raw flags")
            for group, result in groups.items():
                expected_imports = self.baselines[baseline_key][group]
                if result["protected_normal_imports"] != expected_imports:
                    result["defects"].append(dict(kind="normal-import-drift", expected=expected_imports,
                                                  actual=result["protected_normal_imports"]))
        defects = [dict(group=group, **defect) for group, result in groups.items() for defect in result["defects"]]
        for group, classification in groups.items():
            write_json(directory / (group + "-classification.json"), classification)
        row = dict(name=label, profile=p, optimization=opt, native_lto=lto, native_lto_sections=section_mode, bundle=bundle,
                   status="FAIL" if defects else "PASS", defects=defects,
                   raw_flags=list(BUNDLES[bundle]), common_cold_hooks=groups.get("common", {}).get("cold_hooks", []),
                   classifications={g: str(directory / (g + "-classification.json")) for g in groups})
        self.cases.append(row)
        print("%s %s defects=%d" % (row["status"], label, len(defects)), flush=True)

    def finish(self, complete):
        after = {p: digest(p) if Path(p).is_file() else None for p in self.inputs}
        drift = [p for p, value in self.inputs.items() if after[p] != value]
        snapshot_drift = ([row["copy"] for row in self.snapshot["files"]
                           if not Path(row["copy"]).is_file() or digest(row["copy"]) != row["sha256"]]
                          if self.snapshot else [])
        unqualified = [e for e in self.errors if "profile" in e]
        attempted = len(self.cases) + len(unqualified)
        if complete and attempted != self.planned_cells:
            self.errors.append(dict(error="Requested cell inventory did not finish exactly", planned=self.planned_cells, attempted=attempted))
        report = dict(Status="FAIL" if self.errors or drift or snapshot_drift or any(c["status"] == "FAIL" for c in self.cases) else "PASS",
                      CompleteSuite=complete, Scope="Additional raw-flag software-freeze gate for native source groups; does not replace documented mandatory counterflags; no runtime or architecture execution claim",
                      ExternalMemoryPolicy="memcpy/memset are normal imports, not forbidden compiler hooks. External implementations and other integration callbacks require separate complete GRO/transitive qualification; their bodies are not supplied or qualified by this object gate.",
                      AuditOnly=bool(self.a.audit_only), HistoricalCm7Prefix=self.a.cm7_prefix_root,
                      Cases=self.cases, Controls=self.controls, Errors=self.errors, PreflightChecks=self.preflight_checks,
                      CellCounts=dict(planned=self.planned_cells, attempted=attempted, completed=len(self.cases),
                                      passed=sum(c["status"] == "PASS" for c in self.cases),
                                      failed=sum(c["status"] == "FAIL" for c in self.cases), unqualified=len(unqualified)),
                      UnqualifiedCells=unqualified,
                      InputDrift=drift, Inputs=[dict(path=p, before_sha256=h, after_sha256=after[p],
                                                   captured_bytes=self.input_copies.get(p)) for p, h in sorted(self.inputs.items())],
                      InputSnapshot=(dict(manifest=self.a.input_snapshot, files=len(self.snapshot["files"]),
                                          copy_drift=snapshot_drift,
                                          policy="Copied repository/CMSIS inputs only; later changes to original files are not qualification inputs")
                                     if self.snapshot else None),
                      Commands=len(self.commands), Python=sys.executable, PythonVersion=sys.version,
                      Requested=dict(profiles=self.a.profiles, optimizations=self.a.optimizations, bundles=self.a.bundles,
                                     native_lto_sections=self.a.native_lto_sections, cm0_vtor=self.a.cm0_vtor,
                                     all_profiles=self.a.all_profiles),
                      Inventory=profiles(), Excluded=[dict(directory="ARM_CM33F", reason="Incomplete in-progress Secure FP source group; not silently admitted")])
        if not complete:
            report["Status"] = "FAIL"
        write_json(self.build / "results.json", report)
        with (self.build / "sha256.csv").open("w", newline="", encoding="ascii") as stream:
            writer = csv.writer(stream)
            writer.writerow(("path", "sha256"))
            for path in sorted(self.build.rglob("*")):
                if path.is_file() and path.name != "sha256.csv":
                    writer.writerow((str(path.relative_to(self.build)), digest(path)))
        print("%s cases=%d controls=%d errors=%d drift=%d receipt=%s" %
              (report["Status"], len(self.cases), len(self.controls), len(self.errors), len(drift), self.build / "results.json"), flush=True)
        return 0 if report["Status"] == "PASS" or self.a.audit_only else 1


def run_immutable(args):
    repo, cmsis, build = (Path(value).resolve() for value in (args.repo, args.cmsis_core, args.build))
    root = build / "immutable-inputs"
    root.mkdir()
    requested = set(args.profiles.split(","))
    registry = profiles()
    require(args.all_profiles or requested <= {p["name"] for p in registry}, "Unknown snapshot profile")
    selected = [p for p in registry if args.all_profiles or p["name"] in requested]
    fixture = Path(__file__).resolve().parent
    require(fixture.is_relative_to(repo), "Runner must belong to the requested repository snapshot")
    suffixes = {".c", ".h", ".s", ".inc", ".ld"}

    def inventory():
        files = {p.resolve() for directory in (repo, repo / "fiber", repo / "fiber/port")
                 for p in directory.iterdir() if p.is_file() and p.suffix.lower() in suffixes}
        for name in {Path(p["directory"]).parts[0] for p in selected}:
            files.update(p.resolve() for p in (repo / "fiber/port" / name).rglob("*")
                         if p.is_file() and p.suffix.lower() in suffixes)
        files.update(p.resolve() for p in fixture.rglob("*")
                     if p.is_file() and p.suffix.lower() in suffixes | {".py", ".ps1", ".md"})
        files.add(repo / "tools/test_sensitive_port_closure.ps1")
        files.update(p.resolve() for p in cmsis.rglob("*") if p.is_file())
        if args.cm7_prefix_root:
            files.update(p.resolve() for p in Path(args.cm7_prefix_root).resolve().rglob("*")
                         if p.is_file() and p.suffix.lower() in suffixes)
        return files

    files = inventory()
    before = {path: digest(path) for path in files}
    rows = []
    for path in sorted(files):
        if path.is_relative_to(cmsis):
            target = root / "cmsis" / path.relative_to(cmsis)
        elif path.is_relative_to(repo):
            target = root / "repo" / path.relative_to(repo)
        else:
            require(args.cm7_prefix_root and path.is_relative_to(Path(args.cm7_prefix_root).resolve()),
                    "Unexpected snapshot input outside source roots")
            target = root / "cm7-prefix" / path.relative_to(Path(args.cm7_prefix_root).resolve())
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        require(digest(target) == before[path], "Source changed while copying immutable input: " + str(path))
        rows.append(dict(original=str(path), copy=str(target), sha256=before[path]))
    require(inventory() == files and all(digest(path) == value for path, value in before.items()),
            "Source inventory/bytes changed while constructing immutable inputs")
    manifest = root / "manifest.json"
    write_json(manifest, dict(files=rows, profiles=[p["name"] for p in selected],
                             policy="Source inventory and bytes verified before child; copied-but-unconsumed files are not claimed executed or compiled"))
    command = [sys.executable, "-B", root / "repo" / fixture.relative_to(repo) / "run.py",
               "--repo", root / "repo", "--arm-gcc", args.arm_gcc, "--cmsis-core", root / "cmsis",
               "--build", build, "--profiles", args.profiles, "--optimizations", args.optimizations,
               "--bundles", args.bundles, "--native-lto-sections", args.native_lto_sections,
               "--cm0-vtor", args.cm0_vtor,
               "--input-snapshot", manifest]
    if args.all_profiles:
        command += ["--all-profiles"]
    if args.audit_only:
        command += ["--audit-only"]
    if args.cm7_prefix_root:
        command += ["--cm7-prefix-root", root / "cm7-prefix"]
    command = [str(value) for value in command]
    write_json(root / "child-command.json", command)
    print("Verified immutable compiler closure inputs: " + str(root), flush=True)
    return subprocess.run(command).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("repo", "arm-gcc", "cmsis-core", "build"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--profiles", default="C5TF,C3FP,CM7")
    parser.add_argument("--optimizations", default="O2,Os")
    parser.add_argument("--bundles", default="baseline,raw")
    parser.add_argument("--native-lto-sections", default="sectioned,unsectioned")
    parser.add_argument("--cm0-vtor", default="0")
    parser.add_argument("--all-profiles", action="store_true")
    parser.add_argument("--audit-only", action="store_true")
    parser.add_argument("--cm7-prefix-root")
    parser.add_argument("--immutable-inputs", action="store_true")
    parser.add_argument("--input-snapshot", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.immutable_inputs:
        try:
            return run_immutable(args)
        except Exception as error:
            receipt = Path(args.build) / "results.json"
            write_json(receipt, dict(Status="FAIL", CompleteSuite=False, Errors=[dict(error=str(error), traceback=traceback.format_exc())]))
            print("FAIL immutable source construction: " + str(receipt), flush=True)
            return 1
    audit = Audit(args)
    complete = False
    try:
        audit.preflight()
        registry = profiles()
        requested = set(args.profiles.split(","))
        require(args.all_profiles or requested <= {p["name"] for p in registry}, "Unknown selected profile")
        opts, bundles = args.optimizations.split(","), args.bundles.split(",")
        require(set(opts) <= {"O0", "Og", "O2", "Os", "O3"} and len(set(opts)) == len(opts), "Invalid optimization inventory")
        require(set(bundles) <= set(BUNDLES) and len(set(bundles)) == len(bundles), "Invalid compiler bundle inventory")
        bundles = ["baseline"] + [b for b in bundles if b != "baseline"]
        sections = args.native_lto_sections.split(",")
        require(set(sections) <= {"sectioned", "unsectioned"} and len(set(sections)) == len(sections), "Invalid native section inventory")
        vtor = args.cm0_vtor.split(",")
        require(set(vtor) <= {"0", "1"} and len(set(vtor)) == len(vtor), "Invalid CM0 VTOR inventory")
        admitted = []
        for entry in registry:
            if args.all_profiles or entry["name"] in requested:
                for value in vtor if entry["core"] == 0 else ["1"]:
                    profile = dict(entry, vtor=int(value))
                    if entry["name"] == "CM0" and value == "1":
                        profile["cpu"] = "cortex-m0plus"
                    admitted.append(profile)
        audit.planned_cells = len(admitted) * len(opts) * (1 + len(sections)) * len(bundles)
        for profile in admitted:
            for opt in opts:
                for lto, section in [(False, "sectioned")] + [(True, s) for s in sections]:
                    for bundle in bundles:
                        try:
                            audit.case(profile, opt, lto, bundle, section)
                        except Exception as error:
                            profile_label = profile["name"] + ("-vtor1" if profile["core"] == 0 and profile["vtor"] == 1 else "")
                            label = "%s-%s-%s-%s" % (profile_label, opt, "native-lto-"+section if lto else "normal", bundle)
                            failure = dict(case=label, profile=profile["name"], opt=opt, lto=lto, sections=section, bundle=bundle,
                                           error=str(error), traceback=traceback.format_exc())
                            audit.errors.append(failure)
                            if (audit.build / label).is_dir():
                                write_json(audit.build / label / "unqualified.json", failure)
                            print("UNQUALIFIED %s %s %s %s: %s" %
                                  (profile["name"], opt, lto, bundle, str(error).splitlines()[0]), flush=True)
        complete = True
    except Exception as error:
        audit.errors.append(dict(error=str(error), traceback=traceback.format_exc()))
    return audit.finish(complete)


if __name__ == "__main__":
    raise SystemExit(main())
