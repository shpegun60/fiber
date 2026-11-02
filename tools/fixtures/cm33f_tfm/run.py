"""Staged C3FT consumer/host proof and explicit optional modeled CPU execution.

The typed NS provider and test Secure bootstrap are not a real Secure TF-M image.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
FORWARD = set("fiber_port_context_init fiber_port_runtime_memory_barrier fiber_port_panic_wait "
              "fiber_port_require_scheduler_configuration_environment fiber_port_runtime_prepare_start "
              "fiber_port_runtime_select_first fiber_port_runtime_start_first fiber_port_runtime_schedule".split())
PUBLIC = set("fiber_init fiber_current fiber_start fiber_scheduler_set_pick_next fiber_schedule".split())
ADAPTER = set("fiber_port_tfm_initialize fiber_port_tfm_require_initialized "
              "os_wrapper_mutex_create os_wrapper_mutex_acquire os_wrapper_mutex_release os_wrapper_mutex_delete".split())
REVERSE = "fiber_internal_runtime_port_abi_v1_anchor"
STORAGE = "fiber_port_storage_cohort_arm_cm33f_tfm_v1_r0"
CPU_PRIVATE_IMPORTS = {"fiber_port_tfm_require_initialized", "fiber_port_arm_cm33f_tfm_integration_bundle_v1_anchor"}
CPU_BASE_IMPORTS = set("fiber_addr_plausible_ram fiber_addr_plausible_code "
    "fiber_internal_runtime_current_context_slot fiber_internal_runtime_port_abi_v1_anchor "
    "fiber_internal_runtime_publish_current_context fiber_internal_runtime_require_current_context "
    "fiber_internal_runtime_select_scheduler_candidate fiber_internal_task_return fiber_panic".split())
LTO_IR_HIDDEN_IMPORTS = {"fiber_internal_runtime_current_context_slot"}
INIT_IMPORTS = {"fiber_panic", "tfm_ns_interface_init"}
WRAPPER_IMPORTS = {"fiber_current", "fiber_panic", "fiber_port_runtime_schedule"}
HOSTILE = ["-finstrument-functions", "-fstack-protector-all", "-fprofile-arcs", "-ftest-coverage",
           "-fsanitize=undefined", "-fsanitize-coverage=trace-pc"]
HOSTILE_LTO_DRIVER = [flag for flag in HOSTILE if flag != "-fprofile-arcs"]
COMPILER_DEP = re.compile(r"__cyg|__gcov|__ubsan|__asan|__sanitizer|__stack_chk|__llvm_profile")
ORDINARY_COMMON = {"fiber_init", "fiber_scheduler_set_pick_next", "fiber_internal_scheduler_store_pick_next"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="ascii")


class Elf:
    """Minimal structured ARM ELF32 parser; reject ambiguous definitions."""
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        require(self.data[:7] == b"\x7fELF\x01\x01\x01", "not little-endian ELF32")
        h = struct.unpack_from("<16sHHIIIIIHHHHHH", self.data)
        require(h[2] == 40, "not ARM ELF")
        self.sections = []
        for n in range(h[12]):
            x = struct.unpack_from("<10I", self.data, h[6] + n * h[11])
            self.sections.append(dict(zip(("name", "type", "flags", "address", "offset", "size",
                                           "link", "info", "alignment", "entsize"), x)))
        strings = self.payload(self.sections[h[13]])
        for s in self.sections:
            s["name"] = self.string(strings, s["name"])
        self.symbols = []
        for s in self.sections:
            if s["type"] != 2:
                continue
            names = self.payload(self.sections[s["link"]])
            require(s["entsize"] == 16, "bad symbol entry")
            for offset in range(s["offset"], s["offset"] + s["size"], 16):
                name, value, size, info, other, section = struct.unpack_from("<IIIBBH", self.data, offset)
                self.symbols.append(dict(name=self.string(names, name), value=value, size=size,
                                         bind=info >> 4, type=info & 15, section=section, other=other))

    @staticmethod
    def string(data, offset):
        return data[offset:data.index(b"\0", offset)].decode("ascii")

    def payload(self, s):
        return self.data[s["offset"]:s["offset"] + s["size"]]

    def definitions(self, name):
        return [s for s in self.symbols if s["name"] == name and s["section"] != 0]

    def one(self, name):
        found = self.definitions(name)
        require(len(found) == 1, "missing/ambiguous ELF definition: " + name)
        return found[0]

    def at(self, address, length):
        sections = [s for s in self.sections if s["type"] != 8 and
                    s["address"] <= address and address + length <= s["address"] + s["size"]]
        require(len(sections) == 1, "ambiguous/unmapped ELF bytes")
        s = sections[0]
        start = s["offset"] + address - s["address"]
        return self.data[start:start + length]


class Proof:
    def __init__(self, args):
        self.a = args
        self.repo, self.build = Path(args.repo), Path(args.build)
        self.fixture = Path(__file__).resolve().parent
        self.port = self.repo / "fiber/port/ARM_CM33F_TFM/non_secure"
        self.common = self.repo / "fiber"
        self.bin = Path(args.arm_gcc).parent
        self.tools = {name: self.bin / ("arm-none-eabi-" + name + ".exe")
                      for name in ("g++", "gcc-nm", "objdump", "readelf", "gcc-ar")}
        self.commands, self.positives, self.negatives, self.host_runs = [], [], [], []
        self.verified_runtime_selectable = None
        self.role_proofs = []
        self.role_definitions = []
        self.reference_objects, self.hostile_objects = [], []
        self.portable_runs, self.constructor_archives, self.default_policies = [], [], []
        self.execution = dict(status="NOT_RUN", reason="Explicit -QemuRoot required; no implicit provisioning")
        self.flags = ["-mcpu=cortex-m33", "-mthumb", "-mfloat-abi=softfp", "-mfpu=fpv5-sp-d16", "-ffreestanding",
                      "-fno-builtin", "-fno-common", "-ffunction-sections", "-fdata-sections",
                      "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-Wundef"]
        self.selection = ["-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV8M_MAINLINE=1"]
        self.sources = [self.port / n for n in ("fiber_port.c", "fiber_port_boot.c", "fiber_port_tfm.c", "fiber_port_tfm_os_wrapper.c")]
        self.common_sources = [self.common / n for n in ("fiber_core.c", "fiber_runtime_state.c", "fiber_panic.c")]

    def run(self, argv, label, timeout=90, allowed=False):
        argv = list(map(str, argv))
        start = time.monotonic()
        try:
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=timeout, text=True, errors="replace", cwd=self.build)
            result = dict(command=argv, exit=p.returncode, output=p.stdout, timeout=False)
        except subprocess.TimeoutExpired as e:
            output = e.stdout or b""
            if isinstance(output, bytes):
                output = output.decode("utf-8", "replace")
            result = dict(command=argv, exit=None, output=output, timeout=True)
        result.update(label=label, seconds=round(time.monotonic() - start, 3))
        index = len(self.commands)
        write_json(self.build / ("command-%04d.json" % index), result)
        self.commands.append(result)
        if not allowed:
            require(not result["timeout"] and result["exit"] == 0,
                    "%s failed; command-%04d.json\n%s" % (label, index, result["output"][-3500:]))
        return result

    def includes(self, port=None, cmsis=True):
        dirs = [self.fixture, port or self.port, self.common / "port", self.common, self.repo]
        if cmsis:
            dirs.append(Path(self.a.cmsis))
        return ["-I" + str(p) for p in dirs]

    def compile(self, source, output, options, selected=True, port=None, cpu=True,
                cxx=False, extra=(), allowed=False, manifest_runtime=None):
        flags = self.flags + ["-std=gnu++17" if cxx else "-std=gnu11"]
        if Path(source).resolve() in (self.fixture / "manifest.c", self.fixture / "default_policy.c"):
            expected = self.a.expected_runtime_selectable if manifest_runtime is None else manifest_runtime
            flags += ["-DFIBER_PROOF_EXPECTED_RUNTIME_SELECTABLE=" + str(expected)]
        if cxx:
            flags += ["-fno-exceptions", "-fno-rtti"]
        if selected:
            flags += self.selection
        flags += self.includes(port=port, cmsis=cpu)
        if cpu:
            flags += ["-include", str(self.fixture / "main.h")]
        if cxx:
            flags += ["-x", "c++"]
        return self.run([self.tools["g++"] if cxx else self.a.arm_gcc, *flags, *options, *extra,
                         "-c", source, "-o", output], "compile " + str(output), allowed=allowed)

    def nm(self, path, undefined=False):
        text = self.run([self.tools["gcc-nm"], "-P", "-u" if undefined else "--defined-only", path],
                        "symbols " + str(path))["output"]
        result = []
        for line in text.splitlines():
            match = re.fullmatch(r"(\S+)\s+([A-Za-z?])(?:\s+[0-9a-fA-F]+){0,2}", line.strip())
            require(match is not None, "unparsed nm output: " + line)
            result.append((match[1], match[2]))
        return result

    def link(self, objects, output, options, expected=None, duplicate=False):
        result = self.run([self.a.arm_gcc, *self.flags[:4], "-ffunction-sections", "-fdata-sections", *options, "-nostdlib",
                           "-Wl,--gc-sections", "-Wl,--no-undefined", "-Wl,--fatal-warnings",
                           "-T", self.fixture / "production.ld", "-Wl,-Map=" + str(output) + ".map",
                           *objects, "-o", output], "link " + str(output), allowed=expected is not None or duplicate)
        if duplicate:
            require(result["exit"] not in (None, 0) and "multiple definition of" in result["output"] and
                    "SVC_Handler" in result["output"] and "PendSV_Handler" in result["output"],
                    "duplicate-provider negative failed for wrong reason")
        elif expected is not None:
            missing = set(re.findall(r"undefined reference to [`']([^'`]+)['`]", result["output"]))
            require(result["exit"] not in (None, 0) and missing == set(expected) and
                    "multiple definition" not in result["output"],
                    "negative link intended %s but saw %s\n%s" % (expected, sorted(missing), result["output"][-2500:]))
        if expected is not None or duplicate:
            self.negatives.append(dict(name=output.name, expected=sorted(expected or []), duplicate=duplicate))

    def evidence(self, path):
        outputs = {}
        for key, tool, flags in (("dis", "objdump", ["-drwC"]),
                                 ("attributes", "readelf", ["-A"]), ("symbols", "readelf", ["-sW"])):
            out = self.run([self.tools[tool], *flags, path], "ELF " + key + " " + str(path))["output"]
            Path(str(path) + "." + key).write_text(out, encoding="utf-8")
            outputs[key] = out
        return outputs

    def cold_read(self, elf, dis, function, marker):
        sym, anchor = elf.one(function), elf.one(marker)
        begin, end = sym["value"] & ~1, (sym["value"] & ~1) + sym["size"]
        loaded = {}
        found = False
        for line in dis.splitlines():
            insn = re.match(r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{4}\s+){1,2}\s*([a-z][a-z0-9.]*)\s*(.*)", line)
            if not insn or not begin <= int(insn[1], 16) < end:
                continue
            op, operands = insn[2].removesuffix(".w"), insn[3]
            # Objdump may name the same architectural registers ip/sb/sl/fp.
            aliases = {"ip": "r12", "sb": "r9", "sl": "r10", "fp": "r11"}
            operands = re.sub(r"\b(?:ip|sb|sl|fp)\b", lambda m: aliases[m[0]], operands)
            literal = re.match(r"(r\d+),\s*\[pc,\s*#\d+\].*?\(([0-9a-f]+)\s", operands)
            if op == "ldr" and literal:
                value = struct.unpack("<I", elf.at(int(literal[2], 16), 4))[0]
                loaded[literal[1]] = value
            elif op == "ldrb":
                source = re.match(r"r\d+,\s*\[(r\d+)(?:,\s*#(\d+))?\]", operands)
                if source and source[1] in loaded and loaded[source[1]] + int(source[2] or 0) == anchor["value"]:
                    found = True
                destination = re.match(r"(r\d+),", operands)
                if destination:
                    loaded.pop(destination[1], None)
            else:
                # Conservative kill for a destination register, never infer a load.
                destination = re.match(r"(r\d+),", operands)
                if destination and op not in ("cmp", "str", "strb", "strh", "tst"):
                    loaded.pop(destination[1], None)
                if op in ("bl", "blx"):
                    for register in ("r0", "r1", "r2", "r3", "r12"):
                        loaded.pop(register, None)
        require(found, "missing exact generated cold volatile byte read: %s -> %s" % (function, marker))

    def check_elf(self, path, cohort, label, public_roots=True):
        elf = Elf(path)
        outputs = self.evidence(path)
        require(not [s for s in elf.symbols if s["section"] == 0 and s["name"]], "unresolved final ELF")
        require("Tag_CPU_arch: v8-M.mainline" in outputs["attributes"] and
                any('Tag_CPU_name: "' + name + '"' in outputs["attributes"] for name in ("8-M.MAIN", "cortex-m33")),
                "ELF is not the exact M33/v8.0-M target architecture")
        require(("Tag_ABI_VFP_args" in outputs["attributes"]) == self.flags[2].endswith("hard"),
                "unexpected hard/softfp argument ABI")
        # The unchanged portable application has no artificial public root table;
        # ordinary public functions may legally inline under LTO. Its object U set
        # is checked separately before linking the actual common implementation.
        required = FORWARD | ADAPTER | {"SVC_Handler", "PendSV_Handler", REVERSE, STORAGE, cohort}
        if public_roots:
            required |= PUBLIC
        for symbol in sorted(required):
            s = elf.one(symbol)
            require(s["bind"] in (0, 1), "weak provider: " + symbol)
        for name, slot in (("SVC_Handler", 11), ("PendSV_Handler", 14)):
            s = elf.one(name)
            require(s["bind"] == 1 and s["type"] == 2, "handler not strong function")
            table = elf.one("vectors")
            actual = struct.unpack("<I", elf.at(table["value"] + slot * 4, 4))[0]
            require(actual == s["value"] and actual & 1, "wrong strong vector slot")
        for marker in (REVERSE, STORAGE, cohort):
            s = elf.one(marker)
            require(s["size"] == 1 and elf.at(s["value"], 1) == b"\1" and
                    not elf.sections[s["section"]]["flags"] & 1, "not readonly one-byte marker: " + marker)
        forbidden = [s["name"] for s in elf.symbols if re.search(r"SecureContext|secure_context|__cyg|__gcov|__ubsan|__stack_chk", s["name"])]
        require(not forbidden, "forbidden external/runtime dependency: " + repr(forbidden))
        for line in outputs["dis"].splitlines():
            insn = re.match(r"\s*[0-9a-f]+:\s+(?:[0-9a-f]{4}\s+){1,2}\s*([a-z][a-z0-9.]*)", line)
            if insn:
                if insn[1].startswith("v"):
                    owner = elf.one("PendSV_Handler")
                    address = int(line.split(":")[0], 16)
                    require((owner["value"] & ~1) <= address < (owner["value"] & ~1) + owner["size"] and
                            insn[1] in ("vstmdb", "vldmia") and re.search(r"r0!,\s*\{s16-s31\}", line),
                            "FP instruction outside exact high-context transfers: " + line)
        sections = [s for s in elf.sections if s["name"] == ".fiber_port_context_cohort_expectation"]
        require(len(sections) == 1 and sections[0]["size"] >= 4 and sections[0]["size"] % 4 == 0,
                "all public storage contributions must be retained (not fixed size)")
        self.cold_read(elf, outputs["dis"], "fiber_port_context_init", REVERSE)
        self.cold_read(elf, outputs["dis"], "fiber_port_runtime_prepare_start", REVERSE)
        self.cold_read(elf, outputs["dis"], "fiber_port_runtime_prepare_start", cohort)
        self.cold_read(elf, outputs["dis"], "fiber_port_runtime_prepare_start",
                       "fiber_port_arm_cm33f_tfm_integration_bundle_v1_anchor")
        prepare = elf.one("fiber_port_runtime_prepare_start")
        begin, end = prepare["value"] & ~1, (prepare["value"] & ~1) + prepare["size"]
        calls = []
        for line in outputs["dis"].splitlines():
            m = re.match(r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{4}\s+){1,2}\s*(?:bl|b\.w)\s+([0-9a-f]+)\s", line)
            if m and begin <= int(m[1], 16) < end:
                address = int(m[2], 16)
                targets = [s["name"] for s in elf.symbols if s["type"] == 2 and s["section"] and (s["value"] & ~1) == address]
                require(len(targets) == 1, "ambiguous startup call target")
                calls.append(targets[0])
        expected_calls = ["fiber_port_require_start_environment", "fiber_port_require_start_interrupt_state",
                          "fiber_port_tfm_require_initialized", "fiber_port_require_start_environment",
                          "fiber_port_require_start_interrupt_state", "fiber_port_runtime_prepare",
                          "fiber_port_prepare_exception_start", "fiber_port_require_start_environment",
                          "fiber_port_require_start_interrupt_state", "fiber_port_fpu_require_ready"]
        require(calls == expected_calls, "generated prestart initialization order changed: " + repr(calls))
        self.positives.append(dict(name=label, elf=str(path), sha256=digest(path),
                                   expectation_bytes=sections[0]["size"], forward_count=len(FORWARD),
                                   public_symbol_roots=public_roots,
                                   runtimeSelectable=self.a.expected_runtime_selectable))

    def default_policy(self, path, priority_bits):
        elf = Elf(path)
        symbol = elf.one("c3ft_default_policy")
        expected = (0, 1, 1, 0, 0, 1, 32, 2 if priority_bits == 8 else 1 << (8 - priority_bits),
                    self.a.expected_runtime_selectable)
        require(symbol["size"] == 36 and not elf.sections[symbol["section"]]["flags"] & 1,
                "default policy must be exact readonly target data")
        section = elf.sections[symbol["section"]]
        offset = symbol["value"] - section["address"]
        require(section["type"] != 8 and 0 <= offset and offset + 36 <= section["size"],
                "default policy data outside its exact ELF section")
        observed = struct.unpack("<9I", elf.payload(section)[offset:offset + 36])
        require(observed == expected, "default policy changed: " + repr(observed))
        item = dict(object=str(path), values=observed, expected=expected, priority_bits=priority_bits)
        self.default_policies.append(item)
        return item

    def public_compile(self, source, obj, options, cxx=False, alignas_bridge=False, port=None):
        extra = ["-H"]
        if cxx and alignas_bridge:
            extra.append("-D_Alignas(n)=__attribute__((aligned(n)))")
        result = self.compile(source, obj, options, cpu=False, cxx=cxx, extra=extra, port=port)
        headers = [Path(x).resolve() for x in re.findall(r"^\.+ (.+)$", result["output"], re.M)]
        forbidden = {"fiber_portmacro.h", "fiber_port_private.h", "fiber_port_boot.h", "fiber_runtime_state.h",
                     "fiber_runtime_port_abi.h", "fiber_port_runtime_abi.h", "fiber_port_tfm_abi.h",
                     "fiber_port_tfm_os_wrapper.h", "main.h", "mcu_core.h"}
        require(headers and any(h.name == "fiber_core.h" for h in headers) and
                not any(h.name in forbidden or h.is_relative_to(Path(self.a.cmsis).resolve()) for h in headers),
                "public consumer acquired CMSIS/device/private/optional header dependencies")
        if port is not None:
            consumed = {h for h in headers if h.is_relative_to(port.resolve())}
            expected = {port.resolve() / name for name in ("fiber_port_types.h", "fiber_port_boot_types.h")}
            require(consumed == expected, "stale consumer exceeded its exact public storage-header boundary")
        Path(str(obj) + ".includes.json").write_text(json.dumps(list(map(str, headers)), indent=2) + "\n")
        return headers

    def default_policy_control(self, d, options):
        result = self.compile(self.fixture / "default_policy.c", d / "not-default-policy.o", options,
                              extra=["-DFIBER_FPU_LAZY=1"], allowed=True)
        errors = re.findall(r'^.*error: (.+)$', result["output"], re.M)
        require(result["exit"] not in (None, 0) and errors ==
                ['static assertion failed: "C3FT default policy: FIBER_FPU_LAZY == 0"'],
                "default-policy observer control failed for an unrelated reason: " + result["output"])
        self.negatives.append(dict(name="default-policy-observer-" + d.name,
                                   expected="explicit lazy override is not the default-policy tuple"))

    def portable_application(self, d, fixtures, common_objects, port_objects, options, cohort):
        source = self.repo / "tools/fixtures/portable_application.c"
        before = digest(source)
        for cxx in (False, True):
            suffix = "cpp" if cxx else "c"
            app, startup = d / ("portable-" + suffix + ".o"), d / ("portable-startup-" + suffix + ".o")
            headers = self.public_compile(source, app, options, cxx=cxx, alignas_bridge=True)
            imports = {n for n, t in self.nm(app, True)}
            require(imports == PUBLIC | {STORAGE}, "unchanged portable application has non-public dependencies")
            self.compile(self.fixture / "portable_startup.c", startup, options, selected=False, cpu=False, cxx=cxx)
            for archived in (False, True):
                elf = d / ("portable-" + suffix + ("-archive" if archived else "-direct") + ".elf")
                provider = [d / "libfiber-c3ft.a"] if archived else [*common_objects, *port_objects]
                self.link([startup, app, *fixtures, *provider], elf, options)
                self.check_elf(elf, cohort, elf.stem, public_roots=False)
                self.default_policy(elf, 3)
                parsed = Elf(elf)
                for name in ("portable_fixture_stack_1", "portable_fixture_stack_2"):
                    stacks = [s for s in parsed.symbols if s["section"] and s["name"].endswith(name)]
                    require(len(stacks) == 1 and stacks[0]["size"] == 2048 and stacks[0]["value"] % 8 == 0,
                            "unchanged portable application stack size/alignment was lost")
                self.portable_runs.append(dict(source=str(source), source_sha256=before, elf=str(elf),
                    language=suffix, archive=archived, headers=list(map(str, headers)),
                    fixture_only_alignment_bridge=cxx, imports=sorted(imports)))
        require(digest(source) == before, "shared portable_application.c was modified")

    def constructor_archive(self, d, common_objects, port_objects, options):
        # This pre-v1 model removes only the marker definition from real common
        # state. It is not presented as an entire historical source checkout.
        text = self.common_sources[1].read_text()
        marker = ("const unsigned char fiber_internal_runtime_port_abi_v1_anchor =\n"
                  "\t\t(unsigned char)FIBER_RUNTIME_PORT_ABI_VERSION;")
        require(text.count(marker) == 1, "pre-v1 common archive marker definition drift")
        stale_source = d / "pre-v1-common-state.c"
        stale_source.write_text(text.replace(marker, ""))
        stale_obj = d / "pre-v1-common-state.o"
        self.compile(stale_source, stale_obj, options, selected=False, cpu=False)
        require(not any(n == REVERSE for n, kind in self.nm(stale_obj) + self.nm(stale_obj, True)),
                "pre-v1 archive model must contain neither definition nor dependency on v1")
        archives = {}
        for current in (False, True):
            objects = common_objects if current else [common_objects[0], stale_obj, common_objects[2]]
            archive = d / ("libcommon-current-v1.a" if current else "libcommon-pre-v1.a")
            self.run([self.tools["gcc-ar"], "rcs", archive, *objects], "archive real common current/pre-v1")
            listing = self.run([self.tools["gcc-ar"], "t", archive], "inspect common archive members")["output"].splitlines()
            require(listing == [o.name for o in objects], "unexpected common archive members")
            archives[current] = archive
        hooks = d / "constructor-hooks.o"
        self.compile(self.fixture / "constructor_hooks.c", hooks, options, selected=False, cpu=False)
        for cxx in (False, True):
            suffix = "cpp" if cxx else "c"
            app = d / ("public-constructor-" + suffix + ".o")
            self.public_compile(self.fixture / "constructor_public.c", app, options, cxx=cxx)
            require({n for n, kind in self.nm(app, True)} == {"fiber_init", STORAGE},
                    "constructor-only consumer must import exactly public fiber_init and its storage identity")
            for current in (False, True):
                elf = d / ("public-constructor-" + suffix + ("-current.elf" if current else "-pre-v1.elf"))
                self.link([app, hooks, "-Wl,--start-group", archives[current], d / "libc3ft.a", "-Wl,--end-group"],
                          elf, options, expected=None if current else {REVERSE})
                if current:
                    parsed = Elf(elf)
                    out = self.evidence(elf)
                    self.cold_read(parsed, out["dis"], "fiber_port_context_init", REVERSE)
                    anchor = parsed.one(REVERSE)
                    require(anchor["size"] == 1 and parsed.at(anchor["value"], 1) == b"\1" and
                            not parsed.sections[anchor["section"]]["flags"] & 1, "constructor v1 marker not readonly one-byte 1")
                    forbidden = ADAPTER | {"tfm_ns_interface_init", "fiber_start", "fiber_schedule", "SVC_Handler", "PendSV_Handler"}
                    require(not any(parsed.definitions(n) for n in forbidden),
                            "constructor-only positive accidentally retains runtime/TF-M application roots")
                self.constructor_archives.append(dict(elf=str(elf), language=suffix, current=current,
                    common_archive=str(archives[current]), port_archive=str(d / "libc3ft.a"),
                    expected_missing=[] if current else [REVERSE]))

    def role_imports(self, path, expected, role):
        symbols = self.nm(path, True)
        actual = {name for name, kind in symbols}
        require(all(kind == "U" for name, kind in symbols) and actual == expected,
                "role U mismatch %s: extra=%s missing=%s bindings=%s" %
                (role, sorted(actual - expected), sorted(expected - actual), symbols))
        self.role_proofs.append(dict(role=role, object=str(path), expected=sorted(expected), actual=symbols))

    def role_no_common_definitions(self, path, common_owned):
        symbols = self.nm(path)
        forbidden = [(name, kind) for name, kind in symbols if name in common_owned or
                     name.startswith(("fiber_internal_runtime_", "fiber_internal_scheduler_")) or
                     name == "fiber_internal_task_return"]
        require(not forbidden, "role defines common-owned symbols: " + repr(forbidden))
        weak = [(name, kind) for name, kind in symbols if kind in "WwVv"]
        require(not weak, "role defines weak port providers: " + repr(weak))
        self.role_definitions.append(dict(object=str(path), common_owned=sorted(common_owned), definitions=symbols))

    def role_group(self, objects, output, options, lower=False):
        self.run([self.a.arm_gcc, *self.flags[:4], *options, "-nostdlib", "-r",
                  *(["-flinker-output=nolto-rel"] if lower else []), *objects, "-o", output],
                 "role relocatable group " + str(output))
        if lower:
            self.evidence(output)

    def object_roles(self, d, port_objects, common_objects, options, lto):
        common_owned = PUBLIC | {REVERSE, "fiber_panic", "fiber_addr_plausible_ram", "fiber_addr_plausible_code"}
        for obj in common_objects:
            common_owned |= {name for name, kind in self.nm(obj) if name.startswith("fiber_") and kind.isupper()}
        for obj in port_objects:
            self.role_no_common_definitions(obj, common_owned)
        cpu_expected = CPU_BASE_IMPORTS | CPU_PRIVATE_IMPORTS
        ir_expected = cpu_expected - LTO_IR_HIDDEN_IMPORTS if lto else cpu_expected
        group = d / "cpu-boot-group.o"
        self.role_group(port_objects[:2], group, options)
        self.role_no_common_definitions(group, common_owned)
        self.role_imports(group, ir_expected, "CPU+boot IR" if lto else "CPU+boot native")
        self.role_imports(port_objects[2], INIT_IMPORTS, "initializer IR" if lto else "initializer native")
        self.role_imports(port_objects[3], WRAPPER_IMPORTS, "wrapper IR" if lto else "wrapper native")
        if lto:
            for name, objects, expected in (("cpu-boot", port_objects[:2], cpu_expected),
                                             ("initializer", [port_objects[2]], INIT_IMPORTS),
                                             ("wrapper", [port_objects[3]], WRAPPER_IMPORTS)):
                lowered = d / (name + "-lowered.o")
                self.role_group(objects, lowered, options, lower=True)
                self.role_no_common_definitions(lowered, common_owned)
                self.role_imports(lowered, expected, name + " lowered LTO")
        self.role_controls(d, port_objects, options, lto, cpu_expected, ir_expected, common_owned)

    def role_controls(self, d, port_objects, options, lto, cpu_expected, ir_expected, common_owned):
        text = self.sources[0].read_text()
        entry = "void fiber_port_runtime_prepare_start(void)\n{"
        require(text.count(entry) == 1, "CPU public-dependency control anchor drift")
        source = d / "role-cpu-public-leak.c"
        source.write_text(text.replace(entry, entry +
            "\n\textern FiberContext *fiber_current(void);\n\t(void)fiber_current();"))
        mutant = d / "role-cpu-public-leak.o"
        self.compile(source, mutant, options, extra=["-include", str(self.fixture / "tfm_v2_boundary.h")])
        self.role_no_common_definitions(mutant, common_owned)
        for lower in ((False, True) if lto else (False,)):
            group = d / ("role-cpu-leak-lowered.o" if lower else "role-cpu-leak-group.o")
            self.role_group([mutant, port_objects[1]], group, options, lower=lower)
            expected = cpu_expected if lower else ir_expected
            actual = {name for name, kind in self.nm(group, True)}
            require(actual == expected | {"fiber_current"}, "CPU leak control has unrelated dependency changes")
            rejected = False
            try:
                self.role_imports(group, expected, "CPU+boot public-leak control")
            except RuntimeError as error:
                require(str(error).startswith("role U mismatch CPU+boot public-leak control:"),
                        "CPU leak control rejected for unrelated reason")
                rejected = True
            require(rejected, "CPU public fiber_current dependency falsely accepted")
        self.negatives.append(dict(name="compiled-cpu-public-dependency-" + d.name, forbidden="fiber_current"))
        weak_source = d / "role-weak-common-anchor.c"
        weak_source.write_text(text + "\n__attribute__((weak, used)) const unsigned char " + REVERSE + " = 1u;\n")
        weak_object = d / "role-weak-common-anchor.o"
        self.compile(weak_source, weak_object, options, extra=["-include", str(self.fixture / "tfm_v2_boundary.h")])
        # GCC's LTO plugin calls weak data W; native ELF identifies weak objects V.
        controls = [(weak_object, "W" if lto else "V")]
        if lto:
            lowered = d / "role-weak-common-anchor-lowered.o"
            self.role_group([weak_object], lowered, options, lower=True)
            controls.append((lowered, "V"))
        for obj, binding in controls:
            require((REVERSE, binding) in self.nm(obj), "weak common-anchor control was not actually emitted")
            rejected = False
            try:
                self.role_no_common_definitions(obj, common_owned)
            except RuntimeError as error:
                require(str(error) == "role defines common-owned symbols: " + repr([(REVERSE, binding)]),
                        "weak common-anchor control rejected for unrelated reason")
                rejected = True
            require(rejected, "weak common-owned anchor hidden by a later strong provider was accepted")
        self.negatives.append(dict(name="compiled-weak-common-anchor-" + d.name, forbidden=REVERSE,
                                   bindings=[binding for obj, binding in controls]))

    def target(self):
        files = sorted(p.name for p in self.port.iterdir() if p.is_file())
        expected_files = sorted([p.name for p in self.sources] + ["fiber_portmacro.h", "fiber_port_boot.h",
            "fiber_port_boot_types.h", "fiber_port_private.h", "fiber_port_tfm_abi.h", "fiber_port_tfm_os_wrapper.h",
            "fiber_port_types.h", "FREERTOS_PARITY.md"])
        require(files == expected_files, "C3FT complete twelve-file group not ready: " + repr(files))
        forward_header = (self.common / "port/fiber_port_runtime_abi.h").read_text()
        public_header = (self.common / "fiber_api_decl.h").read_text()
        require(set(re.findall(r"\b(fiber_port_[a-z0-9_]+)\s*\(", forward_header)) == FORWARD and len(FORWARD) == 8,
                "generic forward header is not exactly the frozen eight calls")
        require(set(re.findall(r"\b(fiber_[a-z0-9_]+)\s*\(", public_header)) == PUBLIC and len(PUBLIC) == 5,
                "public callable header is not exactly the five operations")
        for abi in ("softfp", "hard"):
            self.flags[2] = "-mfloat-abi=" + abi
            baseline = None
            for optimization in ("-O2", "-Os"):
                for lto in (False, True):
                    name = abi + "-" + optimization[1:].lower() + ("-lto" if lto else "")
                    d = self.build / name
                    d.mkdir()
                    options = [optimization] + (["-flto"] if lto else [])
                    port_objects = []
                    for source in self.sources:
                        obj = d / (source.stem + ".o")
                        self.compile(source, obj, options, extra=["-include", str(self.fixture / "tfm_v2_boundary.h")])
                        self.evidence(obj)
                        port_objects.append(obj)
                    common_objects = []
                    for source in self.common_sources:
                        obj = d / (source.stem + ".o")
                        self.compile(source, obj, options, selected=False, cpu=False)
                        common_objects.append(obj)
                    self.object_roles(d, port_objects, common_objects, options, lto)
                    manifest = d / "manifest.o"
                    self.compile(self.fixture / "manifest.c", manifest, options)
                    undefined = self.nm(manifest, undefined=True)
                    require(len(undefined) == 1 and undefined[0][0].startswith("fiber_port_context_cohort_"),
                            "manifest must derive exactly one private cohort")
                    cohort = undefined[0][0]
                    port_defined = [n for o in port_objects for n, t in self.nm(o) if t in "TDRB"]
                    require(set(port_defined) & FORWARD == FORWARD and all(port_defined.count(n) == 1 for n in FORWARD),
                            "incomplete/nonunique frozen eight-operation forward provider")
                    require(cohort in port_defined and STORAGE in port_defined, "provider missing exact derived cohort/storage")
                    group = d / "port-group.o"
                    self.run([self.a.arm_gcc, *self.flags[:4], *options, "-nostdlib", "-r", *port_objects, "-o", group], "relocatable group")
                    missing = {n for n, t in self.nm(group, True)}
                    expected = set("fiber_addr_plausible_ram fiber_addr_plausible_code fiber_current fiber_internal_runtime_current_context_slot "
                                   "fiber_internal_runtime_port_abi_v1_anchor fiber_internal_runtime_publish_current_context "
                                   "fiber_internal_runtime_require_current_context fiber_internal_runtime_select_scheduler_candidate "
                                   "fiber_internal_task_return fiber_panic tfm_ns_interface_init".split())
                    if lto:
                        # GCC IR nm cannot see inline-assembly references or lowered memory operations.
                        expected -= LTO_IR_HIDDEN_IMPORTS
                    require(missing == expected, "unexpected complete-group undefined set: " + repr(sorted(missing)))
                    self.role_proofs.append(dict(role="combined group IR" if lto else "combined group native",
                                                object=str(group), expected=sorted(expected), actual=sorted(missing)))
                    if lto:
                        lowered = d / "complete-group-lowered.o"
                        self.role_group(port_objects, lowered, options, lower=True)
                        self.role_imports(lowered, (CPU_BASE_IMPORTS | {"fiber_current", "tfm_ns_interface_init"}),
                                          "combined group lowered LTO")
                    fixtures = []
                    for f in ("vectors.c", "provider.c", "memory.c", "default_policy.c"):
                        o = d / (Path(f).stem + ".o")
                        is_policy = f == "default_policy.c"
                        self.compile(self.fixture / f, o, options, selected=is_policy, cpu=is_policy)
                        fixtures.append(o)
                    archive = d / "libc3ft.a"
                    self.run([self.tools["gcc-ar"], "rcs", archive, *port_objects], "archive actual C3FT group")
                    complete_archive = d / "libfiber-c3ft.a"
                    self.run([self.tools["gcc-ar"], "rcs", complete_archive, *common_objects, *port_objects],
                             "archive real common plus complete C3FT provider")
                    policy = fixtures[-1]
                    if lto:
                        policy = d / "default-policy-lowered.o"
                        self.role_group([fixtures[-1]], policy, options, lower=True)
                    self.default_policy(policy, 3)
                    self.default_policy_control(d, options)
                    self.portable_application(d, fixtures, common_objects, port_objects, options, cohort)
                    self.constructor_archive(d, common_objects, port_objects, options)
                    for cxx in (False, True):
                        suffix = "cpp" if cxx else "c"
                        app = d / ("consumer-" + suffix + ".o")
                        self.compile(self.fixture / "consumer.c", app, options, cpu=False, cxx=cxx)
                        app_missing = {n for n, t in self.nm(app, True)}
                        require(app_missing == PUBLIC | {STORAGE}, "public-only allocating consumer dependency surprise: " + repr(app_missing))
                        for archived in (False, True):
                            label = name + "-" + suffix + ("-archive" if archived else "-direct")
                            elf = d / (label + ".elf")
                            objects = [app, *fixtures] + ([complete_archive] if archived else [*common_objects, *port_objects])
                            self.link(objects, elf, options)
                            self.check_elf(elf, cohort, label)
                        self.stale(d, app, fixtures, common_objects, port_objects, options, cxx)
                    self.link_negatives(d, fixtures, common_objects, port_objects, options, cohort)
                    if baseline is None:
                        baseline = d
                    print("C3FT target grid PASS " + name, flush=True)
            self.manifest_negatives(baseline)

    def stale(self, d, app, fixtures, common_objects, port_objects, options, cxx):
        for profile in ("ARM_CM33F_NTZ", "ARM_CM33_TFM", "ARM_CM55_TFM"):
            port = self.common / "port" / profile / "non_secure"
            obj = d / ("stale-" + profile + ("-cpp" if cxx else "-c") + ".o")
            self.public_compile(self.fixture / "consumer.c", obj, options, port=port, cxx=cxx)
            missing = {n for n, t in self.nm(obj, True)}
            token = "fiber_port_storage_cohort_" + profile.lower() + "_v1_r0"
            require(missing == PUBLIC | {token}, "stale consumer not independently identified")
            self.link([obj, *fixtures, *common_objects, *port_objects], obj.with_suffix(".elf"), options, expected={token})

    def link_negatives(self, d, fixtures, common_objects, port_objects, options, cohort):
        app = d / "consumer-c.o"
        base = [app, *fixtures, *common_objects]
        # Rename only the real common marker; callbacks and common state remain real.
        wrong_state = d / "wrong-reverse-state.o"
        self.compile(self.common / "fiber_runtime_state.c", wrong_state, options, selected=False, cpu=False,
                     extra=["-D" + REVERSE + "=fiber_internal_runtime_port_abi_v999_anchor"])
        common_wrong = [wrong_state if p.stem == "fiber_runtime_state" else p for p in common_objects]
        self.link([app, *fixtures, *common_wrong, *port_objects], d / "missing-reverse-v1.elf", options, expected={REVERSE})
        # A genuinely absent external initializer, not an arbitrary prefix allowlist.
        provider_text = (self.fixture / "provider.c").read_text()
        old = "uint32_t tfm_ns_interface_init(void)"
        require(provider_text.count(old) == 1, "external initializer negative source drift")
        wrong_provider = d / "provider-without-init.c"
        wrong_provider.write_text(provider_text.replace(old, "uint32_t test_old_tfm_initializer(void)"))
        wrong_provider_obj = d / "provider-without-init.o"
        self.compile(wrong_provider, wrong_provider_obj, options, selected=False, cpu=False)
        self.link([app, *[wrong_provider_obj if p.stem == "provider" else p for p in fixtures],
                   *common_objects, *port_objects], d / "missing-tfm-v2-init.elf", options, expected={"tfm_ns_interface_init"})
        # Duplicate actual complete providers must never resolve by weak selection.
        self.link([*base, *port_objects, *port_objects], d / "double-provider.elf", options, duplicate=True)
        self.link([*base, *port_objects[:2], port_objects[3]], d / "missing-initializer-unit.elf", options,
                  expected={"fiber_port_tfm_require_initialized", "fiber_port_arm_cm33f_tfm_integration_bundle_v1_anchor"})
        self.link([*base, *port_objects[:3]], d / "missing-wrapper-unit.elf", options,
                  expected={"os_wrapper_mutex_create", "os_wrapper_mutex_acquire", "os_wrapper_mutex_release", "os_wrapper_mutex_delete"})
        # Constructor-only archive extraction must retain the exact common v1 marker.
        constructor = d / "constructor-only.c"
        constructor.write_text('#include "fiber_port_runtime_abi.h"\n'
            '#include "fiber_port_types.h"\nstatic FiberContext c; static unsigned s[256];\n'
            'static void e(void *p) {(void)p;}\nvoid Reset_Handler(void) {'
            'fiber_port_context_init(&c,s,s+256,e,0);for(;;){}}\n')
        obj = d / "constructor-only.o"
        self.compile(constructor, obj, options, cpu=False)
        # Force strong handlers via vectors only for complete-group controls above.
        minimal = [obj, *[p for p in fixtures if p.stem != "vectors"], *common_wrong, d / "libc3ft.a"]
        self.link(minimal, d / "constructor-missing-v1.elf", options, expected={REVERSE})
        self.link([obj, *[p for p in fixtures if p.stem != "vectors"], *common_objects, d / "libc3ft.a"],
                  d / "constructor-current-v1.elf", options)
        ctor_elf = Elf(d / "constructor-current-v1.elf")
        dis = self.evidence(d / "constructor-current-v1.elf")["dis"]
        self.cold_read(ctor_elf, dis, "fiber_port_context_init", REVERSE)
        # Actual alternate private policies are compiled, not guessed cohort strings.
        alternate = d / "manifest-policy.o"
        self.compile(self.fixture / "manifest.c", alternate, options, extra=["-DFIBER_SCHEDULER_BASEPRI=64"])
        alt = {n for n, t in self.nm(alternate, True)}
        require(len(alt) == 1 and cohort not in alt, "private-policy negative did not change identity")
        for index in (0, 1):
            obj = d / ("wrong-policy-" + self.sources[index].stem + ".o")
            self.compile(self.sources[index], obj, options, extra=["-DFIBER_SCHEDULER_BASEPRI=64"])
            # Provider identity lives in runtime.o; its reverse mismatch is all fresh expectations.
            expected = {cohort} if index == 0 else alt
            self.link([*base, *[obj if n == index else p for n, p in enumerate(port_objects)]],
                      obj.with_suffix(".elf"), options, expected=expected)
        # A real compiled decoy cohort byte read must not satisfy reverse-v1 proof.
        boot = self.sources[1].read_text()
        old = "FIBER_RUNTIME_PORT_ABI_RETAIN_V1();"
        require(boot.count(old) == 1, "constructor cold-read mutant anchor drift")
        mutant = d / "constructor-without-v1-read.c"
        mutant.write_text(boot.replace(old, "FIBER_PORT_CONTEXT_COHORT_RETAIN();"))
        mutant_obj = d / "constructor-without-v1-read.o"
        self.compile(mutant, mutant_obj, options)
        mutant_elf = d / "constructor-without-v1-read.elf"
        self.link([*base, port_objects[0], mutant_obj, *port_objects[2:]], mutant_elf, options)
        outputs = self.evidence(mutant_elf)
        rejected = False
        try:
            self.cold_read(Elf(mutant_elf), outputs["dis"], "fiber_port_context_init", REVERSE)
        except RuntimeError as error:
            require(str(error).startswith("missing exact generated cold volatile byte read:"), "wrong cold-read mutant rejection")
            rejected = True
        require(rejected, "constructor decoy byte read falsely accepted as reverse-v1")
        self.negatives.append(dict(name="compiled-constructor-decoy-" + d.name, rejection="exact reverse-v1 cold read absent"))

    def manifest_negatives(self, d):
        wrong_device = d / "wrong-core.h"
        wrong_device.write_text((self.fixture / "main.h").read_text().replace("C3FT_TEST_DEVICE_H", "C3FT_WRONG_DEVICE_H")
                                .replace('"core_cm33.h"', '"core_cm55.h"'))
        fpu_used = d / "injected-fpu-used.h"
        fpu_used.write_text("#undef __FPU_USED\n#define __FPU_USED 0\n")
        cases = [
            ("secure", ["-mcmse"], "does not accept a Secure CMSE build"),
            ("wrong-core", ["-mcpu=cortex-m55", "-DC3FT_TEST_DEVICE_H=1", "-include", str(wrong_device)],
             "manifest requires CMSIS __CORTEX_M == 33"),
            ("wrong-arch", ["-mcpu=cortex-m4"], "requires an ARMv8-M Mainline compiler target"),
            ("no-fp", ["-mfloat-abi=soft"], "requires CMSIS __FPU_USED == 1"),
            ("v81-target", ["-mcpu=cortex-m55"], "build-selected FIBER_PORT_ARMV* conflicts with compiler __ARM_ARCH_* macros"),
            ("v81-fact", ["-D__ARM_ARCH_8_1M_MAIN__=1"], "does not accept ARMv8.1-M code generation"),
            ("no-fpu", ["-D__FPU_PRESENT=0"], "requires CMSIS __FPU_PRESENT == 1"),
            ("mve", ["-D__ARM_FEATURE_MVE=1"], "does not permit MVE"),
            ("pac", ["-D__ARM_FEATURE_PAUTH=1"], "does not permit PAC"),
            ("bti", ["-D__ARM_FEATURE_BTI=1"], "does not permit BTI"),
            ("vtor", ["-D__VTOR_PRESENT=0"], "requires __VTOR_PRESENT == 1"),
            ("fpu-used", ["-include", str(fpu_used)], "requires CMSIS __FPU_USED == 1"),
            ("mpu", ["-DFIBER_PORT_MPU_TOTAL_REGIONS=8"], "is non-MPU"),
            ("cm55-mpu", ["-DFIBER_PORT_CM55_MPU_TOTAL_REGIONS=16"], "is non-MPU"),
            ("priority-zero", ["-D__NVIC_PRIO_BITS=0"], "requires 1..8 implemented NVIC priority bits"),
            ("priority-nine", ["-D__NVIC_PRIO_BITS=9"], "requires 1..8 implemented NVIC priority bits"),
            ("runtime-override", ["-DFIBER_PORT_RUNTIME_SELECTABLE=1"], "runtime-selectable state must not be predefined"),
            ("runtime-override-zero", ["-DFIBER_PORT_RUNTIME_SELECTABLE=0"], "runtime-selectable state must not be predefined"),
            ("inline-override", ["-Dfiber_portFORCE_INLINE=ignored"], "force-inline protection is selected-port-owned"),
        ]
        for profile in ("CM4", "CM33", "CM33F", "CM55", "CM55F", "CM55_MVEF"):
            for label, value in (("empty", ""), ("zero", "0"), ("eight", "8"), ("sixteen", "16"),
                                 ("negative", "-1"), ("token", "not_a_number")):
                cases.append(("foreign-" + profile.lower() + "-" + label,
                              ["-DFIBER_PORT_" + profile + "_MPU_TOTAL_REGIONS=" + value], "is non-MPU"))
        for name, flags, diagnostic in cases:
            result = self.compile(self.fixture / "manifest.c", d / ("negative-" + name + ".o"), ["-O2"], extra=flags, allowed=True)
            require(result["exit"] not in (None, 0) and diagnostic in result["output"],
                    "manifest negative wrong diagnostic: " + name + "\n" + result["output"][-1500:])
            self.negatives.append(dict(name="manifest-" + name, diagnostic=diagnostic))
        bad_abi = d / "wrong-tfm-v2-signature.c"
        bad_abi.write_text('#include "tfm_v2_boundary.h"\nuint64_t tfm_ns_interface_init(void) {return 0;}\n')
        result = self.compile(bad_abi, d / "wrong-tfm-v2-signature.o", ["-O2"], selected=False, cpu=False, allowed=True)
        require(result["exit"] not in (None, 0) and "conflicting types for 'tfm_ns_interface_init'" in result["output"],
                "typed TF-M v2 initializer ABI negative failed for wrong reason")
        self.negatives.append(dict(name="typed-tfm-v2-init-signature"))

    def runtime_manifest(self):
        self.compile(self.fixture / "manifest.c", self.build / "expected-runtime-manifest.o", ["-O2"])
        self.verified_runtime_selectable = self.a.expected_runtime_selectable
        wrong = 1 - self.a.expected_runtime_selectable
        result = self.compile(self.fixture / "manifest.c", self.build / "wrong-runtime-expectation.o",
                              ["-O2"], allowed=True, manifest_runtime=wrong)
        diagnostic = "C3FT independent manifest: FIBER_PORT_RUNTIME_SELECTABLE == FIBER_PROOF_EXPECTED_RUNTIME_SELECTABLE"
        require(not result["timeout"] and result["exit"] not in (None, 0) and diagnostic in result["output"] and
                len(re.findall(r"\berror:", result["output"])) == 1,
                "wrong runtime-selectability expectation must fail its sole manifest assertion: " + result["output"])
        self.negatives.append(dict(name="manifest-wrong-runtime-expectation", expected=wrong, diagnostic=diagnostic))

    def reference(self):
        reference = Path(self.a.reference)
        port = reference / "portable/GCC/ARM_CM33_NTZ/non_secure"
        for abi in ("softfp", "hard"):
            self.flags[2] = "-mfloat-abi=" + abi
            for opt in ("-O2", "-Os"):
                for lto in (False, True):
                    d = self.build / ("reference-" + abi + opt.lower() + ("-lto" if lto else ""))
                    d.mkdir()
                    options = [opt] + (["-flto"] if lto else [])
                    objects = []
                    for source in (port / "port.c", port / "portasm.c",
                                   reference / "portable/ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c",
                                   self.fixture / "reference_configuration.c"):
                        obj = d / (source.stem + ".o")
                        self.run([self.a.arm_gcc, *self.flags, *options, "-std=gnu11",
                                  "-I" + str(self.fixture), "-I" + str(reference / "include"), "-I" + str(port),
                                  "-I" + self.a.cmsis, "-include", self.fixture / "main.h",
                                  "-c", source, "-o", obj], "actual pinned M33 FP/TF-M reference")
                        self.evidence(obj)
                        self.reference_objects.append(dict(object=str(obj), source=str(source), abi=abi, lto=lto))
                        objects.append(obj)
                    if lto:
                        self.role_group(objects, d / "reference-lowered.o", options, lower=True)

    def compiler_dependencies(self, obj):
        return [(name, kind) for name, kind in self.nm(obj) + self.nm(obj, True) if COMPILER_DEP.search(name)]

    def common_sensitive_dependencies(self, obj, dis):
        """Ordinary configuration APIs are not claimed sensitive by the common ABI."""
        symbols = self.nm(obj)
        counters = [(n, k) for n, k in symbols if COMPILER_DEP.search(n)]
        for name, kind in counters:
            require(kind in ("b", "d") and re.fullmatch(r"__gcov(?:[0-9]+|_)\.([A-Za-z0-9_]+)", name) and
                    name.split(".", 1)[1] in ORDINARY_COMMON,
                    "unexpected common compiler storage/definition: " + repr((name, kind)))
        owner = None
        observations = []
        for line in dis.splitlines():
            symbol = re.fullmatch(r"[0-9a-f]+ <([^>]+)>:", line)
            if symbol:
                owner = symbol[1]
            if not COMPILER_DEP.search(line):
                continue
            generated = re.fullmatch(r"_sub_[ID]_00100_[0-9]+(?:\.(?:lto_priv\.)?[0-9]+)?", owner or "") is not None
            require(owner in ORDINARY_COMMON or (generated and counters),
                    "sensitive common/port function has compiler dependency: %s: %s" % (owner, line))
            observations.append(dict(function=owner, reference=line.strip()))
        return observations

    @staticmethod
    def fp_transfer_scan(dis):
        owner = None
        for line in dis.splitlines():
            symbol = re.fullmatch(r"[0-9a-f]+ <([^>]+)>:", line)
            if symbol:
                owner = symbol[1]
            instruction = re.match(r"\s*[0-9a-f]+:\s+(?:[0-9a-f]{4}\s+){1,2}\s*(v[a-z0-9.]+)\s+(.*)", line)
            if instruction:
                require(owner == "PendSV_Handler" and instruction[1] in ("vstmdb", "vldmia") and
                        re.fullmatch(r"r0!,\s*\{s16-s31\}", instruction[2].strip()),
                        "raw FP instruction outside named high-context transfers: " + line)

    def hostile(self):
        for abi in ("softfp", "hard"):
            self.flags[2] = "-mfloat-abi=" + abi
            for opt in ("-O2", "-Os"):
                for lto in (False, True):
                    name = "hostile-" + abi + opt.lower() + ("-lto" if lto else "")
                    d = self.build / name
                    d.mkdir()
                    options = [opt] + (["-flto"] if lto else [])
                    flags = HOSTILE + ["-DFIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS=1",
                                       "-DFIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1",
                                       "-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=1"]
                    objects = []
                    common_observations = []
                    for source in self.common_sources + self.sources:
                        obj = d / (source.stem + ".o")
                        common = source in self.common_sources
                        self.compile(source, obj, options, selected=not common, cpu=not common, extra=flags)
                        evidence = self.evidence(obj)
                        self.fp_transfer_scan(evidence["dis"])
                        if common:
                            common_observations += self.common_sensitive_dependencies(obj, evidence["dis"])
                        else:
                            require(not self.compiler_dependencies(obj), "raw hostile compiler dependencies: " + str(obj))
                        objects.append(obj)
                        self.hostile_objects.append(dict(object=str(obj), flags=flags, abi=abi, lto=lto, raw=True,
                            scope="common sensitive functions" if common else "complete new port object"))
                    if lto:
                        lowered = d / "whole-chain-lowered.o"
                        # Per-TU profiling remains effective (compiled control below).
                        # Repeating -fprofile-arcs at this -r step also links libgcov.
                        self.role_group(objects, lowered, options + HOSTILE_LTO_DRIVER, lower=True)
                        self.fp_transfer_scan(Path(str(lowered) + ".dis").read_text())
                        common_observations += self.common_sensitive_dependencies(lowered, Path(str(lowered) + ".dis").read_text())
                        self.hostile_objects.append(dict(object=str(lowered), abi=abi, lto=True, lowered=True))
                    write_json(d / "ordinary-common-instrumentation.json", common_observations)
                    control = d / "unprotected-control.o"
                    self.compile(self.fixture / "hostile_control.c", control, options, extra=HOSTILE)
                    if lto:
                        lowered = d / "unprotected-control-lowered.o"
                        self.role_group([control], lowered, options + HOSTILE_LTO_DRIVER, lower=True)
                        control = lowered
                    deps = self.compiler_dependencies(control)
                    names = " ".join(n for n, kind in deps)
                    for family in ("__cyg_profile", "__gcov", "__stack_chk", "__ubsan", "__sanitizer_cov"):
                        require(family in names, "hostile compiler flags ineffective: missing " + family)
                    # Remove only the canonical protection from the actual local hash helper.
                    text = self.sources[1].read_text()
                    old = "static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY\nuint32_t fiber_port_hash32_accum"
                    require(text.count(old) == 1, "A32 helper control anchor drift")
                    source = d / "unprotected-hash.c"
                    source.write_text(text.replace(old, "static FIBER_GENERAL_REGS_ONLY\nuint32_t fiber_port_hash32_accum"))
                    mutant = d / "unprotected-hash.o"
                    self.compile(source, mutant, options, extra=flags)
                    if lto:
                        lowered = d / "unprotected-hash-lowered.o"
                        self.role_group([mutant], lowered, options + HOSTILE_LTO_DRIVER, lower=True)
                        mutant = lowered
                    require(any(n.startswith("__cyg_profile") for n, kind in self.compiler_dependencies(mutant)),
                            "A32 unprotected hash helper was not detected")
                    self.negatives.append(dict(name=name + "-unprotected-hash", rejection="raw __cyg_profile dependency"))
                    header = (self.port / "fiber_portmacro.h").read_text()
                    matches = list(re.finditer(r"fiber_portFORCE_INLINE uint32_t fiber_port_cpu_control\(void\)\s*(\{[^{}]*\})", header))
                    require(len(matches) == 1, "A32 inline CPU control anchor drift")
                    source = d / "unprotected-inline.c"
                    source.write_text('#include "fiber_port_private.h"\n'
                        'static inline __attribute__((always_inline)) FIBER_GENERAL_REGS_ONLY\n'
                        'uint32_t unprotected_control(void) ' + matches[0][1] + '\n'
                        'volatile uint32_t inline_observation;\n'
                        'FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY void protected_caller(void)\n'
                        '{ inline_observation = unprotected_control(); }\n')
                    mutant = d / "unprotected-inline.o"
                    self.compile(source, mutant, options, extra=flags)
                    if lto:
                        lowered = d / "unprotected-inline-lowered.o"
                        self.role_group([mutant], lowered, options + HOSTILE_LTO_DRIVER, lower=True)
                        mutant = lowered
                    require(any(n.startswith("__cyg_profile") for n, kind in self.compiler_dependencies(mutant)),
                            "A32 unprotected inline helper was not detected")
                    self.negatives.append(dict(name=name + "-unprotected-inline", rejection="raw __cyg_profile dependency"))
                    control = d / "fp-control.o"
                    self.compile(self.fixture / "fp_control.c", control, options, extra=HOSTILE)
                    if lto:
                        lowered = d / "fp-control-lowered.o"
                        self.role_group([control], lowered, options + HOSTILE_LTO_DRIVER, lower=True)
                        control = lowered
                    evidence = self.evidence(control)
                    rejected = False
                    try:
                        self.fp_transfer_scan(evidence["dis"])
                    except RuntimeError as error:
                        require(str(error).startswith("raw FP instruction outside named high-context transfers:"),
                                "FP control rejected for unrelated reason")
                        rejected = True
                    require(rejected, "actual compiled ordinary FP instruction was not rejected")
                    self.negatives.append(dict(name=name + "-ordinary-fp", rejection="raw FP owner/form"))
                    print("C3FT raw hostile PASS " + name, flush=True)

    def host_sources(self, d):
        init = self.sources[2].read_text()
        mutex = self.sources[3].read_text()
        include = '#include "fiber_port_private.h"'
        for text in (init, mutex):
            require(text.count(include) == 1, "source-derived host include boundary drift")
        init, mutex = init.replace(include, '#include "host_port.h"'), mutex.replace(include, '#include "host_port.h"')
        public_include = '#include "../../../fiber_api_decl.h"'
        require(mutex.count(public_include) == 1, "source-derived public declaration include drift")
        mutex = mutex.replace(public_include, '#include "fiber_api_decl.h"')
        receipt = []
        for name, replacement in (
            ("fiber_port_tfm_primask_save_disable", '{\n uint32_t state = test_cpu[1]; test_cpu[1] = 1; ++test_mask_writes;\n'
             ' fiber_portDATA_SYNC_BARRIER(); fiber_portINST_SYNC_BARRIER(); return state;\n}'),
            ("fiber_port_tfm_primask_restore", '{\n fiber_portDATA_SYNC_BARRIER(); fiber_portINST_SYNC_BARRIER();\n'
             ' test_cpu[1] = state; ++test_mask_writes; fiber_portDATA_SYNC_BARRIER(); fiber_portINST_SYNC_BARRIER();\n'
             " FIBER_REQUIRE(fiber_port_cpu_primask() == state, 'r');\n}")):
            pattern = r"\b" + name + r"\([^;{}]*\)\s*(\{[^{}]*\})"
            matches = list(re.finditer(pattern, mutex))
            require(len(matches) == 1, "exact host primitive boundary drift: " + name)
            m = matches[0]
            original = m[1]
            receipt.append(dict(function=name, original=original, replacement=replacement,
                                original_sha256=hashlib.sha256(original.encode()).hexdigest().upper()))
            mutex = mutex[:m.start(1)] + replacement + mutex[m.end(1):]
        require("fiber_portASM" not in mutex, "unreplaced target asm in host adapter")
        write_json(d / "source-transformations.json", receipt)
        return init, mutex

    @staticmethod
    def host_pass(result, scenario):
        if result["timeout"] or result["exit"] != 0:
            return False
        return re.fullmatch(r"PASS:C3FT-HOST:" + re.escape(scenario) + r":[1-9][0-9]*\r?\n", result["output"]) is not None

    def host_compile(self, d, init, mutex, options):
        ip, mp = d / "derived-initialize.c", d / "derived-wrapper.c"
        ip.write_text(init)
        mp.write_text(mutex)
        executable = d / "host-adapter.exe"
        self.run([self.a.host_gcc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNDEBUG",
                  *options, *self.includes(cmsis=False), ip, mp, self.fixture / "host.c", "-o", executable],
                 "compile source-derived host adapter")
        return executable

    def host(self):
        scenarios = [["init-ok"], ["init-reentry"], ["init-require"], ["mutex-fpca"],
                     ["init-error", "1"], ["init-error", "3"], ["init-error", "4"],
                     ["mutex-basic"], ["mutex-wait", "1"], ["mutex-wait", "3"], ["mutex-no-owner"]]
        scenarios += [["init-change", str(n)] for n in range(8)]
        for slot in range(5):
            for value in ((1, 2, 3) if slot == 4 else (1,)):
                scenarios.append(["init-admission", str(slot), str(value)])
        for operation in range(4):
            for slot in range(5):
                values = (1, 2, 3) if operation == 0 else ((0, 1, 3) if operation in (1, 2) else (1, 3))
                for value in (values if slot == 4 else (1,)):
                    scenarios.append(["mutex-admission", str(operation), str(slot), str(value)])
        for opt in ("-O2", "-Os"):
            for lto in (False, True):
                name = "host-" + opt[1:].lower() + ("-lto" if lto else "")
                d = self.build / name
                d.mkdir()
                init, mutex = self.host_sources(d)
                options = [opt] + (["-flto"] if lto else [])
                exe = self.host_compile(d, init, mutex, options)
                for args in scenarios:
                    result = self.run([exe, *args], "host " + " ".join(args), timeout=5, allowed=True)
                    require(self.host_pass(result, args[0]), "host adapter scenario failed: " + repr(args) + "\n" + result["output"])
                    self.host_runs.append(dict(build=name, scenario=args, output=result["output"].strip()))
                print("C3FT source-derived host PASS " + name + " (%d scenarios)" % len(scenarios), flush=True)
        self.host_mutants(init, mutex)
        self.classifier_controls()

    def host_mutants(self, init, mutex):
        mutants = [
            ("external-error-is-success", "init", "if (result != FIBER_PORT_TFM_SUCCESS)", "if ((result != FIBER_PORT_TFM_SUCCESS) && 0)",
             ["init-error", "1"], "init-external-error"),
            ("ready-not-idempotent", "init", "if (state == fiber_portTFM_READY)", "if (0)",
             ["init-ok"], "init-idempotent"),
            ("failed-not-sticky", "init", "if (state != fiber_portTFM_UNINITIALIZED)",
             "if ((state != fiber_portTFM_UNINITIALIZED) && (state != fiber_portTFM_FAILED))",
             ["init-error", "1"], "init-failed-sticky"),
            ("lost-control-readback", "init", "FIBER_REQUIRE(fiber_port_cpu_control() == before->control, 'l');", "(void)before;",
             ["init-change", "4"], "missing-panic"),
            ("lost-cpacr-readback", "init", "FIBER_REQUIRE(fiber_portCPACR_REG == before->cpacr, 'e');", "(void)before;",
             ["init-change", "6"], "missing-panic"),
            ("lost-fpccr-readback", "init", "FIBER_REQUIRE(fiber_portFPCCR_REG == before->fpccr, 'E');", "(void)before;",
             ["init-change", "7"], "missing-panic"),
            ("recursive-allowed", "mutex", "if (fiber_port_tfm_mutex.owner == current)", "if (0)",
             ["mutex-basic"], "recursive"),
            ("foreign-release", "mutex", "(fiber_port_tfm_mutex.owner != current)",
             "((fiber_port_tfm_mutex.owner == NULL) || (current == NULL))",
             ["mutex-basic"], "foreign-release"),
            ("finite-yields", "mutex", "if (timeout != FIBER_PORT_TFM_OS_WRAPPER_WAIT_FOREVER)",
             "if (timeout == 123456789u)", ["mutex-basic"], "finite-contended"),
            ("owned-delete", "mutex", "(fiber_port_tfm_mutex.owner != NULL)", "(control == 99u)",
             ["mutex-basic"], "delete-owned"),
        ]
        for name, source, old, new, scenario, failure in mutants:
            d = self.build / ("mutant-" + name)
            d.mkdir()
            text = init if source == "init" else mutex
            require(text.count(old) == 1, "mutant anchor drift: " + name)
            changed = text.replace(old, new)
            exe = self.host_compile(d, changed if source == "init" else init,
                                    changed if source == "mutex" else mutex, ["-O2", "-flto"])
            result = self.run([exe, *scenario], "mutant " + name, allowed=True, timeout=5)
            require(not result["timeout"] and result["exit"] == 23 and
                    result["output"].strip() == "FAIL:" + failure,
                    "compiled mutant wrong failure: " + name + "\n" + result["output"])
            self.negatives.append(dict(name="compiled-host-" + name, exact_failure=failure))

    def classifier_controls(self):
        controls = [
            ("bad-exit", "import sys; print('PASS:C3FT-HOST:probe:1');sys.exit(2)"),
            ("missing", "pass"),
            ("duplicate", "print('PASS:C3FT-HOST:probe:1\\nPASS:C3FT-HOST:probe:1')"),
            ("crash", "import os;os._exit(99)"),
            ("timeout", "import time;time.sleep(10)"),
        ]
        for name, code in controls:
            result = self.run([sys.executable, "-B", "-c", code], "classifier " + name, allowed=True, timeout=0.5)
            expected_exits = {"bad-exit": 2, "missing": 0, "duplicate": 0, "crash": 99, "timeout": None}
            require(result["exit"] == expected_exits[name] and result["timeout"] == (name == "timeout"),
                    "classifier control did not reach intended exit: " + name)
            require(not self.host_pass(result, "probe"), "classifier false PASS: " + name)
            self.negatives.append(dict(name="classifier-" + name))
        require(self.host_pass(dict(exit=0, timeout=False, output="PASS:C3FT-HOST:probe:1\n"), "probe"),
                "classifier matching positive failed")

    def reference_clean(self, suffix):
        root = self.a.reference
        head = self.run(["git", "-C", root, "rev-parse", "HEAD"], "reference HEAD " + suffix)["output"].strip()
        status = self.run(["git", "-C", root, "status", "--porcelain", "--untracked-files=all"],
                          "reference status " + suffix)["output"].strip()
        write_json(self.build / ("reference-" + suffix + ".json"), dict(head=head, status=status))
        require(head == PIN and not status, "FreeRTOS reference must be pinned and tracked/untracked clean")

    def inputs(self):
        python_binary = Path(sys.executable)
        try:
            with python_binary.open("rb") as binary:
                binary.read(1)
        except OSError:
            # Windows Store app-execution aliases are launchable but not readable files.
            python_binary = Path(sys.base_prefix) / python_binary.name
        paths = {Path(__file__).resolve(), self.repo / "tools/test_cm33f_tfm.ps1", python_binary,
                 Path(self.a.arm_gcc), Path(self.a.host_gcc), *self.tools.values()}
        paths.add(self.repo / "tools/fixtures/portable_application.c")
        paths.add(self.repo / "tools/fixtures/arm_control/qemu.sh")
        if self.a.qemu_root:
            wsl = shutil.which("wsl.exe")
            require(wsl is not None, "explicit QEMU execution requires installed WSL")
            paths.add(Path(wsl).resolve())
        for directory, extensions in ((self.fixture, None), (self.port, None), (self.common, {".c", ".h"}),
                                      (self.common / "port", {".h"}), (Path(self.a.cmsis), {".h"})):
            for p in directory.iterdir():
                if p.is_file() and (extensions is None or p.suffix in extensions):
                    paths.add(p)
        paths.update(p for p in self.fixture.rglob("*") if p.is_file())
        paths.update((Path(self.a.reference) / "include").glob("*.h"))
        paths.update((Path(self.a.reference) / "portable/GCC/ARM_CM33_NTZ/non_secure").glob("*.h"))
        for old in ("ARM_CM33F_NTZ", "ARM_CM33_TFM", "ARM_CM55_TFM"):
            paths.update(self.common / "port" / old / "non_secure" / name
                         for name in ("fiber_port_types.h", "fiber_port_boot_types.h"))
        for relative in ("portable/GCC/ARM_CM33_NTZ/non_secure/port.c",
                         "portable/GCC/ARM_CM33_NTZ/non_secure/portasm.c",
                         "portable/ThirdParty/GCC/ARM_TFM/README.md",
                         "portable/ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c"):
            p = Path(self.a.reference) / relative
            require(p.is_file(), "missing actual pinned reference input " + str(p))
            paths.add(p)
        for cc in (self.a.arm_gcc, self.a.host_gcc):
            for name in ("cc1", "cc1plus", "lto1", "lto-wrapper", "as", "ld", "collect2"):
                p = Path(self.run([cc, "-print-prog-name=" + name], "resolve compiler " + name)["output"].strip())
                if not p.is_file():
                    located = shutil.which(str(p))
                    require(located is not None, "missing compiler executable " + str(p))
                    p = Path(located)
                paths.add(p.resolve())
            includes = Path(self.run([cc, "-print-file-name=include"], "resolve compiler include")["output"].strip())
            paths.update(includes.rglob("*.h"))
        target_include = self.bin.parent / "arm-none-eabi/include"
        paths.update(target_include.rglob("*.h"))
        # MinGW's public C headers live outside GCC's internal include directory.
        host_include = Path(self.a.host_gcc).parent.parent / "include"
        require(host_include.is_dir(), "host GCC public include directory missing")
        paths.update(host_include.rglob("*.h"))
        paths.add(Path(shutil.which("git")).resolve())
        self.input_paths = sorted({p.resolve() for p in paths}, key=str)
        require(all(p.is_file() for p in self.input_paths),
                "missing input file: " + repr([str(p) for p in self.input_paths if not p.is_file()]))
        return {str(p): digest(p) for p in self.input_paths}

    def execute(self):
        require(not sys.flags.optimize, "optimized Python unsupported; proof must not drop assertions")
        before, after = None, None
        reference_error = None
        success = False
        try:
            self.reference_clean("before")
            before = self.inputs()
            write_json(self.build / "inputs.before.json", before)
            snapshots = self.build / "consumed-documents"
            snapshots.mkdir()
            documents = []
            for path in self.input_paths:
                if path.suffix.lower() != ".md":
                    continue
                target = snapshots / (hashlib.sha256(str(path).encode()).hexdigest().upper()[:12] + "-" + path.name)
                target.write_bytes(path.read_bytes())
                require(digest(target) == before[str(path)], "consumed document drift during snapshot")
                documents.append(dict(source=str(path), sha256=before[str(path)], snapshot=str(target.relative_to(self.build))))
            write_json(snapshots / "index.json", documents)
            for compiler in (self.a.arm_gcc, self.a.host_gcc):
                self.run([compiler, "--version"], "compiler version")
            require(self.a.expected_runtime_selectable == 0, "C3FT remains staged; runtime expectation must be 0")
            provenance = json.loads((self.fixture / "provenance.json").read_text())
            for snapshot in provenance["snapshots"]:
                require(hashlib.sha256(snapshot["snapshot_text"].encode("utf-8")).hexdigest().upper() == snapshot["sha256"],
                        "progenitor snapshot bytes/hash mismatch: " + snapshot["path"])
            self.runtime_manifest()
            self.reference()
            self.target()
            self.host()
            self.hostile()
            if self.a.qemu_root:
                from execution import Execution
                execution = Execution(self)
                try:
                    self.execution = execution.execute()
                except Exception:
                    self.execution = dict(status="FAIL", receipt=str(execution.root / "execution.receipt.json"))
                    raise
            else:
                print("C3FT actual execution NOT_RUN: explicit -QemuRoot required", flush=True)
            success = True
        finally:
            if before is not None:
                try:
                    self.reference_clean("after")
                except Exception as error:
                    reference_error = str(error)
                after = {str(p): digest(p) if p.is_file() else None for p in self.input_paths}
                write_json(self.build / "inputs.after.json", after)
            write_json(self.build / "commands.json", self.commands)
            write_json(self.build / "receipt.json", dict(success=success and before == after and reference_error is None,
                target_positives=self.positives, negatives=self.negatives, host_runs=self.host_runs,
                role_proofs=self.role_proofs, role_definitions=self.role_definitions,
                portable_application=self.portable_runs, constructor_archives=self.constructor_archives,
                default_policies=self.default_policies,
                reference_objects=self.reference_objects, hostile_objects=self.hostile_objects,
                execution=self.execution,
                proof_scope="Staged M33 FP public/default-policy/archive/host proof with explicit optional modeled CPU execution",
                input_count=len(before or {}), drift=[] if before == after else
                    [p for p in before or {} if before[p] != (after or {}).get(p)],
                boundary=("Actual M33 NS common/FP execution with test-only Secure bootstrap and typed NS TF-M provider. No real Secure TF-M image or board proof."
                    if self.execution.get("status") == "PASS" else
                    "M33 compile/link, raw hostile objects and source-derived host adapter tests. Actual execution NOT_RUN or failed; no real Secure TF-M or board proof."),
                reference_pin=PIN, reference_error=reference_error,
                runtimeSelectable=self.verified_runtime_selectable,
                expectedRuntimeSelectable=self.a.expected_runtime_selectable, forward_count=8))
            hashes = {str(p.relative_to(self.build)): digest(p) for p in self.build.rglob("*") if p.is_file()}
            write_json(self.build / "artifacts.sha256.json", hashes)
        require(before == after, "recorded input drift: failed qualification")
        require(reference_error is None, "reference final qualification failed: " + str(reference_error))
        print("PASS C3FT: " +
              "%d target ELFs, %d negatives, %d source-derived host scenarios, %d inputs, drift0" %
              (len(self.positives), len(self.negatives), len(self.host_runs), len(before)), flush=True)



def main():
    parser = argparse.ArgumentParser()
    for name in ("repo", "arm-gcc", "host-gcc", "cmsis", "reference", "build"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--expected-runtime-selectable", type=int, choices=(0, 1), default=0)
    parser.add_argument("--qemu-root")
    parser.add_argument("--wsl-distro", default="Ubuntu-24.04")
    args = parser.parse_args()
    proof = Proof(args)
    try:
        proof.execute()
    except Exception as error:
        print("FAIL C3FT: " + str(error), file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
