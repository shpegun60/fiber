"""Dual-ABI M55 constructor and bounded real SVC/PendSV R9 execution."""
import json
from pathlib import Path
import re
import shutil
import struct

SEEDS = (0x13579BDF, 0x2468ACE1, 0x90ABCDEF, 0x0BADCAFE)
HOSTILE = ("-finstrument-functions", "-fstack-protector-all", "-fprofile-arcs", "-ftest-coverage",
           "-fsanitize=undefined", "-fsanitize-coverage=trace-pc")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def reserved_hooks(image):
    """Exact bytes: reserved hooks read R9, never borrow or restore-write it."""
    for name, target in (("fiber_addr_plausible_ram", "r9_hook_ram"),
                         ("fiber_addr_plausible_code", "r9_hook_code")):
        symbol = image.one(name)
        begin = symbol["value"] & ~1
        code = image.at(begin, symbol["size"])
        require(len(code) == 10 and code[:4] == bytes.fromhex("10b54a46") and
                code[-2:] == bytes.fromhex("10bd"), "reserved hook writes/borrows R9: " + name)
        first, second = struct.unpack("<HH", code[4:8])
        require(first & 0xf800 == 0xf000 and second & 0xd000 == 0xd000,
                "reserved hook must call its C boundary with one Thumb BL")
        sign, j1, j2 = (first >> 10) & 1, (second >> 13) & 1, (second >> 11) & 1
        offset = (sign << 24) | ((1 ^ j1 ^ sign) << 23) | ((1 ^ j2 ^ sign) << 22) | \
                 ((first & 0x3ff) << 12) | ((second & 0x7ff) << 1)
        if sign:
            offset -= 1 << 25
        require(begin + 8 + offset == image.one(target)["value"] & ~1,
                "reserved hook calls wrong C boundary")


def run_r9(p, Elf):
    wsl = shutil.which("wsl.exe")
    require(wsl is not None, "R9 effect probe needs existing WSL; no automatic provisioning")
    root = p.build / "r9-effect"
    root.mkdir()
    script = root / "qemu.sh"
    script.write_text((p.repo / "tools/fixtures/arm_control/qemu.sh").read_text(), encoding="ascii", newline="\n")
    prefix = [wsl, "-d", p.a.wsl_distro, "--exec"]

    def linux(path):
        return p.run([*prefix, "wslpath", "-a", "-u", str(path).replace("\\", "/")], "R9 WSL path")["output"].strip()

    linux_script = linux(script)

    def inspect(label):
        directory = root / label
        directory.mkdir()
        p.run([*prefix, "bash", linux_script, "inspect", p.a.qemu_root, linux(directory)], "R9 QEMU inspect " + label)
        ldd = (directory / "qemu-ldd.txt").read_text()
        libraries = re.findall(r"(?:=>\s+|^\s*)(/\S+)\s+\(0x[0-9a-f]+\)", ldd, re.M)
        files = sorted(set(libraries + [p.a.qemu_root.rstrip("/") + "/usr/bin/qemu-system-arm"]))
        hashes = p.run([*prefix, "sha256sum", *files], "R9 actual QEMU/loader libraries " + label)["output"]
        (directory / "executables.sha256.txt").write_text(hashes)
        require("mps3-an547" in (directory / "qemu-machines.txt").read_text(), "existing QEMU has no M55 AN547 model")
        return hashes

    before = inspect("tools-before")
    cases, failures = [], []
    nvic_bits = 3

    def build_case(name, optimization, lto, hostile, reserved, mutant=None, probe=False):
        d = root / name
        d.mkdir()
        fixed = ["-ffixed-r9"] if reserved else []
        options = [optimization] + (["-flto"] if lto else []) + fixed
        objects = []
        for source in p.common_sources + p.sources:
            actual = source
            if mutant == "caller-r9-scratch" and source.name == "fiber_core.c":
                text = source.read_text()
                call = "fiber_port_context_init(ctx, stack_begin, stack_end, entry, arg);"
                require(text.count(call) == 1, "R9 caller mutant anchor drift")
                text = text.replace(call,
                    'register uint32_t scratch __asm("r9") = 0xdeadc0deu;\n\t'
                    '__asm volatile("" : "+r"(scratch) :: "memory");\n\t' + call + '\n\t'
                    '__asm volatile("" : "+r"(scratch) :: "memory");')
                actual = d / source.name
                actual.write_text(text)
            if mutant == "caller-r9-broken" and source.name == "fiber_core.c":
                text = source.read_text()
                call = "fiber_port_context_init(ctx, stack_begin, stack_end, entry, arg);"
                require(text.count(call) == 1, "R9 caller-preservation mutant anchor drift")
                # Deliberately violate AAPCS: omit the R9 clobber/preservation declaration.
                text = text.replace(call, '__asm volatile("mov r9, %0" :: "r"(0xdeadc0deu) : "memory");\n\t' + call)
                actual = d / source.name
                actual.write_text(text)
            if mutant == "wrong-frame-r9" and source.name == "fiber_port.c":
                text = source.read_text()
                read = "frame[fiber_portFRAME_R9] = initial_r9;"
                require(text.count(read) == 1, "R9 frame mutant anchor drift")
                actual = d / source.name
                actual.write_text(text.replace(read, "frame[fiber_portFRAME_R9] = initial_r9 ^ (initial_r9 ^ 0xdeadc0deu);"))
            if mutant in ("wrong-saved-r9", "wrong-restored-r9") and source.name == "fiber_port.c":
                text = source.read_text()
                split = "void PendSV_Handler(void)"
                require(text.count(split) == 1, "R9 real PendSV mutant anchor drift")
                head, body = text.split(split)
                anchor = ('"stmdb r0!, {r2-r11}                    \\n"' if mutant == "wrong-saved-r9" else
                          '"ldmia r0!, {r2-r11}                    \\n"')
                require(body.count(anchor) == 1, "R9 transfer instruction mutant anchor drift")
                corrupt = ('\n\t\t\t"movw r2, #0xc0de \\n"\n\t\t\t"movt r2, #0xdead \\n"\n'
                           '\t\t\t"str r2, [r0, #28] \\n"' if mutant == "wrong-saved-r9" else
                           '\n\t\t\t"movw r9, #0xc0de \\n"\n\t\t\t"movt r9, #0xdead \\n"')
                actual = d / source.name
                actual.write_text(head + split + body.replace(anchor, anchor + corrupt))
            obj = d / (source.stem + ".o")
            common = source in p.common_sources
            p.compile(actual, obj, options, selected=not common, cpu=not common,
                      extra=["-D__NVIC_PRIO_BITS=" + str(nvic_bits)] + (list(HOSTILE) if hostile else []))
            p.evidence(obj)
            objects.append(obj)
        # Test-only instrumentation/coverage/trap boundaries never inherit hostile flags.
        for filename in ("r9_secure.c", "r9_effect.c", "memory.c"):
            obj = d / (Path(filename).stem + ".o")
            extra = ["-D__NVIC_PRIO_BITS=" + str(nvic_bits)] + (["-mcmse"] if filename == "r9_secure.c" else [])
            if hostile and filename == "r9_effect.c":
                extra += ["-DR9_HOSTILE=1"]
            if reserved:
                extra += ["-DR9_RESERVED=1"]
            if probe and filename == "r9_effect.c":
                extra += ["-DR9_MODEL_PROBE=1"]
            fixture_options = [optimization, *fixed] if hostile or filename == "r9_secure.c" else options
            p.compile(p.fixture / filename, obj, fixture_options, selected=filename == "r9_effect.c",
                      cpu=filename != "memory.c", extra=extra)
            objects.append(obj)
        startup = d / "r9_startup.o"
        p.run([p.a.arm_gcc, *p.flags[:3], *fixed, *(["-DR9_RESERVED=1"] if reserved else []),
               "-c", p.fixture / "r9_startup.S", "-o", startup], "R9 seed/bootstrap assembly")
        objects.append(startup)
        elf = d / "r9.elf"
        p.run([p.a.arm_gcc, *p.flags[:3], *options, *(HOSTILE if hostile else []),
               "-nostdlib", "-Wl,--gc-sections", "-Wl,--no-undefined",
               "-Wl,--fatal-warnings", "-T", p.fixture / "r9.ld", "-Wl,-Map=" + str(elf) + ".map",
               *objects, "-o", elf], "R9 actual complete-group ELF " + name)
        outputs = p.evidence(elf)
        image = Elf(elf)
        require(image.one("r9_secure_main")["value"] < 0x10000 and
                0x10000 <= image.one("r9_ns_reset")["value"] < 0x20000,
                "R9 fixture bootstrap/NS placement is wrong")
        if not probe:
            for function in ("fiber_init", "fiber_port_context_init", "fiber_port_init_context_frame", "r9_call_init"):
                image.one(function)
            if reserved:
                reserved_hooks(image)
        require('Tag_CPU_name: "cortex-m55"' in outputs["attributes"], "R9 target is not actual M55")
        for handler, index in (("SVC_Handler", 11), ("PendSV_Handler", 14)):
            s = image.one(handler)
            require(s["bind"] == 1 and struct.unpack("<I", image.at(0x10000 + index * 4, 4))[0] == s["value"],
                    "R9 fixture shadowed actual strong handlers")
        # Assembly seed wrapper and real symbol must be present even with whole-program LTO.
        actual = p.run([*prefix, "bash", linux_script, "run", p.a.qemu_root, linux(d),
                        "mps3-an547", linux(elf), "8"], "R9 actual M55 execution " + name, timeout=25, allowed=True)
        if probe:
            m = re.fullmatch(r"MODEL:C5TF:PRIORITY=([0-9A-F]{8})\r?\nPASS:C5TF-R9:MODEL\r?\n", actual["output"])
            require(not actual["timeout"] and actual["exit"] == 0 and m is not None, "R9 independent model probe failed: " + actual["output"])
            mask = int(m[1], 16)
            bits = mask.bit_count()
            require(1 <= bits <= 8 and mask == ((0xff << (8 - bits)) & 0xff), "R9 model has invalid implemented priority mask")
            p.r9_model = dict(priority_mask=mask, nvic_priority_bits=bits, elf=str(elf), output=actual["output"])
            print("C5TF actual M55 model priority mask=%02X bits=%d" % (mask, bits), flush=True)
            return bits
        record = dict(name=name, elf=str(elf), optimization=optimization, lto=lto, hostile=hostile,
                      nvic_priority_bits=nvic_bits,
                      abi_mode="reserved" if reserved else "ordinary", fixed_r9=reserved, control=mutant,
                      hostile_flags=list(HOSTILE) if hostile else [], output=actual["output"], exit=actual["exit"],
                      scope="Real NS construction, first SVC and four PendSV transfers; typed TF-M initializer only, no Secure TF-M service")
        cases.append(record)
        output = actual["output"].replace("\r\n", "\n")
        if mutant == "wrong-frame-r9":
            m = re.fullmatch(r"PANIC:C5TF-R9:code=00000039 caller=([0-9A-F]{8}) frame=DEADC0DE IPSR=00000000\n", output)
            constructor = image.one("fiber_port_context_init")
            begin = constructor["value"] & ~1
            require(not actual["timeout"] and actual["exit"] == 47 and m is not None and
                    begin <= (int(m[1], 16) & ~1) < begin + constructor["size"],
                    "reserved wrong-seed mutant must hit exact constructor consistency panic9: " + output)
            p.negatives.append(dict(name="r9-reserved-wrong-frame", exact_failure="constructor panic9", no_caller_resume=True))
        elif mutant in ("caller-r9-broken", "wrong-saved-r9", "wrong-restored-r9"):
            expected_id = {"caller-r9-broken": "RETURN-R9", "wrong-saved-r9": "SAVED-R9",
                           "wrong-restored-r9": "INITIAL-RESTORE-R9"}[mutant]
            rows = list(re.finditer(r"R9:C5TF:seed=([0-9A-F]{8}) frame=([0-9A-F]{8}) post=([0-9A-F]{8})\n", output))
            count = 1 if mutant == "caller-r9-broken" else 4
            report_prefix = "".join(row[0] for row in rows)
            constructor_ok = (len(rows) == count and output.startswith(report_prefix) and
                              all(int(row[1], 16) == seed and int(row[3], 16) ==
                                  (0xdeadc0de if mutant == "caller-r9-broken" else seed)
                                  for row, seed in zip(rows, SEEDS)))
            tail = ""
            if constructor_ok and mutant != "caller-r9-broken":
                tail = "ENTER:C5TF:owner=00000000 r9=%08X\n" % int(rows[0][2], 16)
                if mutant == "wrong-restored-r9":
                    tail += "SAVE:C5TF:owner=00000000 r9=A19A19A1\n"
            tail += "FAIL:C5TF-R9:" + expected_id + "\n"
            require(not actual["timeout"] and actual["exit"] == 43 and constructor_ok and
                    output == report_prefix + tail,
                    "ordinary R9 compiled mutant hit wrong failure: " + name + "\n" + output)
            p.negatives.append(dict(name="r9-ordinary-" + mutant, exact_failure=expected_id))
        else:
            rows = list(re.finditer(r"R9:C5TF:seed=([0-9A-F]{8}) frame=([0-9A-F]{8}) post=([0-9A-F]{8})\n", output))
            frames = [int(row[2], 16) for row in rows]
            constructor_ok = (len(rows) == 4 and rows[0].start() == 0 and
                              all(rows[n].end() == rows[n + 1].start() for n in range(3)) and
                              all(int(row[1], 16) == seed and int(row[3], 16) == seed and
                                  (not reserved or int(row[2], 16) == seed) for row, seed in zip(rows, SEEDS)))
            live = SEEDS[:2] if reserved else (0xA19A19A1, 0xB29B29B2)
            tail = ""
            if constructor_ok:
                for event, owner in (("ENTER", 0), ("SAVE", 0), ("ENTER", 1), ("SAVE", 1),
                                     ("RESTORE", 0), ("SAVE", 0), ("RESTORE", 1), ("SAVE", 1), ("RESTORE", 0)):
                    value = frames[owner] if event == "ENTER" else live[owner]
                    tail += "%s:C5TF:owner=%08X r9=%08X\n" % (event, owner, value)
                tail += "PASS:C5TF-R9:%s:4-SEEDS:4-PENDSV\n" % ("RESERVED" if reserved else "ORDINARY")
            passed = (not actual["timeout"] and actual["exit"] == 0 and constructor_ok and
                      output[rows[-1].end():] == tail)
            record["pass"] = passed
            if not passed:
                failures.append(name)
                p.r9_failures.append(record)
                print("C5TF actual M55 R9 FAIL " + name + ": " + actual["output"].strip(), flush=True)
            else:
                (p.r9_compatibility_controls if mutant else p.r9_runs).append(record)
        negative = mutant is not None and mutant != "caller-r9-scratch"
        if negative or record.get("pass"):
            label = "mutant rejected " if negative else ("compatibility PASS " if mutant else "PASS ")
            print("C5TF actual M55 R9 " + label + name, flush=True)

    try:
        nvic_bits = build_case("model-probe", "-O2", False, False, False, probe=True)
        for reserved in (False, True):
            for hostile in (False, True):
                for optimization in ("-O2", "-Os"):
                    for lto in (False, True):
                        name = ("reserved-" if reserved else "ordinary-") + optimization[1:].lower() + ("-lto" if lto else "") + ("-hostile" if hostile else "")
                        build_case(name, optimization, lto, hostile, reserved)
        require(all(any(case["name"] == mode + "-o2" and case.get("pass") for case in cases)
                    for mode in ("ordinary", "reserved")),
                "R9 negative controls require both matching native-O2 positives")
        build_case("ordinary-legal-caller-scratch", "-O2", False, False, False, "caller-r9-scratch")
        build_case("reserved-mutant-wrong-frame", "-O2", False, False, True, "wrong-frame-r9")
        build_case("ordinary-mutant-caller-preservation", "-O2", False, False, False, "caller-r9-broken")
        build_case("ordinary-mutant-save", "-O2", False, False, False, "wrong-saved-r9")
        build_case("ordinary-mutant-restore", "-O2", False, False, False, "wrong-restored-r9")
    finally:
        after = inspect("tools-after")
        (root / "receipt.json").write_text(json.dumps(dict(cases=cases, failures=failures, tool_drift=before != after,
            boundary="Dual-ABI QEMU mps3-an547 NS constructor and bounded SVC/PendSV R9 transfers; not real Secure TF-M"), indent=2) + "\n")
        require(before == after, "R9 QEMU/loader tool drift")
    require(not failures, "actual M55 dual-ABI R9 failure(s): " + ", ".join(failures))
