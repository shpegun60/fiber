"""Shared audited ELF construction for the bounded CM4 MPU basic grid."""
from __future__ import annotations
from collections import Counter
import importlib.util
from pathlib import Path
import re
import struct
import sys

HERE = Path(__file__).resolve().parent
COHORT = ("fiber_port_context_cohort_armv7em_p0x434D344Du_l0x00020008u_f1_e1_h1_j1_v1_"
          "d0_r0_z8u_y1_w2_g8_u10000000_i0_o0xFFFFFFFDu_c1_s0_x0_m0_a0_b0_t0_n0_k0_q0")
MODES = (("O2", False), ("O2", True), ("Os", False), ("Os", True))
GRID = tuple((c, o, l, a) for c in ("context", "fiber") for o, l in MODES for a in (False, True))

def load(name, path):
    if name in sys.modules:
        raise RuntimeError("Unexpected preloaded local module: " + name)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

pilot = load("cm4_mpu_basic_pilot_tools", HERE.parent / "classic_cm4_mpu_context_runtime/run.py")
fp, common = pilot.fp, pilot.common
need, save, digest = common.need, common.save, common.digest

def basic_terminal(actual, consumer, case, addresses):
    if case in (1, 2):
        return pilot.terminal(actual, consumer, case, addresses)
    lines = pilot.semihost_lines(actual)
    if case != 0 or consumer not in ("context", "fiber") or lines is None or len(lines) != 3:
        return False
    label = "CONTEXT" if consumer == "context" else "FIBERV1"
    match = re.fullmatch(r"RETURN:CM4-MPU:CODE=00000052:IPSR=0000000B:PC=([0-9A-F]{8}):PSP=([0-9A-F]{8}):XPSR=([0-9A-F]{8}):CALLS=00000020:SELF=00000001:CROSS=0000001E", lines[0])
    return bool(match and int(match[1], 16) == addresses["return"] and pilot.frame_in_worker_a(int(match[2], 16), int(match[3], 16)) and
        lines[1] == "STRESS:CM4-MPU:R4-R11=0000000F:SP=0000000F:COOKIES=0000001E:PUBLIC=00000010:DIRECT=0000000F" and
        lines[2] == "PASS:CM4-MPU:" + label)

def basic_terminal_controls():
    records = []
    for consumer, label in (("context", "CONTEXT"), ("fiber", "FIBERV1")):
        text = ("RETURN:CM4-MPU:CODE=00000052:IPSR=0000000B:PC=00001010:PSP=20002FC0:XPSR=01000000:CALLS=00000020:SELF=00000001:CROSS=0000001E\n"
                "STRESS:CM4-MPU:R4-R11=0000000F:SP=0000000F:COOKIES=0000001E:PUBLIC=00000010:DIRECT=0000000F\nPASS:CM4-MPU:" + label + "\n")
        good = dict(Exit=0, TimedOut=False, Stdout="", Stderr=text)
        tests = [("positive", good, True), ("timeout", dict(good, TimedOut=True), False),
            ("exit", dict(good, Exit=66), False), ("exit-type", dict(good, Exit=False), False),
            ("stdout", dict(good, Stdout=text, Stderr=""), False),
            ("split", dict(good, Stdout=text.splitlines()[0]+"\n", Stderr="\n".join(text.splitlines()[1:])+"\n"), False),
            ("generic", dict(good, Stderr="HardFault\n"), False),
            ("padding-overflow", dict(good, Stderr=text.replace("PSP=20002FC0:XPSR=01000000", "PSP=20002FE0:XPSR=01000200")), False)]
        for name, before, after in (("sp", "SP=0000000F", "SP=0000000E"), ("cookie", "COOKIES=0000001E", "COOKIES=00000000"),
            ("gpr", "R4-R11=0000000F", "R4-R11=00000000"), ("direct", "DIRECT=0000000F", "DIRECT=00000000"),
            ("public", "PUBLIC=00000010", "PUBLIC=00000000"), ("calls", "CALLS=00000020", "CALLS=00000008"),
            ("origin", "IPSR=0000000B", "IPSR=00000003"), ("pc", "PC=00001010", "PC=00001020")):
            tests.append((name, dict(good, Stderr=text.replace(before, after)), False))
        for name, actual, accepted in tests:
            need(basic_terminal(actual, consumer, 0, {"return": 0x1010}) is accepted, "Basic-grid terminal discriminator: " + name)
            records.append(dict(Consumer=consumer, Name=name, Accepted=accepted))
    need(len(records) == 32, "Literal synthetic terminal controls")
    return dict(Controls=records, Scope="Synthetic terminal discriminators, not observed execution")

class Engine(pilot.Pilot):
    def flags_for(self, consumer, case, opt, lto, model=False):
            flags = pilot.Pilot.flags(self, consumer, case, model)
            need(flags.count("-O2") == 1, "Copied pilot optimization shape changed")
            return ["-" + opt if f == "-O2" else f for f in flags] + (["-flto"] if lto else [])

    def mutation(self, original, name, directory):
            text = original.read_text()
            if name in ("no-save-r4", "no-save-r9"):
                anchor = "void PendSV_Handler(void)"
                need(text.count(anchor) == 1, "PendSV-only mutation boundary")
                head, body = text.split(anchor)
                pattern = r'"stmia\s+r1!,\s*\{r3-r11, lr\}\s+\\n"'
                replacement = ('"str r3, [r1], #4 \\n"\n"add r1, r1, #4 \\n"\n"stmia r1!, {r5-r11, lr} \\n"'
                    if name == "no-save-r4" else
                    '"stmia r1!, {r3-r8} \\n"\n"add r1, r1, #4 \\n"\n"stmia r1!, {r10-r11, lr} \\n"')
                body, count = re.subn(pattern, lambda _: replacement, body)
                need(count == 1, "Exact raw-save mutation count")
                changed = head + anchor + body
                need(changed.split(anchor)[0] == head, "Mutation changed first-SVC or prefix")
            elif name == "no-svc71":
                anchor = '"svc   #" fiber_portSTRINGIFY(fiber_portSVC_YIELD) " \\n"'
                need(text.count(anchor) == 1, "Exact SVC71 mutation")
                changed = text.replace(anchor, '"nop \\n"')
            else:
                anchor = {"no-slot-store": "str r1,[r0]", "no-peer-load": "ldr r0,[r0]", "no-oracle-r9": "cmp r9,r2"}[name]
                need(text.count(anchor) == 1, "Exact fixture omission count")
                changed = text.replace(anchor, "nop")
            target = directory / ("mutant-" + original.name)
            target.write_text(changed, encoding="ascii", newline="\n")
            self.generated[str(target.resolve())] = dict(Path=str(target.resolve()), Sha256=digest(target), Role="TempCompiledOmission")
            record = dict(Name=name, Original=str(original), OriginalSha256=digest(original), Mutated=str(target),
                MutatedSha256=digest(target), Scope="Compiled actual copied source omission; save omissions retain the 40-byte CONTROL/GPR/EXC_RETURN geometry")
            save(directory / "mutation.json", record)
            self.generated_mutations.append(record)
            return target

    def compile_units(self, sources, directory, flags, providers, mutant=None):
            objects, maps = [], []
            for index, original in enumerate(sources):
                need(str(original.resolve()) in self.inputs, "Source not enrolled before compilation")
                applies = mutant and ((mutant in ("no-save-r4", "no-save-r9", "no-svc71") and original == providers[0]) or
                    (mutant in ("no-slot-store", "no-peer-load") and original.name == "access.S") or
                    (mutant == "no-oracle-r9" and original.name == "stress.S"))
                source = self.mutation(original, mutant, directory) if applies else original
                obj = directory / ("%02d-" % index + original.stem + ".o")
                dep = obj.with_suffix(".d")
                result = self.command([self.tools["gcc"], *flags, "-I" + str(original.parent),
                    "-MD", "-MF", dep, "-c", source, "-o", obj], "compile prototype actual source")
                need("warning:" not in result["Stderr"], "Compiler warning in prototype")
                self.dependency_check(dep)
                role = ("port" if original in providers else "expectation" if original.name == "fiber_port_context_cohort_expectation.c"
                    else "fixture" if original.is_relative_to(self.fixture) else "common")
                maps.append(dict(Original=str(original), Compiled=str(source), SourceSha256=digest(source), Object=str(obj),
                    ObjectSha256=digest(obj), Command=result["Record"], Role=role))
                objects.append(obj)
            save(directory / "source-object-map.json", maps)
            return objects, maps

    def audit_basic(self, image, consumer, case, lto, proof, model):
            address = lambda n: image.symbol(n, local=True)["Address"] & ~1
            attrs = image.path.with_suffix(".readelf.txt").read_text()
            need(fp.capability_matches(fp.CM4, attrs, pilot.CPU), "Wrong hard-float CM4 capability")
            need(image.sections[".boot_vectors"]["Address"] == 0 and image.sections[".boot_vectors"]["Size"] == 8 and
                 image.sections[".isr_vector"]["Address"] == 0x400 and image.sections[".isr_vector"]["Size"] == 1024 and
                 image.sections[".privileged_code"]["Address"] == 0x800, "Bootstrap/active/privileged code placement")
            words = struct.unpack("<256I", image.sections[".isr_vector"]["Data"])
            need(words[:2] == struct.unpack("<2I", image.sections[".boot_vectors"]["Data"]) and words[0] == 0x20010000 and
                 words[1] == image.symbol("Reset_Handler", "STT_FUNC")["Address"] and words[1] & 1 and
                 words[4] == image.symbol("MemManage_Handler", "STT_FUNC")["Address"], "Exact boot/reset/fault vectors")
            if model:
                return dict(ModelProbe=True, ActualCpuFacts="NOT_RUN", NoRuntimeProviders=True)
            for n in (*common.PUBLIC, *common.FORWARD, "SVC_Handler", "PendSV_Handler"):
                image.symbol(n, "STT_FUNC")
            need(words[11] == image.symbol("SVC_Handler")["Address"] and words[14] == image.symbol("PendSV_Handler")["Address"] and
                 words[11] & words[14] & 1, "Strong actual Thumb SVC/PendSV vectors")
            admitted = {}
            for n, original in ((common.SLOT, "state"), (common.REVERSE, "state"), (common.CONFIG_ANCHOR, "optional_configuration")):
                if n == common.CONFIG_ANCHOR and consumer == "context":
                    need(n not in image.symbols, "Pure Context consumed configuration")
                    continue
                matches = image.symbols.get(n, [])
                need(len(matches) == 1 and matches[0]["Kind"] == "STT_OBJECT" and matches[0]["Size"] > 0 and
                     common.binding_admitted(n, "STT_OBJECT", matches[0]["Binding"], lto, proof) and
                     n in proof and proof[n]["Source"] == str(self.reader.get_runtime_source_paths(self.repo, (original,))[0]),
                     "Exact actual prelink owner required before private final-LTO LOCAL admission")
                admitted[n] = matches[0]
            slot = admitted[common.SLOT]
            need(slot["Address"] == 0x20000000 and slot["Size"] == 4 and slot["Section"] == ".current_slot" and
                 image.sections[".current_slot"]["Size"] == 32, "Exact isolated current aperture")
            cohorts = [n for n in image.symbols if n.startswith("fiber_port_context_cohort_arm")]
            need(cohorts == [COHORT], "Exact fixed hash/map00 eager CM4 MPU8 cohort")
            storage = [n for n in image.symbols if n.startswith("fiber_port_storage_cohort_") and
                       not re.fullmatch(r"fiber_port_storage_cohort_consumer_expectation(?:\.lto_priv\.\d+)?", n)]
            need(storage == [pilot.STORAGE], "Exact public MPU8 storage cohort")
            image.symbol(COHORT, "STT_OBJECT")
            image.symbol(pilot.STORAGE, "STT_OBJECT")
            expectation = image.sections[".fiber_port_context_cohort_expectation"]
            count = 3 if consumer == "fiber" else 2
            need(expectation["Size"] == 4 * count and not expectation["Flags"] & 5 and
                 Counter(struct.unpack("<" + str(count) + "I", expectation["Data"])) ==
                 Counter({image.symbol(COHORT)["Address"]: 1, image.symbol(pilot.STORAGE)["Address"]: count - 1}),
                 "Exact external readonly expectation pointers/multiplicity")
            need(not set(common.LEGACY) & set(image.symbols), "Legacy substitution")
            if consumer == "fiber":
                for n in ("fiber_v1_init", "fiber_v1_current", "fiber_v1_yield", "fiber_v1_start", "fiber_v1_set_scheduler"):
                    image.symbol(n, "STT_FUNC")
            else:
                need(not any(n.startswith("fiber_v1_") for n in image.symbols), "Pure Context lifecycle substitution")
            roots = image.symbol("fixture_public_api_roots", "STT_OBJECT")
            root_names = ("fiber_v1_init", "fiber_v1_current", "fiber_v1_set_scheduler", "fiber_v1_start", "fiber_v1_yield") if consumer == "fiber" else common.PUBLIC
            need(roots["Size"] == 20 and not image.sections[roots["Section"]]["Flags"] & 1 and
                 struct.unpack("<5I", image.bytes(roots)) == tuple(image.symbol(n, "STT_FUNC")["Address"] for n in root_names),
                 "Readonly fixture roots must resolve the five actual GLOBAL public functions")
            closure = image.no_fp_closure(["fixture_task_entry"])
            need(all(0x10000 <= address(n) < 0x20000 for n in closure), "Thread GRO closure escaped user code")
            metadata = image.symbol("workers", "STT_OBJECT", local=True)
            need(0x20008000 <= metadata["Address"] < metadata["Address"] + metadata["Size"] <= 0x2000e000, "Workers metadata not privileged")
            need(image.sections[".stack0"]["Address"] == 0x20002000 and image.sections[".stack0"]["Size"] == 4096 and
                 image.sections[".stack1"]["Address"] == 0x20004000 and image.sections[".stack1"]["Size"] == 4096, "Exact disjoint worker stacks")
            return dict(AllEightActualProviders=True, ExactVectors=True, ExactCohort=COHORT, ExternalExpectation=True,
                ActualPrivateOwners=admitted, NoFpThreadClosure=closure, ExternalReadonlyPublicApiRoots=root_names,
                Addresses={"return": address("fiber_port_svc_return_return_site"),
                "slot": address("fixture_slot_write_access"), "peer": address("fixture_peer_read_access")})

    def audit_mechanisms(self, image):
            def body(n):
                return [i for i in image.body(n) if not image.is_data(i, n)]
            def operands(i):
                return re.sub(r"\s+", "", i["Operands"].split("@")[0]).lower()
            schedule = body("fiber_port_runtime_schedule")
            need(len(schedule) == 2 and schedule[0]["Mnemonic"] == "svc" and
                 re.fullmatch(r"#?(?:71|0x0*47)", operands(schedule[0])) and
                 schedule[1]["Mnemonic"] == "bx" and operands(schedule[1]) == "lr", "SVC71_OPCODE")
            pd = body("PendSV_Handler")
            need(any(i["Mnemonic"].split(".")[0] == "stmia" and operands(i) == "r1!,{r3,r4,r5,r6,r7,r8,r9,r10,r11,lr}" for i in pd),
                 "PENDSV_RAW_SAVE_TRANSFER")
            for symbol, mnemonic, expected, reason in (("fixture_slot_write_access", "str", "r1,[r0,#0]", "FAULT_SLOT_OPCODE"),
                    ("fixture_peer_read_access", "ldr", "r0,[r0,#0]", "FAULT_PEER_OPCODE")):
                pc = image.symbol(symbol)["Address"] & ~1
                found = [i for i in image.dis if i["Address"] == pc]
                need(len(found) == 1 and found[0]["Mnemonic"] == mnemonic and operands(found[0]) == expected, reason)
            stress = body("fixture_register_stress")
            calls = [i for i in stress if fp.control_form(i) == ("call", image.symbol("fiber_port_runtime_schedule")["Address"] & ~1)]
            need(len(calls) == 1, "DIRECT_REAL_SVC_CALL")
            by_address = {i["Address"]: i for i in stress}
            for reg in range(4, 12):
                matches = [(j, i) for j, i in enumerate(stress) if i["Address"] > calls[0]["Address"] and
                           i["Mnemonic"].split(".")[0] == "cmp" and operands(i) == "r%d,r2" % reg]
                need(len(matches) == 1, "GPR_COMPARE_R%d" % reg)
                j, compare = matches[0]
                branch = stress[j + 1]
                kind, target = fp.control_form(branch)
                target_ins = by_address.get(target)
                need(branch["Mnemonic"].startswith("bne") and kind == "conditional" and target_ins is not None and
                     target_ins["Mnemonic"].split(".")[0] == "movs" and operands(target_ins) == "r0,#121", "GPR_REASON_R%d" % reg)
            need(any(i["Mnemonic"].split(".")[0] == "cmp" and operands(i) == "r2,r3" for i in stress), "SP_COOKIE_COMPARE")
            need(any(i["Mnemonic"] == "mrs" and operands(i) == "r2,control" for i in stress) and
                 any(i["Mnemonic"] == "mrs" and operands(i) == "r2,ipsr" for i in stress), "DIRECT_THREAD_STATE_READS")
