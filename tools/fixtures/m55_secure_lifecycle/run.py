"""Actual M55 SG lifecycle, generated-instruction trace and named mutant kills."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback

sys.path.insert(0, str(Path(__file__).parents[1] / "m55_secure_initialize"))
from oracle import stores, StoreRejected
from fault_oracle import fault_matches, negative_controls
spec = importlib.util.spec_from_file_location("a26_rsp", Path(__file__).parents[1] / "cm33_secure_guards/aircr_rsp.py")
a26 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a26)
Rsp = a26.Rsp


class Rejected(RuntimeError):
    def __init__(self, check, message):
        super().__init__(message)
        self.check = check


def check(value, name, message=""):
    if not value:
        raise Rejected(name, message or name)


def decoded_stores(item, register):
    # GCC M55 spells the larger callee-save PUSH as STMDB SP!. Qualify only
    # that exact stack form; all other unrecognized STM/store forms still fail.
    if item["Opcode"] in ("stmdb", "stmdb.w") and item["Operands"].startswith("sp!, "):
        return stores(dict(item, Opcode="push.w", Operands=item["Operands"][5:]), register)
    return stores(item, register)


def requires_instruction_check(item):
    return item["Opcode"].startswith(("st", "push", "vst", "vpush", "ldr", "msr", "mrs", "bl", "bxns", "dsb", "isb"))


def store_classifier_controls():
    controls = {}
    for opcode, operands in (("stl", "r0, [r1]"), ("stlex", "r2, r0, [r1]"),
                             ("stc", "p0, c0, [r1]"), ("vstmia", "r1!, {s0-s3}")):
        item = dict(Opcode=opcode, Operands=operands)
        check(requires_instruction_check(item), "unobserved-store-control", opcode)
        try:
            decoded_stores(item, lambda _: 0)
        except StoreRejected:
            controls[opcode] = True
        else:
            fail_message = "Unknown store accepted: " + opcode
            raise Rejected("store-classifier-control", fail_message)
    return controls


def main():
    root, secure, nonsecure, seconds, manifest_path = sys.argv[1:]
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8-sig"))
    scenario_bytes = Path(manifest["scenario"]).read_bytes()
    if hashlib.sha256(scenario_bytes).hexdigest().upper() != manifest["scenario_sha256"]:
        raise RuntimeError("Generated scenario changed after compilation")
    steps = json.loads(scenario_bytes)
    directory = Path(manifest_path).parent
    deadline = time.monotonic() + int(seconds)
    case = manifest["case"]
    sites = manifest["sites"]
    pool = sites["pool"]
    entries = {f["entry"]: int(op) for op, f in manifest["functions"].items()}
    code = {}
    for op, function in manifest["functions"].items():
        for item in function["instructions"]:
            code[int(item["Address"], 16)] = dict(item, operation=int(op))
    active = {pc for pc, i in code.items() if requires_instruction_check(i)} | set(entries)
    for i in code.values():
        if i["Opcode"].startswith("bl"):
            active.add(i["Next"])
    active |= {sites[n] for n in ("checkpoint", "thread_checkpoint", "terminal_stop", "direct_done", "fault_handler", "backend_allocate", "backend_lookup")}
    trap_sites = {}
    for kind, site in manifest["traps"].items():
        trap_sites.update({pc: kind for pc in site["udf"]})
    active |= set(trap_sites)
    trace, receipt = [], {"result": "FAIL", "case": case, "machine": "mps3-an547",
                          "default_m55_codegen": True, "physical_no_fp_proof": False,
                          "ns_runtime_provider": False}
    receipt["store_classifier_controls"] = store_classifier_controls()
    process = connection = None
    current = None
    current_index = -1
    completed = set()
    direct_indices = set()
    direct_context = None
    direct_count = 0
    records = {}
    cpu = [0, 0]
    injected = False
    fault_proof = None
    terminal_proof = None
    ready_observed = False
    outcome = error = None
    log_path = directory / "qemu.log"

    def event(kind, **values):
        trace.append(dict(event=kind, step=current_index, **values))

    def word(address):
        return rsp.word(address)

    def write(address, value):
        check(rsp.packet(f"M{address:x},4:{value.to_bytes(4, 'little').hex()}") == "OK", "debug-write")

    def register(name, value=None):
        name = "r12" if name == "ip" else name
        if value is None:
            return rsp.register(name)
        number, bits = rsp.registers[name]
        check(bits == 32 and rsp.packet(f"P{number:x}={value.to_bytes(4, 'little').hex()}") == "OK", "debug-register")

    def masks():
        return {n: register(n) for n in ("primask", "basepri", "faultmask")}

    def banks():
        return {n: register(n) for n in ("msp_ns", "psp_ns", "psplim_ns", "control_ns", "primask_ns", "basepri_ns", "faultmask_ns")}

    def helper(name, arguments, instructions, byte_count):
        saved = {n: register(n) for n in ("pc", "r0", "r1", "r2", "xpsr")}
        for n, value in zip(("r0", "r1", "r2"), arguments):
            register(n, value)
        register("pc", sites[name])
        for _ in range(instructions):
            check(rsp.packet("s").startswith(("S05", "T05")), "fixture-helper-step")
        check(register("pc") == sites[name] + byte_count and register("xpsr") == saved["xpsr"], "fixture-helper-state")
        for n in ("r0", "r1", "r2", "pc"):
            register(n, saved[n])

    def set_masks(values):
        helper("set_masks", [values[n] for n in ("primask", "basepri", "faultmask")], 3, 12)
        check(masks() == values, "fixture-mask-readback")

    def image():
        return rsp.memory(pool, 480)

    def resolve(value):
        if isinstance(value, int):
            return value
        return records[value["handle"]][value["field"]] + value["delta"]

    def memory_load(item):
        operand = item["Operands"].split("\t")[0]
        match = re.fullmatch(r"(r\d+|ip), \[(r\d+|ip|sp)(?:, #(-?(?:0x[0-9a-f]+|\d+)))?\](?:\s*[@;].*)?", operand)
        if match:
            dest, base, offset = match.groups()
            return dest, (register(base) + int(offset or "0", 0)) & 0xFFFFFFFF
        return None, None

    def fail(name, message=""):
        check(False, name, message)

    def before_backend():
        check(current is not None and current["admitted"], "admission-before-backend")

    def barriers(label):
        seq = current["sequence"]
        check(label in seq, "missing-prior-" + label)
        tail = seq[seq.index(label)+1:]
        check("dsb" in tail and "isb" in tail and tail.index("dsb") < tail.index("isb"), "barrier-after-" + label)

    try:
        for path, key in ((secure, "secure_sha256"), (nonsecure, "nonsecure_sha256")):
            digest = hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()
            check(digest == manifest[key], "elf-hash-drift")
            receipt[key] = digest
        with tempfile.TemporaryDirectory(prefix="fiber-c55s-life-") as temp:
            sock = str(Path(temp) / "rsp.sock")
            command = [str(Path(root) / "usr/bin/qemu-system-arm"), "-machine", "mps3-an547", "-accel", "tcg",
                       "-display", "none", "-serial", "none", "-monitor", "none", "-no-reboot",
                       "-semihosting-config", "enable=on,target=native", "-L", str(Path(root) / "usr/share/qemu"),
                       "-kernel", secure, "-device", f"loader,file={nonsecure}", "-S", "-chardev",
                       f"socket,id=life,path={sock},server=on,wait=off", "-gdb", "chardev:life"]
            receipt["qemu_command"] = command
            with log_path.open("wb") as log:
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                connection = socket.socket(socket.AF_UNIX)
                while True:
                    check(process.poll() is None, "qemu-startup")
                    try:
                        connection.connect(sock)
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        check(time.monotonic() < deadline, "qemu-startup-timeout")
                        time.sleep(0.01)
                rsp = Rsp(connection, deadline)
                rsp.discover_registers()
                check(rsp.packet("?").startswith(("S", "T")), "initial-stop")
                for pc in active:
                    rsp.breakpoint(pc)
                stop = rsp.packet("c")
                stepping = False
                pending_backend = None
                while True:
                    if stop.startswith("W"):
                        receipt["rsp_exit"] = stop
                        receipt["qemu_exit"] = process.wait(timeout=max(0.01, deadline-time.monotonic()))
                        break
                    check(stop.startswith(("S05", "T05")), "unexpected-stop", stop)
                    pc = register("pc") & ~1
                    receipt["stopped_pc"] = pc
                    if pc not in active:
                        check(stepping, "unexpected-pc", hex(pc))
                        stepping = False
                        stop = rsp.packet("c")
                        continue
                    inject = readback = None
                    if pc in entries:
                        operation = entries[pc]
                        current_index = word(sites["index"])
                        check(current_index < len(steps), "request-index")
                        step = steps[current_index]
                        direct = bool(register("lr") & 1)
                        if not direct and step.get("direct") and current_index not in direct_indices:
                            check(direct_context is None, "nested-direct-probe")
                            direct_indices.add(current_index)
                            direct_context = {n: register(n) for n in [f"r{i}" for i in range(13)]+["sp", "lr", "pc"]}
                            register("pc", sites["direct_probe"])
                            stop, stepping = "T05", True
                            continue
                        if not direct and "seed" in step:
                            cpu = [resolve(v) for v in step["seed"]]
                            helper("set_stacks", cpu, 2, 8)
                        thread_scratch = not direct and step["mode"] == 0
                        if thread_scratch:
                            # Wrong Thread calls still execute compiler CMSE prologues.
                            # Give those a private scratch PSP; this is not a runtime stack.
                            check(cpu == [0, 0], "thread-scratch-precondition")
                            cpu = [0x30005000, 0x30006000]
                            helper("set_stacks", cpu, 2, 8)
                        if case["kind"] == "corruption" and step["name"] == case["target"] and not direct and not injected:
                            address = pool + case["offset"]
                            if case.get("seal"):
                                address = records[1]["top"] + case["offset"]
                            actual = word(address)
                            forced = case.get("value", actual ^ 1)
                            write(address, forced)
                            injected = True
                            event("corrupt", address=address, actual=actual, forced=forced)
                        ipsr = register("xpsr") & 0x1FF
                        check(ipsr == step["mode"], "genuine-exception-origin")
                        check(direct == (direct_context is not None), "genuine-caller-origin")
                        if not direct:
                            check(operation == step["op"] and register("r0") == step["arg"] and register("r1") == step["owner"], "request-arguments")
                        else:
                            direct_count += 1
                        ready = word(sites["gate"]) == 0x53434752
                        if ready and not ready_observed:
                            check(image() == bytes(480), "initialized-pool-image")
                            ready_observed = True
                        admitted = (not direct and ready and ipsr in ((14,) if operation == 3 else (11, 14)) and
                                    "control_read" not in step and (operation == 1 or step["owner"] != 0) and
                                    (operation == 3 or cpu == [0, 0]))
                        original_masks = masks()
                        if case["kind"] != "corruption":
                            set_masks(dict(primask=1, basepri=0x80, faultmask=1))
                        current = dict(op=operation, step=step, direct=direct, admitted=admitted,
                                       snapshot=image(), ns=banks(), masks=masks(), original_masks=original_masks,
                                       stack=register("sp"), sequence=[], writes=[], reads={}, backend=0,
                                       record=(pool + (step["arg"]-1)*24 if 1 <= step["arg"] <= 3 else None),
                                       before_cpu=list(cpu), published=False, publish_read=False, lookups=0)
                        current["thread_scratch"] = thread_scratch
                        check([register("psplim_s"), register("psp_s")] == cpu, "secure-bank-entry")
                        event("entry", operation=operation, direct=direct, ipsr=ipsr, name=step["name"], cpu=cpu, control=register("control_s"))
                    if pc == sites["direct_done"]:
                        check(direct_context is not None, "unexpected-direct-return")
                        for n, value in direct_context.items():
                            register(n, value)
                        direct_context = None
                        current = None
                        stop, stepping = "T05", False
                        continue
                    if pc in (sites["backend_allocate"], sites["backend_lookup"]):
                        before_backend()
                        current["backend"] += 1
                        if pc == sites["backend_lookup"]:
                            current["lookups"] += 1
                        event("backend", pc=pc, operation=current["op"])
                    if pending_backend and pc == pending_backend:
                        event("backend_return", value=register("r0"))
                        pending_backend = None
                    if pc in trap_sites:
                        check(case["kind"] == "corruption" and injected, "unexpected-udf")
                        fault_proof = dict(udf_pc=pc, stack_before=register("sp"), origin_ipsr=register("xpsr") & 0x1FF,
                                           control=register("control_s"), site=trap_sites[pc])
                        event("before_udf", **fault_proof)
                    if pc == sites["fault_handler"]:
                        check(fault_proof is not None, "unexpected-secure-fault")
                        frame = register("msp_s")
                        fault_proof.update(frame=frame, handler_ipsr=register("xpsr") & 0x1FF, handler_lr=register("lr"),
                                           pc=word(frame+24), xpsr=word(frame+28))
                        event("fault_entry", **fault_proof)
                    if pc == sites["checkpoint"]:
                        # Initialization is covered by the separate unchanged 53-case suite.
                        if steps[word(sites["index"])]["op"] == 0:
                            check(word(sites["result"]) == 1, "initializer-result")
                        else:
                            check(current is not None and word(sites["result"]) == current["result"], "ns-result-publication")
                        completed.add(word(sites["index"]))
                    if pc == sites["thread_checkpoint"] and injected and case["kind"] == "readback":
                        fail("terminal-thread-resume", "Partial-update failure resumed Non-secure Thread mode")
                    if pc == sites["terminal_stop"]:
                        check(case["kind"] == "readback" and injected and current is not None and
                              not current["direct"] and current["step"]["name"] == case["target"],
                              "unexpected-terminal-stop")
                        origin = register("xpsr") & 0x1FF
                        check(origin in (11, 14) and origin == current["step"]["mode"] and
                              word(sites["result"]) == 0 and word(sites["terminal"]) == 1,
                              "terminal-handler-origin")
                        terminal_proof = dict(step=current_index, operation=current["op"], ipsr=origin)
                        event("terminal_handler", operation=current["op"], ipsr=origin)
                    if pc in code:
                        item = code[pc]
                        op, operands = item["Opcode"], item["Operands"]
                        # A return PC may share another function's boundary; only process
                        # instructions in the currently entered gateway body.
                        check(current is not None, "instruction-without-entry")
                        seq = current["sequence"]
                        for address, size, source in decoded_stores(item, register):
                            if (0x3000F000 <= address and address+size <= 0x30010000) or \
                                    (current["thread_scratch"] and 0x30005000 <= address and address+size <= 0x30006000):
                                continue  # compiler CMSE/MSP housekeeping, not lifecycle effects
                            check(current["op"] == 3 and current["admitted"] and
                                  (current["step"]["expected"] == 1 or case["kind"] == "readback") and
                                  address == current["record"] and size == 4 and source is not None,
                                  "rejected-call-wrote", hex(address))
                            check(register(source) == current["before_cpu"][1], "save-publish-value")
                            check(not current["published"] and not current["writes"], "save-publish-order")
                            current["published"] = True
                            seq.append("publish")
                            event("publish", address=address, value=register(source))
                        if op in ("dsb", "isb"):
                            seq.append(op)
                        if op.startswith("bl") and "fiber_secure_context_pool_" in operands:
                            pending_backend = item["Next"]
                        if op == "msr":
                            match = re.fullmatch(r"(PSPLIM|PSP), (r\d+|ip)", operands)
                            check(match is not None, "unexpected-system-write", operands)
                            target, source = match[1].lower(), match[2]
                            check(current["admitted"] and (current["step"]["expected"] == 1 or case["kind"] == "readback"), "rejected-register-write")
                            if current.get("failed_read"):
                                fail("readback-failure-advanced")
                            order = current["writes"]
                            check(target == ("psplim" if not order else "psp") and len(order) < 2,
                                  "load-write-order" if current["op"] == 2 else "save-write-order")
                            if current["op"] == 2:
                                record = records[current["step"]["arg"]]
                                expected = record["limit"] if target == "psplim" else record["saved"]
                                if target == "psp":
                                    check("psplim_readback" in seq, "load-limit-readback-order")
                            else:
                                check(current["published"] and current["publish_read"] and current["lookups"] == 2,
                                      "save-publish-readback")
                                barriers("publish")
                                expected = 0
                                if target == "psp":
                                    check("psplim_readback" in seq, "save-limit-readback-order")
                            check(register(source) == expected, "register-write-value")
                            order.append(target)
                            seq.append(target+"_write")
                            cpu[0 if target == "psplim" else 1] = expected
                            event("system_write", target=target, value=expected)
                        elif op == "mrs":
                            match = re.fullmatch(r"(r\d+|ip), (CONTROL|PSPLIM|PSP)", operands)
                            if match:
                                dest, target = match[1], match[2].lower()
                                if target == "control":
                                    readback = (dest, 2 if word(sites["gate"]) == 0x53434752 else 0, "admission-control")
                                    if "control_read" in current["step"] and not current["direct"]:
                                        inject = (dest, current["step"]["control_read"], "control-admission")
                                else:
                                    count = current["reads"].get(target, 0)+1
                                    current["reads"][target] = count
                                    expected = cpu[0 if target == "psplim" else 1]
                                    label = "admission-"+target if not current["writes"] else target+"_readback"
                                    if current["writes"]:
                                        barriers(current["writes"][-1]+"_write")
                                    readback = (dest, expected, label)
                                    if case["kind"] == "readback" and current["step"]["name"] == case["target"] and \
                                            target == case.get("register") and count == case.get("read") and not injected:
                                        inject = (dest, expected ^ 8, "postwrite-readback")
                        elif op.startswith("ldr"):
                            dest, address = memory_load(item)
                            if current["published"] and address == current["record"]:
                                barriers("publish")
                                check(current["lookups"] == 2, "save-owned-recheck-order")
                                readback = (dest, word(address), "publish_readback")
                                current["publish_read"] = True
                                if case["kind"] == "readback" and case.get("register") == "published" and \
                                        current["step"]["name"] == case["target"] and not injected:
                                    inject = (dest, word(address) ^ 8, "publish-readback")
                        if op == "bxns":
                            result = register("r0")
                            terminal = injected and case["kind"] == "readback" and current["step"]["name"] == case["target"]
                            expected = 0 if current["direct"] or terminal else current["step"]["expected"]
                            check(result == expected, "return-value", f"{current['step']['name']}: {result}/{expected}")
                            check(banks() == current["ns"] and masks() == current["masks"], "bank-or-mask-preservation")
                            check(register("sp") == current["stack"], "cmse-stack-balance")
                            check([register("psplim_s"), register("psp_s")] == cpu, "system-register-readback")
                            if current["direct"] or expected == 0 and not terminal:
                                check(image() == current["snapshot"] and cpu == current["before_cpu"], "rejection-mutated-state")
                            elif result and current["op"] == 1:
                                h = result
                                limit = pool + 72+(h-1)*136
                                size = current["step"]["arg"]
                                expected_record = (limit+size, limit, limit+size, current["step"]["owner"], size, 0x53435458)
                                actual = tuple(word(pool+(h-1)*24+i*4) for i in range(6))
                                check(actual == expected_record and rsp.memory(limit+size, 8) == bytes.fromhex("a5edf5fea5edf5fe"), "allocation-image")
                                records[h] = dict(limit=limit, top=limit+size, saved=limit+size, owner=current["step"]["owner"])
                            elif result and current["op"] == 2 and current["step"]["arg"]:
                                check(current["writes"] == ["psplim", "psp"] and image() == current["snapshot"], "load-roundtrip")
                            elif current["op"] == 3 and current["published"]:
                                value = current["before_cpu"][1]
                                check(word(current["record"]) == value, "saved-psp-publication")
                                records[current["step"]["arg"]]["saved"] = value
                                if result:
                                    check(current["writes"] == ["psplim", "psp"] and cpu == [0, 0], "save-clear-roundtrip")
                            current["result"] = result
                            if terminal:
                                write(sites["terminal"], 1)
                            event("return", result=result, operation=current["op"], cpu=list(cpu), masks=masks())
                            set_masks(current["original_masks"])
                            if current["thread_scratch"]:
                                cpu = [0, 0]
                                helper("set_stacks", cpu, 2, 8)
                                event("thread_scratch_restored")
                    rsp.breakpoint(pc, False)
                    stop = rsp.packet("s")
                    if readback:
                        dest, expected, label = readback
                        actual = register(dest)
                        check(actual == expected, "actual-readback", f"{label}:{actual:#x}/{expected:#x}")
                        current["sequence"].append(label)
                        event("read", label=label, value=actual, pc=pc)
                    if inject:
                        dest, value, label = inject
                        register(dest, value)
                        event("inject", label=label, forced=value, actual=readback[1], pc=pc)
                        if label != "control-admission":
                            injected = True
                            current["failed_read"] = True
                    rsp.breakpoint(pc)
                    stepping = True
    except StoreRejected as exc:
        outcome, error = "unqualified-store", str(exc)
    except Rejected as exc:
        outcome, error = exc.check, str(exc)
    except (TimeoutError, socket.timeout) as exc:
        outcome, error = "timeout", str(exc)
    except Exception as exc:
        outcome, error = "execution-error", str(exc)
        receipt["traceback"] = traceback.format_exc()
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            receipt["paused_termination"] = process.wait(timeout=2)
        if connection is not None:
            connection.close()
        text = log_path.read_text(errors="replace") if log_path.exists() else ""
        if outcome is None:
            reports = re.findall(r"(?m)^FAULT:C55S-LIFECYCLE PC=0x([0-9a-f]{8}) CFSR=0x([0-9a-f]{8}) "
                                 r"HFSR=0x([0-9a-f]{8}) IPSR=0x([0-9a-f]{8}) EXC_RETURN=0x([0-9a-f]{8}) "
                                 r"FRAME=0x([0-9a-f]{8}) XPSR=0x([0-9a-f]{8})\r?$", text)
            if receipt.get("qemu_exit") == 42 and len(reports) == 1 and fault_proof:
                values = list(map(lambda v: int(v, 16), reports[0]))
                pc, cfsr, hfsr, ipsr, ret, frame, xpsr = values
                site = manifest["traps"][fault_proof["site"]]
                record = dict(zip(("pc", "cfsr", "hfsr", "ipsr", "exc_return", "frame", "xpsr"), values))
                origin = steps[current_index]["mode"]
                exact = (case["kind"] == "corruption" and injected and fault_matches(record, fault_proof, site, origin) and
                         text.count("FAULT-EXIT:C55S-LIFECYCLE\n") == 1)
                outcome = "exact-corruption-udf" if exact else "wrong-fault-origin"
                if exact:
                    negatives = negative_controls(record, fault_proof, site, origin)
                    receipt["negative_fault_controls"] = negatives
                    if not all(negatives.values()):
                        outcome = "classifier-control-failed"
                receipt["fault"] = record
                receipt["fault_proof"] = fault_proof
            elif receipt.get("qemu_exit") == 0 and not reports and text.count("EXIT:C55S-LIFECYCLE:0\n") == 1:
                if case["kind"] == "success" and len(completed) == len(steps) and direct_count == 6 and \
                        text.count("PASS:C55S-LIFECYCLE:complete\n") == 1:
                    outcome = "verified-lifecycle"
                elif case["kind"] == "readback" and injected:
                    records_found = re.findall(r"(?m)^TERMINAL:C55S-LIFECYCLE STEP=0x([0-9a-f]{8}) "
                                               r"OP=0x([0-9a-f]{8}) IPSR=0x([0-9a-f]{8})\r?$", text)
                    reported = tuple(int(v, 16) for v in records_found[0]) if len(records_found) == 1 else None
                    corroborated = tuple(terminal_proof[k] for k in ("step", "operation", "ipsr")) if terminal_proof else None
                    exact = (terminal_proof is not None and reported == corroborated and
                             text.count("PASS:C55S-LIFECYCLE:terminal-handler\n") == 1)
                    outcome = "verified-terminal-readback" if exact else "wrong-terminal-origin"
                else:
                    outcome = "incomplete-execution"
            else:
                outcome = "unexpected-fault-or-exit"
        expected = case.get("kill") or {"success": "verified-lifecycle", "readback": "verified-terminal-readback",
                                         "corruption": "exact-corruption-udf"}[case["kind"]]
        passed = outcome == expected
        if case.get("kill"):
            observed = dict(step=steps[current_index]["name"], operation=current["op"], direct=current["direct"]) if current else {}
            receipt["mutant_observation"] = observed
            passed = (passed and receipt.get("paused_termination") == -9 and observed.get("step") == case["kill_step"] and
                      observed.get("operation") == case["kill_op"] and observed.get("direct") == case["kill_direct"])
        receipt.update(result="PASS" if passed else "FAIL", classification=outcome, expected=expected, error=error,
                       completed_steps=len(completed), total_steps=len(steps), direct_secure_calls=direct_count, injection=injected)
        receipt["terminal_proof"] = terminal_proof
        (directory / "execution-events.json").write_text(json.dumps(trace, indent=2)+"\n")
        (directory / "execution-receipt.json").write_text(json.dumps(receipt, indent=2)+"\n")
        print(text, end="")
        if not passed:
            print("ERROR:C55S-LIFECYCLE:" + str(error))
        print(f"{'PASS' if passed else 'FAIL'}:C55S-LIFECYCLE-RUN:{outcome}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
