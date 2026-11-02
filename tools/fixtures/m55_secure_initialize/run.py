"""Actual M55 two-image/SG execution and fault injection via private Unix RSP.

No emulated CPU/MMIO model is substituted for production. Readback injections
change a destination register *after* the actual instruction, retaining the
real one-way BSS latch. The A26 transport/parser dependency is read-only.
"""
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
from oracle import StoreRejected, stores, gateway_fault_matches, negative_fault_controls

SPEC = importlib.util.spec_from_file_location(
    "a26_rsp", Path(__file__).parents[1] / "cm33_secure_guards" / "aircr_rsp.py")
A26 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A26)
Rsp = A26.Rsp
require = A26.require

AIRCR = 0xE000ED0C
INITIALIZING, READY, POOL_READY = 0x53434742, 0x53434752, 0x53435052


def main():
    root, secure, nonsecure, seconds, manifest_path = sys.argv[1:]
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8-sig"))
    directory = Path(manifest_path).parent
    deadline = time.monotonic() + int(seconds)
    instructions = {int(i["Address"], 16): i for i in manifest["instructions"]}
    instructions.update({int(i["Address"], 16): i for i in manifest["store_control"]})
    checkpoints = {int(v): k for k, v in manifest["checkpoints"].items()}
    entry, pool_entry = manifest["entry"], manifest["pool_entry"]
    gate, pool_state = manifest["gate"], manifest["pool_state"]
    pool, pool_size = manifest["pool"], manifest["pool_size"]
    case, control, mutant = manifest["case"], manifest["control"], manifest["mutant"]
    events, receipt = [], {"case": case, "machine": "mps3-an547", "injection": case,
                           "transport": "private AF_UNIX", "result": "FAIL",
                           "forbidden_aircr_write_executed": False}
    process = connection = None
    log_path = directory / "qemu.log"
    active_call = "direct"
    svc_entries = rejections = repeats = 0
    wrong = set()
    direct = wrong_done = first_done = injected = False
    committed = aircr_written = pool_returned = False
    pool_return_pc = None
    ready_snapshot = None
    sequence = []
    mask_snapshot = None
    original_masks = None
    fault_proof = None

    def event(kind, **values):
        events.append({"event": kind, **values})
        sequence.append(kind)

    def write_memory(address, data):
        require(rsp.packet(f"M{address:x},{len(data):x}:{data.hex()}") == "OK", "RSP memory write failed")

    def write_register(name, value):
        number, bits = rsp.registers[name]
        require(bits == 32, f"Unexpected injection register width: {name}")
        require(rsp.packet(f"P{number:x}={value.to_bytes(4, 'little').hex()}") == "OK",
                f"RSP register injection failed: {name}")

    def policy(value):
        saved = {name: rsp.register(name) for name in ("pc", "r0", "r1", "xpsr")}
        write_register("r0", value)
        write_register("r1", AIRCR)
        write_register("pc", manifest["policy_store"])
        reply = rsp.packet("s")
        require(reply.startswith(("S05", "T05")) and
                rsp.register("pc") == manifest["policy_store"] + 2,
                "Platform-policy setup did not execute exactly one Secure STR")
        require(rsp.register("xpsr") == saved["xpsr"], "Policy setup changed execution state")
        for name in ("r0", "r1", "pc"):
            write_register(name, saved[name])
        actual = rsp.word(AIRCR)
        event("platform_policy", pending=value, actual=actual)
        require(actual & 0xFFFF == value & 0xFFFF, "Platform AIRCR setup readback mismatch")

    def intact():
        require(rsp.word(gate) == 0 and rsp.word(pool_state) == 0, "Preflight changed a BSS latch")
        require(rsp.memory(pool, pool_size) == b"\xa5" * pool_size, "Preflight changed NOLOAD pool")

    def masks():
        # M-profile XML exposes these as current-bank registers. They are read
        # only at production entry/exit while the Secure bank is selected.
        return {name: rsp.register(name) for name in ("primask", "basepri", "faultmask")}

    def set_masks(values):
        saved = {name: rsp.register(name) for name in ("pc", "r0", "r1", "r2", "xpsr")}
        for register, name in (("r0", "primask"), ("r1", "basepri"), ("r2", "faultmask")):
            write_register(register, values[name])
        write_register("pc", manifest["mask_store"])
        for _ in range(3):
            require(rsp.packet("s").startswith(("S05", "T05")), "Mask setup did not single-step")
        require(rsp.register("pc") == manifest["mask_store"] + 12 and
                rsp.register("xpsr") == saved["xpsr"] and masks() == values,
                "Mask setup did not execute exactly three Secure MSRs")
        for name in ("r0", "r1", "r2", "pc"):
            write_register(name, saved[name])

    def after_barrier(kind):
        require(kind in sequence, f"Missing prior {kind}")
        tail = sequence[sequence.index(kind) + 1:]
        require("dsb" in tail and "isb" in tail and tail.index("dsb") < tail.index("isb"),
                f"Missing ordered DSB/ISB after {kind}")

    def memory_operand(item):
        match = re.fullmatch(
            r"(r\d+),\s*\[(r\d+|sp)(?:,\s*#(-?(?:0x[0-9a-f]+|\d+)))?\]"
            r"!?(?:,\s*#-?(?:0x[0-9a-f]+|\d+))?(?:\s*[;@].*)?", item["Operands"])
        if match:
            register, base, offset = match.groups()
            return register, (rsp.register(base) + int(offset or "0", 0)) & 0xFFFFFFFF
        return None, None

    outcome = None
    error = None
    try:
        for path, key in ((secure, "secure_sha256"), (nonsecure, "nonsecure_sha256")):
            digest = hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()
            require(digest == manifest[key], "ELF changed after generated-code inspection")
            receipt[key] = digest
        with tempfile.TemporaryDirectory(prefix="fiber-c55s-init-") as temp:
            socket_path = str(Path(temp) / "gdb.sock")
            command = [str(Path(root) / "usr/bin/qemu-system-arm"), "-machine", "mps3-an547",
                       "-accel", "tcg", "-display", "none", "-serial", "none", "-monitor", "none",
                       "-no-reboot", "-semihosting-config", "enable=on,target=native",
                       "-L", str(Path(root) / "usr/share/qemu"), "-kernel", secure,
                       "-device", f"loader,file={nonsecure}", "-S", "-chardev",
                       f"socket,id=init,path={socket_path},server=on,wait=off", "-gdb", "chardev:init"]
            receipt["qemu_command"] = command
            with log_path.open("wb") as log:
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                connection = socket.socket(socket.AF_UNIX)
                while True:
                    require(process.poll() is None, "QEMU exited before RSP connection")
                    try:
                        connection.connect(socket_path)
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        require(time.monotonic() < deadline, "RSP startup timeout")
                        time.sleep(0.01)
                rsp = Rsp(connection, deadline)
                rsp.discover_registers()
                receipt["registers"] = rsp.registers
                require(rsp.packet("?").startswith(("S", "T")), "No initial stop")
                active = set(instructions) | set(checkpoints) | {pool_entry, manifest["fault_handler"]} | \
                    set(manifest["fail_closed"]["udf"])
                for address in active:
                    rsp.breakpoint(address)
                stop = rsp.packet("c")
                stepping = False
                while True:
                    if stop.startswith("W"):
                        receipt["rsp_exit"] = stop
                        receipt["actual_qemu_exit"] = process.wait(timeout=max(0.01, deadline-time.monotonic()))
                        break
                    require(stop.startswith(("S05", "T05")), f"Unexpected QEMU stop {stop}")
                    pc = rsp.register("pc") & ~1
                    if pc not in active:
                        require(stepping, f"Unexpected breakpoint PC {pc:#x}")
                        stepping = False
                        stop = rsp.packet("c")
                        continue
                    inject_register = None
                    read_event = None
                    if pc == entry:
                        lr, ipsr = rsp.register("lr"), rsp.register("xpsr") & 0x1FF
                        if lr & 1:
                            require(not direct and ipsr == 11 and not wrong_done, "Wrong direct Secure origin")
                            active_call = "direct"
                            intact()
                            if control in ("register-offset-store", "unrecognized-store"):
                                write_register("r0", 0xDEADBEEF)
                                write_register("r1", 0xE000ED00)
                                write_register("r2", 0x10)
                                write_register("pc", int(manifest["store_control"][0]["Address"], 16))
                                event("store_control_prepared", pc=pc, origin_ipsr=ipsr)
                                stop, stepping = "T05", False
                                continue
                        elif ipsr != 11:
                            require(not wrong_done and ipsr in (0, 14, 15), "Wrong NS rejection origin")
                            active_call = "wrong"
                            wrong.add(ipsr)
                            intact()
                        else:
                            svc_entries += 1
                            require(wrong_done, "NS SVC preceded wrong-exception tests")
                            active_call = "bfhfnmins" if svc_entries < 3 else "valid" if svc_entries == 3 else "repeat"
                            if active_call == "bfhfnmins":
                                intact()
                                if svc_entries == 1:
                                    policy(0x05FA2500)
                                require(rsp.word(AIRCR) & 0xFFFF == 0x2500, "Missing BFHFNMINS seed")
                            elif active_call == "valid":
                                intact()
                                require(rejections == 2, "Missing BFHFNMINS rejections")
                                policy(0x05FA0500)
                                require(rejections == 2 and rsp.word(AIRCR) & 0xFFFF == 0x500, "Invalid retry phase")
                            else:
                                require(first_done and svc_entries == 4 and rsp.word(gate) != 0, "Retry reopened gateway")
                                require(ready_snapshot == (rsp.word(gate), rsp.word(pool_state),
                                                          rsp.memory(pool, pool_size), rsp.word(AIRCR)),
                                        "State changed between first return and repeated entry")
                        original_masks = masks()
                        if not (active_call == "valid" and case.startswith("latch-")):
                            set_masks({"primask": 1, "basepri": 0x80, "faultmask": 1})
                            require(masks() == {"primask": 1, "basepri": 0x80, "faultmask": 1},
                                    "Nonzero Secure mask seed did not take")
                        mask_snapshot = masks()
                        event("entry", pc=pc, lr=lr, ipsr=ipsr, phase=active_call, masks=mask_snapshot)
                    if pc in manifest["fail_closed"]["udf"]:
                        require(case in ("latch-initial", "latch-ready") and injected and active_call == "valid",
                                "Unexpected fail-closed trap entry")
                        fault_proof = {"udf_pc": pc, "stack_before": rsp.register("sp"),
                                       "origin_ipsr": rsp.register("xpsr") & 0x1FF,
                                       "control": rsp.register("control_s")}
                        expected_gate = INITIALIZING if case == "latch-initial" else READY
                        require(rsp.word(gate) == expected_gate and masks() == original_masks,
                                "Latch trap did not retain exact committed state/masks")
                        event("before_udf", **fault_proof, gate=rsp.word(gate), pool_state=rsp.word(pool_state))
                    if pc == manifest["fault_handler"]:
                        require(fault_proof is not None, "Unexpected Secure fault entry")
                        frame = rsp.register("msp_s")
                        fault_proof.update(msp=frame, handler_ipsr=rsp.register("xpsr") & 0x1FF,
                                           handler_lr=rsp.register("lr"), stacked_pc=rsp.word(frame + 24),
                                           stacked_xpsr=rsp.word(frame + 28))
                        event("fault_entry", **fault_proof)
                    if pc in checkpoints:
                        label = checkpoints[pc]
                        if label == "secure_rejected":
                            intact()
                            direct = True
                        elif label == "wrong_done":
                            require(direct and wrong == {0, 14, 15}, "Missing genuine NS rejection paths")
                            wrong_done = True
                        elif label == "rejected":
                            rejections += 1
                            require(rejections <= 2 and active_call == "bfhfnmins", "Unexpected preflight checkpoint")
                        elif label == "first_result":
                            first_done = True
                            require(active_call == "valid" and ready_snapshot is not None, "Unexpected first result")
                        elif label == "repeat_result":
                            repeats += 1
                        event("checkpoint", label=label, pc=pc)
                    if pc == pool_entry:
                        require(active_call == "valid" and rsp.word(gate) == INITIALIZING and aircr_written,
                                "Pool initialization ran before valid commitment")
                        require("psplim_read" in sequence and "psp_read" in sequence, "Pool preceded stack readbacks")
                        require(rsp.word(pool_state) == 0, "Pool already initialized")
                        event("pool_entry", pc=pc)
                    if pc == pool_return_pc:
                        require(rsp.word(pool_state) == POOL_READY and rsp.memory(pool, pool_size) == b"\0" * pool_size,
                                "Production pool did not scrub and publish readiness")
                        require(rsp.register("r0") == 1, "Production pool initialization failed")
                        pool_returned = True
                        event("pool_return", pc=pc)
                        if case == "pool-return" and not injected:
                            write_register("r0", 0)
                            injected = True
                            event("inject", target="pool-return", actual=1, forced=0)
                        pool_return_pc = None
                    if pc in instructions:
                        item = instructions[pc]
                        op, operands = item["Opcode"], item["Operands"]
                        register, address = memory_operand(item)
                        try:
                            decoded = stores(item, lambda name: rsp.register("r12" if name == "ip" else name))
                        except StoreRejected:
                            receipt.update(stopped_pc=pc, store_instruction=item, store_executed=False)
                            raise
                        for written, size, source in decoded:
                            if written in (AIRCR, gate) and size == 4 and op in ("str", "str.w", "str.n"):
                                register, address = source, written
                            elif written < 0xF0000000 and written + size > 0xE0000000:
                                receipt.update(stopped_pc=pc, store_instruction=item, store_executed=False)
                                event("rejected_mmio_store", pc=pc, address=written, size=size, instruction=item)
                                raise StoreRejected("unexpected-mmio-store", f"Unexpected MMIO store {written:#x}/{size}")
                            elif not (0x3000F000 <= written and written + size <= 0x30010000):
                                raise StoreRejected("unexpected-memory-store", f"Unexpected non-stack store {written:#x}/{size}")
                        if decoded and address in (AIRCR, gate):
                            value = rsp.register(register)
                            event("before_store", pc=pc, address=address, value=value, phase=active_call)
                            if address == gate:
                                require(active_call == "valid" or mutant and active_call == "bfhfnmins",
                                        "Rejected invocation committed a latch")
                                if value == INITIALIZING:
                                    require(not committed, "Repeated initialization committed again")
                                    committed = True
                                    event("commit")
                                else:
                                    require(value == READY and pool_returned and "control_read" in sequence,
                                            "READY published before CPU/pool readback")
                                    event("ready_store")
                            else:
                                after_barrier("commit")
                                require(committed and value >> 16 == 0x05FA, "AIRCR key/order is wrong")
                                if mutant:
                                    require(active_call == "bfhfnmins" and svc_entries == 1 and rejections == 0 and
                                            rsp.word(AIRCR) & 0xFFFF == 0x2500 and value & 0xFFFF == 0x6500 and
                                            rsp.word(gate) == INITIALIZING, "Mutant missed exact forbidden AIRCR STR")
                                    event("mutant_killed_before_forbidden_str", pc=pc, address=address, value=value)
                                    receipt.update(stopped_pc=pc, pending_aircr=value, qemu_terminated_while_paused=True)
                                    outcome = "mutant-killed-before-forbidden-str"
                                    break
                                require(active_call == "valid" and value & 0xFFFF == 0x4500 and
                                        rsp.word(AIRCR) & 0xFFFF == 0x500, "AIRCR unrelated bits changed")
                                aircr_written = True
                                event("aircr_store")
                        if op.startswith("ldr") and address in (AIRCR, gate):
                            value = rsp.word(address)
                            if address == AIRCR and aircr_written:
                                after_barrier("aircr_store")
                                read_event = ("aircr_read", register, value)
                                if case == "aircr-readback" and not injected:
                                    inject_register = (register, value ^ 0x4000)
                            elif address == gate and committed:
                                kind = "ready_read" if value == READY else "commit_read"
                                after_barrier("ready_store" if value == READY else "commit")
                                read_event = (kind, register, value)
                                if case == ("latch-ready" if value == READY else "latch-initial") and not injected:
                                    inject_register = (register, 0)
                        if op == "msr":
                            match = re.fullmatch(r"(psplim|psp|control),\s*(r\d+)", operands, re.I)
                            require(match is not None and active_call == "valid", "Unexpected system-register write")
                            target, source = match.groups()
                            target = target.lower()
                            value = rsp.register(source)
                            require(aircr_written and "aircr_read" in sequence, "Stack write preceded AIRCR readback")
                            if target == "control":
                                require(pool_returned and value == 2, "CONTROL write is not post-pool privileged PSP")
                            else:
                                require(value == 0, "Secure stack register not cleared")
                            event(target + "_write", value=value)
                        elif op == "mrs":
                            match = re.fullmatch(r"(r\d+),\s*(psplim|psp|control)", operands, re.I)
                            if match and active_call == "valid":
                                register, target = match.groups()
                                target = target.lower()
                                after_barrier("psp_write") if target != "control" else require(
                                    "isb" in sequence[sequence.index("control_write")+1:], "No ISB after CONTROL")
                                read_event = (target + "_read", register, 2 if target == "control" else 0)
                                if case == target + "-readback" and not injected:
                                    inject_register = (register, 0 if target == "control" else 8)
                                if target == "control" and re.fullmatch(r"control-(6|10|14)", case) and not injected:
                                    inject_register = (register, int(case.split("-")[1]))
                        elif op in ("dsb", "isb"):
                            event(op, pc=pc)
                        elif op.startswith("bl") and "fiber_secure_context_pool_boot_initialize>" in operands:
                            pool_return_pc = item["Next"]
                        if op.startswith("bxns") and mask_snapshot is not None:
                            require(masks() == mask_snapshot, "Initializer changed Secure masks")
                            result = rsp.register("r0")
                            if active_call in ("direct", "wrong", "bfhfnmins"):
                                require(result == 0, "Preflight accepted forbidden caller/policy")
                                intact()
                                require(rsp.register("psp_s") == 0x30006000 and
                                        rsp.register("psplim_s") == 0x30005000,
                                        "Preflight changed Secure stack registers")
                            elif active_call == "valid":
                                if case == "success":
                                    require(result == 1 and rsp.word(gate) == READY and
                                            rsp.word(pool_state) == POOL_READY and pool_returned,
                                            "Success did not publish ready state")
                                    require(rsp.memory(pool, pool_size) == b"\0" * pool_size,
                                            "Pool scrub/readback incomplete")
                                    require(sequence.count("control_read") == 1, "Missing CONTROL=2 readback")
                                    # A live byte must survive the rejected repeated initialization.
                                    write_memory(pool + pool_size - 1, b"\x5a")
                                else:
                                    require(result == 0 and injected and rsp.word(gate) == INITIALIZING,
                                            "Postcommit failure was not sticky")
                                ready_snapshot = (rsp.word(gate), rsp.word(pool_state),
                                                  rsp.memory(pool, pool_size), rsp.word(AIRCR))
                            else:
                                require(result == 0 and ready_snapshot == (rsp.word(gate), rsp.word(pool_state),
                                        rsp.memory(pool, pool_size), rsp.word(AIRCR)),
                                        "Repeated init changed partial/ready state")
                            event("secure_return", phase=active_call, result=result,
                                  gate=rsp.word(gate), pool_state=rsp.word(pool_state), masks=masks())
                            set_masks(original_masks)
                    rsp.breakpoint(pc, False)
                    stop = rsp.packet("s")
                    if read_event:
                        kind, register, expected = read_event
                        actual = rsp.register(register)
                        require(actual == expected, f"Actual {kind} readback mismatch {actual:#x}/{expected:#x}")
                        event(kind, value=actual, pc=pc)
                    if inject_register:
                        register, value = inject_register
                        write_register(register, value)
                        injected = True
                        event("inject", target=case, register=register, forced=value, pc=pc)
                    rsp.breakpoint(pc)
                    stepping = True
    except StoreRejected as exc:
        outcome, error = exc.kind, str(exc)
    except (TimeoutError, socket.timeout) as exc:
        outcome, error = "timeout", str(exc)
    except Exception as exc:
        outcome, error = "execution-proof-rejected", str(exc)
    finally:
        # In particular, NEVER detach/resume the BFHFNMINS mutant at its STR.
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            receipt["termination_exit"] = process.wait(timeout=2)
        if connection is not None:
            connection.close()
        text = log_path.read_text(errors="replace") if log_path.exists() else ""
        if outcome is None:
            faults = re.findall(r"(?m)^FAULT:C55S-INITIALIZE PC=0x([0-9a-f]{8}) CFSR=0x([0-9a-f]{8}) "
                                r"HFSR=0x([0-9a-f]{8}) IPSR=0x([0-9a-f]{8}) EXC_RETURN=0x([0-9a-f]{8}) "
                                r"FRAME=0x([0-9a-f]{8}) XPSR=0x([0-9a-f]{8})\r?$", text)
            exit_code = receipt.get("actual_qemu_exit")
            if exit_code == 42:
                if len(faults) != 1:
                    outcome = "fault-report-count"
                else:
                    pc, cfsr, hfsr, ipsr, exc_return, frame, xpsr = (int(v, 16) for v in faults[0])
                    record = dict(pc=pc, cfsr=cfsr, hfsr=hfsr, ipsr=ipsr, exc_return=exc_return, frame=frame, xpsr=xpsr)
                    receipt["fault"], receipt["fault_proof"] = record, fault_proof
                    target = manifest["unrelated"] if control == "unrelated-fault" else manifest["fail_closed"]
                    exact = (target["start"] <= pc < target["end"] and pc in target["udf"] and
                             cfsr == 0x10000 and hfsr == 0 and ipsr == 6 and
                             text.count("FAULT-EXIT:C55S-INITIALIZE\n") == 1)
                    if control == "unrelated-fault" and exact:
                        outcome = "unrelated-fault-rejected"
                    elif injected and exact and gateway_fault_matches(record, fault_proof, case, target):
                        outcome = "exact-latch-fail-closed"
                        controls = negative_fault_controls(record, fault_proof, case, target)
                        (directory / "classifier-controls.json").write_text(json.dumps(controls, indent=2) + "\n")
                        if not all(controls.values()):
                            outcome = "classifier-control-failed"
                        receipt["negative_fault_controls"] = controls
                    else:
                        outcome = "unexpected-fault"
            elif exit_code == 0 and not faults and text.count("PASS:C55S-INITIALIZE:complete\n") == 1 and \
                    text.count("EXIT:C55S-INITIALIZE:0\n") == 1 and first_done and repeats == 1 and rejections == 2:
                outcome = "verified-sticky-rejection" if injected else "verified-success"
            else:
                outcome = "incomplete-execution"
        expected = {"unrelated-fault": "unrelated-fault-rejected", "missing-report": "fault-report-count",
                    "timeout": "timeout", "register-offset-store": "unexpected-mmio-store",
                    "unrecognized-store": "unrecognized-store"}.get(control)
        if not expected:
            expected = "mutant-killed-before-forbidden-str" if mutant else "exact-latch-fail-closed" if \
                case.startswith("latch-") else "verified-success" if case == "success" else "verified-sticky-rejection"
        passed = outcome == expected
        if control == "timeout":
            passed = passed and direct and text.count("START:C55S-INITIALIZE:Nonsecure-M55\n") == 1 and \
                "FAULT:" not in text and "EXIT:" not in text and receipt.get("termination_exit") == -9
        if control == "missing-report":
            passed = passed and direct and text.count("FAULT-EXIT:C55S-INITIALIZE\n") == 1
        if control in ("register-offset-store", "unrecognized-store"):
            passed = passed and any(e["event"] == "store_control_prepared" for e in events) and \
                receipt.get("store_executed") is False and receipt.get("termination_exit") == -9
        receipt.update(result="PASS" if passed else "FAIL", classification=outcome, expected=expected, error=error,
                       direct_secure_rejected=direct, wrong_exceptions=sorted(wrong), svc_entries=svc_entries,
                       bfhfnmins_rejections=rejections, repeated_rejections=repeats, injection_executed=injected)
        (directory / "execution-events.json").write_text(json.dumps(events, indent=2) + "\n")
        (directory / "execution-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(text, end="")
        if not passed and error:
            print("ERROR:C55S-INITIALIZE-RUN:" + error)
        print(f"{'PASS' if passed else 'FAIL'}:C55S-INITIALIZE-RUN:{outcome}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
