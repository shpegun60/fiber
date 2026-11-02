"""Actual AN505 M33 two-image Fiber runtime, with labelled bounded probes."""
import sys

OPT_ERROR = "Disable PYTHONOPTIMIZE and do not use -O/-OO for C33 Secure-origin regressions"
if not __debug__ or sys.flags.optimize:
    raise SystemExit(OPT_ERROR)

import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def words(data):
    require(len(data) % 4 == 0, "unaligned-observation")
    return [int.from_bytes(data[i:i+4], "little") for i in range(0, len(data), 4)]


def packed(values):
    return b"".join(value.to_bytes(4, "little") for value in values)


def preflight():
    script = str(Path(__file__).resolve())
    for flag in ("-O", "-OO"):
        for source in (None, f"import runpy; runpy.run_path({script!r},run_name='extracted')",
                       "import importlib.util; " + f"s=importlib.util.spec_from_file_location('origin',{script!r}); "
                       "m=importlib.util.module_from_spec(s); s.loader.exec_module(m)"):
            command = [sys.executable, "-B", flag, script] if source is None else [sys.executable, "-B", flag, "-c", source]
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            require(result.returncode == 1 and result.stdout == "" and result.stderr.splitlines() == [OPT_ERROR],
                    "optimized-guard-not-exact-"+repr(result))
    fake = subprocess.run([sys.executable, "-B", "-c", f"raise RuntimeError({OPT_ERROR!r})"],
                          capture_output=True, text=True, timeout=20)
    require(fake.returncode == 1 and fake.stderr.splitlines() != [OPT_ERROR], "counterfeit-traceback-accepted")
    print("PASS:C33-ORIGIN:Python-guards:7")


def main():
    root, timeout, manifest, transport = sys.argv[1:]
    path = Path(manifest)
    m = json.loads(path.read_text(encoding="utf-8-sig"))
    directory = path.parent
    receipt = dict(result="FAIL", case=m["case"], scenario=m["scenario"], trace=[])
    deadline = time.monotonic() + int(timeout)
    process = connection = None
    scenario, case = m["scenario"], m["case"]
    pending, cold, allocations, pointers, counts = {}, {}, {}, {}, {}
    switches = resumes = 0
    entered = set()
    call = injected = failure = None
    last_secure = None
    panic_seen = bounded = False
    try:
        for image in ("secure", "nonsecure"):
            require(hashlib.sha256(Path(m[image]).read_bytes()).hexdigest().upper() == m[image+"_sha256"], "image-drift-"+image)
        spec = importlib.util.spec_from_file_location("c33_origin_transport", transport)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        environment = dict(os.environ)
        environment["LD_LIBRARY_PATH"] = str(Path(root)/"usr/lib/x86_64-linux-gnu") + (
            ":"+environment["LD_LIBRARY_PATH"] if environment.get("LD_LIBRARY_PATH") else "")
        with tempfile.TemporaryDirectory(prefix="fiber-c33-origin-") as temporary:
            sock = str(Path(temporary)/"rsp.sock")
            command = [str(Path(root)/"usr/bin/qemu-system-arm"), "-machine", "mps2-an505", "-accel", "tcg",
                       "-display", "none", "-serial", "none", "-monitor", "none", "-no-reboot",
                       "-semihosting-config", "enable=on,target=native", "-L", str(Path(root)/"usr/share/qemu"),
                       "-kernel", m["secure"], "-device", "loader,file="+m["nonsecure"], "-S", "-chardev",
                       "socket,id=origin,path="+sock+",server=on,wait=off", "-gdb", "chardev:origin"]
            receipt["qemu_command"] = command
            with (directory/"qemu.log").open("wb") as output:
                process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                           env=environment, start_new_session=True)
                connection = socket.socket(socket.AF_UNIX)
                while True:
                    require(process.poll() is None, "early-QEMU-exit")
                    try:
                        connection.connect(sock)
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        require(time.monotonic() < deadline, "RSP-startup-timeout")
                        time.sleep(.01)
                rsp = module.Rsp(connection, deadline)
                rsp.discover_registers()

                def cpu():
                    return {name: rsp.register(name) for name in (
                        "xpsr", "lr", "sp", "control_s", "control_ns", "psp_s", "psp_ns", "psplim_s", "psplim_ns",
                        "msp_s", "msp_ns", "primask_ns", "basepri_ns", "faultmask_ns")}

                def gprs():
                    return [rsp.register("r%d" % i) for i in range(13)] + [rsp.register("lr")]

                def event(name, **fields):
                    receipt["trace"].append(dict(event=name, **fields))

                def read(address, size):
                    return b"".join(rsp.memory(address+i, min(512, size-i)) for i in range(0, size, 512))

                def write(address, data):
                    require(rsp.packet("M%x,%x:%s" % (address, len(data), data.hex())) == "OK", "debugger-memory-write")
                    require(read(address, len(data)) == data, "ineffective-memory-write")

                def owner(task):
                    return m["contexts"] + task*80

                def attached(task):
                    return scenario in (1, 4) or scenario == 2 and task == 0 or scenario == 3 and task == 1

                def pool():
                    return read(m["pool_start"], m["pool_end"]-m["pool_start"])

                def bank(state):
                    return {k: v for k, v in state.items() if k.endswith("_ns")}

                def basic(before):
                    values = before["gprs"]
                    return values[:4] + [values[12], values[13], before["pc"]+4, before["cpu"]["xpsr"]]

                def overlay(image, address, data):
                    offset = address-m["pool_start"]
                    require(0 <= offset <= offset+len(data) <= len(image), "independent-pool-offset")
                    image[offset:offset+len(data)] = data

                def geometry(task):
                    limit = m["stacks_s"]+(allocations[owner(task)]-1)*1032
                    return limit, limit+512

                fixed = {m[key]: label for key, label in (
                    ("secure_ready", "secure-ready"), ("prepared", "prepared"), ("task_entry", "task-entry"),
                    ("pendsv", "pendsv"), ("selector", "selector"), ("pd_return", "pd-return"),
                    ("ns_checkpoint", "ns-checkpoint"), ("ns_resumed", "ns-resumed"),
                    ("s_checkpoint", "s-checkpoint"), ("s_resumed", "s-resumed"), ("panic", "panic"))}
                entries = {row["address"]: row["operation"] for row in m["gateways"]}
                exits = {row["address"]: row["operation"] for row in m["exits"]}
                for address in entries:
                    require(address not in fixed, "entry-address-alias")
                    fixed[address] = "gateway-entry"
                for address in exits:
                    require(address not in fixed, "exit-address-alias")
                    fixed[address] = "gateway-exit"
                active = dict(fixed)
                require(rsp.packet("?").startswith(("S", "T")), "initial-stop")
                rsp.breakpoint(m["secure_ready"])
                stop = rsp.packet("c")
                while True:
                    if stop.startswith("W"):
                        expected = 93 if case in (11, 12, 13, 20) else 0
                        require(stop == "W%02x" % expected and process.wait(timeout=max(.01, deadline-time.monotonic())) == expected,
                                "unexpected-process-exit-"+stop)
                        if expected:
                            require(panic_seen, "unobserved-terminal-panic")
                            receipt.update(result="PASS", proof="exact-terminal-negative", exit_code=expected)
                        else:
                            require(switches == 2 and resumes == 1 and entered == {0, 1}, "incomplete-real-switch-cycle")
                            require({key: counts.get(key, 0) for key in ("initialize", "allocate", "save", "load")} ==
                                    dict(initialize=1, allocate=sum(attached(i) for i in (0, 1)), save=2, load=3), "exact-stateful-inventory")
                            receipt.update(result="PASS", proof="actual-two-switch-Thread-resume", exit_code=0)
                        break
                    require(stop.startswith(("S05", "T05")), "unexpected-stop-"+stop)
                    pc = rsp.register("pc") & ~1
                    watch = re.search(r"rwatch:([0-9a-fA-F]+);", stop)
                    if watch:
                        state = cpu()
                        address = int(watch[1], 16)
                        require(case == 11 and injected is not None and address == injected["sp"]+4 and
                                state["xpsr"] & 511 == 14 and m["validator_start"] <= pc < m["validator_end"],
                                "unqualified-read-watchpoint-stop")
                        event("header-read-before-extent-rejection", address=address, expected_address=injected["sp"]+4,
                              cpu=state, pc=pc, rsp_stop=stop)
                        raise RuntimeError("header-read-before-extent-rejection")
                    require(pc in active, "unknown-breakpoint-%x" % pc)
                    kind, state = active[pc], cpu()
                    task = rsp.word(m["selected"])
                    if kind == "secure-ready":
                        require(m["pool_end"]-m["pool_start"] in (3172, 3176) and pool() == b"\xa5"*(m["pool_end"]-m["pool_start"]) and
                                rsp.word(m["gateway_state"]) == 0, "actual-NOLOAD-poison-and-BSS-gate")
                        event(kind, cpu=state)
                        for address in fixed:
                            if address != pc:
                                rsp.breakpoint(address)
                    elif kind == "prepared":
                        require(not cold and not allocations and rsp.word(m["current_slot"]) == 0, "real-public-prestart-state")
                        for index in (0, 1):
                            start = m["stacks_ns"]+index*2048
                            limit, top = start+40, start+2040
                            context = words(read(owner(index), 80))
                            require(context[:8] == [top-76, start+3, start+2045, limit, top, top-limit,
                                                    m["task_entry"]|1, index], "independent-public-constructor-geometry")
                            require(context[10] == 0x20001, "actual-generation-two-storage")
                            values = words(read(top-76, 76))
                            expected = [0, limit, 0xFFFFFFBC]+[0]*8+[index, 0, 0, 0, 0, m["task_return"]|1, m["task_entry"], 0x01000000]
                            require(all(value == expected[i] for i, value in enumerate(values) if i != 8), "independent-initial-frame-except-ordinary-R9")
                            cold[index] = dict(start=start, limit=limit, top=top, r9=values[8])
                        event(kind, cpu=state, cold=cold)
                    elif kind == "task-entry":
                        require(task in cold and task not in entered and rsp.register("r0") == task and
                                state["xpsr"] & 511 == 0 and state["control_ns"] == 2 and state["psp_ns"] == cold[task]["top"], "actual-first-Thread-entry")
                        entered.add(task)
                        event(kind, task=task, cpu=state)
                    elif kind.endswith("checkpoint"):
                        secure = kind.startswith("s-")
                        expected = [0xE002ED04 if secure else 0xE000ED04, 0x10000000]+[
                            i*0x11000000 | i | task << 16 for i in range(2, 13)]+[0xEE00000E | task << 16]
                        require(task in entered and task not in pending and gprs() == expected and state["xpsr"] & 511 == 0, "independent-live-GPR-window")
                        require(read(pc, 4) == b"\x00\xbf\x01\x60", "actual-pending-store")
                        pending[task] = dict(cpu=state, gprs=gprs(), pc=pc, secure=secure, historic_sp=rsp.word(owner(task)),
                                             handle=rsp.word(m["live_handle"]), stack=read(cold[task]["start"], 2048))
                        event(kind, task=task, cpu=state, gprs=gprs())
                    elif kind == "pendsv":
                        before = pending[task]
                        event(kind, task=task, cpu=state, gprs=gprs())
                        require(state["xpsr"] & 511 == 14 and state["lr"] == (0xFFFFFFFC if before["secure"] else 0xFFFFFFBC), "actual-EXC_RETURN-S-DCRS-provenance")
                        require(state["control_ns"] == 0 and state["sp"] == state["msp_ns"] and
                                state["primask_ns"] == state["basepri_ns"] == state["faultmask_ns"] == 0, "actual-PendSV-bank-and-masks")
                        require(state["psp_ns"] == before["cpu"]["psp_ns"]-(0 if before["secure"] else 32), "actual-NS-hardware-frame-presence")
                        before["exception"] = state
                        before["entry_stack"] = read(cold[task]["start"], 2048)
                        if before["secure"]:
                            require(state["psp_s"] == before["cpu"]["psp_s"]-72 and before["entry_stack"] == before["stack"], "Secure-hardware-frame-with-no-NS-stack-change")
                        else:
                            require(words(read(state["psp_ns"], 32)) == basic(before), "independent-NS-hardware-frame")
                    elif kind == "selector":
                        if rsp.register("r0") == 0:
                            require(not pending and state["xpsr"] & 511 == 0, "real-initial-selector")
                        else:
                            before = pending[task]
                            require(counts.get("save", 0) == switches+1 and state["basepri_ns"] == 2, "Save-before-select-and-BASEPRI")
                            saved = rsp.word(owner(task))
                            required = 12 if before["secure"] else 76
                            event("selector-observed", task=task, cpu=state, saved=saved,
                                  expected_saved=before["cpu"]["psp_ns"]-required)
                            require(saved == before["cpu"]["psp_ns"]-required, "saved-size")
                            expected = [before["handle"], before["cpu"]["psplim_ns"], 0xFFFFFFFC if before["secure"] else 0xFFFFFFBC]
                            if not before["secure"]:
                                expected += before["gprs"][4:12]+basic(before)
                            require(words(read(saved, required)) == expected, "independent-complete-saved-image")
                            image = bytearray(before["entry_stack"])
                            data = packed(expected[:3] if before["secure"] else expected[:11])
                            offset = saved-cold[task]["start"]
                            image[offset:offset+len(data)] = data
                            require(read(cold[task]["start"], 2048) == image, "only-correct-NS-software-words-written")
                            event(kind, task=task, cpu=state, saved=saved, image=packed(expected).hex())
                            if switches == 1 and case in (10, 11, 12, 13):
                                target = cold[0]["top"]-(4 if case == 11 else 12) if case in (10, 11) else rsp.word(owner(0))
                                header = [allocations[owner(0)], cold[0]["limit"], 0xFFFFFFFC]
                                if case == 12:
                                    header[0] = 0
                                if case == 13:
                                    header[2] ^= 0x20
                                write(target, packed(header[:1] if case == 11 else header))
                                if case == 11:
                                    write(cold[0]["top"], b"\xa5"*8)
                                    require(rsp.packet("Z3,%x,4" % (target+4)) == "OK", "required-read-watchpoint-unsupported")
                                write(owner(0), packed([target]))
                                injected = dict(sp=target, header=header)
                                failure = dict(contexts=read(m["contexts"], 160), current=rsp.word(m["current_slot"]),
                                               counts=dict(counts), bank=bank(state))
                                event("bounded-image-injection", case=case, **injected)
                            switches += 1
                    elif kind == "pd-return":
                        before = pending.get(task)
                        if state["lr"] == 0xFFFFFFFC:
                            expected = cold[0]["top"] if case == 10 else before["cpu"]["psp_ns"]
                            event("Secure-restore-before-BX", task=task, cpu=state, expected_psp=expected)
                            require(state["psp_ns"] == expected, "restore-NS-PSP")
                            if case == 10:
                                require(injected is not None and switches == 2 and rsp.word(m["current_slot"]) == owner(0) and
                                        state["psplim_ns"] == cold[0]["limit"] and rsp.word(m["live_handle"]) == allocations[owner(0)], "minimal-three-word-restore-publication")
                                event("bounded-before-exception-return", cpu=state, sp=injected["sp"])
                                receipt.update(result="PASS", proof="stopped-valid-three-word-representation-no-Thread-return")
                                bounded = True
                                break
                        event(kind, task=task, cpu=state)
                    elif kind == "gateway-entry":
                        operation = entries[pc]
                        event(kind, operation=operation, cpu=state, r0=rsp.register("r0"), r1=rsp.register("r1"))
                        require(call is None, "overlapping-gateway-call")
                        if case == 20:
                            require(operation.startswith("query-"), "stale-stateful-entry")
                        origin = state["xpsr"] & 511
                        if operation == "initialize":
                            require(origin == 11 and not allocations, "real-SVC-initializer-origin")
                        elif operation == "allocate":
                            require(rsp.register("r0") == 512 and rsp.register("r1") in (owner(0), owner(1)), "independent-allocation-request")
                        elif operation in ("save", "load"):
                            require(origin in (11, 14) and rsp.register("r1") == owner(task) and rsp.register("r0") == allocations.get(owner(task), 0), "independent-owned-handle-and-origin")
                            if operation == "save":
                                before = pending[task]
                                require(origin == 14 and rsp.word(owner(task)) == before["historic_sp"] and
                                        read(cold[task]["start"], 2048) == before["entry_stack"], "Secure-Save-before-any-NS-store")
                                if before["secure"]:
                                    values = words(read(state["psp_s"], 72))
                                    require(values[0] == 0xFEFA125B and values[2:10] == before["gprs"][4:12] and values[10:18] == basic(before), "independent-Secure-hardware-r4-r11-and-basic-frame")
                        counts[operation] = counts.get(operation, 0)+1
                        target = state["lr"]
                        require(target % 2 == 0 and 0x10000 <= target < 0x20000 and target not in active, "genuine-unique-NS-SG-return")
                        call = dict(operation=operation, cpu=state, pool=pool(), r0=rsp.register("r0"), r1=rsp.register("r1"), exited=False)
                        active[target] = "gateway-return"
                        rsp.breakpoint(target)
                    elif kind == "gateway-exit":
                        operation = exits[pc]
                        require(call is not None and call["operation"] == operation and not call["exited"], "unpaired-real-BXNS")
                        expected = bytearray(call["pool"])
                        result = rsp.register("r0")
                        if operation == "initialize":
                            overlay(expected, m["records"], bytes(72))
                            overlay(expected, m["stacks_s"], bytes(3096))
                            overlay(expected, m["pool_state"], packed([0x53435049]))
                            require(result == 1 and rsp.word(m["gateway_state"]) == 0x53434752 and
                                    state["psp_s"] == state["psplim_s"] == 0 and state["control_s"] == 2 and
                                    rsp.word(0xE000ED0C) & 0xFFFF == 0x4000, "real-initializer-state-and-AIRCR")
                        elif operation == "allocate":
                            token = call["r1"]
                            require(token not in allocations and result == len(allocations)+1, "independent-static-handle")
                            allocations[token] = result
                            index = result-1
                            limit = m["stacks_s"]+index*1032
                            top = limit+512
                            pointers[token] = top
                            overlay(expected, m["records"]+index*24, packed([top, limit, top, token, 512, 0x53435458]))
                            overlay(expected, top, packed([0xFEF5EDA5]*2))
                        elif operation == "save":
                            if call["r0"]:
                                pointers[call["r1"]] = call["cpu"]["psp_s"]
                                overlay(expected, m["records"]+(call["r0"]-1)*24, packed([call["cpu"]["psp_s"]]))
                            require(result == 1 and state["psp_s"] == state["psplim_s"] == 0, "real-Save-unloads-Secure-bank")
                        elif operation == "load":
                            limit = m["stacks_s"]+(call["r0"]-1)*1032 if call["r0"] else 0
                            pointer = pointers[call["r1"]] if call["r0"] else 0
                            require(result == 1 and state["psp_s"] == pointer and state["psplim_s"] == limit and state["control_s"] == 2, "real-owned-or-explicit-zero-Load")
                        require(pool() == expected, "exact-entire-pool-byte-transition")
                        last_secure = dict(pool=pool(), gateway_state=rsp.word(m["gateway_state"]))
                        call["exited"] = True
                        event(kind, operation=operation, cpu=state, result=result)
                    elif kind == "gateway-return":
                        require(call is not None and call["exited"] and bank(state) == bank(call["cpu"]), "real-BXNS-NS-bank-preservation")
                        event(kind, operation=call["operation"], cpu=state)
                        call = None
                        del active[pc]
                    elif kind.endswith("resumed"):
                        before = pending[task]
                        require(task == 0 and switches == 2 and gprs() == before["gprs"], "all-GPRs-hardware-and-software-restored")
                        require(state["psp_ns"] == before["cpu"]["psp_ns"] and state["psp_s"] == before["cpu"]["psp_s"] and
                                state["psplim_ns"] == before["cpu"]["psplim_ns"] and state["control_ns"] == 2 and
                                state["xpsr"] & 511 == 0 and state["primask_ns"] == state["basepri_ns"] == state["faultmask_ns"] == 0, "actual-resume-banks-and-masks")
                        resumes += 1
                        event(kind, task=task, cpu=state, gprs=gprs())
                    elif kind == "panic":
                        code = rsp.register("r0")
                        event(kind, code=code, cpu=state, gprs=gprs())
                        if case in (11, 12, 13):
                            require(injected is not None and code == {11: 88, 12: 68, 13: 120}[case] and state["xpsr"] & 511 == 14, "panic-code-origin")
                            require(call is None and resumes == 0 and read(m["contexts"], 160) == failure["contexts"] and
                                    rsp.word(m["current_slot"]) == failure["current"] and counts == failure["counts"], "invalid-restore-no-publication-SG-or-repair")
                            require(all(state[key] == failure["bank"][key] for key in (
                                "control_ns", "psp_ns", "psplim_ns", "primask_ns", "basepri_ns", "faultmask_ns")),
                                "invalid-restore-NS-state-not-repaired")
                        elif case == 20:
                            require(code == 81 and state["xpsr"] & 511 == 11 and not entered and
                                    counts == {"query-0": 1, "query-1": 1, "query-2": 1} and
                                    last_secure is not None and last_secure["pool"] == b"\xa5"*(m["pool_end"]-m["pool_start"]) and last_secure["gateway_state"] == 0 and
                                    state["psp_s"] == state["psplim_s"] == state["control_s"] == 0, "stale-layout-before-initialize-and-CPU-change")
                        else:
                            raise RuntimeError("unexpected-panic-"+str(code))
                        panic_seen = True
                    else:
                        raise RuntimeError("unhandled-event-"+kind)
                    rsp.breakpoint(pc, False)
                    step = rsp.packet("s")
                    if pc in fixed:
                        rsp.breakpoint(pc)
                    if step.startswith("W"):
                        stop = step
                    else:
                        require(step.startswith(("S05", "T05")), "unexpected-single-step-"+step)
                        stop = step if (rsp.register("pc") & ~1) in active else rsp.packet("c")
            if not bounded:
                text = (directory/"qemu.log").read_text(errors="replace")
                if panic_seen:
                    require(text.count("PANIC-EXIT:C33-ORIGIN\n") == 1 and "PASS" not in text and "FAULT" not in text and "FAIL" not in text, "exact-terminal-report")
                else:
                    require(text.count("PASS:C33-ORIGIN:runtime\n") == 1 and "FAIL" not in text and "FAULT" not in text and "PANIC" not in text, "exact-positive-report")
        receipt.update(switches=switches, resumes=resumes, gateway_counts=counts)
    except Exception as error:
        receipt.update(result="FAIL", error=str(error), error_type=type(error).__name__)
        raise
    finally:
        if connection:
            connection.close()
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        (directory/"receipt.json").write_text(json.dumps(receipt, indent=2)+"\n")
    print("PASS:C33-ORIGIN:"+str(case))


if __name__ == "__main__":
    if sys.argv[1:] == ["--preflight"]:
        preflight()
    else:
        main()
