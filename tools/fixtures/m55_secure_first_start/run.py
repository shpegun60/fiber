"""Real dual-image M55 first-start proof. Stdlib and an existing QEMU only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    root, seconds, manifest_path, rsp_source = sys.argv[1:]
    path = Path(manifest_path)
    m = json.loads(path.read_text(encoding="utf-8-sig"))
    directory = path.parent
    deadline = time.monotonic() + int(seconds)
    receipt = dict(result="FAIL", hardware=False, machine="mps3-an547", case=m["case"],
                   kind=m["kind"], trace=[], calls={}, query_calls={}, entries=0)
    process = connection = None
    reference = m["kind"] == "reference"
    negative = "panic_code" in m
    call = None
    before_bx = None
    prepared = False
    panic_seen = False
    context = frame = limit = top = 0
    original_context = original_frame = b""
    secure_memory = {}
    expected_handle = int(m["case"] != 0)

    def check(condition, label):
        require(condition, label)

    try:
        for kind in ("secure", "nonsecure"):
            digest = hashlib.sha256(Path(m[kind]).read_bytes()).hexdigest().upper()
            check(digest == m[kind + "_sha256"], kind + "-ELF-drift")
            receipt[kind + "_sha256"] = digest
        spec = importlib.util.spec_from_file_location("first_rsp", rsp_source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        environment = dict(os.environ)
        environment["LD_LIBRARY_PATH"] = str(Path(root) / "usr/lib/x86_64-linux-gnu") + (
            ":" + environment["LD_LIBRARY_PATH"] if environment.get("LD_LIBRARY_PATH") else "")
        with tempfile.TemporaryDirectory(prefix="fiber-c55s-first-") as temporary:
            socket_path = str(Path(temporary) / "gdb.sock")
            command = [str(Path(root) / "usr/bin/qemu-system-arm"), "-machine", "mps3-an547",
                       "-accel", "tcg", "-display", "none", "-serial", "none", "-monitor", "none",
                       "-no-reboot", "-semihosting-config", "enable=on,target=native", "-L",
                       str(Path(root) / "usr/share/qemu"), "-kernel", m["secure"], "-device",
                       "loader,file=" + m["nonsecure"], "-S", "-chardev",
                       "socket,id=first,path=" + socket_path + ",server=on,wait=off", "-gdb", "chardev:first"]
            receipt["qemu_command"] = command
            with (directory / "qemu.log").open("wb") as output:
                process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                           env=environment, start_new_session=True)
                connection = socket.socket(socket.AF_UNIX)
                while True:
                    check(process.poll() is None, "QEMU-exited-before-RSP")
                    try:
                        connection.connect(socket_path)
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        check(time.monotonic() < deadline, "RSP-startup-timeout")
                        time.sleep(0.01)
                rsp = module.Rsp(connection, deadline)
                rsp.discover_registers()
                receipt["registers"] = rsp.registers
                check(rsp.packet("?").startswith(("S", "T")), "missing-initial-stop")

                def reg(name):
                    return rsp.register(name)

                def write_reg(name, value):
                    number, bits = rsp.registers[name]
                    value &= (1 << bits) - 1
                    check(rsp.packet("P%x=%s" % (number, value.to_bytes(bits // 8, "little").hex())) == "OK",
                          "write-register-" + name)

                def write_word(address, value):
                    check(rsp.packet("M%x,4:%s" % (address, int(value).to_bytes(4, "little").hex())) == "OK",
                          "write-memory")

                def write_halfword(address,value):
                    check(rsp.packet("M%x,2:%s" % (address,int(value).to_bytes(2,"little").hex()))=="OK",
                          "write-code-halfword")

                def ns_cpu():
                    return {n: reg(n) for n in ("control_ns", "primask_ns", "basepri_ns", "faultmask_ns",
                                                "msp_ns", "psp_ns", "psplim_ns")}

                def words(address, count):
                    data = secure_read(address, count * 4) if address >= 0x30000000 else rsp.memory(address, count * 4)
                    return [int.from_bytes(data[i*4:i*4+4], "little") for i in range(count)]

                def refresh_secure():
                    regions = [(m["reference_records"],48), (m["reference_heap"],1024),
                               (m["reference_heap_used"],4)] if reference else [
                                   (m["pool"],480),(m["pool_state"],4),(m["gateway_state"],4)]
                    for address, size in regions:
                        secure_memory[address] = rsp.memory(address,size)

                def secure_read(address, size):
                    for base, data in secure_memory.items():
                        if address >= base and address+size <= base+len(data):
                            return data[address-base:address-base+size]
                    raise RuntimeError("missing-actual-Secure-memory-snapshot")

                def secure_word(address):
                    return int.from_bytes(secure_read(address,4),"little")

                def event(name, **values):
                    receipt["trace"].append(dict(event=name, **values))

                def counts():
                    return {n: receipt["calls"].get(n, 0) for n in ("priority", "initialize", "allocate", "load")}

                def image(allocated):
                    if reference:
                        base = m["reference_records"]
                        row = [m["reference_heap"] + 64, m["reference_heap"], m["reference_heap"] + 64, context]
                        expected = row + [0] * 8 if allocated else [0] * 12
                        check(words(base, 12) == expected, "reference-independent-records")
                        check(secure_word(m["reference_heap_used"]) == (72 if allocated else 0), "reference-heap-request")
                        if allocated:
                            check(words(m["reference_heap"] + 64, 2) == [0xFEF5EDA5] * 2, "reference-seals")
                        return
                    data = bytearray(480)
                    if allocated:
                        stack_limit = m["pool"] + 72
                        row = [stack_limit + 64, stack_limit, stack_limit + 64, context, 64, 0x53435458]
                        for index, value in enumerate(row):
                            data[index*4:index*4+4] = value.to_bytes(4, "little")
                        data[72+64:72+72] = (0xFEF5EDA5).to_bytes(4, "little") * 2
                    check(secure_read(m["pool"], 480) == data, "independent-whole-pool-image")
                    check(secure_word(m["pool_state"]) == 0x53435052, "pool-ready-marker")
                    check(secure_word(m["gateway_state"]) == 0x53434752, "gateway-ready-marker")

                def unchanged(handle=0):
                    if reference:
                        return
                    check(rsp.memory(context, 80) == original_context, "context-unchanged")
                    expected = bytearray(original_frame)
                    expected[:4] = handle.to_bytes(4, "little")
                    check(rsp.memory(frame, 76) == expected, "saved-19-word-image-unchanged")

                fixed = {m["secure_ready"]: ("secure-ready",None),m["prepared"]: ("prepared", None), m["restore_bx"]: ("restore-bx", None),
                         m["entry"]: ("entry", None)}
                if not reference:
                    for field in ("panic", "svc", "dispatch", "prepare"):
                        fixed[m[field]] = (field, None)
                for item in m["secure_entries"]:
                    fixed[item["address"]] = ("secure-entry", item["operation"])
                for item in m["secure_exits"]:
                    fixed[item["address"]] = ("secure-exit",item["operation"])
                active = {m["secure_ready"]:fixed[m["secure_ready"]]}
                rsp.breakpoint(m["secure_ready"])
                stop = rsp.packet("c")
                while True:
                    if stop.startswith("W"):
                        expected_code = 93 if negative else 0
                        check(stop == "W%02x" % expected_code, "unexpected-exit-packet-" + stop)
                        code = process.wait(timeout=max(0.01, deadline-time.monotonic()))
                        check(code == expected_code, "unexpected-QEMU-exit")
                        check(prepared, "missing-prepared-proof")
                        if negative:
                            check(panic_seen and receipt["entries"] == 0, "missing-terminal-panic-proof")
                        else:
                            check(receipt["entries"] == 1 and before_bx is not None, "missing-first-return-proof")
                            expected = dict(priority=1 if reference else 0, initialize=1,
                                            allocate=int(m["case"] == 1), load=int(m["case"] == 1) if reference else 1)
                            check(counts() == expected, "exact-final-primitive-counts")
                            if not reference:
                                check(receipt["query_calls"] == {str(i): 1 for i in range(8)}, "exact-eight-query-counts")
                        receipt.update(result="PASS", exit_code=code, final_counts=counts())
                        break
                    check(stop.startswith(("S05", "T05")), "unexpected-stop-" + stop)
                    pc = reg("pc") & ~1
                    check(pc in active, "unrecognized-stop-PC-%x" % pc)
                    kind, operation = active[pc]
                    rearm = pc in fixed
                    if kind == "secure-ready":
                        check(not prepared and not secure_memory,"duplicate-Secure-ready")
                        refresh_secure()
                        if not reference:
                            check(secure_read(m["pool"],480)==b"\xa5"*480,"initial-NOLOAD-poison")
                            check(secure_word(m["pool_state"])==0 and secure_word(m["gateway_state"])==0,
                                  "initial-zero-Secure-markers")
                        for address,item in fixed.items():
                            if address not in active:
                                rsp.breakpoint(address)
                                active[address]=item
                        event("Secure-ready",snapshots={hex(a):hashlib.sha256(d).hexdigest() for a,d in secure_memory.items()})
                    elif kind == "prepared":
                        check(not prepared, "duplicate-prepared")
                        prepared = True
                        if reference:
                            context = rsp.word(m["current_slot"])
                            frame = rsp.word(context)
                            limit = rsp.word(frame+4)
                            top = frame+76
                        else:
                            context = m["context"]
                            expected_attachment = {str(i): 1 for i in range(8)} if m["case"] != 0 else {}
                            check(receipt.get("attachment_queries", {}) == expected_attachment,
                                  "exact-attachment-query-prefix")
                            frame = rsp.word(m["original_frame"])
                            limit = rsp.word(context+12)
                            top = rsp.word(context+16)
                            original_context = rsp.memory(context, 80)
                            original_frame = rsp.memory(frame, 76)
                            check(secure_read(m["pool"], 480) == b"\xa5" * 480, "prepared-NOLOAD-poison")
                            check(secure_word(m["pool_state"]) == 0 and secure_word(m["gateway_state"]) == 0,
                                  "initial-zero-Secure-markers")
                            if m["case"] == 11:
                                write_word(m["current_slot"], 0)
                            if m["case"] == 26:
                                write_halfword(m["owned_return"]-2,0xDFFF)
                        for address, item in fixed.items():
                            if address not in active:
                                rsp.breakpoint(address)
                                active[address] = item
                        event("prepared", context=context, frame=frame, limit=limit, top=top, cpu=ns_cpu())
                    elif kind == "prepare":
                        if m["case"] == 23:
                            write_reg("r0", 0x20019000)
                    elif kind == "svc":
                        raw = reg("msp_ns")
                        check(reg("lr") == 0xFFFFFFB8 and (reg("xpsr") & 511) == 11, "actual-SVC-origin-B8")
                        event("svc", raw_msp=raw, exc_return=reg("lr"), stacked_pc=rsp.word(raw+24))
                        if m["case"] in (15, 16, 17):
                            value = rsp.word(raw+28)
                            value = value & ~0x01000000 if m["case"] == 15 else value | (0x200 if m["case"] == 16 else 1)
                            write_word(raw+28, value)
                        if m["case"] in (18, 19, 20, 21):
                            value = {18: 0, 19: m["owned_return"] | 1, 20: 0xE000ED02,
                                     21: m["foreign_return"]}[m["case"]]
                            write_word(raw+24, value)
                    elif kind == "dispatch":
                        if m["case"] in (13, 14, 25):
                            write_reg("r0", {13: 0x20017FF8, 14: 0x2001FFE8, 25: reg("r0") + 4}[m["case"]])
                    elif kind == "secure-entry":
                        refresh_secure()
                        check(call is None, "nested-SG-operation")
                        lr = reg("lr")
                        tail = reference and operation == "load" and lr == 0xFFFFFFBC and m["reference_tail_load"]
                        check((lr & 1) == 0 and (0x10000 <= lr < 0x20000 or tail),
                              "genuine-NS-to-SG-origin-%x" % lr)
                        check((reg("xpsr") & 511) == (11 if prepared else 0), "genuine-SG-phase-origin")
                        if operation.startswith("query-"):
                            index = operation.split("-")[1]
                            target=receipt["query_calls"] if prepared else receipt.setdefault("attachment_queries",{})
                            check(int(index)==len(target),"exact-query-order")
                            target[index] = target.get(index, 0) + 1
                            check(target[index] == 1, "duplicate-query")
                        else:
                            check(prepared,"primitive-before-first-start")
                            receipt["calls"][operation] = receipt["calls"].get(operation, 0) + 1
                            check(receipt["calls"][operation] == 1, "duplicate-primitive-" + operation)
                        if operation == "allocate":
                            check(reg("r0") == 64 and reg("r1") == context, "independent-allocation-arguments")
                        if operation == "load":
                            check(reg("r0") == expected_handle and reg("r1") == context, "independent-load-arguments")
                            if not reference:
                                unchanged(expected_handle)
                        target = rsp.word(reg("psp_ns")+24) if tail else lr
                        check(target not in active and 0x10000 <= target < 0x20000 and (target & 1)==0,
                              "ambiguous-SG-return-address")
                        call = dict(operation=operation, return_address=target, cpu=ns_cpu(),prepared=prepared,
                                    secure_exit=False,tail_exception_return=tail)
                        active[target] = ("secure-return", operation)
                        rsp.breakpoint(target)
                        event("secure-entry", operation=operation, lr=lr, tail_exception_return=tail,
                              return_target=target,r0=reg("r0"), r1=reg("r1"), cpu=ns_cpu())
                    elif kind == "secure-exit":
                        check(call is not None and operation==call["operation"] and not call["secure_exit"],
                              "unpaired-Secure-exit")
                        refresh_secure()
                        call["secure_exit"]=True
                        event("Secure-exit",operation=operation,result=reg("r0"),
                              snapshots={hex(a):hashlib.sha256(d).hexdigest() for a,d in secure_memory.items()})
                    elif kind == "secure-return":
                        check(call is not None and operation == call["operation"], "unpaired-SG-return")
                        check(call["secure_exit"],"missing-actual-Secure-exit-snapshot")
                        after = ns_cpu()
                        if call["prepared"] and "disturb" in m and operation == "query-" + str(m["query_index"]):
                            field = m["disturb"] + "_ns"
                            toggles = {"primask_ns": 1, "basepri_ns": 128, "faultmask_ns": 1,
                                       "control_ns": 2, "psplim_ns": 8}
                            expected = dict(call["cpu"])
                            expected[field] ^= toggles[field]
                            check(after == expected, "actual-bank-disturbance")
                        else:
                            expected=dict(call["cpu"])
                            if call["tail_exception_return"]:
                                expected["psp_ns"]+=32
                                expected["control_ns"]=2
                                check((reg("xpsr")&511)==0,"reference-tail-real-Thread-resume")
                            check(after == expected, "NS-bank-preserved-across-SG")
                        result = reg("r0")
                        if not reference and operation in ("initialize", "allocate", "load"):
                            check(result == (0 if m.get("bad_primitive") == operation else 1), "exact-primitive-result")
                        if operation == "initialize":
                            check(reg("control_s") == 2 and reg("psp_s") == 0 and reg("psplim_s") == 0,
                                  "Secure-initial-registers")
                            image(False)
                        if operation == "allocate":
                            image(True)
                            check(reg("psp_s") == 0 and reg("psplim_s") == 0, "allocation-no-stack-load")
                        if operation == "load":
                            image(bool(expected_handle))
                            secure_limit = (m["reference_heap"] if reference else m["pool"]+72) if expected_handle else 0
                            secure_top = secure_limit+64 if expected_handle else 0
                            check(reg("psp_s") == secure_top and reg("psplim_s") == secure_limit and
                                  reg("control_s") == 2, "Secure-loaded-registers")
                        event("secure-return", operation=operation, result=result, cpu=after,
                              secure_psp=reg("psp_s"), secure_limit=reg("psplim_s"), secure_control=reg("control_s"))
                        if operation=="load" and m["case"] in (400,401):
                            write_word(0x10000 if m["case"]==400 else 0x1002C,
                                       0x2001FFF8 if m["case"]==400 else m["fault_handler"]|1)
                        call = None
                        rearm = False
                        del active[pc]
                    elif kind == "restore-bx":
                        check(not negative and before_bx is None, "unexpected-first-restore")
                        check((reg("xpsr") & 511) == 11 and reg("r3") == 0xFFFFFFBC, "actual-BC-Handler-return")
                        check(reg("control_ns") == 2 and reg("psp_ns") == top-32 and reg("psplim_ns") == limit,
                              "NS-first-registers-before-BC")
                        check(reg("sp") == reg("msp_ns") and 0x20018000 <= reg("sp") < 0x20020000,
                              "physical-Handler-MSP-with-written-SPSEL")
                        check(reg("primask_ns") == 0 and reg("basepri_ns") == 0 and reg("faultmask_ns") == 0,
                              "first-return-masks")
                        before_bx = [reg("r%d" % i) for i in range(4, 12)]
                        if reference:
                            check(before_bx[0] == m["live_handle"], "reference-r4-is-global-address-not-saved-r4")
                            image(False)
                        else:
                            check(before_bx == [0, 0, 0, 0, 0, 0x91A2B3C4, 0, 0], "first-restored-r4-r11")
                            unchanged(expected_handle)
                            image(bool(expected_handle))
                            check(rsp.word(m["live_handle"]) == expected_handle, "published-live-handle")
                            check(words(m["plan"], 3) == [0x20020000, context, 2], "committed-first-plan")
                        event("restore-bx", exc_return=reg("r3"), r4_r11=before_bx, cpu=ns_cpu(), physical_sp=reg("sp"))
                    elif kind == "entry":
                        check(not negative and before_bx is not None and receipt["entries"] == 0, "unexpected-Thread-entry")
                        receipt["entries"] += 1
                        check((reg("xpsr") & 511) == 0 and reg("control_ns") == 2 and reg("psp_ns") == top,
                              "actual-NS-Thread-PSP-entry")
                        check(reg("psplim_ns") == limit and reg("r0") == 0x12345678, "entry-argument-limit")
                        check([reg("r%d" % i) for i in range(4, 12)] == before_bx, "entry-GPRs-survive-BC")
                        if not reference:
                            unchanged(expected_handle)
                        event("Thread-entry", r4_r11=before_bx, lr=reg("lr"), cpu=ns_cpu())
                    elif kind == "panic":
                        check(negative and not panic_seen and receipt["entries"] == 0, "unexpected-panic")
                        check(reg("r0") == m["panic_code"] and (reg("xpsr") & 511) == m["panic_ipsr"],
                              "exact-panic-code-origin")
                        panic_seen = True
                        expected_state = 2 if m["case"] >= 100 else (0 if m["case"]==27 else
                            (1 if m["panic_ipsr"] == 11 or m["case"] == 12 else 0))
                        check(rsp.word(m["plan"]+8)==expected_state,"exact-terminal-plan-state")
                        check(rsp.word(m["current_slot"])==(0 if m["case"]==11 else context),
                              "common-publication-preserved-on-failure")
                        check(rsp.word(m["live_handle"])==(1 if m["case"]>=400 else 0),
                              "exact-failure-live-handle-publication")
                        initialized = counts()["initialize"] != 0
                        allocated = counts()["allocate"] != 0
                        loaded = counts()["load"] != 0
                        unchanged(int(loaded and allocated))
                        if initialized:
                            image(allocated)
                        else:
                            check(secure_read(m["pool"], 480) == b"\xa5" * 480, "rejection-before-Secure-pool-effects")
                            check(reg("psp_s") == 0x30006000 and reg("psplim_s") == 0x30005000,
                                  "rejection-before-Secure-register-effects")
                        if "expected_counts" in m:
                            check(counts() == m["expected_counts"], "exact-failure-call-counts")
                        query_count = m["query_index"] + 1 if "query_index" in m else (
                            8 if m["case"] >= 300 else 0)
                        check(receipt["query_calls"] == {str(i): 1 for i in range(query_count)},
                              "exact-terminal-query-prefix")
                        event("terminal-panic", code=reg("r0"), ipsr=reg("xpsr") & 511, counts=counts())
                    else:
                        raise RuntimeError("unhandled-event-" + kind)
                    rsp.breakpoint(pc, False)
                    step = rsp.packet("s")
                    if rearm:
                        rsp.breakpoint(pc)
                    if step.startswith("W"):
                        stop = step
                    else:
                        check(step.startswith(("S05", "T05")), "unexpected-single-step-" + step)
                        stop = step if (reg("pc") & ~1) in active else rsp.packet("c")
            text = (directory / "qemu.log").read_text(errors="replace")
            check("START:C55S-FIRST:Secure-M55\n" in text and "START:C55S-FIRST:NS-" in text, "missing-boot-reports")
            check("FAULT" not in text and "FAIL" not in text, "unexpected-fault-or-assertion")
            if negative:
                marker = "PANIC:C55S-FIRST code=0x%08x IPSR=0x%08x\n" % (m["panic_code"], m["panic_ipsr"])
                check(text.count(marker) == 1 and text.count("PANIC-EXIT:C55S-FIRST\n") == 1,
                      "exact-terminal-panic-report")
                check("ENTRY:C55S-FIRST" not in text and "PASS-EXIT" not in text, "negative-resumed-Thread")
            else:
                check(text.count("PASS:C55S-FIRST:" + m["kind"] + "\n") == 1 and
                      text.count("PASS-EXIT:C55S-FIRST\n") == 1, "exact-completion-report")
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
        (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("PASS:C55S-FIRST:" + m["kind"] + ":" + str(m["case"]))


if __name__ == "__main__":
    main()
