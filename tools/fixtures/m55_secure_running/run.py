"""Live M55 two-image running-task observation; no architectural encoding model."""
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
    root, timeout, manifest_path, transport = sys.argv[1:]
    path = Path(manifest_path)
    m = json.loads(path.read_text(encoding="utf-8-sig"))
    directory = path.parent
    deadline = time.monotonic() + int(timeout)
    receipt = dict(result="FAIL", scope=m["kind"]+"-running-transfer", case=m["case"], trace=[])
    process = connection = None
    pending = {}
    stride=m["stride"]
    reference=m["kind"]=="reference"
    scenario=m.get("scenario",m["case"])
    negative="panic_code" in m
    pool_fault=m.get("pool_fault",False)
    switches = 0
    resumes = 0
    call = None
    allocations = {}
    points = {}
    operation_counts = {}
    last_regions = {}
    cold = {}
    entered = set()
    injected=False
    failure_snapshot=None
    panic_seen=False
    fault=None
    fault_seen=False
    try:
        for name in ("secure", "nonsecure"):
            require(hashlib.sha256(Path(m[name]).read_bytes()).hexdigest().upper() == m[name+"_sha256"],
                    name+"-image-drift")
        spec = importlib.util.spec_from_file_location("running_transport", transport)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        environment = dict(os.environ)
        environment["LD_LIBRARY_PATH"] = str(Path(root)/"usr/lib/x86_64-linux-gnu") + (
            ":"+environment["LD_LIBRARY_PATH"] if environment.get("LD_LIBRARY_PATH") else "")
        with tempfile.TemporaryDirectory(prefix="fiber-c55s-running-") as temporary:
            sock = str(Path(temporary)/"rsp.sock")
            command = [str(Path(root)/"usr/bin/qemu-system-arm"), "-machine", "mps3-an547", "-accel", "tcg",
                       "-display", "none", "-serial", "none", "-monitor", "none", "-no-reboot",
                       "-semihosting-config", "enable=on,target=native", "-L", str(Path(root)/"usr/share/qemu"),
                       "-kernel", m["secure"], "-device", "loader,file="+m["nonsecure"], "-S", "-chardev",
                       "socket,id=run,path="+sock+",server=on,wait=off", "-gdb", "chardev:run"]
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
                        time.sleep(0.01)
                rsp = module.Rsp(connection, deadline)
                rsp.discover_registers()

                def cpu():
                    return {name: rsp.register(name) for name in (
                        "xpsr", "lr", "sp", "control_s", "control_ns", "psp_s", "psp_ns", "psplim_s",
                        "psplim_ns", "msp_s", "msp_ns", "primask_ns", "basepri_ns", "faultmask_ns",
                        "primask_s","basepri_s","faultmask_s")}

                def gprs():
                    return [rsp.register("r%d" % i) for i in range(13)] + [rsp.register("lr")]

                def event(name, **fields):
                    receipt["trace"].append(dict(event=name, **fields))

                def snapshot(address, size):
                    return dict(address=address, bytes=rsp.memory(address, size).hex())

                def words(data):
                    require(len(data) % 4 == 0,"unaligned-observation")
                    return [int.from_bytes(data[i:i+4],"little") for i in range(0,len(data),4)]

                def basic_frame(before):
                    values=before["gprs"]
                    return values[:4]+[values[12],values[13],before["stacked_pc"],before["cpu"]["xpsr"]]

                def ns_cpu(state):
                    return {key:value for key,value in state.items() if key.endswith("_ns")}

                def read_bytes(address,size):
                    return b"".join(rsp.memory(address+offset,min(512,size-offset)) for offset in range(0,size,512))

                def regions():
                    if reference:
                        return dict(records=read_bytes(m["records"],48),heap=read_bytes(m["heap"],1560))
                    return dict(pool=read_bytes(m["records"],3168),pool_state=rsp.memory(m["pool_state"],4),
                                gateway_state=rsp.memory(m["gateway_state"],4))

                def hashes(data):
                    return {key:hashlib.sha256(value).hexdigest() for key,value in data.items()}

                def attached(task):
                    return scenario in (1,4) or scenario==2 and task==0 or scenario==3 and task==1

                def target_owner(task):
                    return m["tcbs"]+task*stride

                def cold_unchanged(owner,handle):
                    task=(owner-m["tcbs"])//stride
                    if task in entered:
                        return
                    image=bytearray(cold[task]["frame"])
                    image[:4]=handle.to_bytes(4,"little")
                    require(rsp.memory(cold[task]["sp"],76)==image,"exact-cold-frame-through-allocation-load")
                    require(rsp.memory(owner,stride)==cold[task]["context"],"cold-context-metadata-preserved")

                def geometry(owner):
                    index=allocations[owner]-1
                    limit=m["heap"]+index*(520 if reference else 1032)
                    return index,limit,limit+512

                def gateway_effects(operation, before, after, result, state):
                    expected={key:bytearray(value) for key,value in before["regions"].items()}
                    owner=before["r1"]
                    if operation=="initialize":
                        require(not allocations,"unexpected-reinitialize")
                        if reference:
                            expected["records"][:]=bytes(48)
                        else:
                            expected["pool"][:]=bytes(3168)
                            expected["pool_state"][:]=(0x53435052).to_bytes(4,"little")
                            expected["gateway_state"][:]=(0x53434752).to_bytes(4,"little")
                        require(state["psp_s"]==state["psplim_s"]==0 and state["control_s"]==2,
                                "real-initializer-bank-state")
                    elif operation=="allocate":
                        handle=len(allocations)+1
                        require(result==handle and owner not in allocations,"independent-allocation-handle")
                        allocations[owner]=handle
                        index,limit,top=geometry(owner)
                        points[owner]=top
                        row=[top,limit,top,owner]+([] if reference else [512,0x53435458])
                        image=expected["records" if reference else "pool"]
                        row_offset=index*(16 if reference else 24)
                        image[row_offset:row_offset+len(row)*4]=b"".join(value.to_bytes(4,"little") for value in row)
                        stack=expected["heap" if reference else "pool"]
                        seal=(index*520 if reference else 72+index*1032)+512
                        require(not any(stack[seal-512:seal]),"independent-new-stack-zero-state")
                        stack[seal:seal+8]=(0xFEF5EDA5).to_bytes(4,"little")*2
                        require(state["psp_s"]==state["psplim_s"]==0,"allocation-does-not-load-stack")
                        cold_unchanged(owner,0)
                    elif operation=="save":
                        handle=before["r0"]
                        if handle:
                            index,limit,top=geometry(owner)
                            pointer=before["cpu"]["psp_s"]
                            require(before["cpu"]["psplim_s"]==limit and limit<=pointer<=top and pointer%8==0,
                                    "independent-live-Secure-stack-bounds")
                            points[owner]=pointer
                            image=expected["records" if reference else "pool"]
                            offset=index*(16 if reference else 24)
                            image[offset:offset+4]=pointer.to_bytes(4,"little")
                        else:
                            require(before["cpu"]["psp_s"]==before["cpu"]["psplim_s"]==0,"zero-save-empty-bank")
                        require(state["psp_s"]==state["psplim_s"]==0,"save-unloads-real-Secure-bank")
                    elif operation=="load":
                        require(before["cpu"]["psp_s"]==before["cpu"]["psplim_s"]==0,"load-requires-unloaded-bank")
                        limit=geometry(owner)[1] if before["r0"] else 0
                        pointer=points[owner] if before["r0"] else 0
                        require(state["psp_s"]==pointer and state["psplim_s"]==limit and state["control_s"]==2,
                                "load-restores-independent-owned-stack")
                        cold_unchanged(owner,before["r0"])
                    else:
                        require(all(state[key]==before["cpu"][key] for key in ("control_s","psp_s","psplim_s")),
                                "query-or-priority-Secure-bank-preserved")
                    require(all(after[key]==value for key,value in expected.items()),"exact-entire-Secure-memory-transition")
                    if not reference and operation in ("initialize","save","load"):
                        require(result==1,"exact-primitive-success-result")

                def write_reg(name,value):
                    number,bits=rsp.registers[name]
                    require(rsp.packet("P%x=%s"%(number,(value&((1<<bits)-1)).to_bytes(bits//8,"little").hex()))=="OK",
                            "register-injection-"+name)
                    require(rsp.register(name)==value&((1<<bits)-1),"ineffective-debugger-register-write-"+name)

                def write_word(address,value):
                    require(rsp.packet("M%x,4:%s"%(address,(value&0xFFFFFFFF).to_bytes(4,"little").hex()))=="OK",
                            "memory-injection")

                def real_state_write(field,value):
                    original_pc=rsp.register("pc")&~1
                    original_cpu=cpu()
                    original_gprs=gprs()
                    require(original_cpu["xpsr"]&511==14,"actual-state-injection-Handler-origin")
                    bank=field.rsplit("_",1)[1]
                    domain="s" if original_cpu["sp"]==original_cpu["msp_s"] else "ns"
                    require(original_cpu["sp"]==original_cpu["msp_"+domain] and not (domain=="ns" and bank=="s"),
                            "actual-injection-domain")
                    prefix="s_" if domain=="s" else ""
                    write_word(m[prefix+"control_return"],original_pc|1)
                    write_word(m[prefix+"control_value"],value)
                    fields=[base+"_"+bank for base in ("control","primask","basepri","faultmask","psplim","psp")]
                    write_word(m[prefix+"control_register"],fields.index(field)+(6 if domain=="s" and bank=="ns" else 0))
                    rsp.breakpoint(m[prefix+"control_done"])
                    write_reg("pc",m[prefix+"control_injection"])
                    reply=rsp.packet("c")
                    require(reply.startswith(("S05","T05")) and rsp.register("pc")&~1==m[prefix+"control_done"],
                            "real-MSR-state-stop")
                    after=cpu()
                    expected=dict(original_cpu)
                    expected[field]=value
                    require(after==expected and after["sp"]==after["msp_"+domain] and gprs()==original_gprs,
                            "actual-MSR-preserves-GPRs-flags-physical-MSP-and-other-banks")
                    rsp.breakpoint(m[prefix+"control_done"],False)
                    reply=rsp.packet("c")
                    require(reply.startswith(("S05","T05")) and rsp.register("pc")&~1==original_pc,
                            "actual-state-trampoline-return")
                    event("actual-MSR-state-injection",field=field,before=original_cpu,after=after,return_pc=original_pc)

                def inject(when):
                    nonlocal injected,failure_snapshot
                    if not negative or injected or m["attack"]["when"]!=when or rsp.register("xpsr")&511!=14:
                        return
                    action=m["attack"]["action"]
                    current=target_owner(0)
                    next_context=target_owner(1)
                    if action=="return-zero":
                        original=rsp.register("r0")
                        require(original!=0,"nonzero-real-return-before-result-fault")
                        write_reg("r0",0)
                        event("actual-result-fault",operation=when,original=original,injected=0)
                    elif action.startswith("secure-"):
                        field=action[len("secure-"):]+'_s'
                        real_state_write(field,rsp.register(field)+4 if field=="psp_s" else 0)
                    elif action=="gateway-owner":
                        write_reg("r1",rsp.register("r1")+4)
                    elif action=="gateway-handle":
                        write_reg("r0",99)
                    elif action=="record-owner":
                        owner=target_owner(0)
                        offset=(allocations[owner]-1)*24+12
                        write_word(m["records"]+offset,owner+4)
                    elif action in ("seal-first","seal-second","record-pointer","record-limit"):
                        index,limit,top=geometry(target_owner(0))
                        address=(top+(4 if action=="seal-second" else 0)) if action.startswith("seal-") else (
                            m["records"]+index*24+(4 if action=="record-limit" else 0))
                        write_word(address,rsp.word(address)^4)
                    elif action.startswith("exc-"):
                        bit={"exc-dcrs":32,"exc-es":1,"exc-mode":8,"exc-fp":16,"exc-stack":4,"exc-fake-secure":64}[action]
                        write_reg("lr",rsp.register("lr")^bit)
                    elif action in ("control","primask","basepri","faultmask","psplim","psp"):
                        field=action+"_ns"
                        value={"control":2,"primask":1,"basepri":64 if when=="selector" else 32,"faultmask":1}.get(action)
                        real_state_write(field,rsp.register(field)+8 if value is None else value)
                    elif action.startswith("current-"):
                        slots={"current-zero":0,"current-unaligned":current+2,"current-foreign":0x20000000,
                               "current-msp":0x20019000,"current-overflow":0xFFFFFFFC}
                        if action in slots:
                            write_word(m["current_slot"],slots[action])
                        elif action=="current-hash":
                            write_word(current+76,rsp.word(current+76)^1)
                        elif action=="current-canary":
                            address=(rsp.word(current+4)+3)&~3
                            write_word(address,rsp.word(address)^1)
                        else:
                            raise RuntimeError("unknown-current-attack")
                    elif action.startswith("psp-"):
                        if action=="psp-argument":
                            write_reg("r1",rsp.register("r1")+8)
                        else:
                            values={"psp-unaligned":rsp.register("psp_ns")+4,"psp-zero":0,
                                    "psp-underflow":cold[0]["limit"]-8,"psp-overflow":cold[0]["top"]+8}
                            real_state_write("psp_ns",values[action])
                    elif action.startswith("hw-"):
                        raw=pending[0]["exception"]["psp_ns"]
                        if action in ("hw-t","hw-ipsr"):
                            value=rsp.word(raw+28)
                            write_word(raw+28,value&~0x01000000 if action=="hw-t" else value|1)
                        else:
                            value={"hw-pc-odd":rsp.word(raw+24)|1,"hw-pc-zero":0,"hw-pc-foreign":0xE000ED02}[action]
                            write_word(raw+24,value)
                    elif action.startswith("next-"):
                        saved=cold[1]["sp"]
                        if action=="next-null":
                            pass
                        elif action in ("next-sp-unaligned","next-sp-foreign","next-sp-short"):
                            values={"next-sp-unaligned":saved+4,"next-sp-foreign":0x20008004,"next-sp-short":cold[1]["top"]-4}
                            write_word(next_context,values[action])
                        elif action=="next-hash":
                            write_word(next_context+76,rsp.word(next_context+76)^1)
                        elif action=="next-canary":
                            address=(rsp.word(next_context+4)+3)&~3
                            write_word(address,rsp.word(address)^1)
                        else:
                            offsets={"next-psplim":4,"next-exc":8,"next-hw-t":72,"next-hw-pc":68,
                                     "next-cold-r0":44,"next-cold-pc":68,"next-cold-r4":12}
                            address=saved+offsets[action]
                            value=rsp.word(address)
                            value=value&~0x01000000 if action=="next-hw-t" else value|1 if action=="next-hw-pc" else (
                                value+2 if action=="next-cold-pc" else value^(8 if action=="next-psplim" else 32 if action=="next-exc" else 1))
                            write_word(address,value)
                    else:
                        raise RuntimeError("unknown-maintained-attack-"+action)
                    injected=True
                    frames={cold[1]["sp"]:rsp.memory(cold[1]["sp"],76)}
                    raw=pending[0]["exception"]["psp_ns"]
                    if not pending[0]["secure"]:
                        frames[raw]=rsp.memory(raw,32)
                    if m["plan_state"]>=2:
                        saved=rsp.word(current)
                        frames[saved]=rsp.memory(saved,12 if pending[0]["secure"] else 76)
                    failure_snapshot=dict(contexts=rsp.memory(m["tcbs"],stride*2),frames=frames,
                        plan=rsp.memory(m["plan"],32),slot=rsp.word(m["current_slot"]),cpu=cpu(),counts=dict(operation_counts))
                    if pool_fault:
                        failure_snapshot["regions"]=regions()
                    event("fault-injection",when=when,action=action,cpu=cpu(),plan=failure_snapshot["plan"].hex())

                fixed = {m["secure_ready"]: "secure-ready",m["prepared"]:"prepared",m["task_entry"]:"task-entry",
                         m["pendsv"]: "pendsv", m["selector"]: "selector",m["ns_checkpoint"]: "ns-checkpoint",
                         m["ns_resumed"]: "ns-resumed", m["s_checkpoint"]: "s-checkpoint",
                         m["s_resumed"]: "s-resumed"}
                gateway_entries={item["address"]:item["operation"] for item in m["gateways"]["entries"]}
                gateway_exits={item["address"]:item["operation"] for item in m["gateways"]["exits"]}
                for address in gateway_entries:
                    require(address not in fixed,"gateway-entry-alias")
                    fixed[address]="gateway-entry"
                for address in gateway_exits:
                    require(address not in fixed,"gateway-exit-alias")
                    fixed[address]="gateway-exit"
                active=dict(fixed)
                if not reference:
                    fixed[m["panic"]]="panic"
                    active[m["panic"]]="panic"
                    for field in ("pool_fail","fault_entry","fault_terminal"):
                        fixed[m[field]]=field
                        active[m[field]]=field
                    if negative and m["attack"]["when"] in ("prepare","ram","code"):
                        key={"prepare":"prepare_save","ram":"ram_hook","code":"code_hook"}[m["attack"]["when"]]
                        fixed[m[key]]=m["attack"]["when"]
                        active[m[key]]=m["attack"]["when"]
                require(rsp.packet("?").startswith(("S", "T")), "initial-stop")
                rsp.breakpoint(m["secure_ready"])
                stop = rsp.packet("c")
                while True:
                    if stop.startswith("W"):
                        exit_code=91 if pool_fault else 93 if negative else 0
                        require(stop == "W%02x"%exit_code and process.wait(timeout=max(.01,deadline-time.monotonic())) == exit_code,
                                "unexpected-exit-"+stop)
                        if negative:
                            require((fault_seen if pool_fault else panic_seen) and injected and resumes==0 and entered=={0},
                                    "incomplete-terminal-negative")
                            receipt.update(result="PASS",exit_code=exit_code,gateway_counts=operation_counts)
                            break
                        require(switches == 2 and resumes == 1 and entered=={0,1}, "incomplete-switch-cycle")
                        wanted=dict(initialize=1,allocate=sum(attached(i) for i in (0,1)),
                                    save=sum(attached(i) for i in (0,1)) if reference else 2,
                                    load=(sum(attached(i) for i in (0,1))+int(attached(0))) if reference else 3)
                        require({op:operation_counts.get(op,0) for op in wanted}==wanted,"exact-operation-inventory")
                        require(operation_counts.get("priority",0)==int(reference),"exact-priority-call-inventory")
                        if not reference:
                            query_rounds=sum(attached(i) for i in (0,1))+1+int(attached(1))
                            require(all(operation_counts.get("query-%d"%i,0)==query_rounds for i in range(8)),
                                    "exact-eight-query-rounds")
                        receipt.update(result="PASS", switches=switches, resumes=resumes,gateway_counts=operation_counts)
                        break
                    require(stop.startswith(("S05", "T05")), "unexpected-stop-"+stop)
                    pc = rsp.register("pc") & ~1
                    require(pc in active, "unknown-breakpoint-%x" % pc)
                    kind = active[pc]
                    rearm=pc in fixed
                    state = cpu()
                    selected = rsp.word(m["selected"])
                    if kind == "secure-ready":
                        initial=regions()
                        if not reference:
                            require(initial["pool"]==b"\xa5"*3168 and initial["pool_state"]==initial["gateway_state"]==bytes(4),
                                    "actual-NOLOAD-poison-and-cold-markers")
                        event(kind,cpu=state)
                        for address in fixed:
                            if address != pc:
                                rsp.breakpoint(address)
                    elif kind == "prepared":
                        require(not cold and not allocations,"duplicate-or-late-preparation")
                        require(state["xpsr"]&511==0 and state["control_ns"]==0 and
                                rsp.word(m["current_slot"])==target_owner(0),"real-prestart-publication")
                        for task in (0,1):
                            owner=target_owner(task)
                            start=m["stacks"]+task*4096
                            limit=start+(32 if reference else 40)
                            top=start+(4096 if reference else 4088)
                            saved=rsp.word(owner)
                            require(saved==top-76,"independent-initial-saved-SP")
                            if reference:
                                values=[0,limit,0xFFFFFFBC]+[0x04040404,0x05050505,0x06060606,0x07070707,
                                    0x08080808,0x09090909,0x10101010,0x11111111]+[task,0x01010101,0x02020202,
                                    0x03030303,0x12121212,m["task_return"]|1,m["task_entry"]|1,0x01000000]
                            else:
                                require(rsp.word(owner+12)==limit and rsp.word(owner+16)==top,"independent-boot-stack-bounds")
                                values=[0,limit,0xFFFFFFBC,0,0,0,0,0,0x91000000|task,0,0,task,0,0,0,0,
                                        m["task_return"]|1,m["task_entry"],0x01000000]
                            require(words(rsp.memory(saved,76))==values,"independent-all-19-initial-words")
                            cold[task]=dict(context=rsp.memory(owner,stride),frame=rsp.memory(saved,76),sp=saved,limit=limit,top=top)
                        event(kind,cpu=state,frames={task:dict(sp=row["sp"],sha256=hashlib.sha256(row["frame"]).hexdigest())
                                                   for task,row in cold.items()})
                    elif kind == "task-entry":
                        event("task-entry-observed",task=selected,cpu=state,gprs=gprs())
                        require(selected not in entered and selected in cold and rsp.register("r0")==selected,
                                "actual-new-task-argument-entry")
                        require(state["xpsr"]&511==0 and state["control_ns"]==2 and
                                state["psp_ns"]==cold[selected]["top"] and state["psplim_ns"]==cold[selected]["limit"],
                                "actual-new-task-Thread-stack")
                        if not reference:
                            values=gprs()
                            require(values[:13]==[selected,0,0,0,0,0,0,0,0,0x91000000|selected,0,0,0],
                                    "initial-all-GPRs-including-inherited-r9")
                            cold_unchanged(target_owner(selected),allocations.get(target_owner(selected),0))
                        entered.add(selected)
                        event(kind,task=selected,cpu=state,gprs=gprs())
                    elif kind.endswith("checkpoint"):
                        require(selected in (0,1) and selected not in pending, "duplicate-task-window")
                        secure = kind.startswith("s-")
                        expected = [selected << 16] + [(i*0x11000000 | i | selected << 16) for i in range(1,13)] + [
                            0xEE00000E | selected << 16]
                        expected[0] = 0xE002ED04 if secure else 0xE000ED04
                        expected[1] = 0x10000000
                        require(gprs() == expected, "independent-live-register-pattern")
                        require(state["xpsr"] & 511 == 0, "window-not-Thread")
                        require(rsp.word(m["live_handle"])==allocations.get(target_owner(selected),0),
                                "independent-live-handle-publication")
                        require(rsp.memory(pc,4)==b"\x00\xbf\x01\x60","actual-pending-store-instructions")
                        pending[selected] = dict(cpu=state, gprs=gprs(), secure=secure,
                            stacked_pc=pc+4,historic_sp=rsp.word(m["tcbs"]+selected*stride),
                            handle=rsp.word(m["live_handle"]),
                            ns_bytes=rsp.memory(state["psp_ns"]-80,112).hex())
                        event(kind, task=selected, cpu=state, gprs=gprs(),
                              ns=snapshot(state["psp_ns"]-80,112),
                              secure_stack=snapshot(state["psp_s"]-96,128) if secure else None)
                    elif kind == "pendsv":
                        require(selected in pending and state["xpsr"] & 511 == 14, "actual-PendSV-origin")
                        before = pending[selected]
                        require(state["lr"] == (0xFFFFFFFC if before["secure"] else 0xFFFFFFBC),
                                "actual-observed-EXC_RETURN-S-DCRS")
                        require(state["control_ns"]==0 and state["sp"]==state["msp_ns"] and
                                state["primask_ns"]==state["basepri_ns"]==state["faultmask_ns"]==0,
                                "actual-PendSV-entry-CPU")
                        require(state["psp_ns"]==before["cpu"]["psp_ns"]-(0 if before["secure"] else 32),
                                "no-NS-hardware-frame-for-Secure-origin")
                        if before["secure"]:
                            require(state["psp_s"]==before["cpu"]["psp_s"]-72,"actual-Secure-hardware-push")
                            require(rsp.memory(before["cpu"]["psp_ns"]-80,112).hex()==before["ns_bytes"],
                                    "Secure-origin-NS-stack-untouched-at-entry")
                        else:
                            require(words(rsp.memory(state["psp_ns"],32))==basic_frame(before),
                                    "independent-NS-basic-hardware-frame")
                        before["exception"]=state
                        before["entry_ns_bytes"]=rsp.memory(before["cpu"]["psp_ns"]-80,112).hex()
                        event(kind, task=selected, cpu=state, gprs=gprs(),
                              ns=snapshot(state["psp_ns"]-16,112))
                        inject("entry")
                    elif kind == "selector":
                        if not pending:
                            require(not reference and rsp.register("r0")==0 and state["xpsr"]&511==0,
                                    "initial-common-candidate-selection")
                            event("initial-selection",cpu=state)
                            rsp.breakpoint(pc,False)
                            step=rsp.packet("s")
                            rsp.breakpoint(pc)
                            require(step.startswith(("S05","T05")),"initial-selector-step")
                            stop=step if (rsp.register("pc")&~1) in active else rsp.packet("c")
                            continue
                        event("selector-entry-observed",task=selected,cpu=state)
                        wanted_saves=sum(attached(i) for i in range(switches+1)) if reference else switches+1
                        require(operation_counts.get("save",0)==wanted_saves,"missing-actual-Secure-save-before-NS-save")
                        require(state["xpsr"] & 511 == 14 and state["basepri_ns"] == (128 if reference else 32),
                                "selector-explicit-profile-priority")
                        saved = rsp.word(m["tcbs"]+selected*stride)
                        before = pending[selected]
                        count = 12 if before["secure"] else 76
                        require(saved == before["cpu"]["psp_ns"]-count, "actual-reference-save-size")
                        handle=before["handle"]
                        expected=[handle,before["cpu"]["psplim_ns"],0xFFFFFFFC if before["secure"] else 0xFFFFFFBC]
                        if not before["secure"]:
                            expected+=before["gprs"][4:12]+basic_frame(before)
                        require(words(rsp.memory(saved,count))==expected,"independent-complete-NS-save-image")
                        event(kind, task=selected, cpu=state, saved=saved, saved_bytes=rsp.memory(saved,count).hex())
                        inject("selector")
                        switches += 1
                    elif kind in ("prepare","ram","code"):
                        inject(kind)
                    elif kind == "pool_fail":
                        event("pool-fail-observed",cpu=state,gprs=gprs(),instruction=rsp.memory(pc,2).hex())
                        require(pool_fault and injected and fault is None and call is not None and call["operation"]=="save",
                                "unexpected-pool-fail-closed")
                        require(state["xpsr"]&511==14 and state["sp"]==state["msp_s"] and state["control_s"]==2 and
                                rsp.memory(pc,2)==b"\xff\xde","real-Secure-PendSV-UDF-origin")
                        fault=dict(cpu=state,gprs=gprs(),pc=pc)
                    elif kind == "fault_entry":
                        event("fault-entry-observed",cpu=state,frame=rsp.memory(state["msp_s"],32).hex(),
                              cfsr=rsp.word(0xe000ed28),hfsr=rsp.word(0xe000ed2c),sfsr=rsp.word(0xe000ede4))
                        require(pool_fault and fault is not None and "frame" not in fault,"unexpected-fault-entry")
                        require(state["xpsr"]&511==6 and state["lr"]==0xFFFFFFF5 and state["sp"]==state["msp_s"] and
                                state["msp_s"]==fault["cpu"]["msp_s"]-32 and state["psp_s"]==fault["cpu"]["psp_s"],
                                "exact-UsageFault-Handler-MSP-independent-of-SPSEL")
                        frame=fault["gprs"][:4]+[fault["gprs"][12],fault["gprs"][13],fault["pc"],fault["cpu"]["xpsr"]]
                        require(words(rsp.memory(state["msp_s"],32))==frame,"exact-fault-basic-frame-from-real-UDF")
                        require(rsp.word(0xe000ed28)==0x10000 and rsp.word(0xe000ed2c)==rsp.word(0xe000ede4)==0,
                                "exact-UNDEFINSTR-only-fault-status")
                        fault.update(frame=state["msp_s"],words=frame)
                    elif kind == "fault_terminal":
                        event("fault-terminal-observed",cpu=state,frame=rsp.register("r0"),ret=rsp.register("r1"))
                        require(pool_fault and fault is not None and "frame" in fault and not fault_seen,
                                "unexpected-fault-terminal")
                        require(state["xpsr"]&511==6 and state["sp"]==state["msp_s"] and rsp.register("r0")==fault["frame"] and
                                rsp.register("r1")==0xFFFFFFF5 and words(rsp.memory(fault["frame"],32))==fault["words"],
                                "exact-terminal-Secure-Handler-fault-record")
                        require(rsp.word(0xe000ed28)==0x10000 and rsp.word(0xe000ed2c)==rsp.word(0xe000ede4)==0 and
                                all(state[key]==fault["cpu"][key] for key in (
                                    "psp_s","psplim_s","control_ns","psp_ns","psplim_ns","primask_ns","basepri_ns","faultmask_ns")),
                                "fault-status-and-task-banks-still-unchanged-at-terminal")
                        require(rsp.memory(m["plan"],32)==failure_snapshot["plan"] and rsp.word(m["plan"]+28)==1 and
                                rsp.word(m["current_slot"])==target_owner(0) and rsp.word(m["live_handle"])==1 and
                                rsp.memory(m["tcbs"],stride*2)==failure_snapshot["contexts"] and
                                operation_counts==failure_snapshot["counts"] and regions()==failure_snapshot["regions"] and
                                all(rsp.memory(address,len(data))==data for address,data in failure_snapshot["frames"].items()),
                                "fault-sticky-plan-pool-context-frame-and-no-publication")
                        require(resumes==0 and entered=={0} and call is not None and not call["exited"],
                                "fault-no-gateway-or-Thread-return")
                        fault_seen=True
                    elif kind == "panic":
                        observed_plan=rsp.memory(m["plan"],32)
                        event("panic-observed",code=rsp.register("r0"),cpu=state,plan=observed_plan.hex(),plan_words=words(observed_plan))
                        require(negative and not panic_seen and injected and failure_snapshot is not None,"unexpected-panic")
                        require(rsp.register("r0")==m["panic_code"] and state["xpsr"]&511==14,
                                "exact-terminal-panic-code-origin")
                        require(resumes==0 and entered=={0} and call is None,"terminal-failure-must-not-resume-or-escape-SG")
                        require(rsp.memory(m["plan"],32)==failure_snapshot["plan"] and
                                rsp.word(m["plan"]+28)==m["plan_state"],"exact-sticky-terminal-plan")
                        require(rsp.memory(m["tcbs"],stride*2)==failure_snapshot["contexts"],"failure-contexts-unchanged")
                        require(all(rsp.memory(address,len(data))==data for address,data in failure_snapshot["frames"].items()),
                                "failure-frames-unchanged")
                        require(rsp.word(m["current_slot"])==failure_snapshot["slot"],"no-failure-publication-or-repair")
                        require(operation_counts==failure_snapshot["counts"],"no-gateway-operation-after-invalid-input")
                        require(all(state[key]==failure_snapshot["cpu"][key] for key in (
                            "control_s","psp_s","psplim_s","control_ns","primask_ns","basepri_ns","faultmask_ns","psplim_ns","psp_ns")),
                            "no-terminal-state-repair")
                        require(rsp.word(m["live_handle"])==(0 if m["plan_state"]>=2 else pending[0]["handle"]),
                                "exact-terminal-live-handle")
                        panic_seen=True
                        event(kind,code=rsp.register("r0"),cpu=state,plan=failure_snapshot["plan"].hex())
                    elif kind == "gateway-entry":
                        operation=gateway_entries[pc]
                        event("gateway-call-observed",operation=operation,cpu=state,r0=rsp.register("r0"),r1=rsp.register("r1"))
                        require(call is None,"overlapping-gateway-operation")
                        origin=state["xpsr"]&511
                        require(origin in (0,11,14),"actual-gateway-origin")
                        if operation in ("initialize","priority"):
                            require(origin==11,"initializer-real-SVC-origin")
                        if operation=="allocate":
                            owner=rsp.register("r1")
                            require(rsp.register("r0")==512 and owner in (target_owner(0),target_owner(1)) and
                                    attached((owner-m["tcbs"])//stride),"independent-allocation-arguments")
                            require(origin==(11 if reference or switches==0 else 14),"allocation-real-origin")
                        if operation in ("save","load"):
                            owner=rsp.register("r1")
                            require(owner==target_owner(selected) and rsp.register("r0")==allocations.get(owner,0),
                                    "independent-owned-handle-arguments")
                        if operation=="save":
                            before=pending[selected]
                            require(state["xpsr"]&511==14 and rsp.register("r1")==m["tcbs"]+selected*stride and
                                    rsp.register("r0")==before["handle"],
                                    "actual-Save-SG-owner-origin")
                            require(rsp.word(m["tcbs"]+selected*stride)==before["historic_sp"] and
                                    rsp.memory(before["cpu"]["psp_ns"]-80,112).hex()==before["entry_ns_bytes"],
                                    "Secure-save-before-any-NS-software-save")
                            if before["secure"]:
                                saved=words(rsp.memory(state["psp_s"],72))
                                require(saved[0]==0xFEFA125B and saved[2:10]==before["gprs"][4:12] and
                                        saved[10:18]==basic_frame(before),"actual-Secure-hardware-frame")
                        operation_counts[operation]=operation_counts.get(operation,0)+1
                        if origin==14:
                            inject(operation)
                        state=cpu()
                        event(kind,operation=operation, task=selected, cpu=state, handle=rsp.register("r0"), owner=rsp.register("r1"),
                              records=snapshot(m["records"],48 if reference else 72),
                              secure_stack=snapshot(state["psp_s"],72) if operation == "save" and pending[selected]["secure"] else None)
                        tail=reference and operation=="load" and state["lr"]==0xFFFFFFBC and m["gateways"]["reference_tail_load"]
                        require(state["lr"]%2==0 and (0x10000<=state["lr"]<0x20000 or tail),"genuine-NS-to-SG-caller")
                        target=rsp.word(state["psp_ns"]+24) if tail else state["lr"]
                        require(target not in active and 0x10000<=target<0x20000 and target%2==0,"unique-SG-return-target")
                        call=dict(operation=operation,cpu=state,r0=rsp.register("r0"),r1=rsp.register("r1"),
                                  regions=regions(),tail=tail,exited=False,
                                  reject=(negative and injected and m["attack"]["when"]==operation and operation in ("save","load")))
                        active[target]="gateway-return"
                        rsp.breakpoint(target)
                    elif kind == "gateway-exit":
                        operation=gateway_exits[pc]
                        require(call is not None and call["operation"]==operation and not call["exited"],"unpaired-BXNS-exit")
                        after=regions()
                        if call["reject"]:
                            require(rsp.register("r0")==0 and after==call["regions"] and
                                    all(state[key]==call["cpu"][key] for key in ("control_s","psp_s","psplim_s")),
                                    "exact-rejected-gateway-no-effects")
                        else:
                            gateway_effects(operation,call,after,rsp.register("r0"),state)
                        last_regions=after
                        call["exited"]=True
                        event(kind,operation=operation,cpu=state,result=rsp.register("r0"),memory=hashes(after))
                        if state["xpsr"]&511==14:
                            inject(operation+"-exit")
                    elif kind == "gateway-return":
                        require(call is not None and call["exited"],"missing-real-BXNS-proof")
                        expected=ns_cpu(call["cpu"])
                        if call["tail"]:
                            require(state["xpsr"]&511==0,"actual-reference-tail-Thread-return")
                            expected["psp_ns"]+=32
                            expected["control_ns"]=2
                        require(ns_cpu(state)==expected,"actual-gateway-NS-bank-preservation")
                        event(kind,operation=call["operation"],cpu=state)
                        call=None
                        del active[pc]
                    elif kind.endswith("resumed"):
                        require(selected == 0 and selected in pending, "unexpected-task-resume")
                        before = pending[selected]
                        require(gprs() == before["gprs"], "all-GPRs-survive-switch")
                        require(state["xpsr"] & 511 == 0, "resume-not-Thread")
                        require(state["psp_s" if before["secure"] else "psp_ns"] ==
                                before["cpu"]["psp_s" if before["secure"] else "psp_ns"], "resume-stack")
                        require(state["psp_ns"]==before["cpu"]["psp_ns"] and state["control_ns"]==2 and
                                state["psplim_ns"]==before["cpu"]["psplim_ns"] and
                                state["primask_ns"]==state["basepri_ns"]==state["faultmask_ns"]==0,
                                "resumed-NS-bank-and-masks")
                        resumes += 1
                        event(kind, task=selected, cpu=state, gprs=gprs())
                    else:
                        raise RuntimeError("unhandled-event")
                    rsp.breakpoint(pc,False)
                    step = rsp.packet("s")
                    if rearm:
                        rsp.breakpoint(pc)
                    if step.startswith("W"):
                        stop = step
                    else:
                        require(step.startswith(("S05", "T05")), "unknown-single-step-"+step)
                        stop = step if (rsp.register("pc") & ~1) in active else rsp.packet("c")
            text = (directory/"qemu.log").read_text(errors="replace")
            if pool_fault:
                marker="FAULT:C55S-RUNNING PC=0x%08x RET=0xfffffff5 IPSR=0x00000006 CFSR=0x00010000 HFSR=0x00000000 XPSR=0x%08x\n"%(fault["pc"],fault["words"][7])
                require(text.count(marker)==1 and text.count("FAULT-EXIT:C55S-RUNNING\n")==1 and
                        "PANIC" not in text and "PASS" not in text and "FAIL" not in text,"exact-pool-corruption-fault-report")
            elif negative:
                marker="PANIC:C55S-RUNNING code=0x%08x IPSR=0x0000000e\n"%m["panic_code"]
                require(text.count(marker)==1 and text.count("PANIC-EXIT:C55S-RUNNING\n")==1 and
                        "PASS" not in text and "FAULT" not in text and "FAIL" not in text,"exact-negative-report")
            else:
                require(text.count("PASS:C55S-RUNNING:"+m["kind"]+"\n") == 1 and
                        "FAIL" not in text and "FAULT" not in text, "missing-or-failed-report")
    except Exception as error:
        receipt.update(result="FAIL", error=str(error), error_type=type(error).__name__)
        raise
    finally:
        if connection:
            connection.close()
        if process and process.poll() is None:
            os.killpg(process.pid,signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL)
                process.wait(timeout=2)
        (directory/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print("PASS:C55S-RUNNING:"+m["kind"]+":"+str(m["case"]))


if __name__ == "__main__":
    main()
