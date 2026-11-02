"""Execute the real two-image CM33 case; stop unsafe mutants before AIRCR STR.

Only Python's standard library and an existing QEMU prefix are used. All RSP
traffic uses a fresh private WSL Unix socket, never a TCP port.
"""

import hashlib
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
import xml.etree.ElementTree as ET


class Rsp:
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline
        self.registers = {}

    def byte(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("RSP deadline expired")
        self.connection.settimeout(remaining)
        value = self.connection.recv(1)
        if not value:
            raise RuntimeError("Unexpected RSP EOF")
        return value

    def packet(self, command):
        payload = command.encode("ascii")
        self.connection.sendall(b"$" + payload + b"#" +
                                f"{sum(payload) & 255:02x}".encode("ascii"))
        while True:
            first = self.byte()
            if first == b"-":
                raise RuntimeError("RSP rejected packet checksum")
            if first != b"$":
                if first != b"+":
                    raise RuntimeError(f"Unexpected RSP prefix {first!r}")
                continue
            encoded = bytearray()
            while True:
                value = self.byte()
                if value == b"#":
                    break
                encoded.extend(value)
            checksum = self.byte() + self.byte()
            if int(checksum, 16) != (sum(encoded) & 255):
                raise RuntimeError("Bad RSP response checksum")
            try:
                self.connection.sendall(b"+")
            except (BrokenPipeError, ConnectionResetError):
                # QEMU can close immediately after a checksummed exit packet.
                if encoded[:1] not in (b"W", b"X"):
                    raise
            decoded = bytearray()
            index = 0
            while index < len(encoded):
                value = encoded[index]
                if value == ord("}"):
                    index += 1
                    decoded.append(encoded[index] ^ 0x20)
                elif value == ord("*"):
                    index += 1
                    decoded.extend(bytes([decoded[-1]]) * (encoded[index] - 29))
                else:
                    decoded.append(value)
                index += 1
            response = decoded.decode("ascii")
            if response.startswith("O") and response != "OK":
                raise RuntimeError("Unexpected RSP console packet")
            return response

    def feature(self, name):
        result = ""
        while True:
            part = self.packet(f"qXfer:features:read:{name}:{len(result):x},fff")
            if not part or part[0] not in "ml":
                raise RuntimeError(f"Missing target XML {name}: {part}")
            result += part[1:]
            if part[0] == "l":
                return result

    def discover_registers(self):
        self.packet("qSupported:qXfer:features:read+")
        next_number = 0

        def visit(name):
            nonlocal next_number
            document = self.feature(name)
            # QEMU's RSP target.xml uses xi:include without declaring xi.
            if "<xi:include" in document and "xmlns:xi=" not in document:
                document = document.replace(
                    "<target", '<target xmlns:xi="http://www.w3.org/2001/XInclude"', 1)
            for element in ET.fromstring(document).iter():
                if element.tag.endswith("}include"):
                    visit(element.attrib["href"])
                elif element.tag == "reg":
                    next_number = int(element.attrib.get("regnum", next_number))
                    self.registers[element.attrib["name"].lower()] = (
                        next_number, int(element.attrib["bitsize"]))
                    next_number += 1

        visit("target.xml")

    def register(self, name):
        number, bits = self.registers[name]
        reply = self.packet(f"p{number:x}")
        if len(reply) != bits // 4 or not re.fullmatch("[0-9a-fA-F]+", reply):
            raise RuntimeError(f"Cannot read {name}: {reply}")
        return int.from_bytes(bytes.fromhex(reply), "little")

    def memory(self, address, size):
        reply = self.packet(f"m{address:x},{size:x}")
        if len(reply) != size * 2 or not re.fullmatch("[0-9a-fA-F]+", reply):
            raise RuntimeError(f"Cannot read memory {address:#x}/{size}: {reply}")
        return bytes.fromhex(reply)

    def word(self, address):
        return int.from_bytes(self.memory(address, 4), "little")

    def breakpoint(self, address, insert=True):
        reply = self.packet(f"{'Z' if insert else 'z'}0,{address:x},2")
        if reply != "OK":
            raise RuntimeError(f"Cannot change breakpoint {address:#x}: {reply}")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    root, secure, nonsecure, seconds, manifest_path = sys.argv[1:]
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8-sig"))
    directory = Path(manifest_path).parent
    deadline = time.monotonic() + int(seconds)
    aircr = 0xE000ED0C
    gate = manifest["gate"]
    stores = {int(item["Address"], 16): item for item in manifest["stores"]}
    entry = manifest["entry"]
    prepared = manifest["prepared"]
    checkpoint = manifest["checkpoint"]
    mutant = manifest["mutant"]
    trace = []
    process = None
    connection = None
    qemu_log = directory / "rsp-qemu.log"
    receipt = {"python": sys.executable, "python_version": sys.version,
               "transport": "private AF_UNIX", "mutant": mutant,
               "forbidden_aircr_write_executed": False}

    def event(kind, **values):
        trace.append({"event": kind, **values})

    try:
        for image, key in ((secure, "secure_sha256"), (nonsecure, "nonsecure_sha256")):
            digest = hashlib.sha256(Path(image).read_bytes()).hexdigest().upper()
            require(digest == manifest[key], f"ELF changed after disassembly: {image}")
            receipt[key] = digest
        with tempfile.TemporaryDirectory(prefix="fiber-cm33-aircr-") as temporary:
            socket_path = str(Path(temporary) / "gdb.sock")
            command = [str(Path(root) / "usr/bin/qemu-system-arm"),
                       "-machine", "mps2-an505", "-accel", "tcg", "-display", "none",
                       "-serial", "none", "-monitor", "none", "-no-reboot",
                       "-semihosting-config", "enable=on,target=native",
                       "-L", str(Path(root) / "usr/share/qemu"), "-kernel", secure,
                       "-device", f"loader,file={nonsecure}", "-S",
                       "-chardev", f"socket,id=aircr,path={socket_path},server=on,wait=off",
                       "-gdb", "chardev:aircr"]
            receipt["qemu_command"] = command
            with qemu_log.open("wb") as log:
                connection = socket.socket(socket.AF_UNIX)
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
                while True:
                    require(process.poll() is None, "QEMU exited before RSP connection")
                    try:
                        connection.connect(socket_path)
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        require(time.monotonic() < deadline, "QEMU socket startup timeout")
                        time.sleep(0.01)
                rsp = Rsp(connection, deadline)
                rsp.discover_registers()
                receipt["registers"] = rsp.registers
                require(rsp.packet("?").startswith(("S", "T")), "No initial QEMU stop")
                rsp.breakpoint(prepared)
                stop = rsp.packet("c")
                active = {prepared}
                checkpoints = entries = positive_writes = 0
                armed = after_step = False

                def intact():
                    require(rsp.word(gate) == 0, "BFHFNMINS failure mutated private BSS gate")
                    require(rsp.word(aircr) & 0xFFFF == 0x2500,
                            "BFHFNMINS=1 / PRIS=0 seed was not preserved")
                    for region in manifest["poison"]:
                        require(rsp.memory(region["address"], region["size"]) ==
                                b"\xa5" * region["size"],
                                "BFHFNMINS failure mutated private pool/marker")

                while True:
                    if stop.startswith("W"):
                        require(not mutant and checkpoints == 2 and positive_writes == 1,
                                "QEMU exited before complete AIRCR proof")
                        require(stop == "W00", f"Unexpected QEMU exit packet {stop}")
                        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
                        require(code == 0, f"QEMU returned {code}")
                        receipt.update(checkpoints=checkpoints, ns_entries=entries,
                                       positive_aircr_writes=positive_writes,
                                       actual_qemu_exit=code, result="PASS")
                        break
                    require(stop.startswith(("S05", "T05")), f"Unexpected QEMU stop: {stop}")
                    pc = rsp.register("pc") & ~1
                    if pc not in active:
                        require(after_step, f"Unexpected breakpoint PC {pc:#x}")
                        after_step = False
                        stop = rsp.packet("c")
                        continue
                    if pc == prepared:
                        intact()
                        require(not armed and rsp.register("xpsr") & 0x1FF == 11,
                                "Preparation did not execute in SVCall")
                        event("prepared", pc=pc, gate=0, aircr=rsp.word(aircr))
                        for address in set(stores) | {entry, checkpoint}:
                            rsp.breakpoint(address)
                            active.add(address)
                        armed = True
                    elif pc == entry:
                        entries += 1
                        lr, ipsr = rsp.register("lr"), rsp.register("xpsr") & 0x1FF
                        require(armed and lr & 1 == 0 and ipsr == 11,
                                "Initializer entry is not actual NS SVCall through SG")
                        require(rsp.word(gate) == 0, "Initializer committed before precondition")
                        require((entries <= 2 and rsp.word(aircr) & 0xFFFF == 0x2500) or
                                (not mutant and entries == 3 and checkpoints == 2 and
                                 rsp.word(aircr) & 0xFFFF == 0x500),
                                "Unexpected initialization phase")
                        event("ns_svc_entry", pc=pc, lr=lr, ipsr=ipsr, call=entries)
                    elif pc == checkpoint:
                        intact()
                        checkpoints += 1
                        require(not mutant and entries == checkpoints and checkpoints <= 2,
                                "Unexpected rejection checkpoint")
                        event("rejected_gate_pool_unchanged", pc=pc, call=checkpoints, gate=0)
                    else:
                        instruction = stores[pc]
                        require(re.fullmatch(r"str(?:\.w)?", instruction["Opcode"]),
                                f"Unqualified store opcode: {instruction}")
                        match = re.fullmatch(
                            r"(r\d+), \[(r\d+|sp)(?:, #(-?(?:0x[0-9a-f]+|\d+)))?\]"
                            r"!?(?:, #-?(?:0x[0-9a-f]+|\d+))?(?:\s*[;@].*)?",
                            instruction["Operands"])
                        require(match is not None, f"Unqualified store operands: {instruction}")
                        source, base, offset = match.groups()
                        address = (rsp.register(base) + int(offset or "0", 0)) & 0xFFFFFFFF
                        value = rsp.register(source)
                        event("before_str", pc=pc, address=address, value=value,
                              instruction=instruction["Text"])
                        if address == aircr:
                            if mutant:
                                require(entries == 1 and checkpoints == 0 and
                                        rsp.word(aircr) & 0xFFFF == 0x2500 and
                                        value >> 16 == 0x05FA and value & 0xFFFF == 0x6500 and
                                        rsp.word(gate) == 0x53434742,
                                        "Mutant did not reach the exact forbidden keyed AIRCR STR")
                                receipt.update(result="PASS:guard-removal-killed-before-AIRCR-STR",
                                               stopped_pc=pc, effective_address=address,
                                               pending_value=value, ns_entries=entries)
                                event("mutant_stopped_before_forbidden_str", pc=pc,
                                      address=address, pending_value=value)
                                break
                            require(entries == 3 and checkpoints == 2 and
                                    rsp.word(aircr) & 0xFFFF == 0x500 and
                                    value >> 16 == 0x05FA and value & 0xFFFF == 0x4500,
                                    "Unexpected or forbidden production AIRCR STR")
                            positive_writes += 1
                        elif address == gate:
                            require((mutant or entries == 3) and value == 0x53434742,
                                    "Production rejection wrote INITIALIZING")
                        else:
                            require(not 0xE0000000 <= address < 0xF0000000,
                                    f"Unexpected initializer MMIO STR {address:#x}")
                    rsp.breakpoint(pc, False)
                    active.remove(pc)
                    stop = rsp.packet("s")
                    after_step = True
                    if pc != prepared:
                        rsp.breakpoint(pc)
                        active.add(pc)
                    if positive_writes:
                        for address in active:
                            rsp.breakpoint(address, False)
                        active.clear()
                        after_step = False
                        stop = rsp.packet("c")
                if mutant:
                    # The inferior is still paused at STR. Never resume it.
                    os.killpg(process.pid, signal.SIGKILL)
                    receipt["paused_termination_exit"] = process.wait(timeout=2)
                    receipt["paused_termination_signal"] = "SIGKILL"
                    receipt["qemu_terminated_while_paused"] = True
    finally:
        # Kill before closing RSP, including failures: disconnect must never
        # give a paused inferior a chance to execute a forbidden pending STR.
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
        if connection is not None:
            connection.close()
        (directory / "aircr-rsp-events.json").write_text(json.dumps(trace, indent=2) + "\n")
        (directory / "aircr-rsp-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        if qemu_log.exists():
            print(qemu_log.read_text(errors="replace"), end="")
    if mutant:
        print("PASS:GUARDS:BFHFNMINS-mutant-stopped-before-AIRCR-STR")
    else:
        print("PASS:GUARDS:BFHFNMINS-two-rejections-gate0-before-positive-AIRCR-STR")


if __name__ == "__main__":
    main()
