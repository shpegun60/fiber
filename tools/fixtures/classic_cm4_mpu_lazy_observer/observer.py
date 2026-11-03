"""Linux stdlib-only, read-only RSP observation of the frozen CM4 FP pilot.

This helper collects facts. Independent contracts decide FP/lazy semantics.
Z1/z1 change debugger breakpoint state only; no register or guest-memory writes,
software breakpoints, stepping, monitor commands, or addressed continues exist.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
MAX_PACKET = 16384
MAX_PACKETS = 4096
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_OUTPUT = 65536
MAX_XML = 262144
CORE = ("r0", "r3", "lr", "pc", "xpsr", "psp")
SEQUENCE = (0, 0) + (1, 2, 0) * 6 + (1, 2)
ANCHOR_BYTES = {"Pre": "1ef0100f", "Post": "13f0010f"}
MMIO = {"FPCCR": 0xE000EF34, "FPCAR": 0xE000EF38, "CPACR": 0xE000ED88}


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("OBSERVER_DEADLINE")
    return value


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="ascii")


def digest(path, deadline):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size <= 512 * 1024 * 1024,
             "INPUT_NOT_BOUNDED_REGULAR_FILE")
        while True:
            remaining(deadline)
            data = stream.read(1024 * 1024)
            if not data:
                break
            result.update(data)
        after = os.fstat(stream.fileno())
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "INPUT_CHANGED_DURING_HASH")
    return result.hexdigest().upper()


def unique_json(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "MANIFEST_DUPLICATE_KEY")
        value[key] = item
    return value


def address(value, alignment=4):
    need(type(value) is int and 0 <= value <= 0xFFFFFFFF and value % alignment == 0,
         "MANIFEST_ADDRESS")
    return value


def manifest_read(path):
    with path.open("rb") as stream:
        data = stream.read(16385)
    need(len(data) <= 16384, "MANIFEST_SIZE")
    value = json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique_json)
    fields = {"Elf", "ElfSha256", "Consumer", "Lazy", "Pre", "Post", "CurrentSlot",
              "Workers", "Stacks", "ReturnPC"}
    need(type(value) is dict and fields <= set(value) <= fields | {"SchemaVersion"}, "MANIFEST_FIELDS")
    need(value.get("SchemaVersion", 1) == 1 and type(value.get("SchemaVersion", 1)) is int,
         "MANIFEST_SCHEMA")
    need(type(value["Elf"]) is str and Path(value["Elf"]).is_absolute(), "MANIFEST_ELF_PATH")
    need(type(value["ElfSha256"]) is str and re.fullmatch(r"[0-9A-Fa-f]{64}", value["ElfSha256"]),
         "MANIFEST_ELF_HASH")
    value["ElfSha256"] = value["ElfSha256"].upper()
    need(value["Consumer"] in ("context", "fiber") and type(value["Lazy"]) is bool,
         "MANIFEST_CONSUMER_POLICY")
    for name in ("Pre", "Post"):
        anchor = value[name]
        need(type(anchor) is dict and set(anchor) == {"Address", "Bytes", "Width"}, "MANIFEST_ANCHOR")
        address(anchor["Address"], 2)
        need(type(anchor["Width"]) is int and anchor["Width"] == 4 and
             type(anchor["Bytes"]) is str and anchor["Bytes"].lower() == ANCHOR_BYTES[name],
             "MANIFEST_ANCHOR_TST_WIDTH_BYTES")
    need(value["Pre"]["Address"] < value["Post"]["Address"], "MANIFEST_ANCHOR_ORDER")
    address(value["CurrentSlot"])
    need(type(value["Workers"]) is list and len(value["Workers"]) == 3, "MANIFEST_WORKERS")
    for worker in value["Workers"]:
        address(worker)
    need(len(set(value["Workers"])) == 3, "MANIFEST_WORKERS")
    need(type(value["Stacks"]) is list and len(value["Stacks"]) == 3, "MANIFEST_STACKS")
    for stack in value["Stacks"]:
        need(type(stack) is dict and set(stack) == {"Begin", "End"}, "MANIFEST_STACKS")
        address(stack["Begin"], 8)
        address(stack["End"], 8)
        need(104 <= stack["End"] - stack["Begin"] <= 1024 * 1024, "MANIFEST_STACK_BOUNDS")
    ordered = sorted((s["Begin"], s["End"]) for s in value["Stacks"])
    need(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])), "MANIFEST_STACK_OVERLAP")
    address(value["ReturnPC"], 2)
    return value


def elf_anchors(path, manifest):
    with path.open("rb") as stream:
        data = stream.read(32 * 1024 * 1024 + 1)
    need(52 <= len(data) <= 32 * 1024 * 1024 and data[:7] == b"\x7fELF\x01\x01\x01",
         "ELF_FORMAT")
    header = struct.unpack_from("<16sHHIIIIIHHHHHH", data)
    need(header[1:3] == (2, 40) and header[8] == 52 and header[9] == 32 and
         1 <= header[10] <= 64, "ELF_ARM_EXEC_HEADERS")
    offset, count = header[5], header[10]
    need(offset + count * 32 <= len(data), "ELF_PROGRAM_HEADERS")
    segments = [struct.unpack_from("<8I", data, offset + i * 32) for i in range(count)]
    for name in ("Pre", "Post"):
        target = manifest[name]["Address"]
        matches = [s for s in segments if s[0] == 1 and s[6] & 1 and
                   s[2] <= target and target + 4 <= s[2] + s[4] and s[1] + s[4] <= len(data)]
        need(len(matches) == 1, "ELF_ANCHOR_SEGMENT")
        segment = matches[0]
        start = segment[1] + target - segment[2]
        need(data[start:start + 4].hex() == manifest[name]["Bytes"].lower(), "ELF_ANCHOR_BYTES")


def frame(payload):
    return b"$" + payload + b"#" + ("%02x" % (sum(payload) & 255)).encode("ascii")


def decode_payload(encoded):
    need(len(encoded) <= MAX_PACKET, "RSP_PACKET_LIMIT")
    result, index = bytearray(), 0
    while index < len(encoded):
        value = encoded[index]
        need(value in (9, 10, 13) or 32 <= value <= 126, "RSP_NON_ASCII")
        if value == 125:
            index += 1
            need(index < len(encoded), "RSP_TRUNCATED_ESCAPE")
            value = encoded[index] ^ 32
            need(value in (9, 10, 13) or 32 <= value <= 126, "RSP_NON_ASCII")
            result.append(value)
        elif value == 42:
            index += 1
            need(result and index < len(encoded), "RSP_BAD_REPEAT")
            count = encoded[index]
            need(32 <= count <= 126 and count not in b"$#+-", "RSP_BAD_REPEAT")
            need(len(result) + count - 29 <= MAX_PACKET, "RSP_DECODE_LIMIT")
            result.extend(bytes([result[-1]]) * (count - 29))
        else:
            result.append(value)
        need(len(result) <= MAX_PACKET, "RSP_DECODE_LIMIT")
        index += 1
    return result.decode("ascii")


class CommandGate:
    def __init__(self, manifest):
        self.anchors = {manifest[n]["Address"]: manifest[n]["Width"] for n in ("Pre", "Post")}
        self.memory = {(a, 4) for a in (*self.anchors, *MMIO.values(), manifest["CurrentSlot"])}
        self.features, self.registers, self.active = {"target.xml"}, set(), set()
        self.frame_word, self.ready, self.allow_exit = None, False, False

    def validate(self, command):
        need(type(command) is str and len(command) <= 200, "RSP_COMMAND_DENIED")
        if command in ("qSupported:qXfer:features:read+", "?"):
            return
        match = re.fullmatch(r"qXfer:features:read:([A-Za-z0-9_.-]{1,80}):([0-9a-f]+),([0-9a-f]+)", command)
        if match:
            need(match[1] in self.features and int(match[2], 16) <= MAX_XML and
                 1 <= int(match[3], 16) <= 1024, "RSP_COMMAND_DENIED")
            return
        match = re.fullmatch(r"p([0-9a-f]+)", command)
        if match:
            need(int(match[1], 16) in self.registers, "RSP_COMMAND_DENIED")
            return
        match = re.fullmatch(r"m([0-9a-f]+),([0-9a-f]+)", command)
        if match:
            region = int(match[1], 16), int(match[2], 16)
            need(region in self.memory or region == self.frame_word, "RSP_COMMAND_DENIED")
            return
        match = re.fullmatch(r"([Zz])1,([0-9a-f]+),4", command)
        if match:
            target = int(match[2], 16)
            need(self.ready and self.anchors.get(target) == 4 and
                 ((not self.active) if match[1] == "Z" else (self.active == {target})),
                 "RSP_COMMAND_DENIED")
            return
        if command == "c":
            need(self.ready and (self.active or self.allow_exit), "RSP_COMMAND_DENIED")
            return
        raise RuntimeError("RSP_COMMAND_DENIED")

    def commit(self, command, response):
        if command.startswith(("Z1,", "z1,")):
            need(response == "OK", "RSP_HARDWARE_BREAKPOINT_REFUSED")
            target = int(command.split(",")[1], 16)
            if command[0] == "Z":
                self.active.add(target)
            else:
                self.active.remove(target)


class Rsp:
    def __init__(self, connection, gate, packets, packet_sink=None):
        self.connection, self.gate, self.packets = connection, gate, packets
        self.packet_sink, self.log_bytes = packet_sink, 0
        self.registers, self.xml = {}, {}

    def log(self, direction, payload, wire):
        self.log_bytes += len(wire) + len(payload)
        need(len(self.packets) < MAX_PACKETS and self.log_bytes <= MAX_LOG_BYTES, "RSP_LOG_LIMIT")
        record = dict(Direction=direction, Payload=payload, WireHex=wire.hex())
        self.packets.append(record)
        if self.packet_sink:
            self.packet_sink(record)

    def packet(self, command):
        self.gate.validate(command)  # Must precede even a fake connection sendall.
        payload = command.encode("ascii")
        wire = frame(payload)
        self.log("tx", command, wire)
        self.connection.sendall(wire)
        need(self.connection.byte() == b"+", "RSP_ACK_REQUIRED")
        need(self.connection.byte() == b"$", "RSP_FRAME_REQUIRED")
        encoded = bytearray()
        while True:
            value = self.connection.byte()
            if value == b"#":
                break
            encoded.extend(value)
            need(len(encoded) <= MAX_PACKET, "RSP_PACKET_LIMIT")
        checksum = self.connection.byte() + self.connection.byte()
        need(re.fullmatch(b"[0-9a-fA-F]{2}", checksum), "RSP_CHECKSUM_SYNTAX")
        need(int(checksum, 16) == sum(encoded) & 255, "RSP_CHECKSUM")
        response = decode_payload(encoded)
        received = b"$" + encoded + b"#" + checksum
        self.log("rx", response, received)
        need(not response.startswith("O") or response == "OK", "RSP_CONSOLE_PACKET")
        need(not response.startswith(("F", "%")), "RSP_UNSUPPORTED_PACKET")
        try:
            self.connection.sendall(b"+")
        except (BrokenPipeError, ConnectionResetError):
            need(response == "W00", "RSP_ACK_WRITE")
        self.gate.commit(command, response)
        return response

    def feature(self, name):
        result, offset = "", 0
        for _ in range(257):
            reply = self.packet("qXfer:features:read:%s:%x,400" % (name, offset))
            need(reply and reply[0] in "ml" and len(reply) <= 1025, "RSP_XML_REPLY")
            need(reply[0] == "l" or len(reply) > 1, "RSP_XML_NO_PROGRESS")
            result += reply[1:]
            offset += len(reply) - 1
            need(len(result) <= MAX_XML, "RSP_XML_LIMIT")
            if reply[0] == "l":
                return result
        raise RuntimeError("RSP_XML_LIMIT")

    def discover(self):
        supported = self.packet("qSupported:qXfer:features:read+")
        need("qXfer:features:read+" in supported.split(";"), "RSP_XML_UNAVAILABLE")
        next_number, total = 0, 0
        numbers, visiting = set(), set()

        def visit(annex, depth):
            nonlocal next_number, total
            need(depth <= 8 and len(self.xml) < 16 and annex not in visiting and annex not in self.xml,
                 "RSP_XML_INCLUDE_LIMIT")
            need(re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", annex) and annex not in (".", ".."),
                 "RSP_XML_INCLUDE_NAME")
            visiting.add(annex)
            self.gate.features.add(annex)
            document = self.feature(annex)
            self.xml[annex] = document
            total += len(document)
            need(total <= MAX_XML and "<!ENTITY" not in document.upper(), "RSP_XML_LIMIT_OR_ENTITY")
            doctypes = re.findall(r"<!DOCTYPE[^>]*>", document, re.I)
            need(all(re.fullmatch(r'<!DOCTYPE\s+(?:target|feature)\s+SYSTEM\s+"gdb-target.dtd"\s*>', d)
                     for d in doctypes), "RSP_XML_DOCTYPE")
            parsed = document
            # Known QEMU target.xml spelling; preserve the original in TargetXML.
            if "<xi:include" in parsed and "xmlns:xi=" not in parsed:
                parsed, count = re.subn(r"<(target|feature)(?=[\s>])",
                    r'<\1 xmlns:xi="http://www.w3.org/2001/XInclude"', parsed, count=1)
                need(count == 1, "RSP_XML_NAMESPACE")
            root = ET.fromstring(parsed)
            elements = list(root.iter())
            need(len(elements) <= 2048, "RSP_XML_ELEMENT_LIMIT")
            for element in elements:
                need(len(element.attrib) <= 16, "RSP_XML_ATTRIBUTE_LIMIT")
                if element.tag == "{http://www.w3.org/2001/XInclude}include":
                    need(set(element.attrib) == {"href"}, "RSP_XML_INCLUDE_ATTRIBUTES")
                    visit(element.attrib["href"], depth + 1)
                elif element.tag == "reg":
                    register_name = element.attrib.get("name", "").lower()
                    need(re.fullmatch(r"[a-z][a-z0-9_]{0,63}", register_name), "RSP_XML_REGISTER_NAME")
                    need(re.fullmatch(r"[0-9]{1,4}", element.attrib.get("regnum", str(next_number))) and
                         re.fullmatch(r"[0-9]{1,4}", element.attrib.get("bitsize", "0")),
                         "RSP_XML_REGISTER_NUMBER")
                    number = int(element.attrib.get("regnum", str(next_number)))
                    bits = int(element.attrib.get("bitsize", "0"))
                    need(0 <= number <= 1023 and bits in (8, 16, 32, 64, 96, 128, 256) and
                         register_name not in self.registers and number not in numbers and len(numbers) < 256,
                         "RSP_XML_REGISTER_DUPLICATE_OR_SIZE")
                    self.registers[register_name] = dict(Number=number, Bits=bits)
                    numbers.add(number)
                    next_number = number + 1
            visiting.remove(annex)

        visit("target.xml", 0)
        need("psp" in self.registers and self.registers["psp"]["Bits"] == 32,
             "DIRECT_PSP_REGISTER_UNAVAILABLE_NO_DERIVATION")
        need(all(n in self.registers and self.registers[n]["Bits"] == 32 for n in CORE),
             "RSP_REQUIRED_CORE_REGISTER_UNAVAILABLE")
        names = CORE + (("control",) if "control" in self.registers else ())
        need(all(self.registers[n]["Bits"] == 32 for n in names), "RSP_CORE_REGISTER_SIZE")
        self.gate.registers = {self.registers[n]["Number"] for n in names}
        self.gate.ready = True

    def register(self, name):
        reply = self.packet("p%x" % self.registers[name]["Number"])
        need(re.fullmatch(r"[0-9a-fA-F]{8}", reply), "RSP_REGISTER_READ_" + name.upper())
        return int.from_bytes(bytes.fromhex(reply), "little")

    def memory(self, address, size=4):
        reply = self.packet("m%x,%x" % (address, size))
        need(re.fullmatch(r"[0-9a-fA-F]{%d}" % (2 * size), reply), "RSP_MEMORY_READ")
        return bytes.fromhex(reply)

    def word(self, address):
        return int.from_bytes(self.memory(address), "little")

    def breakpoint(self, anchor, insert):
        return self.packet(("Z" if insert else "z") + "1,%x,4" % anchor["Address"])


class ChildIO:
    """Drain bounded child channels even while waiting for partial RSP packets."""
    def __init__(self, process, deadline, directory):
        self.process, self.deadline, self.connection = process, deadline, None
        self.selector, self.buffer, self.eof = selectors.DefaultSelector(), bytearray(), False
        self.outputs = {"Stdout": bytearray(), "Stderr": bytearray()}
        self.files = {k: (directory / ("qemu." + k.lower())).open("wb") for k in self.outputs}
        for stream, name in ((process.stdout, "Stdout"), (process.stderr, "Stderr")):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, name)

    def attach(self, connection):
        self.connection = connection
        connection.setblocking(False)
        self.selector.register(connection, selectors.EVENT_READ, "rsp")

    def pump(self):
        for key, _ in self.selector.select(min(0.1, remaining(self.deadline))):
            if key.data == "rsp":
                chunk = self.connection.recv(4096)
                if not chunk:
                    self.eof = True
                    self.selector.unregister(self.connection)
                else:
                    self.buffer.extend(chunk)
                    need(len(self.buffer) <= MAX_PACKET + 4096, "RSP_BUFFER_LIMIT")
            else:
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    self.selector.unregister(key.fileobj)
                    key.fileobj.close()
                else:
                    value = self.outputs[key.data]
                    need(len(value) + len(chunk) <= MAX_OUTPUT, "QEMU_OUTPUT_LIMIT")
                    value.extend(chunk)
                    self.files[key.data].write(chunk)
                    self.files[key.data].flush()

    def byte(self):
        while not self.buffer:
            need(not self.eof, "RSP_EOF")
            self.pump()
        value = bytes(self.buffer[:1])
        del self.buffer[:1]
        return value

    def sendall(self, data):
        view = memoryview(data)
        while view:
            remaining(self.deadline)
            try:
                count = self.connection.send(view)
                need(count > 0, "RSP_SEND_EOF")
                view = view[count:]
            except BlockingIOError:
                self.pump()

    def wait(self):
        while self.process.poll() is None or any(k.data != "rsp" for k in self.selector.get_map().values()):
            self.pump()
        return self.process.returncode

    def close(self):
        self.selector.close()
        for stream in (self.process.stdout, self.process.stderr):
            if not stream.closed:
                stream.close()
        for stream in self.files.values():
            stream.close()


def stopped(reply):
    need(reply == "S05" or re.fullmatch(r"T05(?:[A-Za-z0-9]+:[A-Za-z0-9.,_-]*;)*", reply),
         "RSP_UNEXPECTED_STOP")
    need("swbreak:" not in reply, "RSP_SOFTWARE_BREAKPOINT_STOP")


def snapshot(rsp, manifest, stage, pair):
    rsp.gate.frame_word = None
    registers = {name: rsp.register(name) for name in CORE}
    anchor = manifest["Pre" if stage == "pre" else "Post"]
    need(registers["pc"] == anchor["Address"], "STOP_PC_NOT_ANCHOR")
    code = {}
    for name in ("Pre", "Post"):
        code[name] = rsp.memory(manifest[name]["Address"]).hex()
        need(code[name] == manifest[name]["Bytes"].lower(), "LIVE_CODE_ANCHOR_CHANGED")
    current = rsp.word(manifest["CurrentSlot"])
    need(current in manifest["Workers"], "CURRENT_NOT_MANIFEST_WORKER")
    stack = manifest["Stacks"][manifest["Workers"].index(current)]
    psp = registers["psp"]
    need(psp % 4 == 0 and stack["Begin"] <= psp <= stack["End"] - 32, "PSP_CORE_BOUNDS")
    rsp.gate.frame_word = (psp + 28, 4)
    xpsr = rsp.word(psp + 28)
    size = (32 if registers["lr"] & 16 else 104) + (4 if xpsr & 512 else 0)
    need(psp <= stack["End"] - size, "PSP_COMPLETE_FRAME_BOUNDS")
    event = dict(Stage=stage, Pair=pair, PC=registers["pc"], R0=registers["r0"],
                 R3=registers["r3"], LR=registers["lr"], XPSR=registers["xpsr"], PSP=psp,
                 Current=current, StackedXPSR=xpsr,
                 CodeBytes=code["Pre" if stage == "pre" else "Post"], AnchorBytes=code)
    event.update({name: rsp.word(location) for name, location in MMIO.items()})
    if "control" in rsp.registers:
        event["CONTROL"] = rsp.register("control")  # Debug view, not architectural MRS evidence.
    rsp.gate.frame_word = None
    return event


def maps(pid, output):
    text = Path("/proc/%s/maps" % pid).read_text(encoding="utf-8")
    need(len(text) <= 2 * 1024 * 1024, "PROC_MAPS_LIMIT")
    output.write_text(text, encoding="utf-8")
    result = set()
    for line in text.splitlines():
        columns = line.split(None, 5)
        if len(columns) != 6 or not columns[5].startswith("/"):
            continue
        name = columns[5]
        if name.startswith("/memfd:"):
            continue
        need(not name.endswith(" (deleted)"), "MAPPED_FILE_DELETED")
        path = Path(name)
        need(path.is_file(), "MAPPED_FILE_UNAVAILABLE")
        result.add(str(path.resolve(strict=True)))
    return result


def inventory(script, manifest_path, elf, qemu, root, directory, suffix, pid, deadline):
    paths = set()
    def add(path, role):
        value = Path(path).resolve(strict=True)
        need(value.is_file(), "INPUT_NOT_REGULAR_FILE")
        paths.add((str(value), role))
    add(script, "ObserverScript")
    add(manifest_path, "Manifest")
    add(elf, "Elf")
    add(Path("/proc/self/exe").resolve(strict=True), "PythonExecutable")
    add(qemu, "QemuExecutable")
    for module in tuple(sys.modules.values()):
        for attribute in ("__file__", "__cached__"):
            name = getattr(module, attribute, None)
            if isinstance(name, str) and Path(name).is_file():
                add(name, "PythonModule")
    for name in maps("self", directory / ("python-maps-" + suffix + ".txt")):
        add(name, "MappedLibrary")
    for name in maps(pid, directory / ("qemu-maps-" + suffix + ".txt")):
        add(name, "MappedLibrary")
    support = root / "usr/share/qemu"
    need(support.is_dir(), "QEMU_SUPPORT_MISSING")
    for count, item in enumerate(support.rglob("*"), 1):
        remaining(deadline)
        need(count <= 8192, "QEMU_SUPPORT_LIMIT")
        if item.is_file():
            add(item, "QemuSupport")
    need(len(paths) <= 8192, "INPUT_INVENTORY_LIMIT")
    hashes = {}
    result = []
    for path, role in sorted(paths):
        if path not in hashes:
            hashes[path] = digest(path, deadline)
        result.append(dict(Path=path, Sha256=hashes[path], Role=role))
    return result


def drift(before, after):
    a = {(r["Path"], r["Role"]): r["Sha256"] for r in before}
    b = {(r["Path"], r["Role"]): r["Sha256"] for r in after}
    return [dict(Path=k[0], Role=k[1], Before=a.get(k), After=b.get(k))
            for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]


def terminal(actual, manifest):
    need(type(actual["Exit"]) is int and actual["Exit"] == 0 and
         actual["TimedOut"] is False and actual["Stdout"] == "", "QEMU_TERMINAL_STATUS")
    label = "CONTEXT" if manifest["Consumer"] == "context" else "FIBERV1"
    lazy = str(int(manifest["Lazy"]))
    pattern = (r"CHECK:CM4-MPU-FP:API=" + label + ":LAZY=" + lazy +
        r":CALLS=00000017:SELF=00000001:CROSS=00000015:EXT0=00000008:EXT1=00000007:BASIC2=00000007:CHALLENGE=0000000F:POSTCONTROL=([0-9A-F]{8}):LSPACT=00000000\n"
        r"RETURN:CM4-MPU-FP:CODE=00000052:IPSR=0000000B:PC=([0-9A-F]{8}):PSP=([0-9A-F]{8}):XPSR=([0-9A-F]{8})\n"
        r"PASS:CM4-MPU-FP:" + label + ":LAZY=" + lazy + r"\n")
    match = re.fullmatch(pattern, actual["Stderr"])
    need(match is not None, "QEMU_TERMINAL_GRAMMAR")
    control, pc, psp, xpsr = (int(v, 16) for v in match.groups())
    stack = manifest["Stacks"][0]
    need(control != 0 and control & ~0x22 == 0 and pc == manifest["ReturnPC"] and psp % 8 == 0 and
         stack["Begin"] <= psp <= stack["End"] - 104 - (4 if xpsr & 512 else 0) and
         xpsr & 0x010001FF == 0x01000000, "QEMU_TERMINAL_FRAME")


def self_controls():
    """Pure fake-connection command/packet controls, never CPU observations."""
    class Fake:
        def __init__(self, response):
            self.response, self.sent = bytearray(response), []
        def sendall(self, data):
            self.sent.append(bytes(data))
        def byte(self):
            need(self.response, "RSP_EOF")
            value = bytes(self.response[:1])
            del self.response[:1]
            return value
    controls = []
    fixture = {"Pre": {"Address": 0x1000, "Width": 4},
               "Post": {"Address": 0x1100, "Width": 4}, "CurrentSlot": 0x20000000}
    forbidden = ("P0=00000000", "M20000000,4:00000000", "X20000000,1:x", "G00",
                 "Z0,1000,4", "z0,1000,4", "s", "s1000", "c1000", "C05", "vCont;c",
                 "qRcmd,7265736574", "monitor reset", "Z1,1000,2", "Z1,1004,4",
                 "m20000004,4", "me000ef34,8", "p99", "qXfer:features:read:../x:0,400", "?\n")
    for command in forbidden:
        gate = CommandGate(fixture)
        gate.ready, gate.registers = True, {0}
        fake = Fake(b"+" + frame(b"OK"))
        reason = None
        try:
            Rsp(fake, gate, []).packet(command)
        except RuntimeError as error:
            reason = str(error)
        need(reason == "RSP_COMMAND_DENIED" and not fake.sent, "TRANSPORT_SELF_CONTROL_GATE")
        controls.append(dict(Name="deny-" + command, Accepted=False, Reason=reason, Sends=0))
    cases = [("plain", b"+" + frame(b"S05"), None),
             ("escaped", b"+" + frame(b"a}\x03b"), None),
             ("repeat", b"+" + frame(b"0* "), None),
             ("non-xml-control-byte", b"+" + frame(b"x\x0b"), "RSP_NON_ASCII"),
             ("checksum", b"+$S05#00", "RSP_CHECKSUM"),
             ("escape", b"+" + frame(b"x}"), "RSP_TRUNCATED_ESCAPE"),
             ("repeat-no-previous", b"+" + frame(b"* "), "RSP_BAD_REPEAT"),
             ("repeat-no-count", b"+" + frame(b"x*"), "RSP_BAD_REPEAT"),
             ("console", b"+" + frame(b"O6869"), "RSP_CONSOLE_PACKET"),
             ("file-io", b"+" + frame(b"Fopen"), "RSP_UNSUPPORTED_PACKET"),
             ("negative-ack", b"-", "RSP_ACK_REQUIRED"),
             ("missing-ack", frame(b"S05"), "RSP_ACK_REQUIRED"),
             ("duplicate-ack", b"++", "RSP_FRAME_REQUIRED"),
             ("packet-limit", b"+$" + b"x" * (MAX_PACKET + 1), "RSP_PACKET_LIMIT")]
    for name, response, expected in cases:
        fake, packets, reason = Fake(response), [], None
        try:
            value = Rsp(fake, CommandGate(fixture), packets).packet("?")
            if name == "plain":
                need(value == "S05", "TRANSPORT_SELF_CONTROL_VALUE")
            elif name == "escaped":
                need(value == "a#b", "TRANSPORT_SELF_CONTROL_VALUE")
            elif name == "repeat":
                need(value == "0000", "TRANSPORT_SELF_CONTROL_VALUE")
        except RuntimeError as error:
            reason = str(error)
        need(reason == expected, "TRANSPORT_SELF_CONTROL_PACKET:" + name + ":" + str(reason))
        need(bytes.fromhex(packets[0]["WireHex"]) == frame(b"?"), "TRANSPORT_SELF_CONTROL_WIRE")
        controls.append(dict(Name=name, Accepted=reason is None, Reason=reason))
    gate = CommandGate(fixture)
    gate.ready = True
    fake = Fake(b"".join(b"+" + frame(p) for p in (b"OK", b"S05", b"OK", b"W00")))
    rsp = Rsp(fake, gate, [])
    rsp.packet("Z1,1000,4")
    need(gate.active == {0x1000}, "TRANSPORT_SELF_CONTROL_BREAKPOINT")
    before = len(fake.sent)
    rejected = None
    try:
        rsp.packet("Z1,1100,4")
    except RuntimeError as failure:
        rejected = str(failure)
    need(rejected == "RSP_COMMAND_DENIED" and len(fake.sent) == before,
         "TRANSPORT_SELF_CONTROL_SIMULTANEOUS_BREAKPOINT")
    controls.append(dict(Name="deny-simultaneous-breakpoints", Accepted=False, Reason=rejected, Sends=0))
    need(rsp.packet("c") == "S05", "TRANSPORT_SELF_CONTROL_CONTINUE")
    rsp.packet("z1,1000,4")
    need(not gate.active, "TRANSPORT_SELF_CONTROL_BREAKPOINT")
    gate.allow_exit = True
    need(rsp.packet("c") == "W00", "TRANSPORT_SELF_CONTROL_EXIT")
    controls.append(dict(Name="hardware-breakpoint-continue-remove-exit", Accepted=True, Reason=None))

    # Nested includes exercise register-number continuity and document-name lifetime.
    documents = {
        "target.xml": '<target><xi:include href="core.xml"/><xi:include href="system.xml"/></target>',
        "core.xml": '<feature>' + ''.join('<reg name="%s" bitsize="32"/>' % n
                                         for n in CORE[:-1]) + '</feature>',
        "system.xml": '<feature><reg name="psp" bitsize="32"/><reg name="control" bitsize="32"/></feature>'}
    for name, changed, expected in (
            ("xml-nested-registers", documents, None),
            ("xml-no-psp", dict(documents, **{"system.xml": '<feature><reg name="control" bitsize="32"/></feature>'}),
             "DIRECT_PSP_REGISTER_UNAVAILABLE_NO_DERIVATION"),
            ("xml-cycle", dict(documents, **{"system.xml": '<feature><xi:include href="target.xml"/></feature>'}),
             "RSP_XML_INCLUDE_LIMIT")):
        fake = Fake(b"+" + frame(b"qXfer:features:read+"))
        gate, reason = CommandGate(fixture), None
        rsp = Rsp(fake, gate, [])
        rsp.feature = lambda annex: changed[annex]
        try:
            rsp.discover()
        except RuntimeError as failure:
            reason = str(failure)
        need(reason == expected, "TRANSPORT_SELF_CONTROL_XML:" + name + ":" + str(reason))
        need(gate.ready == (expected is None), "TRANSPORT_SELF_CONTROL_XML_READY")
        if expected is None:
            need(set(rsp.xml) == set(documents) and rsp.registers["psp"]["Number"] == 5 and
                 gate.registers == set(range(7)), "TRANSPORT_SELF_CONTROL_XML_REGISTERS")
        controls.append(dict(Name=name, Accepted=reason is None, Reason=reason))
    multiline = ('<target>\r\n\t<feature>\n' +
                 ''.join('\t<reg name="%s" bitsize="32"/>\r\n' % n for n in CORE) +
                 '</feature>\n</target>\n')
    fake = Fake(b"+" + frame(b"qXfer:features:read+") +
                b"+" + frame(b"l" + multiline.encode("ascii")))
    rsp = Rsp(fake, CommandGate(fixture), [])
    rsp.discover()
    need(rsp.xml == {"target.xml": multiline} and rsp.gate.ready and
         rsp.registers["psp"]["Number"] == 5, "TRANSPORT_SELF_CONTROL_MULTILINE_XML")
    controls.append(dict(Name="xml-multiline-wire-decode-discover", Accepted=True, Reason=None))
    return dict(Controls=controls, Scope="Pure fake transport/gate controls only; no target or CPU observations")


def run(args):
    need(sys.platform.startswith("linux") and not sys.flags.optimize and __debug__, "LINUX_UNOPTIMIZED_PYTHON_REQUIRED")
    need(5 <= args.seconds <= 45, "SECONDS_RANGE")
    started = time.monotonic()
    deadline = started + args.seconds
    work_deadline = deadline - 2
    output = Path(args.output_dir)
    need(output.is_absolute() and not os.path.lexists(output), "FRESH_ABSOLUTE_OUTPUT_REQUIRED")
    output.parent.resolve(strict=True)
    output.mkdir(mode=0o700)
    trace = dict(SchemaVersion=1, Verdict="FAIL", Error=None, ElfSha256=None, Events=[],
                 Actual=dict(Exit=None, TimedOut=False, Stdout="", Stderr=""), PacketLog=[],
                 Registers={}, TargetXML={}, InputsBefore=[], InputsAfter=[], InputDrift=[],
                 Child=dict(Exited=False, Exit=None, SocketGone=False), Command=[],
                 ReadOnly=True, NoTargetWrites=True, TransportControls={})
    process = connection = io = temporary = packet_file = event_file = rsp = None
    socket_path, error = None, None
    inventory_context = None
    try:
        manifest_path = Path(args.manifest).resolve(strict=True)
        script = Path(__file__).resolve(strict=True)
        script_hash = digest(script, work_deadline)
        manifest_hash = digest(manifest_path, work_deadline)
        manifest = manifest_read(manifest_path)
        elf = Path(manifest["Elf"]).resolve(strict=True)
        root = Path(args.qemu_root)
        need(root.is_absolute() and root.is_dir(), "EXISTING_ABSOLUTE_QEMU_ROOT_REQUIRED")
        root = root.resolve(strict=True)
        qemu = (root / "usr/bin/qemu-system-arm").resolve(strict=True)
        need(qemu.is_file() and os.access(qemu, os.X_OK) and qemu.is_relative_to(root), "QEMU_EXECUTABLE_REQUIRED")
        need(not output.resolve().is_relative_to(root), "OUTPUT_INSIDE_QEMU_PREFIX")
        trace["ElfSha256"] = digest(elf, work_deadline)
        need(trace["ElfSha256"] == manifest["ElfSha256"], "ELF_HASH_MISMATCH")
        elf_anchors(elf, manifest)
        trace["TransportControls"] = self_controls()
        temporary = tempfile.TemporaryDirectory(prefix="cm4-lazy-rsp-", dir="/tmp")
        private = Path(temporary.name)
        need(stat.S_IMODE(private.stat().st_mode) == 0o700, "PRIVATE_DIRECTORY_MODE")
        socket_path = private / "gdb.sock"
        need(len(os.fsencode(socket_path)) < 100, "UNIX_SOCKET_PATH_LIMIT")
        command = [str(qemu), "-machine", "mps2-an386", "-accel", "tcg", "-display", "none",
                   "-serial", "none", "-monitor", "none", "-no-reboot",
                   "-semihosting-config", "enable=on,target=native", "-L", str(root / "usr/share/qemu"),
                   "-kernel", str(elf), "-S", "-chardev",
                   "socket,id=observer,path=%s,server=on,wait=off" % socket_path,
                   "-gdb", "chardev:observer"]
        trace["Command"] = command
        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        environment["LD_LIBRARY_PATH"] = str(root / "usr/lib/x86_64-linux-gnu") + (
            ":" + environment["LD_LIBRARY_PATH"] if environment.get("LD_LIBRARY_PATH") else "")
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=environment, start_new_session=True, bufsize=0)
        inventory_context = (script, manifest_path, elf, qemu, root, output)
        io = ChildIO(process, work_deadline, output)
        while connection is None:
            remaining(work_deadline)
            need(process.poll() is None, "QEMU_EXITED_BEFORE_CONNECT")
            candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            candidate.settimeout(min(0.1, remaining(work_deadline)))
            try:
                candidate.connect(str(socket_path))
                connection = candidate
            except (FileNotFoundError, ConnectionRefusedError):
                candidate.close()
                io.pump()
            except BaseException:
                candidate.close()
                raise
        io.attach(connection)
        packet_file = (output / "packets.jsonl").open("w", encoding="ascii")
        event_file = (output / "events.jsonl").open("w", encoding="ascii")
        def packet_sink(record):
            packet_file.write(json.dumps(record, ensure_ascii=True) + "\n")
            packet_file.flush()
        rsp = Rsp(io, CommandGate(manifest), trace["PacketLog"], packet_sink)
        trace["Registers"], trace["TargetXML"] = rsp.registers, rsp.xml
        stopped(rsp.packet("?"))
        trace["InputsBefore"] = inventory(*inventory_context, "before", process.pid, work_deadline)
        need(digest(script, work_deadline) == script_hash and
             digest(manifest_path, work_deadline) == manifest_hash, "OPENING_HELPER_OR_MANIFEST_DRIFT")
        rsp.discover()
        # Prove direct PSP can actually be read before any continue or breakpoint.
        rsp.register("psp")
        need(digest(elf, work_deadline) == manifest["ElfSha256"], "ELF_OPENING_DRIFT")
        for name in ("Pre", "Post"):
            need(rsp.memory(manifest[name]["Address"]).hex() == manifest[name]["Bytes"].lower(),
                 "LIVE_CODE_ANCHOR_CHANGED")
        rsp.breakpoint(manifest["Pre"], True)
        for pair in range(len(SEQUENCE)):
            for stage, anchor in (("pre", manifest["Pre"]), ("post", manifest["Post"])):
                stopped(rsp.packet("c"))
                event = snapshot(rsp, manifest, stage, pair)
                trace["Events"].append(event)
                need(len(trace["Events"]) <= 44, "EVENT_LIMIT")
                event_file.write(json.dumps(event, ensure_ascii=True) + "\n")
                event_file.flush()
                rsp.breakpoint(anchor, False)
                if stage == "pre":
                    rsp.breakpoint(manifest["Post"], True)
                elif pair < len(SEQUENCE) - 1:
                    rsp.breakpoint(manifest["Pre"], True)
        need(not rsp.gate.active, "BREAKPOINTS_REMAIN")
        trace["InputsAfter"] = inventory(*inventory_context, "after", process.pid, work_deadline)
        trace["InputDrift"] = drift(trace["InputsBefore"], trace["InputsAfter"])
        need(not trace["InputDrift"], "INPUT_OR_MAPPED_FILE_DRIFT")
        rsp.gate.allow_exit = True
        need(rsp.packet("c") == "W00", "RSP_EXIT_NOT_W00")
        need(io.wait() == 0, "QEMU_EXIT_NONZERO")
        trace["Actual"] = dict(Exit=process.returncode, TimedOut=False,
            Stdout=bytes(io.outputs["Stdout"]).decode("utf-8", "strict"),
            Stderr=bytes(io.outputs["Stderr"]).decode("utf-8", "strict"))
        terminal(trace["Actual"], manifest)
        # Rehash the same before/last-post dependency union after process exit.
        for row in trace["InputsAfter"]:
            need(digest(row["Path"], work_deadline) == row["Sha256"], "FINAL_FILE_DRIFT")
        need(len(trace["Events"]) == 44, "EVENT_COUNT")
    except Exception as failure:
        error = type(failure).__name__ + ": " + str(failure)[:500]
        trace["Actual"]["TimedOut"] = isinstance(failure, (TimeoutError, socket.timeout))
    finally:
        def cleanup_error(reason):
            nonlocal error
            error = ((error + "; ") if error else "") + str(reason)[:300]

        # Preserve closing evidence on a failed stopped-target handoff when time permits.
        if (error and inventory_context and process and process.poll() is None and
                trace["InputsBefore"] and not trace["InputsAfter"] and
                time.monotonic() < work_deadline):
            try:
                trace["InputsAfter"] = inventory(*inventory_context, "failed-after", process.pid, work_deadline)
                trace["InputDrift"] = drift(trace["InputsBefore"], trace["InputsAfter"])
            except Exception as failure:
                cleanup_error("CLOSING_INVENTORY:" + str(failure))
        if process is not None:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=min(0.6, max(0.01, deadline - time.monotonic())))
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=max(0.01, deadline - time.monotonic()))
                        except subprocess.TimeoutExpired:
                            cleanup_error("CHILD_NOT_REAPED")
                except OSError as failure:
                    cleanup_error("CHILD_CLEANUP:" + str(failure))
            trace["Child"]["Exited"] = process.poll() is not None
            trace["Child"]["Exit"] = process.returncode
            if io:
                # Drain remaining bounded pipe bytes after termination, not target traffic.
                io.deadline = deadline
                if trace["Child"]["Exited"]:
                    try:
                        io.wait()
                    except Exception as failure:
                        cleanup_error("OUTPUT_DRAIN:" + str(failure))
                trace["Actual"].update(Exit=process.returncode,
                    Stdout=bytes(io.outputs["Stdout"]).decode("utf-8", "replace"),
                    Stderr=bytes(io.outputs["Stderr"]).decode("utf-8", "replace"))
        for resource in (connection, io, packet_file, event_file):
            if resource is not None:
                try:
                    resource.close()
                except Exception as failure:
                    cleanup_error("RESOURCE_CLOSE:" + str(failure))
        if temporary is not None:
            try:
                temporary.cleanup()
            except Exception as failure:
                cleanup_error("PRIVATE_DIRECTORY_CLEANUP:" + str(failure))
        trace["Child"]["SocketGone"] = socket_path is None or not socket_path.exists()
        if not trace["Child"]["SocketGone"] or (process is not None and not trace["Child"]["Exited"]):
            cleanup_error("CHILD_OR_SOCKET_CLEANUP")
        trace["Error"] = error
        trace["Verdict"] = "FAIL" if error else "PASS"
        save(output / "target-xml.json", trace["TargetXML"])
        save(output / "snapshots.json", trace["Events"])
        save(output / "inputs-before.json", trace["InputsBefore"])
        save(output / "inputs-after.json", trace["InputsAfter"])
        # A late artifact write must not leave a success receipt after a failed helper.
        try:
            save(output / "trace.json", trace)
            artifacts = {p.name: hashlib.sha256(p.read_bytes()).hexdigest().upper()
                         for p in sorted(output.iterdir()) if p.is_file() and p.name != "artifacts.json"}
            save(output / "artifacts.json", dict(Artifacts=artifacts))
        except Exception as failure:
            trace["Verdict"] = "FAIL"
            trace["Error"] = "ARTIFACT_FINALIZATION:" + str(failure)[:300]
            save(output / "trace.json", trace)
            raise
    return trace["Verdict"] == "PASS"


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--qemu-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--seconds", type=int, default=45)
    args = parser.parse_args()
    try:
        ok = run(args)
    except Exception as error:
        print("LAZY_OBSERVER_FAIL " + type(error).__name__ + ": " + str(error)[:300])
        return 1
    print("LAZY_OBSERVER_" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
