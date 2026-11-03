"""Pure validation of packet-bound PendSV observations; no target or file I/O."""
from copy import deepcopy
import re
from types import SimpleNamespace
import xml.etree.ElementTree as ET

from cm4_mpu_fp_contracts import parse_actual

SEQUENCE = (0, 0) + (1, 2, 0) * 6 + (1, 2)
FIELDS = ('PC', 'R0', 'R3', 'LR', 'XPSR', 'PSP', 'FPCCR', 'FPCAR',
          'CPACR', 'Current', 'StackedXPSR')
CORE = {'r' + str(i) for i in range(13)} | {
    'sp', 'lr', 'pc', 'xpsr', 'psp', 'msp', 'control', 'primask', 'basepri', 'faultmask'}
REG_FIELDS = {'pc': 'PC', 'r0': 'R0', 'r3': 'R3', 'lr': 'LR', 'xpsr': 'XPSR',
              'psp': 'PSP', 'control': 'CONTROL'}
MMIO = {0xE000EF34: 'FPCCR', 0xE000EF38: 'FPCAR', 0xE000ED88: 'CPACR'}


def need(ok, reason):
    if not ok:
        raise RuntimeError('lazy-observer: ' + reason)


def word(value, reason):
    need(type(value) is int and 0 <= value <= 0xFFFFFFFF, reason)
    return value


def raw_bytes(value, reason):
    need(type(value) is str and len(value) % 2 == 0 and
         re.fullmatch(r'[0-9A-Fa-f]*', value) is not None, reason)
    return bytes.fromhex(value)


def sha(value):
    return type(value) is str and re.fullmatch(r'[0-9A-F]{64}', value) is not None


def wire(record):
    """Check a complete framed packet, not a claimed decoded command alone."""
    need('WireHex' in record, 'missing-' + record['Direction'] + '-wire')
    data = raw_bytes(record['WireHex'], 'wire-hex')
    need(len(data) >= 4 and data[:1] == b'$' and data[-3:-2] == b'#', 'wire-frame')
    need(re.fullmatch(b'[0-9A-Fa-f]{2}', data[-2:]) is not None and
         sum(data[1:-3]) % 256 == int(data[-2:], 16), 'wire-checksum')
    body, decoded, i = data[1:-3], bytearray(), 0
    while i < len(body):
        value = body[i]
        if value == 0x7D:
            i += 1
            need(i < len(body), 'wire-escape')
            decoded.append(body[i] ^ 0x20)
        elif value == 0x2A:
            i += 1
            need(i < len(body) and decoded and 3 <= body[i] - 29 <= 97, 'wire-rle')
            decoded.extend(bytes((decoded[-1],)) * (body[i] - 29))
        else:
            need(value not in (0x23, 0x24), 'wire-unescaped-frame')
            decoded.append(value)
        need(len(decoded) <= 262144, 'wire-size')
        i += 1
    need(bytes(decoded) == record['Payload'].encode('utf-8'), 'wire-payload-mismatch')


def register_map(trace):
    xmls, reported = trace.get('TargetXML'), trace.get('Registers')
    need(type(xmls) is dict and 1 <= len(xmls) <= 16 and 'target.xml' in xmls, 'target-xml-inventory')
    need(type(reported) is dict, 'register-map')
    found, numbers, visited, counter = {}, set(), set(), [0]

    def visit(name):
        need(name in xmls and name not in visited and
             re.fullmatch(r'[A-Za-z0-9_.-]+\.xml', name) is not None, 'xml-include')
        visited.add(name)
        text = xmls[name]
        need(type(text) is str and 0 < len(text.encode('utf-8')) <= 65536, 'xml-size')
        parsed = text
        need('<!ENTITY' not in text.upper(), 'xml-entity')
        if '<xi:include' in parsed and 'xmlns:xi=' not in parsed:
            parsed, count = re.subn(r'<(target|feature)(?=[\s>])',
                r'<\1 xmlns:xi="http://www.w3.org/2001/XInclude"', parsed, count=1)
            need(count == 1, 'xml-namespace')
        try:
            tree = ET.fromstring(parsed)
        except ET.ParseError as failure:
            raise RuntimeError('lazy-observer: xml-parse') from failure
        for element in tree.iter():
            tag = element.tag.rsplit('}', 1)[-1]
            if tag == 'include':
                visit(element.get('href'))
            elif tag == 'reg':
                name = element.get('name', '').lower()
                need(re.fullmatch(r'[a-z][a-z0-9_]{0,63}', name) is not None, 'xml-register-name')
                try:
                    number = int(element.get('regnum', str(counter[0])), 0)
                    bits = int(element.get('bitsize', ''), 10)
                except ValueError as failure:
                    raise RuntimeError('lazy-observer: xml-register-number') from failure
                need(0 <= number <= 4095 and 0 < bits <= 2048 and bits % 8 == 0 and
                     name not in found and number not in numbers, 'xml-register-identity')
                found[name] = dict(Number=number, Bits=bits)
                numbers.add(number)
                counter[0] = number + 1

    visit('target.xml')
    need(visited == set(xmls), 'unreferenced-target-xml')
    for name, desc in reported.items():
        need(name in found and type(desc) is dict and type(desc.get('Number')) is int and
             type(desc.get('Bits')) is int and desc == found[name], 'reported-register-identity')
    need('psp' in found and 'psp' in reported, 'missing-direct-xml-psp')
    for name in ('pc', 'r0', 'r3', 'lr', 'xpsr', 'psp'):
        need(name in reported and reported[name]['Bits'] == 32, 'required-core-register')
    return {desc['Number']: name for name, desc in reported.items()
            if name in CORE and desc['Bits'] == 32}


def event_checks(manifest, trace):
    events = trace.get('Events')
    need(type(events) is list and len(events) == 44, '44-ordered-events')
    workers, stacks = manifest.get('Workers'), manifest.get('Stacks')
    need(type(workers) is list and len(workers) == 3 and type(stacks) is list and len(stacks) == 3,
         'three-workers-stacks')
    need(all(word(w, 'worker-address') and w % 4 == 0 for w in workers) and
         len(set(workers)) == 3, 'distinct-workers')
    for stack in stacks:
        need(type(stack) is dict, 'stack-object')
        base, limit = word(stack.get('Begin'), 'stack-begin'), word(stack.get('End'), 'stack-end')
        need(base % 8 == limit % 8 == 0 and base < limit, 'stack-bounds')
    for i, left in enumerate(stacks):
        for right in stacks[i + 1:]:
            need(left['End'] <= right['Begin'] or right['End'] <= left['Begin'], 'overlapping-stacks')
    for pair, worker in enumerate(SEQUENCE):
        pre, post = events[2 * pair:2 * pair + 2]
        active = worker < 2
        for stage, event in (('pre', pre), ('post', post)):
            need(type(event) is dict and event.get('Stage') == stage and
                 type(event.get('Stage')) is str and type(event.get('Pair')) is int and
                 event['Pair'] == pair, 'event-order')
            for field in FIELDS:
                word(event.get(field), 'event-word-' + field)
            anchor = manifest[stage.title()]
            need(event['PC'] == anchor['Address'] and
                 raw_bytes(event.get('CodeBytes'), 'event-code-bytes') == raw_bytes(anchor['Bytes'], 'anchor-bytes'),
                 'event-anchor')
            if 'AnchorBytes' in event:
                code = event['AnchorBytes']
                need(type(code) is dict and set(code) == {'Pre', 'Post'} and all(
                     raw_bytes(code[s], 'event-anchor-bytes') == raw_bytes(manifest[s]['Bytes'], 'anchor-bytes')
                     for s in ('Pre', 'Post')), 'reported-anchor-bytes')
            need(event['XPSR'] & 0x010001FF == 0x0100000E, 'handler-ipsr-thumb')
            need(event['Current'] == workers[worker], 'current-worker-sequence')
            need(event['LR'] == (0xFFFFFFED if active else 0xFFFFFFFD), 'worker-exc-return')
            stacked = event['StackedXPSR']
            extent = (104 if active else 32) + (4 if stacked & 512 else 0)
            stack = stacks[worker]
            need(stacked & 0x010001FF == 0x01000000 and event['PSP'] % 8 == 0 and
                 stack['Begin'] <= event['PSP'] <= stack['End'] - extent, 'full-own-hardware-frame')
            need(event['CPACR'] & 0x00F00000 == 0x00F00000, 'cpacr-full')
            need(event['FPCCR'] & 0xC0000000 == (0xC0000000 if manifest['Lazy'] else 0x80000000),
                 'aspen-lspen-policy')
            pending = stage == 'pre' and active and manifest['Lazy']
            need(event['FPCCR'] & 1 == int(pending), 'lspact-transition')
            if pending:
                need(event['FPCAR'] & 0xFFFFFFF8 == event['PSP'] + 32, 'pending-fpcar')
            need(event['R0'] == event['PSP'] + (32 if stage == 'pre' else 0), 'copy-pointer-stage')
            need(event['R3'] == (1 if stage == 'pre' else event['FPCCR']), 'raw-r3-stage')
            if 'CONTROL' in event:
                word(event['CONTROL'], 'reported-gdb-control')
        need(all(pre[k] == post[k] for k in ('PSP', 'Current', 'LR', 'StackedXPSR')), 'paired-frame-identity')
    return events


def packet_checks(manifest, trace, events, registers):
    packets = trace.get('PacketLog')
    need(type(packets) is list and 2 <= len(packets) <= 8192 and len(packets) % 2 == 0, 'packet-log')
    active, stopped, reads, exited = set(), -1, {}, False
    xml_chunks, xml_done = {}, set()
    anchors = {manifest[s]['Address']: manifest[s] for s in ('Pre', 'Post')}
    required = set(FIELDS) | {'CodeBytesPre', 'CodeBytesPost'}

    def close_event():
        if stopped >= 0:
            extra = {'CONTROL'} if 'CONTROL' in events[stopped] else set()
            need(required | extra <= set(reads), 'missing-packet-bound-event-read')

    def observed(field, value):
        if stopped >= 0:
            expected = (raw_bytes(manifest[field[9:]]['Bytes'], 'anchor-bytes')
                        if field.startswith('CodeBytes') else events[stopped][field])
            need(value == expected, 'packet-event-payload-' + field)
            need(field not in reads or reads[field] == value, 'changing-stopped-read')
            reads[field] = value

    for index in range(0, len(packets), 2):
        tx, rx = packets[index:index + 2]
        need(type(tx) is dict and type(rx) is dict and tx.get('Direction') == 'tx' and
             rx.get('Direction') == 'rx' and type(tx.get('Payload')) is str and
             type(rx.get('Payload')) is str and not exited, 'packet-direction-or-after-exit')
        wire(tx)
        wire(rx)
        command, response = tx['Payload'], rx['Payload']
        need(len(command) <= 2048 and len(response.encode('utf-8')) <= 65536, 'packet-size')
        if re.fullmatch(r'qSupported(?::[A-Za-z0-9_.:+;=-]{0,1024})?', command):
            need(stopped == -1 and not response.startswith('E'), 'supported-response')
        elif command == '?':
            need(stopped == -1 and re.fullmatch(r'(?:S05|T05[^\r\n]*)', response) is not None, 'initial-stop')
        elif command.startswith('qXfer:'):
            match = re.fullmatch(r'qXfer:features:read:([A-Za-z0-9_.-]+\.xml):([0-9a-fA-F]+),([0-9a-fA-F]+)', command)
            need(match is not None and stopped == -1, 'bounded-qxfer')
            name, offset, count = match[1], int(match[2], 16), int(match[3], 16)
            need(name in trace['TargetXML'] and name not in xml_done and 0 < count <= 4096 and
                 offset + count <= 65536 and response[:1] in ('m', 'l'), 'qxfer-range')
            previous = xml_chunks.get(name, b'')
            data = response[1:].encode('utf-8')
            need(offset == len(previous) and len(data) <= count and (data or response[0] == 'l'), 'qxfer-payload')
            xml_chunks[name] = previous + data
            if response[0] == 'l':
                need(xml_chunks[name] == trace['TargetXML'][name].encode('utf-8'), 'xml-wire-payload')
                xml_done.add(name)
        elif re.fullmatch(r'[Zz]1,[0-9a-fA-F]+,[0-9a-fA-F]+', command):
            kind, address, width = command.split(',')
            address, width = int(address, 16), int(width, 16)
            need(address in anchors and width == anchors[address]['Width'] and response == 'OK', 'hardware-breakpoint-anchor')
            need((address not in active) if kind == 'Z1' else (address in active), 'hardware-breakpoint-balance')
            if kind == 'Z1':
                need(not active and stopped + 1 < len(events) and
                     address == events[stopped + 1]['PC'], 'hardware-breakpoint-alternation')
            else:
                need(active == {address} and stopped >= 0 and
                     address == events[stopped]['PC'], 'hardware-breakpoint-alternation')
            active.add(address) if kind == 'Z1' else active.remove(address)
        elif re.fullmatch(r'p[0-9a-fA-F]+', command):
            number = int(command[1:], 16)
            need(number in registers and len(response) == 8, 'named-core-register-read')
            value = int.from_bytes(raw_bytes(response, 'register-payload'), 'little')
            name = registers[number]
            if name in REG_FIELDS and (name != 'control' or (stopped >= 0 and 'CONTROL' in events[stopped])):
                observed(REG_FIELDS[name], value)
        elif re.fullmatch(r'm[0-9a-fA-F]+,[0-9a-fA-F]+', command):
            address, count = (int(v, 16) for v in command[1:].split(','))
            data = raw_bytes(response, 'memory-payload')
            need(len(data) == count, 'memory-reply-width')
            if address in anchors and count == anchors[address]['Width']:
                need(data == raw_bytes(anchors[address]['Bytes'], 'anchor-bytes'), 'wire-anchor-payload')
                if stopped >= 0:
                    observed('CodeBytes' + ('Pre' if address == manifest['Pre']['Address'] else 'Post'), data)
            elif count == 4 and address in MMIO:
                observed(MMIO[address], int.from_bytes(data, 'little'))
            elif count == 4 and address == manifest['CurrentSlot']:
                observed('Current', int.from_bytes(data, 'little'))
            elif stopped >= 0 and 'PSP' in reads and count == 4 and address == reads['PSP'] + 28:
                observed('StackedXPSR', int.from_bytes(data, 'little'))
            else:
                need(False, 'memory-read-not-whitelisted')
        elif command == 'c':
            close_event()
            need(xml_done == set(trace['TargetXML']), 'unbound-target-xml')
            need(active == ({events[stopped + 1]['PC']} if stopped + 1 < len(events) else set()),
                 'hardware-breakpoint-alternation')
            stopped += 1
            reads = {}
            if stopped == len(events):
                need(response == 'W00' and not active, 'final-w00-or-breakpoint-cleanup')
                exited = True
            else:
                need(stopped < len(events) and events[stopped]['PC'] in active and
                     re.fullmatch(r'(?:S05|T05[^\r\n]*)', response) is not None, 'event-breakpoint-stop')
        else:
            need(False, 'tx-not-whitelisted')
    need(exited and stopped == 44, 'missing-final-w00')


def validate_trace(manifest, trace):
    """Return one-image counters and terminal facts, never aggregate admission."""
    need(type(manifest) is dict and type(trace) is dict, 'manifest-trace-types')
    need(type(manifest.get('Elf')) is str and manifest['Elf'] and sha(manifest.get('ElfSha256')) and
         manifest.get('Consumer') in ('context', 'fiber') and type(manifest.get('Lazy')) is bool, 'manifest-identity')
    word(manifest.get('ReturnPC'), 'return-pc')
    need(word(manifest.get('CurrentSlot'), 'current-slot') % 4 == 0, 'current-slot-alignment')
    for stage in ('Pre', 'Post'):
        anchor = manifest.get(stage)
        need(type(anchor) is dict and type(anchor.get('Width')) is int, 'anchor-object')
        address, data = word(anchor.get('Address'), 'anchor-address'), raw_bytes(anchor.get('Bytes'), 'anchor-bytes')
        need(address % 2 == 0 and len(data) in (2, 4) and anchor['Width'] == len(data), 'anchor-width')
        need(len(data) == (4 if int.from_bytes(data[:2], 'little') & 0xF800 >= 0xE800 else 2), 'decoded-thumb-width')
    need(manifest['Pre']['Address'] != manifest['Post']['Address'], 'distinct-anchors')
    need(type(trace.get('SchemaVersion')) is int and trace['SchemaVersion'] == 1 and
         trace.get('Verdict') == 'PASS' and type(trace.get('Verdict')) is str and
         'Error' in trace and trace['Error'] is None and trace.get('ElfSha256') == manifest['ElfSha256'], 'trace-pass-identity')
    need(trace.get('ReadOnly') is True and trace.get('NoTargetWrites') is True, 'typed-read-only-flags')
    need(type(trace.get('InputDrift')) is list and not trace['InputDrift'], 'input-drift')
    child = trace.get('Child')
    need(type(child) is dict and child.get('Exited') is True and child.get('SocketGone') is True and
         type(child.get('Exit')) is int and child['Exit'] == 0, 'child-closing')
    roles = {'PythonExecutable', 'QemuExecutable', 'PythonModule', 'MappedLibrary',
             'QemuSupport', 'ObserverScript', 'Manifest', 'Elf'}
    inventories = []
    for key in ('InputsBefore', 'InputsAfter'):
        rows = trace.get(key)
        need(type(rows) is list and rows, 'input-inventory')
        inventory, hashes = {}, {}
        for row in rows:
            need(type(row) is dict and type(row.get('Path')) is str and row['Path'] and
                 type(row.get('Role')) is str and row['Role'] in roles and
                 sha(row.get('Sha256')) and (row['Path'], row['Role']) not in inventory, 'input-record')
            need(row['Path'] not in hashes or hashes[row['Path']] == row['Sha256'], 'same-path-input-hash')
            hashes[row['Path']] = row['Sha256']
            inventory[row['Path'], row['Role']] = row['Sha256']
        need({r[1] for r in inventory} == roles and all(
             sum(r[1] == role for r in inventory) == 1 for role in
             ('QemuExecutable', 'PythonExecutable', 'ObserverScript', 'Manifest', 'Elf')), 'input-roles')
        inventories.append(inventory)
    need(inventories[0] == inventories[1], 'input-manifest-drift')
    command = trace.get('Command')
    need(type(command) is list and command and all(type(v) is str and v for v in command), 'qemu-command')
    need((command[0], 'QemuExecutable') in inventories[0], 'qemu-executable-binding')
    elf = manifest['Elf']
    if re.match(r'^[A-Za-z]:[\\/]', elf):
        elf = '/mnt/' + elf[0].lower() + '/' + elf[3:].replace('\\', '/')
    need(inventories[0].get((elf, 'Elf')) == manifest['ElfSha256'], 'elf-input-binding')
    need(command.count('-kernel') == 1 and command.index('-kernel') + 1 < len(command) and
         command[command.index('-kernel') + 1] == elf and '-S' in command, 'qemu-kernel-binding')
    events = event_checks(manifest, trace)
    registers = register_map(trace)
    packet_checks(manifest, trace, events, registers)
    actual = trace.get('Actual')
    terminal = parse_actual(actual, dict(Model=False, Mutation=None, Consumer=manifest['Consumer'],
                                        Lazy=manifest['Lazy'], Audit=dict(ReturnPC=manifest['ReturnPC'])))
    return dict(Pairs=22, Extended=15, Basic=7, PreSnapshots=22, PostSnapshots=22,
                ReadOnly=True, ReadOnlySource='Checksum-bound TX WireHex whitelist and packet-bound raw event reads',
                Actual=deepcopy(actual), Return=terminal)


def _frame(payload):
    encoded = bytearray()
    for value in payload.encode('utf-8'):
        encoded.extend((0x7D, value ^ 0x20) if value in (0x23, 0x24, 0x7D, 0x2A) else (value,))
    return (b'$' + encoded + b'#' + ('%02x' % (sum(encoded) % 256)).encode('ascii')).hex()


def _synthetic(consumer, lazy):
    """Parser-only data. No packet here is sent and no target observation is claimed."""
    manifest = dict(Elf='/synthetic/runtime.elf', ElfSha256='A' * 64, Consumer=consumer, Lazy=lazy,
        Pre=dict(Address=0x1000, Bytes='1EF0100F', Width=4),
        Post=dict(Address=0x1010, Bytes='13F0010F', Width=4), CurrentSlot=0x20000000,
        Workers=[0x20008000, 0x20008100, 0x20008200],
        Stacks=[dict(Begin=b, End=b + 4096) for b in (0x20002000, 0x20004000, 0x20006000)], ReturnPC=0x1200)
    numbers = dict(r0=0, r3=3, lr=14, pc=15, xpsr=25, psp=26, control=27)
    xml = '<!DOCTYPE target SYSTEM "gdb-target.dtd"><target><xi:include href="core.xml"/></target>'
    core = '<feature name="synthetic">' + ''.join(
        '<reg name="%s" bitsize="32" regnum="%d"/>' % (name.upper(), number)
        for name, number in numbers.items()) + '</feature>'
    inputs = [dict(Path='/synthetic/' + role, Sha256='B' * 64, Role=role) for role in
              ('PythonExecutable', 'QemuExecutable', 'PythonModule', 'MappedLibrary',
               'QemuSupport', 'ObserverScript', 'Manifest')]
    inputs.append(dict(Path=manifest['Elf'], Sha256=manifest['ElfSha256'], Role='Elf'))
    inputs.append(dict(Path='/synthetic/PythonExecutable', Sha256='B' * 64, Role='MappedLibrary'))
    label = 'CONTEXT' if consumer == 'context' else 'FIBERV1'
    terminal = ('CHECK:CM4-MPU-FP:API=%s:LAZY=%d:CALLS=00000017:SELF=00000001:CROSS=00000015:'
        'EXT0=00000008:EXT1=00000007:BASIC2=00000007:CHALLENGE=0000000F:POSTCONTROL=00000022:LSPACT=00000000\n'
        'RETURN:CM4-MPU-FP:CODE=00000052:IPSR=0000000B:PC=00001200:PSP=20002F00:XPSR=01000000\n'
        'PASS:CM4-MPU-FP:%s:LAZY=%d\n') % (label, lazy, label, lazy)
    trace = dict(SchemaVersion=1, Verdict='PASS', Error=None, ElfSha256=manifest['ElfSha256'], Events=[],
        Actual=dict(Exit=0, TimedOut=False, Stdout='', Stderr=terminal), PacketLog=[],
        Registers={name: dict(Number=number, Bits=32) for name, number in numbers.items()},
        TargetXML={'target.xml': xml, 'core.xml': core}, InputsBefore=deepcopy(inputs), InputsAfter=deepcopy(inputs), InputDrift=[],
        Child=dict(Exited=True, Exit=0, SocketGone=True),
        Command=['/synthetic/QemuExecutable', '-kernel', manifest['Elf'], '-S'], ReadOnly=True, NoTargetWrites=True)

    def exchange(command, response):
        trace['PacketLog'].extend((dict(Direction='tx', Payload=command, WireHex=_frame(command)),
                                   dict(Direction='rx', Payload=response, WireHex=_frame(response))))

    exchange('qSupported', 'qXfer:features:read+')
    exchange('?', 'S05')
    exchange('qXfer:features:read:target.xml:0,1000', 'l' + xml)
    exchange('qXfer:features:read:core.xml:0,1000', 'l' + core)
    a = manifest['Pre']
    exchange('Z1,%x,%x' % (a['Address'], a['Width']), 'OK')
    for pair, worker in enumerate(SEQUENCE):
        psp = manifest['Stacks'][worker]['End'] - 256
        for stage in ('pre', 'post'):
            pending = lazy and worker < 2 and stage == 'pre'
            fpccr = (0xC0000000 if lazy else 0x80000000) | int(pending)
            event = dict(Stage=stage, Pair=pair, PC=manifest[stage.title()]['Address'],
                R0=psp + (32 if stage == 'pre' else 0), R3=1 if stage == 'pre' else fpccr,
                LR=0xFFFFFFED if worker < 2 else 0xFFFFFFFD, XPSR=0x0100000E, PSP=psp,
                FPCCR=fpccr, FPCAR=psp + 32, CPACR=0x00F00000,
                Current=manifest['Workers'][worker], StackedXPSR=0x01000000,
                CodeBytes=manifest[stage.title()]['Bytes'], CONTROL=0)
            trace['Events'].append(event)
            exchange('c', 'S05')
            for name, field in REG_FIELDS.items():
                exchange('p%x' % numbers[name], event[field].to_bytes(4, 'little').hex())
            for address, field in {**MMIO, manifest['CurrentSlot']: 'Current', psp + 28: 'StackedXPSR'}.items():
                exchange('m%x,4' % address, event[field].to_bytes(4, 'little').hex())
            for s in ('Pre', 'Post'):
                exchange('m%x,%x' % (manifest[s]['Address'], manifest[s]['Width']), manifest[s]['Bytes'])
            exchange('z1,%x,%x' % (event['PC'], manifest[stage.title()]['Width']), 'OK')
            if stage == 'pre' or pair < len(SEQUENCE) - 1:
                a = manifest['Post' if stage == 'pre' else 'Pre']
                exchange('Z1,%x,%x' % (a['Address'], a['Width']), 'OK')
    exchange('c', 'W00')
    return manifest, trace


def control_tests():
    """Finite synthetic counterexamples to the actual pure validator, never CPU evidence."""
    records = []

    def test(name, manifest, trace, expected, rejection=None):
        error = None
        try:
            facts = validate_trace(manifest, trace)
            accepted = True
            need((facts['Pairs'], facts['Extended'], facts['Basic']) == (22, 15, 7), 'control-facts')
        except RuntimeError as failure:
            accepted, error = False, str(failure)
        need(accepted is expected and (rejection is None or error == 'lazy-observer: ' + rejection),
             'control-verdict-' + name + ': ' + str(error))
        records.append(dict(Name=name, Expected=expected, Accepted=accepted, Rejection=error))

    for consumer in ('context', 'fiber'):
        for lazy in (False, True):
            m, t = _synthetic(consumer, lazy)
            test(consumer + ('-lazy' if lazy else '-eager') + '-positive-gdb-control-zero', m, t, True)
    m, t = _synthetic('context', False)
    t['Events'][0]['FPCCR'] = 0x40000000
    test('eager-aspen-lspen-bits-not-interchanged', m, t, False, 'aspen-lspen-policy')
    manifest, trace = _synthetic('context', True)

    def event_case(name, index, changes, reason):
        mutated = deepcopy(trace)
        mutated['Events'][index].update(changes)
        test(name, manifest, mutated, False, reason)

    for name, changes, reason in (
        ('wrong-current', dict(Current=manifest['Workers'][1]), 'current-worker-sequence'),
        ('wrong-handler-origin', dict(XPSR=0x0100000B), 'handler-ipsr-thumb'),
        ('missing-thumb', dict(XPSR=14), 'handler-ipsr-thumb'),
        ('wrong-exc-return', dict(LR=0xFFFFFFFD), 'worker-exc-return'),
        ('wrong-stage-pc-and-payload', dict(PC=0x1010), 'event-anchor'),
        ('wrong-code-payload', dict(CodeBytes='00BF00BF'), 'event-anchor'),
        ('wrong-pre-r3', dict(R3=0), 'raw-r3-stage'),
        ('no-pending-lazy', dict(FPCCR=0xC0000000), 'lspact-transition'),
        ('wrong-fpcar', dict(FPCAR=trace['Events'][0]['FPCAR'] + 8), 'pending-fpcar'),
        ('wrong-cpacr', dict(CPACR=0x00700000), 'cpacr-full'),
        ('wrong-policy', dict(FPCCR=0x40000001), 'aspen-lspen-policy'),
        ('bool-pair', dict(Pair=False), 'event-order'),
        ('bool-raw-word', dict(R3=True), 'event-word-R3'),
        ('padding-crosses-stack', dict(PSP=0x20002F98, R0=0x20002FB8, StackedXPSR=0x01000200), 'full-own-hardware-frame')):
        event_case(name, 0, changes, reason)
    event_case('post-still-pending', 1, dict(FPCCR=0xC0000001, R3=0xC0000001), 'lspact-transition')
    event_case('post-copy-pointer', 1, dict(R0=trace['Events'][1]['PSP'] + 32), 'copy-pointer-stage')
    event_case('pair-psp-changes', 1, dict(PSP=trace['Events'][1]['PSP'] + 8, R0=trace['Events'][1]['PSP'] + 8), 'paired-frame-identity')
    t = deepcopy(trace); t['Events'].pop()
    test('missing-event', manifest, t, False, '44-ordered-events')
    t = deepcopy(trace); t['Error'] = ''
    test('empty-error-is-failure', manifest, t, False, 'trace-pass-identity')
    t = deepcopy(trace); t['Child']['SocketGone'] = 'True'
    test('child-string-bool', manifest, t, False, 'child-closing')
    t = deepcopy(trace); t['InputsAfter'][1]['Sha256'] = 'C' * 64
    test('input-drift', manifest, t, False, 'input-manifest-drift')
    t = deepcopy(trace); t['TargetXML']['core.xml'] = t['TargetXML']['core.xml'].replace('name="PSP"', 'name="MSP"'); t['Registers'].pop('psp')
    test('no-direct-xml-psp', manifest, t, False, 'missing-direct-xml-psp')

    def packet_case(name, command, replacement, reason, response=None, keep_wire=False):
        t = deepcopy(trace)
        index = next(i for i, row in enumerate(t['PacketLog']) if row['Direction'] == 'tx' and row['Payload'] == command)
        t['PacketLog'][index]['Payload'] = replacement
        if not keep_wire:
            t['PacketLog'][index]['WireHex'] = _frame(replacement)
        if response is not None:
            t['PacketLog'][index + 1].update(Payload=response, WireHex=_frame(response))
        test(name, manifest, t, False, reason)

    for command in ('Z0,1000,4', 's', 'G00', 'P0=00000000', 'M20000000,4:00000000',
                    'X20000000,1:x', 'qRcmd,68656c70', 'c1000', 'vCont;s'):
        packet_case('forbidden-' + command, 'qSupported', command, 'tx-not-whitelisted')
    packet_case('wire-payload-disagrees', 'qSupported', 's', 'wire-payload-mismatch', keep_wire=True)
    packet_case('wrong-breakpoint-anchor', 'Z1,1000,4', 'Z1,1002,4', 'hardware-breakpoint-anchor')
    packet_case('wrong-breakpoint-width', 'Z1,1000,4', 'Z1,1000,2', 'hardware-breakpoint-anchor')
    packet_case('unknown-register', 'p0', 'pffff', 'named-core-register-read')
    packet_case('unbounded-memory', 'm20000000,4', 'm20000000,8', 'memory-read-not-whitelisted', '00' * 8)
    packet_case('packet-register-value-disagrees', 'p0', 'p0', 'packet-event-payload-R0', '00000000')
    packet_case('packet-code-disagrees', 'm1000,4', 'm1000,4', 'wire-anchor-payload', '00' * 4)
    packet_case('not-successful-final-exit', 'c', 'c', 'event-breakpoint-stop', 'W00')
    t = deepcopy(trace)
    i = next(i for i, row in enumerate(t['PacketLog']) if row['Direction'] == 'tx' and row['Payload'] == 'p3')
    del t['PacketLog'][i:i + 2]
    test('missing-packet-bound-register', manifest, t, False, 'missing-packet-bound-event-read')
    t = deepcopy(trace); t['PacketLog'][0].pop('WireHex')
    test('missing-transmitted-wire-bytes', manifest, t, False, 'missing-tx-wire')
    t = deepcopy(trace); t['PacketLog'][1].pop('WireHex')
    test('missing-received-wire-bytes', manifest, t, False, 'missing-rx-wire')
    t = deepcopy(trace)
    first_continue = next(i for i, r in enumerate(t['PacketLog']) if r['Direction'] == 'tx' and r['Payload'] == 'c')
    t['PacketLog'][first_continue:first_continue] = [
        dict(Direction='tx', Payload='Z1,1010,4', WireHex=_frame('Z1,1010,4')),
        dict(Direction='rx', Payload='OK', WireHex=_frame('OK'))]
    test('simultaneous-breakpoints', manifest, t, False, 'hardware-breakpoint-alternation')
    need(len(records) == 48 and sum(r['Accepted'] for r in records) == 4, 'literal-control-inventory')
    return dict(Controls=records, Scope='Synthetic packet/snapshot parser controls only; no packets sent, no CPU observations')


def producer_controls(observer_module):
    """Exercise the real producer's snapshot function using a read-only fake RSP."""
    records = []
    for consumer in ('context', 'fiber'):
        for lazy in (False, True):
            manifest, trace = _synthetic(consumer, lazy)

            class FakeRsp:
                def __init__(self, event):
                    self.event, self.gate = event, SimpleNamespace(frame_word=None)
                    self.registers = trace['Registers']

                def register(self, name):
                    need(name in REG_FIELDS, 'producer-register-not-whitelisted')
                    return self.event[REG_FIELDS[name]]

                def memory(self, address, size=4):
                    for stage in ('Pre', 'Post'):
                        anchor = manifest[stage]
                        if address == anchor['Address']:
                            need(size == anchor['Width'], 'producer-code-width')
                            return raw_bytes(anchor['Bytes'], 'producer-code')
                    need(size == 4, 'producer-memory-width')
                    if address in MMIO:
                        value = self.event[MMIO[address]]
                    elif address == manifest['CurrentSlot']:
                        value = self.event['Current']
                    else:
                        need(address == self.event['PSP'] + 28 and self.gate.frame_word == (address, 4),
                             'producer-frame-read')
                        value = self.event['StackedXPSR']
                    return value.to_bytes(4, 'little')

                def word(self, address):
                    return int.from_bytes(self.memory(address), 'little')

            original = trace['Events']
            trace['Events'] = [observer_module.snapshot(FakeRsp(event), manifest, event['Stage'], event['Pair'])
                               for event in original]
            facts = validate_trace(manifest, trace)
            need((facts['Pairs'], facts['Extended'], facts['Basic']) == (22, 15, 7), 'producer-facts')
            records.append(dict(Consumer=consumer, Lazy=lazy, Snapshots=len(trace['Events']), Accepted=True))
    need(len(records) == 4 and sum(r['Snapshots'] for r in records) == 176, 'producer-control-inventory')
    return dict(Controls=records, Scope='Actual observer.snapshot with synthetic read-only RSP; no I/O, packets sent or CPU observations')
