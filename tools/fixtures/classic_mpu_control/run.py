"""Actual classic MPU CONTROL guards and native codegen; never target execution."""
import sys
if not __debug__ or sys.flags.optimize:
    raise SystemExit('Disable Python optimization for classic MPU CONTROL qualification')
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import traceback
from types import SimpleNamespace

MODES = [('O0', False), ('Og', False), ('O2', False), ('Os', False),
         ('O3', False), ('O2', True), ('Os', True)]
PROFILES = [
    ('CM0-v0', 'ARM_CM0_MPU', 'cortex-m0plus', 'ARMV6M', 0, 0, 0, 8),
    ('CM0-v1', 'ARM_CM0_MPU', 'cortex-m0plus', 'ARMV6M', 0, 0, 1, 8),
    ('CM3', 'ARM_CM3_MPU', 'cortex-m3', 'ARMV7M', 3, 0, 1, 8),
    ('CM4-r8', 'ARM_CM4_MPU', 'cortex-m4', 'ARMV7EM', 4, 1, 1, 8),
    ('CM4-r16', 'ARM_CM4_MPU', 'cortex-m4', 'ARMV7EM', 4, 1, 1, 16),
    ('CM7-r8', 'ARM_CM4_MPU', 'cortex-m7', 'ARMV7EM', 7, 1, 1, 8),
    ('CM7-r16', 'ARM_CM4_MPU', 'cortex-m7', 'ARMV7EM', 7, 1, 1, 16),
]
REQUIRED_VALIDATORS = {'fiber_port_pendsv_validate_save_current', 'fiber_port_context_validate_save_current'}
SOURCE_SUFFIXES = {'.c', '.h', '.py', '.ps1', '.ld', '.md'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n', encoding='ascii')


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def close_delimiter(text, start, opening='(', closing=')'):
    """C delimiter scan which does not count comments or string/character contents."""
    require(text[start] == opening, 'Bad delimiter start')
    depth, i = 1, start + 1
    while i < len(text):
        if text.startswith('/*', i):
            end = text.find('*/', i + 2)
            require(end >= 0, 'Unterminated C comment')
            i = end + 2
            continue
        if text.startswith('//', i):
            i = text.find('\n', i + 2)
            require(i >= 0, 'Unterminated C line comment')
            continue
        if text[i] in ('"', "'"):
            quote, i = text[i], i + 1
            while i < len(text) and text[i] != quote:
                i += 2 if text[i] == '\\' else 1
            require(i < len(text), 'Unterminated C literal')
        elif text[i] == opening:
            depth += 1
        elif text[i] == closing:
            depth -= 1
            if not depth:
                return i
        i += 1
    raise RuntimeError('Unterminated C delimiter')


def function(text, name):
    match = re.search(r'(?m)^(?:void|int|uint32_t|uintptr_t|FiberContext\s*\*)\s*' +
                      re.escape(name) + r'\s*\(', text)
    require(match is not None, 'Missing actual definition: ' + name)
    end_args = close_delimiter(text, text.index('(', match.start()))
    brace = end_args + 1
    while text[brace].isspace():
        brace += 1
    require(text[brace] == '{', 'Expected actual body: ' + name)
    end = close_delimiter(text, brace, '{', '}')
    return text[match.start():end + 1]


def conditions(body):
    result = []
    for match in re.finditer(r'\bFIBER_REQUIRE\s*\(', body):
        opening = body.index('(', match.start())
        end = close_delimiter(body, opening)
        args = body[opening + 1:end]
        comma = args.rfind(',')
        require(comma >= 0 and re.fullmatch(r"\s*'[^']'\s*", args[comma + 1:]),
                'Unsupported FIBER_REQUIRE argument shape')
        result.append(args[:comma].strip())
    return result


def project(expression, kind):
    # The isolated guard receives the selected scalar field. Other validated
    # metadata is held at the actual header's initial constants, not a host copy.
    result = re.sub(r'\b(?:ctx|first)->boot\.abi_initial_control\b',
                    'fiber_portINITIAL_CONTROL_UNPRIVILEGED', expression)
    result = re.sub(r'\b(?:ctx|first)->boot\.abi_initial_exc_return\b',
                    'fiber_portINITIAL_EXC_RETURN', result)
    result = re.sub(r'\bboot->abi_initial_control\b', 'value', result)
    result = re.sub(r'\bboot->abi_initial_exc_return\b', 'value', result)
    suffix = 'control' if kind == 'control' else 'exc_return'
    result = re.sub(r'\b(?:ctx|first)->protected_context(?:\.basic\.core)?\.' + suffix + r'\b', 'value', result)
    result = re.sub(r'\b(?:core|image)->' + suffix + r'\b', 'value', result)
    result = result.replace('fiber_port_cpu_read_control()', 'value')
    result = result.replace('fiber_port_cpu_read_ipsr()', 'value')
    result = re.sub(r'\b' + suffix + r'\b', 'value', result)
    return result


def extract_guards(root, profile):
    directory = root / 'fiber/port' / profile[1]
    sources = {name: (directory / name).read_text() for name in ('fiber_port.c', 'fiber_port_boot.c')}
    rows = []

    def add(file, name, kind, allowed, indices=None):
        body = function(sources[file], name)
        if kind == 'control':
            candidates = [x for x in conditions(body) if re.search(r'(?:\bcontrol\b|abi_initial_control|fiber_port_cpu_read_control\()', x)
                          and 'before->control' not in x
                          and not re.search(r'&\s*(?:ctx|first)->protected_context\.control', x)]
        elif kind == 'ipsr':
            candidates = [x for x in conditions(body) if 'fiber_port_cpu_read_ipsr()' in x]
        else:
            candidates = [x for x in conditions(body) if re.search(r'\bexc_return\b|abi_initial_exc_return', x)]
        chosen = list(range(len(candidates))) if indices is None else indices
        require(chosen and max(chosen) < len(candidates), 'Actual guard missing: ' + name + '/' + kind)
        for index in chosen:
            rows.append(dict(name='%s/%s/%s/%d' % (file, name, kind, index),
                             file=file, function=name, kind=kind, condition=candidates[index],
                             expression=project(candidates[index], kind), allowed=allowed))

    add('fiber_port_boot.c', 'fiber_port_context_fast_check', 'control', [3])
    add('fiber_port_boot.c', 'fiber_port_context_initial_image_check' if profile[4] == 0
        else 'fiber_port_context_init', 'control', [3])
    if profile[5]:
        add('fiber_port_boot.c', 'fiber_port_context_validate_initial_restore', 'control', [3])
        add('fiber_port_boot.c', 'fiber_port_context_validate_restore', 'control', [1, 3], [0])
        add('fiber_port_boot.c', 'fiber_port_context_validate_restore', 'control', [1], [1])
        add('fiber_port_boot.c', 'fiber_port_context_validate_restore', 'eret', [0xFFFFFFFD], [0])
        add('fiber_port_boot.c', 'fiber_port_context_validate_restore', 'eret', [0xFFFFFFED], [1])
        add('fiber_port_boot.c', 'fiber_port_context_validate_running_svc', 'control', [1])
        add('fiber_port_boot.c', 'fiber_port_context_validate_running_svc', 'eret', [0xFFFFFFFD, 0xFFFFFFED])
    else:
        add('fiber_port_boot.c', 'fiber_port_context_validate_restore', 'control', [1, 3])
        add('fiber_port_boot.c', 'fiber_port_context_validate_running_frame', 'control', [1, 3])
        add('fiber_port_boot.c', 'fiber_port_context_validate_restore', 'eret', [0xFFFFFFFD])
        if profile[4] == 0:
            add('fiber_port_boot.c', 'fiber_port_context_validate_initial_restore', 'control', [3])
        else:
            add('fiber_port.c', 'fiber_port_runtime_select_first', 'control', [3])
            add('fiber_port.c', 'fiber_port_runtime_start_first', 'control', [3])
    add('fiber_port.c', 'fiber_port_pendsv_validate_save_current', 'control', [1])
    add('fiber_port.c', 'fiber_port_pendsv_validate_save_current', 'ipsr', [14])
    add('fiber_port.c', 'fiber_port_pendsv_validate_save_current', 'eret',
        [0xFFFFFFFD, 0xFFFFFFED] if profile[5] else [0xFFFFFFFD])
    for name in ('fiber_port_scheduler_pick_next_from_pendsv', 'fiber_port_mpu_switch_to_context'):
        add('fiber_port.c', name, 'control', [1, 5] if profile[5] else [1])
        add('fiber_port.c', name, 'ipsr', [14])
    require(len(rows) == (16 if profile[5] else 13 if profile[4] == 0 else 14),
            'Exact production CONTROL/EXC_RETURN/IPSR guard inventory changed')
    return rows


def normalized(mnemonic, operands):
    mnemonic = re.sub(r'\.[wn]$', '', mnemonic.lower())
    operands = operands.lower().replace(' ', '').replace('\t', '')
    for alias, register in (('sb', 'r9'), ('sl', 'r10'), ('fp', 'r11'), ('ip', 'r12')):
        operands = re.sub(r'\b' + alias + r'\b', register, operands)
    return mnemonic, operands


class Native:
    """Executable transfers use section/entry/extent identities, never name keys."""
    def __init__(self, elf, dis):
        self.elf, self.functions, self.instructions, self.relocations = elf, {}, {}, {}
        self.coverage = {}
        for f in elf.functions:
            key = f['section'], f['value'] & ~1, f['size']
            self.functions.setdefault(key, set()).add(f['name'])
        for r in elf.relocations:
            self.relocations.setdefault((r['section'], r['offset']), []).append(r)
        section = None
        for line in dis.splitlines():
            header = re.match(r'Disassembly of section (.+):$', line)
            if header:
                matches = [s['index'] for s in elf.sections if s['name'] == header[1]]
                require(len(matches) == 1, 'Ambiguous native section')
                section = matches[0]
            row = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+){1,2})\s*([a-z][a-z0-9.]*)\s*(.*)', line)
            if row and section is not None:
                address = int(row[1], 16)
                operands = re.split(r'\s+@|\s+[0-9a-f]+:\s+R_ARM_', row[4])[0].strip()
                key = section, address
                require(key not in self.instructions, 'Duplicate instruction address')
                encoded = b''.join(int(part, 16).to_bytes(2, 'little') for part in row[2].split())
                require(elf.payload(elf.sections[section])[address:address + len(encoded)] == encoded,
                        'Decoded instruction bytes disagree with actual ELF')
                self.instructions[key] = dict(section=section, address=address, size=2 * len(row[2].split()),
                    mnemonic=normalized(row[3], operands)[0], operands=normalized(row[3], operands)[1])

    def named(self, name):
        return {key for key, names in self.functions.items() if name in names}

    def unique(self, name):
        keys = self.named(name)
        require(len(keys) == 1, 'Expected one actual native entry: ' + name)
        return next(iter(keys))

    def body(self, key):
        return [row for (section, address), row in sorted(self.instructions.items())
                if section == key[0] and key[1] <= address < key[1] + key[2]]

    def name(self, key):
        return sorted(self.functions[key])[0]

    def describe(self, key):
        result = dict(Section=key[0], Entry=key[1], Extent=key[2], Names=sorted(self.functions[key]))
        if key in self.coverage:
            result.update(self.coverage[key])
        return result

    def target(self, row):
        rels = self.relocations.get((row['section'], row['address']), [])
        if rels:
            require(len(rels) == 1 and rels[0]['type'] in {10, 30, 51, 102, 103}, 'Unsupported executable relocation')
            rel, addend = rels[0], 0
            payload = self.elf.payload(self.elf.sections[row['section']])
            upper = struct.unpack_from('<H', payload, row['address'])[0]
            if rel['type'] in {102, 103}:
                bits = 12 if rel['type'] == 102 else 9
                value = (upper & (0x7FF if rel['type'] == 102 else 0xFF)) << 1
            else:
                lower = struct.unpack_from('<H', payload, row['address'] + 2)[0]
                sign, j1, j2 = (upper >> 10) & 1, (lower >> 13) & 1, (lower >> 11) & 1
                if rel['type'] == 51:
                    bits, value = 21, (sign << 20) | (j2 << 19) | (j1 << 18) | ((upper & 0x3F) << 12) | ((lower & 0x7FF) << 1)
                else:
                    bits, value = 25, (sign << 24) | ((1 ^ j1 ^ sign) << 23) | ((1 ^ j2 ^ sign) << 22) | ((upper & 0x3FF) << 12) | ((lower & 0x7FF) << 1)
            addend = value - (1 << bits) if value & (1 << (bits - 1)) else value
            symbol = rel['symbol']
            if symbol['section'] == 0:
                require(addend + 4 == 0 and symbol['name'], 'Non-entry external executable target')
                return None, symbol['name']
            return (symbol['section'], (symbol['value'] & ~1) + addend + 4), None
        text = row['operands'].split(',')[-1]
        match = re.match(r'([0-9a-f]+)<', text)
        require(match is not None, 'Unsupported indirect executable transfer')
        return (row['section'], int(match[1], 16)), None

    def entry(self, target):
        keys = {key for key in self.functions if key[:2] == target}
        require(len(keys) == 1, 'Non-entry executable target')
        return next(iter(keys))

    @staticmethod
    def transfer(row):
        mnemonic, operands = row['mnemonic'], row['operands']
        condition = r'(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)?'
        if re.fullmatch(r'(?:bx|blx)' + condition, mnemonic) or mnemonic in {'tbb', 'tbh'}:
            require(re.fullmatch('bx' + condition, mnemonic) and operands == 'lr', 'Unsupported indirect executable transfer')
            return 'return'
        if mnemonic == 'bl':
            return 'call'
        if re.fullmatch(r'b(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)?', mnemonic) or mnemonic in {'cbz', 'cbnz'}:
            return 'branch'
        # Ordinary compiler epilogues are returns; other computed PC writes
        # cannot silently become unobserved cross-function transfers.
        if re.match(r'pc,', operands) or ('pc' in operands and re.match(r'(?:pop|ldm)', mnemonic)):
            require((re.fullmatch('pop' + condition, mnemonic) or
                     re.fullmatch('ldmia' + condition, mnemonic) and operands.startswith('sp!,')) and
                    (operands.endswith(',pc}') or operands == '{pc}'), 'Unsupported computed PC write')
            return 'return'
        require(not mnemonic.startswith('bl') or mnemonic in {'bls'}, 'Unsupported conditional call')
        return None

    def prefix(self, allowed_external=()):
        key = self.unique('PendSV_Handler')
        rows = self.body(key)
        captures = [i for i, r in enumerate(rows) if r['mnemonic'] == 'mrs' and r['operands'].endswith(',control')]
        require(captures, 'Actual PendSV raw CONTROL capture missing')
        index = captures[0]
        roots, external, address = set(), set(), key[1]
        for row in rows[:index]:
            require(row['address'] == address, 'Undecoded pre-MRS instruction')
            address += row['size']
            require(not row['mnemonic'].startswith('v'), 'FP instruction before raw CONTROL capture')
            kind = self.transfer(row)
            if not kind:
                continue
            require(kind != 'return', 'Unsupported pre-MRS return')
            target, imported = self.target(row)
            if imported:
                require(imported in {'fiber_panic'} | set(allowed_external), 'Unqualified external pre-MRS call: ' + imported)
                external.add(imported)
            elif kind == 'call':
                roots.add(self.entry(target))
            elif target[0] == key[0] and key[1] <= target[1] < rows[index]['address']:
                require(target in self.instructions, 'Undecoded pre-MRS branch target')
            else:
                # The only admitted jump out of the prefix is the exact local
                # terminal panic stub, not a path that skips the CONTROL read.
                require(target[0] == key[0], 'Unsupported pre-MRS branch')
                stub = [self.instructions.get((target[0], target[1]))]
                for _ in range(2):
                    previous = stub[-1]
                    stub.append(self.instructions.get((target[0], previous['address'] + previous['size'])) if previous else None)
                require(all(stub) and stub[0]['mnemonic'] == 'movs' and re.fullmatch(r'r0,#\d+', stub[0]['operands']) and
                        stub[1]['mnemonic'] == 'bl' and self.target(stub[1]) == (None, 'fiber_panic') and
                        stub[2]['mnemonic'] == 'b' and self.target(stub[2]) == (target, None), 'Unsupported pre-MRS branch')
                external.add('fiber_panic')
        require(rows[index]['address'] == address, 'Undecoded CONTROL capture prefix')
        require(roots, 'Actual pre-MRS prefix calls no native helper')
        return roots, external, rows, index

    def flow(self, key, allowed_external=()):
        """Overapproximate every supported successor; missing reachable bytes fail.

        No flags are assumed true. Conditional transfers retain their false
        edge. Only an unconditional return/tail branch or known noreturn panic
        suppresses fallthrough, so data/pools are allowed only off this CFG.
        """
        pending, visited, called, external = [(key[1], 0)], {}, set(), set()
        while pending:
            address, it_left = pending.pop()
            if address in visited:
                require(visited[address] == it_left, 'Inconsistent native IT state')
                continue
            row = self.instructions.get((key[0], address))
            require(row is not None and key[1] <= address and address + row['size'] <= key[1] + key[2],
                    'Reachable undecoded native bytes: ' + self.name(key))
            visited[address] = it_left
            mnemonic, operands = row['mnemonic'], row['operands']
            next_it = max(it_left - 1, 0)
            predicated = it_left > 0
            kind = self.transfer(row)
            fallthrough = True
            if re.fullmatch(r'it[te]{0,3}', mnemonic):
                half = struct.unpack_from('<H', self.elf.payload(self.elf.sections[key[0]]), address)[0]
                mask = half & 15
                require(not it_left and half & 0xFF00 == 0xBF00 and mask and ((half >> 4) & 15) < 14,
                        'Unsupported native IT instruction')
                next_it = 4 - ((mask & -mask).bit_length() - 1)
                require(next_it == len(mnemonic) - 1, 'Native IT length disagrees with bytes')
            elif kind:
                require(it_left <= 1, 'Unsupported transfer inside native IT block')
                if kind == 'return':
                    conditional_return = mnemonic not in {'bx', 'pop', 'ldmia'}
                    fallthrough = predicated or conditional_return
                else:
                    target, imported = self.target(row)
                    conditional_branch = kind == 'branch' and mnemonic != 'b'
                    conditional = predicated or conditional_branch
                    if imported:
                        require(imported in {'fiber_panic'} | set(allowed_external),
                                'Unqualified external pre-MRS call: ' + imported)
                        external.add(imported)
                    elif kind == 'branch' and target[0] == key[0] and key[1] <= target[1] < key[1] + key[2]:
                        pending.append((target[1], 0))
                    else:
                        called.add(self.entry(target))
                    if kind == 'branch':
                        fallthrough = conditional
                    elif imported == 'fiber_panic' and not conditional:
                        fallthrough = False
            else:
                require(mnemonic not in {'udf', 'svc', 'bkpt'}, 'Unsupported terminating native instruction')
            if fallthrough:
                pending.append((address + row['size'], next_it))

        covered = set()
        for address in visited:
            row = self.instructions[(key[0], address)]
            byte_range = set(range(address, address + row['size']))
            require(not covered & byte_range, 'Overlapping reachable native instructions')
            covered.update(byte_range)
        missing, spans = sorted(set(range(key[1], key[1] + key[2])) - covered), []
        for address in missing:
            if spans and spans[-1][1] == address:
                spans[-1][1] += 1
            else:
                spans.append([address, address + 1])
        self.coverage[key] = dict(ReachableInstructionAddresses=sorted(visited), ReachableBytes=len(covered),
                                  ProvenUnreachableByteSpans=spans)
        return called, external

    def closure(self, roots, allowed_external=()):
        reached, work, external = set(roots), list(roots), set()
        while work:
            called, imported = self.flow(work.pop(), allowed_external)
            external.update(imported)
            for key in called - reached:
                reached.add(key)
                work.append(key)
        return reached, external


def call_closure(elf, disassembly, allowed_external=()):
    model = Native(elf, disassembly)
    roots, terminal, _, _ = model.prefix(allowed_external)
    reached, external = model.closure(roots, allowed_external)
    names = sorted({name for key in reached for name in model.functions[key]})
    return model, reached, names, sorted(external | terminal)


def audit_before_mrs(elf, dis, profile):
    model, reached, reachable, external = call_closure(elf, dis)
    require(REQUIRED_VALIDATORS <= set(reachable), 'Actual prefix does not reach mandatory validators')
    for key in sorted(reached):
        require(not any(r['mnemonic'].startswith('v') for r in model.body(key)),
                'FP instruction in actual pre-MRS success closure: ' + model.name(key))
    roots, _, rows, index = model.prefix()
    expected = [('mrs', 'r2,control'), ('mov', 'r4,lr'), ('stmia', 'r3!,{r0,r2,r4}')]
    if profile[4] == 3:
        expected = [('mrs', 'r2,control'), ('stmia', 'r3!,{r2,r4,r5,r6,r7,r8,r9,r10,r11,lr}')]
    if profile[5]:
        expected = [('mrs', 'r3,control'), ('add', 'r0,r0,#32'), ('tst', 'lr,#16'), ('ittt', 'eq'),
                    ('vstmiaeq', 'r1!,{s16-s31}'), ('vldmiaeq', 'r0,{s0-s16}'), ('vstmiaeq', 'r1!,{s0-s16}'),
                    ('sub', 'r0,r0,#32'), ('stmia', 'r1!,{r3,r4,r5,r6,r7,r8,r9,r10,r11,lr}')]
    actual = [(r['mnemonic'], r['operands']) for r in rows[index:index + len(expected)]]
    require(actual == expected, 'Raw CONTROL capture/store sequence changed')
    for before, after in zip(rows[index:index + len(expected)], rows[index + 1:index + len(expected)]):
        require(before['address'] + before['size'] == after['address'], 'Undecoded CONTROL capture/store instruction')
    if profile[4] == 0:
        for name in ('fiber_port_restore_first_context_from_svc', 'PendSV_Handler'):
            actual = '\n'.join(r['mnemonic'] + ' ' + r['operands'] for r in model.body(model.unique(name)))
            require(re.search(r'(?s)msr control,r3.*?mrs r4,control\nmovs r6,#1\ncmp r4,r6\nbne', actual),
                    'CM0 actual Handler CONTROL readback is not exactly 1: ' + name)
    details = dict(Roots=[model.describe(k) for k in sorted(roots)],
                   Functions=[model.describe(k) for k in sorted(reached)])
    return reachable, external, details


def require_rejection(callback, diagnostic):
    try:
        callback()
    except RuntimeError as error:
        require(str(error) == diagnostic, 'Counterexample rejected for an unrelated reason: ' + str(error))
        return str(error)
    else:
        raise RuntimeError('Compiled counterexample accepted: ' + diagnostic)


class Suite:
    def __init__(self, args):
        self.a, self.build = args, Path(args.build).resolve()
        require(not self.build.exists(), 'Use a fresh evidence root: ' + str(self.build))
        self.build.mkdir(parents=True)
        self.live = Path(args.repo).resolve()
        self.root, self.cmsis = self.build / 'snapshot/repo', self.build / 'snapshot/cmsis'
        self.gcc, self.host = Path(args.gcc).resolve(), Path(args.host_gcc).resolve()
        self.tools, self.inputs, self.rows, self.controls, self.commands = {}, {}, [], [], []
        self.assurance = []
        self.report = dict(Verdict='FAIL', CompleteSuite=False, CPUExecuted=False,
                           Scope='Classic MPU CONTROL guard projections, actual ARM codegen and private cohort links; no exception execution',
                           InputDrift=[], Cases=self.rows, Controls=self.controls, Errors=[])
        write_json(self.build / 'results.json', self.report)

    def run(self, args, may_fail=False):
        args = [str(x) for x in args]
        index = len(self.commands)
        result = subprocess.run(args, text=True, capture_output=True, timeout=180,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        log = self.build / ('command-%05d.json' % index)
        write_json(log, dict(Command=args, Exit=result.returncode, Stdout=result.stdout, Stderr=result.stderr))
        self.commands.append(str(log))
        require(may_fail or result.returncode == 0, 'Command failed: ' + str(log))
        return result

    def snapshot(self):
        fixture = self.live / 'tools/fixtures/classic_mpu_control'
        files = {p for directory in (self.live, self.live / 'context', self.live / 'fiber', self.live / 'fiber/port')
                 for p in directory.iterdir() if p.is_file() and p.suffix == '.h'}
        for name in {p[1] for p in PROFILES}:
            files.update(p for p in (self.live / 'fiber/port' / name).iterdir()
                         if p.suffix in {'.c', '.h'} or p.name == 'FREERTOS_PARITY.md')
        files.update(p for p in fixture.iterdir() if p.is_file() and p.suffix in SOURCE_SUFFIXES)
        files.update(self.live / p for p in ('tools/test_classic_mpu_control.ps1', 'tools/compile_matrix.ps1',
                     'tools/fixtures/sensitive_port_closure/run.py', 'tools/fixtures/sensitive_port_closure/active_control.c',
                     'tools/fixtures/context_facade/run.py'))
        for path in sorted(files):
            self.capture(path, self.root / path.relative_to(self.live))
        external = Path(self.a.cmsis).resolve()
        for path in sorted(external.rglob('*.h')):
            self.capture(path, self.cmsis / path.relative_to(external))
        python_image = Path(sys.executable).resolve()
        try:
            sha(python_image)
        except OSError:
            python_image = Path(sys.base_prefix) / 'python.exe'
        self.report['PythonImage'] = str(python_image)
        for path in (self.gcc, self.host, python_image):
            self.inputs[str(path)] = sha(path)
        for name in ('objdump', 'readelf', 'nm', 'ar'):
            path = self.gcc.parent / ('arm-none-eabi-' + name + '.exe')
            require(path.is_file(), 'Required native binutils missing: ' + str(path))
            self.tools[name] = path
            self.inputs[str(path)] = sha(path)
        for option in ('cc1', 'lto1', 'as', 'ld', 'lto-wrapper'):
            value = self.run([self.gcc, '-print-prog-name=' + option]).stdout.strip()
            path = Path(value).resolve()
            require(path.is_file(), 'Cannot resolve actual compiler delegate: ' + option)
            self.inputs[str(path)] = sha(path)
            self.tools[option] = path
        driver = self.run([self.gcc, '-###', '-flto', '-nostdlib', '-r', '-x', 'c', fixture / 'cohort.c']).stderr
        matches = re.findall(r'(?:^|\s)-plugin\s+(?:"([^"]+)"|(\S+))', driver)
        require(len(matches) == 1, 'Expected one driver-selected LTO plugin')
        plugin = Path(next(part for part in matches[0] if part)).resolve()
        queried = Path(self.run([self.gcc, '-print-file-name=' + plugin.name]).stdout.strip()).resolve()
        require(plugin == queried and plugin.is_file(), 'Driver/query LTO plugin mismatch')
        self.inputs[str(plugin)] = sha(plugin)
        self.tools['plugin'] = plugin
        self.run([self.gcc, '--version'])
        self.run([self.host, '--version'])
        self.closure = module(self.root / 'tools/fixtures/sensitive_port_closure/run.py', 'control_closure')
        self.link_classifier = module(self.root / 'tools/fixtures/context_facade/run.py', 'control_facade')
        self.fixture = self.root / 'tools/fixtures/classic_mpu_control'
        write_json(self.build / 'inputs-before.json', self.inputs)

    def capture(self, source, target):
        value = sha(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        require(sha(target) == value == sha(source), 'Input capture drift: ' + str(source))
        self.inputs[str(source)] = value
        self.inputs[str(target)] = value

    def check_inputs(self):
        after = {p: sha(p) if Path(p).is_file() else None for p in self.inputs}
        require(all(self.inputs[p] == after[p] for p in self.inputs), 'Closing input drift')
        return after

    def copy_closing_control(self):
        directory = self.build / 'copied-classifier-control'
        source = self.root / 'tools/fixtures/sensitive_port_closure/run.py'
        suffix = b'\n# intentional late copied-input drift\n'
        before = sha(source)
        record = dict(Kind='COPIED-CLASSIFIER-CLOSING', CopyEnrolledBeforeImport=True,
                      Positive='ACCEPT', Negative='REJECT', Diagnostic='Closing input drift',
                      BeforeSHA256=before, AfterSHA256=hashlib.sha256(source.read_bytes() + suffix).hexdigest().upper())
        self.assurance.append(record)
        for poisoned in (False, True):
            args = dict(vars(self.a), build=str(directory / ('drift' if poisoned else 'stable')))
            probe = Suite(SimpleNamespace(**args))
            # Exercise the actual finalizer with genuine parent observations,
            # explicitly as a closing-only control, never a second compile run.
            probe.report['Scope'] = 'ACTUAL FINALIZER CONTROL ONLY; observations from parent ' + str(self.build)
            probe.inputs, probe.tools = dict(self.inputs), dict(self.tools)
            probe.rows, probe.controls, probe.assurance = list(self.rows), list(self.controls), list(self.assurance)
            probe.report['Cases'], probe.report['Controls'] = probe.rows, probe.controls
            copied = probe.build / 'classifier.py'
            probe.capture(source, copied)
            require(probe.inputs[str(copied)] == before, 'Classifier copy was not enrolled before import')
            module(copied, 'control_copy_closing_' + str(poisoned))
            if poisoned:
                copied.write_bytes(copied.read_bytes() + suffix)
                require_rejection(lambda: probe.finish(True), 'Closing input drift')
                probe.finish(False, 'EXPECTED negative control: late copied-classifier input drift')
                require(probe.report['Verdict'] == 'FAIL' and probe.report['InputDrift'] == [str(copied)],
                        'Actual finalizer did not persist its intended copied-input drift failure')
            else:
                require(probe.finish(True), 'Actual finalizer rejected the unchanged classifier copy')
        write_json(directory / 'control.json', record)

    def flags(self, p, opt='O2', lto=False, raw=False, root=None):
        root = self.root if root is None else root
        result = ['-mcpu=' + p[2], '-mthumb', '-' + opt, '-std=gnu11', '-ffreestanding',
                  '-ffunction-sections', '-fdata-sections', '-fno-common', '-Wall', '-Wextra', '-Werror',
                  '-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_PORT_' + p[3] + '=1',
                  '-DCONTROL_CORE=' + str(p[4]), '-DCONTROL_FP=' + str(p[5]), '-DCONTROL_VTOR=' + str(p[6]),
                  '-DFIBER_PORT_CM4_MPU_TOTAL_REGIONS=' + str(p[7]),
                  '-I' + str(self.fixture), '-I' + str(root / 'fiber/port' / p[1]),
                  '-I' + str(root), '-I' + str(root / 'fiber'), '-I' + str(root / 'fiber/port'),
                  '-I' + str(self.cmsis), '-include', str(self.fixture / 'main.h')]
        result += ['-mfpu=' + ('fpv5-d16' if p[4] == 7 else 'fpv4-sp-d16'), '-mfloat-abi=hard'] if p[5] else ['-mfloat-abi=soft']
        if lto:
            result += ['-flto', '-fno-fat-lto-objects']
        if raw:
            result += list(self.closure.BUNDLES['raw'])
        return result

    def compile(self, source, output, flags):
        self.compiler_dependencies(self.gcc, source, output.with_suffix('.d'), flags)
        self.run([self.gcc, *flags, '-MD', '-MF', output.with_suffix('.d'), '-c', source, '-o', output])
        return output

    def compiler_dependencies(self, compiler, source, dep, flags):
        self.run([compiler, *flags, '-M', '-MF', dep, source])
        text = dep.read_text().replace('\\\n', ' ')
        require(': ' in text, 'Unrecognized compiler dependency format')
        for token in re.findall(r'(?:\\ |[^\s])+', text.split(': ', 1)[1]):
            path = Path(token.replace('\\ ', ' ')).resolve()
            require(path.is_file(), 'Actual compiler dependency missing: ' + str(path))
            value = sha(path)
            require(self.inputs.setdefault(str(path), value) == value, 'Actual dependency drift: ' + str(path))

    def native(self, objects, output, flags, lto):
        if lto:
            for obj in objects:
                sections = self.closure.Elf(obj).sections
                require(any(s['name'].startswith('.gnu.lto_') for s in sections), 'Expected actual slim LTO input')
                require(not any(s['flags'] & 4 and s['size'] for s in sections), 'LTO input has native fallback code')
        # Coverage generation has already happened in each TU; do not ask the
        # link driver to inject libgcov into a freestanding relocatable link.
        flags = [f for f in flags if f not in self.closure.FAMILIES['coverage']]
        self.run([self.gcc, *flags, '-nostdlib', '-r', *(['-flinker-output=nolto-rel', '-save-temps=obj'] if lto else []),
                  *objects, '-o', output])
        elf = self.closure.Elf(output)
        elf.native()
        dis = self.run([self.tools['objdump'], '-drwC', output]).stdout
        output.with_suffix('.dis').write_text(dis, encoding='ascii')
        return elf, dis

    def host_guards(self, p):
        rows = extract_guards(self.root, p)
        directory = self.build / (p[0] + '-guards')
        directory.mkdir()
        target = directory / 'projected.c'
        text = '#include "fiber_portmacro.h"\n'
        for i, row in enumerate(rows):
            text += 'int guard_%d(uint32_t value) { return !!(%s); }\n' % (i, row['expression'])
        target.write_text(text, encoding='ascii')
        pre = self.run([self.gcc, *self.flags(p), '-E', '-P', target]).stdout
        (directory / 'actual-preprocessed.c').write_text(pre, encoding='ascii')
        header = ''
        for i in range(len(rows)):
            header += function(pre, 'guard_' + str(i)) + '\n'
        header += 'typedef struct { const char *name; int (*call)(uint32_t); uint32_t allowed[2]; unsigned allowed_count; } Guard;\n'
        header += 'static const Guard guards[] = {\n'
        for i, row in enumerate(rows):
            values = ','.join('UINT32_C(0x%08X)' % x for x in row['allowed'])
            header += '{"%s", guard_%d, {%s}, %d},\n' % (row['name'], i, values, len(row['allowed']))
        header += '};\n'
        (directory / 'guards.h').write_text(header, encoding='ascii')
        write_json(directory / 'extraction.json', rows)
        for opt in ('O0', 'Og', 'O2', 'Os', 'O3'):
            exe = directory / (opt + '.exe')
            flags = ['-' + opt, '-std=c11', '-Wall', '-Wextra', '-Werror', '-I' + str(directory)]
            self.compiler_dependencies(self.host, self.fixture / 'host.c', exe.with_suffix('.d'), flags)
            self.run([self.host, *flags, self.fixture / 'host.c', '-o', exe])
            result = self.run([exe])
            require(re.fullmatch(r'HOST-PASS checks=' + str(459 * len(rows)) + ' guards=' + str(len(rows)) + r'\n', result.stdout)
                    and not result.stderr, 'Unexpected host truth-table result')
            self.rows.append(dict(Kind='HOST-GUARDS', Profile=p[0], Optimization=opt,
                                  Checks=int(re.search(r'checks=(\d+)', result.stdout)[1]), Guards=len(rows)))
        # Compile changes to the actual selected scalar guard, never a hand-
        # maintained replacement implementation. Each must fail its numeric oracle.
        selected = [i for i, r in enumerate(rows) if r['kind'] == 'control' and r['allowed'] in ([1], [1, 3], [1, 5], [3])]
        for i in selected:
            row = rows[i]
            body = function(pre, 'guard_' + str(i))
            expression = body[body.index('return') + 6:body.rfind(';')].strip()
            if row['allowed'] == [3]:
                changed = '((value == 1u) || (value == 3u))'
            elif row['allowed'] == [1, 5]:
                changed = '((value & 3u) == 1u)'
            else:
                changed = '(value == %du)' % (7 if p[5] and row['allowed'] == [1] else 3)
            mutation = header.replace(body, body.replace(expression, changed), 1)
            require(mutation != header, 'Guard mutation did not change actual projected body')
            case = directory / ('mutant-%02d' % i)
            case.mkdir()
            (case / 'guards.h').write_text(mutation, encoding='ascii')
            exe = case / 'control.exe'
            flags = ['-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', '-I' + str(case)]
            self.compiler_dependencies(self.host, self.fixture / 'host.c', exe.with_suffix('.d'), flags)
            self.run([self.host, *flags, self.fixture / 'host.c', '-o', exe])
            result = self.run([exe], True)
            require(result.returncode == 1 and result.stdout == '' and re.fullmatch(
                'CONTROL-MISMATCH ' + re.escape(row['name']) + r' value=[0-9A-F]{8} expected=[01] actual=[01]\n', result.stderr),
                'Actual guard mutation did not fail for its exact intended witness')
            self.controls.append(dict(Kind='COMPILED-GUARD-MUTATION', Profile=p[0], Guard=row['name'], Diagnostic=result.stderr.strip()))

    def codegen(self, p, opt, lto, unsectioned=False):
        label = '%s-%s-%s%s' % (p[0], opt, 'LTO' if lto else 'normal', '-unsectioned' if unsectioned else '')
        directory = self.build / label
        directory.mkdir()
        flags = self.flags(p, opt, lto, True)
        if unsectioned:
            flags = [x for x in flags if x != '-ffunction-sections'] + ['-fno-function-sections']
        objects = [self.compile(self.root / 'fiber/port' / p[1] / name, directory / (name + '.o'), flags)
                   for name in ('fiber_port.c', 'fiber_port_boot.c')]
        elf, dis = self.native(objects, directory / 'actual-native.o', flags, lto)
        result = self.closure.inspect(directory / 'actual-native.o', dis)
        write_json(directory / 'closure.json', result)
        require(not result['defects'], 'Actual raw classic MPU closure leaked hooks: ' + label)
        reachable, external, extents = audit_before_mrs(elf, dis, p)
        write_json(directory / 'pre-mrs-extents.json', extents)
        active = self.compile(self.root / 'tools/fixtures/sensitive_port_closure/active_control.c', directory / 'active.o', flags)
        _, active_dis = self.native([active], directory / 'active-native.o', flags, lto)
        active_result = self.closure.inspect(directory / 'active-native.o', active_dis,
            {'closure_sensitive_control'}, True, {'closure_unannotated_control'})
        observed = {x['family'] for x in active_result['hooks'] if x['function'] == 'closure_unannotated_control'}
        require(set(self.closure.FAMILIES) <= observed, 'Raw compiler family inactive: ' + label + repr(observed))
        self.controls.append(dict(Kind='COMPILED-RAW-FAMILIES', Case=label, Observed=sorted(observed)))
        self.rows.append(dict(Kind='ARM-CODEGEN', Profile=p[0], Optimization=opt, NativeLTO=lto,
                              Unsectioned=unsectioned, PreMRSClosure=reachable, ExternalTerminal=external))
        if opt == 'O2' and not unsectioned:
            self.cohorts(p, directory, opt, lto)
            self.codegen_controls(p, directory, flags, lto, objects)

    def codegen_controls(self, p, directory, flags, lto, objects):
        changed = directory / 'annotation-removal'
        changed.mkdir()
        removed = [self.compile(self.root / 'fiber/port' / p[1] / name, changed / (name + '.o'),
                               flags + list(self.closure.ANNOTATION_REMOVAL))
                   for name in ('fiber_port.c', 'fiber_port_boot.c')]
        elf, dis = self.native(removed, changed / 'native.o', flags, lto)
        permitted = {s['name'] for s in elf.symbols if s['section'] == 0 and self.closure.family(s['name'])}
        model = Native(elf, dis)
        roots, _, _, _ = model.prefix(permitted)
        validator = model.unique('fiber_port_pendsv_validate_save_current')
        require(validator in roots, 'Annotation control lost its actual pre-MRS validator entry')
        direct_hook = any(model.transfer(row) == 'call' and model.target(row)[1] is not None and
                          self.closure.family(model.target(row)[1]) == 'instrument'
                          for row in model.body(validator))
        classification = self.closure.inspect(changed / 'native.o', dis)
        write_json(changed / 'classification.json', classification)
        require(direct_hook and any(h['family'] == 'instrument' and h['function'] in model.functions[validator]
                                   for h in classification['hooks']),
                'Actual annotation removal did not expose direct instrumentation in pre-MRS validator entry')
        self.controls.append(dict(Kind='COMPILED-PRE-MRS-ANNOTATION-REMOVAL', Profile=p[0], NativeLTO=lto))
        if p[4] == 0:
            changed = directory / 'old-handler-readback'
            changed.mkdir()
            source = self.root / 'fiber/port' / p[1] / 'fiber_port.c'
            text = source.read_text()
            pattern = r'("movs\s+r6,\s*#)1(\s*\\n")'
            mutation, count = re.subn(pattern, r'\g<1>3\2', text)
            require(count == 2, 'Expected exact two actual CM0 readback constants')
            mutant = changed / 'port.c'
            mutant.write_text(mutation, encoding='ascii')
            obj = self.compile(mutant, changed / 'port.o', flags)
            elf, bad = self.native([obj, objects[1]], changed / 'native.o', flags, lto)
            require(len(re.findall(r'(?is)msr\s+CONTROL,\s*r3.*?mrs\s+r4,\s*CONTROL.*?movs\s+r6,\s*#3\b', bad)) == 2,
                    'Actual old CM0 readback control did not compile into its intended two bad guards')
            require_rejection(lambda: audit_before_mrs(elf, bad, p),
                'CM0 actual Handler CONTROL readback is not exactly 1: fiber_port_restore_first_context_from_svc')
            self.controls.append(dict(Kind='COMPILED-OLD-CM0-READBACK', Profile=p[0], NativeLTO=lto,
                                      ExpectedBadReadbacks=2))
        if p[5]:
            source = self.root / 'fiber/port' / p[1] / 'fiber_port.c'
            boot = self.root / 'fiber/port' / p[1] / 'fiber_port_boot.c'
            for label, selected in (('before-mrs', source), ('transitive-helper', boot)):
                changed = directory / ('vfp-poison-' + label)
                changed.mkdir()
                text = selected.read_text()
                if label == 'before-mrs':
                    body = function(text, 'PendSV_Handler')
                    mutation, count = re.subn(r'(?m)^(\s*)("mrs\s+r3,\s*control\s*\\n")',
                        r'\1"vmov s0, s0 \\n"\n\1\2', body)
                    require(count == 1, 'Raw MRS poison anchor changed')
                    text = text.replace(body, mutation, 1)
                else:
                    body = function(text, 'fiber_port_hash32_accum')
                    text = text.replace(body, body.replace('{', '{\n __asm volatile("vmov s0, s0");', 1), 1)
                mutant = changed / selected.name
                mutant.write_text(text, encoding='ascii')
                obj = self.compile(mutant, changed / 'mutant.o', flags)
                group = [obj, objects[1]] if selected == source else [objects[0], obj]
                elf, bad = self.native(group, changed / 'native.o', flags, lto)
                if label == 'before-mrs':
                    body = re.search(r'(?ms)^[0-9a-f]+ <PendSV_Handler>:\n(.*?)(?=^[0-9a-f]+ <|\Z)', bad)[1]
                    prefix = body[:re.search(r'\bmrs\s+r3,\s*CONTROL\b', body, re.I).start()]
                    require(re.search(r'\bvmov(?:\.f32)?\s+s0,\s*s0', prefix), 'Compiled raw-MRS VFP poison not observed')
                    diagnostic = 'FP instruction before raw CONTROL capture'
                else:
                    _, _, reached, _ = call_closure(elf, bad)
                    require('fiber_port_hash32_accum' in reached, 'Poisoned actual helper is not in pre-MRS call closure')
                    body = re.search(r'(?ms)^[0-9a-f]+ <fiber_port_hash32_accum>:\n(.*?)(?=^[0-9a-f]+ <|\Z)', bad)[1]
                    require(re.search(r'\bvmov(?:\.f32)?\s+s0,\s*s0', body), 'Compiled transitive VFP poison not observed')
                    diagnostic = 'FP instruction in actual pre-MRS success closure: fiber_port_hash32_accum'
                require_rejection(lambda: audit_before_mrs(elf, bad, p), diagnostic)
                self.controls.append(dict(Kind='COMPILED-VFP-POISON-' + label, Profile=p[0], NativeLTO=lto))
                if label == 'transitive-helper':
                    model, reached, _, _ = call_closure(elf, bad)
                    victim = model.unique('fiber_port_hash32_accum')
                    instructions = [r for r in model.body(victim) if r['mnemonic'] in {'vmov', 'vmov.f32'} and r['operands'] == 's0,s0']
                    require(victim in reached and len(instructions) == 1 and
                            instructions[0]['address'] in model.coverage[victim]['ReachableInstructionAddresses'],
                            'Disguised-data control lost its reachable actual FP instruction')
                    instruction = instructions[0]
                    word = struct.unpack_from('<I', elf.payload(elf.sections[victim[0]]), instruction['address'])[0]
                    section, substitutions, lines = None, 0, []
                    for line in bad.splitlines():
                        header = re.match(r'Disassembly of section (.+):$', line)
                        if header:
                            section = header[1]
                        row = re.match(r'\s*([0-9a-f]+):', line)
                        if section == elf.sections[victim[0]]['name'] and row and int(row[1], 16) == instruction['address']:
                            line = '%x: %08x .word 0x%08x' % (instruction['address'], word, word)
                            substitutions += 1
                        lines.append(line)
                    require(substitutions == 1, 'Disguised-data control did not replace exactly its intended row')
                    disguised = '\n'.join(lines) + '\n'
                    (changed / 'disguised-data.dis').write_text(disguised, encoding='ascii')
                    observed = require_rejection(lambda: audit_before_mrs(elf, disguised, p),
                                                 'Reachable undecoded native bytes: fiber_port_hash32_accum')
                    self.assurance.append(dict(Kind='COMPILED-BYTE-COVERAGE', Profile=p[0], NativeLTO=lto,
                        Case='same-ELF-disguised-data', Expected='REJECT', ELFHash=sha(changed / 'native.o'),
                        Section=victim[0], Address=instruction['address'], Word=word, Diagnostic=observed))
            self.scanner_controls(p, directory, flags, lto, objects)

    def scanner_controls(self, p, directory, flags, lto, objects):
        source = self.root / 'fiber/port' / p[1] / 'fiber_port.c'
        original = source.read_text()
        original_body = function(original, 'PendSV_Handler')
        anchor = r'(?m)^(\s*)("mrs\s+r3,\s*control\s*\\n")'

        def port(case, before='', after='', wrong_register=False):
            def replacement(match):
                capture = match[2].replace('r3', 'r2') if wrong_register else match[2]
                return match[1] + before + capture + after
            body, count = re.subn(anchor, replacement, original_body)
            require(count == 1, 'Expected exact actual PendSV CONTROL anchor')
            path = case / 'fiber_port.c'
            path.write_text(original.replace(original_body, body, 1), encoding='ascii')
            return self.compile(path, case / 'port.o', flags)

        def assembled(case, obj, helpers=()):
            elf, dis = self.native([obj, objects[1], *helpers], case / 'native.o', flags, lto)
            model = Native(elf, dis)
            return elf, dis, model

        def remember(kind, case, expected):
            record = dict(Kind=kind, Profile=p[0], NativeLTO=lto, Case=case.name, Expected=expected)
            self.assurance.append(record)
            write_json(case / 'control.json', record)

        for label, poison, wrong in (('eor-clobber', 'eor.w r3, r3, r3', False),
                                    ('mov-clobber', 'mov.w r3, #0', False), ('wrong-capture', '', True)):
            case = directory / label
            case.mkdir()
            after = '\n"' + poison + ' \\n"' if poison else ''
            obj = port(case, after=after, wrong_register=wrong)
            elf, dis, model = assembled(case, obj)
            rows = model.body(model.unique('PendSV_Handler'))
            require(any(r['mnemonic'] == ('mrs' if wrong else poison.split('.')[0]) and
                        r['operands'] == ('r2,control' if wrong else 'r3,r3,r3' if label == 'eor-clobber' else 'r3,#0')
                        for r in rows), 'Actual capture/clobber poison not emitted')
            require_rejection(lambda: audit_before_mrs(elf, dis, p), 'Raw CONTROL capture/store sequence changed')
            remember('COMPILED-CAPTURE-SEQUENCE', case, 'REJECT exact capture/store sequence')

        envelope = '"push {r0-r3, r12, lr} \\n"\n"bl %s \\n"\n"pop {r0-r3, r12, lr} \\n"\n'
        for label in ('clean-new-helper', 'fp-new-helper', 'indirect-prefix', 'interior-helper-entry'):
            case = directory / label
            case.mkdir()
            helper = self.compile(self.fixture / 'extra_helper.c', case / 'helper.o',
                                  flags + (['-DCONTROL_HELPER_POISON=1'] if label == 'fp-new-helper' else []))
            before = envelope % ('control_new_pre_mrs_helper + 2' if label == 'interior-helper-entry' else 'control_new_pre_mrs_helper')
            if label == 'indirect-prefix':
                before = '"blx r3 \\n"\n'
            obj = port(case, before=before)
            elf, dis, model = assembled(case, obj, [helper])
            if label == 'clean-new-helper':
                _, _, extents = audit_before_mrs(elf, dis, p)
                helper_id = model.unique('control_new_pre_mrs_helper')
                require(any((r['Section'], r['Entry'], r['Extent']) == helper_id for r in extents['Roots']),
                        'New actual prefix helper was not derived as a root')
                remember('COMPILED-DERIVED-PREFIX', case, 'ACCEPT actual new clean root')
            else:
                diagnostic = {'fp-new-helper': 'FP instruction in actual pre-MRS success closure: control_new_pre_mrs_helper',
                              'indirect-prefix': 'Unsupported indirect executable transfer',
                              'interior-helper-entry': 'Non-entry executable target'}[label]
                require_rejection(lambda: audit_before_mrs(elf, dis, p), diagnostic)
                remember('COMPILED-DERIVED-PREFIX', case, 'REJECT ' + diagnostic)

        for label, macro in (('reachable-hword', 'CONTROL_HELPER_DATA_POISON'),
                             ('conditional-return-data', 'CONTROL_HELPER_CONDITIONAL_RETURN_DATA'),
                             ('conditional-branch-data', 'CONTROL_HELPER_CONDITIONAL_BRANCH_DATA'),
                             ('unreachable-pool', 'CONTROL_HELPER_LITERAL_POOL')):
            case = directory / label
            case.mkdir()
            helper = self.compile(self.fixture / 'extra_helper.c', case / 'helper.o', flags + ['-D' + macro + '=1'])
            obj = port(case, before=envelope % 'control_new_pre_mrs_helper')
            elf, dis, model = assembled(case, obj, [helper])
            helper_id = model.unique('control_new_pre_mrs_helper')
            payload = elf.payload(elf.sections[helper_id[0]])
            needle = bytes.fromhex('b0ee400a')
            offsets = [i for i in range(helper_id[1], helper_id[1] + helper_id[2] - 3) if payload[i:i + 4] == needle]
            require(len(offsets) == 1, 'Actual helper data-word control lost its single FP encoding')
            address = offsets[0]
            require((helper_id[0], address) not in model.instructions, 'Data-word control unexpectedly decoded as an instruction')
            if label != 'unreachable-pool':
                if label == 'reachable-hword':
                    require(payload[address - 2:address + 6] == bytes.fromhex('00bfb0ee400a00bf'),
                            'Actual compiled hword control lost its NOP/data/NOP sequence')
                observed = require_rejection(lambda: audit_before_mrs(elf, dis, p),
                                             'Reachable undecoded native bytes: control_new_pre_mrs_helper')
            else:
                observed = None
                audit_before_mrs(elf, dis, p)
                checked, reached, _, _ = call_closure(elf, dis)
                require(helper_id in reached, 'Literal-pool positive is not actually in the pre-MRS closure')
                spans = checked.coverage[helper_id]['ProvenUnreachableByteSpans']
                require(any(start <= address and address + 4 <= end for start, end in spans),
                        'Literal pool is not proven unreachable by the actual CFG')
                write_json(case / 'helper-coverage.json', checked.describe(helper_id))
            self.assurance.append(dict(Kind='COMPILED-BYTE-COVERAGE', Profile=p[0], NativeLTO=lto, Case=label,
                                       Expected='REJECT' if label != 'unreachable-pool' else 'ACCEPT',
                                       ELFHash=sha(case / 'native.o'), Section=helper_id[0], Address=address, Diagnostic=observed))

        for poisoned in (False, True):
            case = directory / ('duplicate-helper-' + ('poison' if poisoned else 'clean'))
            case.mkdir()
            helpers = [self.compile(self.fixture / 'duplicate_helper.c', case / (suffix + '.o'), flags + defines)
                       for suffix, defines in (('a', ['-DCONTROL_DUP_A=1'] + (['-DCONTROL_DUP_POISON=1'] if poisoned else [])),
                                               ('b', []))]
            obj = port(case, before=(envelope % 'control_duplicate_entry_a') + (envelope % 'control_duplicate_entry_b'))
            for reverse in (False, True):
                ordered = list(reversed(helpers)) if reverse else helpers
                target = case / ('reverse.o' if reverse else 'forward.o')
                elf, dis = self.native([obj, objects[1], *ordered], target, flags, lto)
                model, reached, _, _ = call_closure(elf, dis)
                duplicates = {key for key in reached if any(name.startswith('control_duplicate_helper') for name in model.functions[key])}
                require(len(duplicates) == 2, 'Actual duplicate-local helper extents were lost')
                if not lto:
                    require(len(model.named('control_duplicate_helper')) == 2, 'Ordinary duplicate-name control lacks duplicate native names')
                poisoned_ids = [key for key in duplicates if any(r['mnemonic'] in {'vmov', 'vmov.f32'} and r['operands'] == 's0,s0' for r in model.body(key))]
                require(len(poisoned_ids) == int(poisoned), 'Duplicate-helper VFP poison not emitted in exactly its intended body')
                if poisoned:
                    require_rejection(lambda: audit_before_mrs(elf, dis, p),
                        'FP instruction in actual pre-MRS success closure: ' + model.name(poisoned_ids[0]))
                else:
                    audit_before_mrs(elf, dis, p)
                record = dict(Kind='COMPILED-DUPLICATE-HELPERS', Profile=p[0], NativeLTO=lto,
                              Poisoned=poisoned, Reverse=reverse, Expected='REJECT' if poisoned else 'ACCEPT',
                              Extents=[model.describe(key) for key in sorted(duplicates)])
                self.assurance.append(record)
                write_json(target.with_suffix('.control.json'), record)

    def cohorts(self, p, directory, opt, lto):
        flags = self.flags(p, opt, lto)
        source = self.root / 'fiber/port' / p[1] / 'fiber_port.c'
        provider = self.compile(source, directory / 'provider.o', flags)
        current = self.compile(self.fixture / 'cohort.c', directory / 'consumer-v2.o', flags)
        version = '0x000100%02Xu' % p[7] if p[5] else '0x00010001u'
        stale = self.compile(self.fixture / 'cohort.c', directory / 'consumer-v1.o', flags + ['-DCONTROL_OLD_LAYOUT=' + version])
        def identity(obj):
            symbols = self.run([self.tools['nm'], '--plugin=' + str(self.tools['plugin']), '-u', obj]).stdout
            found = re.findall(r'\bU\s+(fiber_port_context_cohort_\w+)', symbols)
            require(len(found) == 1, 'Consumer must import one exact private cohort')
            return found[0]
        old_identity, new_identity = identity(stale), identity(current)
        current_version = version.replace('0x0001', '0x0002')
        require('_l' + version + '_' in old_identity and '_l' + current_version + '_' in new_identity,
                'Actual input objects did not import exact layout-v1/v2 cohorts')
        # This is an identity-only mutation of the current actual provider,
        # not a historical source or behavioral receipt for layout v1.
        old_root = directory / 'identity-v1-provider'
        shutil.copytree(self.root, old_root)
        header = old_root / 'fiber/port' / p[1] / 'fiber_portmacro.h'
        text = header.read_text()
        require(text.count(current_version) == 1, 'Provider layout mutation is not exact')
        header.write_text(text.replace(current_version, version), encoding='ascii')
        old_provider = self.compile(old_root / 'fiber/port' / p[1] / 'fiber_port.c',
                                    directory / 'provider-v1.o', self.flags(p, opt, lto, root=old_root))
        for generation, supplied_obj, matched, mismatched, expected in (
                ('v2', provider, current, stale, old_identity), ('v1', old_provider, stale, current, new_identity)):
            archive = directory / ('provider-' + generation + '.a')
            self.run([self.tools['ar'], '--plugin=' + str(self.tools['plugin']), 'rcs', archive, supplied_obj])
            for kind, supplied in (('direct', supplied_obj), ('archive', archive)):
                label = generation + '-' + kind
                base = [self.gcc, *flags, '-nostdlib', '-Wl,--gc-sections', '-Wl,-T,' + str(self.fixture / 'link.ld')]
                good = directory / ('matching-' + label + '.elf')
                self.run([*base, matched, supplied, '-o', good])
                require(not self.run([self.tools['nm'], '-u', good]).stdout.strip(), 'Matching cohort ELF has undefined imports')
                symbols = self.run([self.tools['nm'], good]).stdout
                require(len(re.findall(r'\b[Rr]\s+fiber_port_context_cohort_\w+', symbols)) == 1,
                        'Matching final ELF lacks its single actual runtime cohort')
                bad = self.run([*base, mismatched, supplied, '-o', directory / ('stale-' + label + '.elf')], True)
                self.link_classifier.classify_unresolved(bad, expected, self.tools['ld'])
                counterfeit = subprocess.CompletedProcess([], 1, '', bad.stderr.replace(
                    'collect2.exe: error: ld returned 1 exit status\n',
                    'unrelated-link-error\ncollect2.exe: error: ld returned 1 exit status\n'))
                try:
                    self.link_classifier.classify_unresolved(counterfeit, expected, self.tools['ld'])
                except self.link_classifier.StaleLinkDiagnosticError:
                    pass
                else:
                    raise RuntimeError('Mixed-error stale-cohort classifier control accepted')
                self.controls.append(dict(Kind='ACTUAL-RUNTIME-V1-V2-COHORT', Profile=p[0], NativeLTO=lto,
                    Packaging=kind, ProviderGeneration=generation, ExpectedMissing=expected, ProviderSHA256=sha(supplied_obj)))
                self.rows.append(dict(Kind='COHORT-MATCHING-LINK', Profile=p[0], NativeLTO=lto,
                                      Packaging=kind, ProviderGeneration=generation))

    def finish(self, complete, error=None):
        self.report.update(Verdict='FAIL', CompleteSuite=False, ArtifactsVerifiedBeforePass=False)
        self.report['Errors'] = [] if error is None else [error]
        write_json(self.build / 'results.json', self.report)
        after = {p: sha(p) if Path(p).is_file() else None for p in self.inputs}
        self.report['InputDrift'] = [p for p in self.inputs if self.inputs[p] != after[p]]
        write_json(self.build / 'inputs-before.json', self.inputs)
        write_json(self.build / 'inputs-after.json', after)
        write_json(self.build / 'assurance-controls.json', self.assurance)
        artifacts = {str(p.relative_to(self.build)): sha(p) for p in self.build.rglob('*')
                     if p.is_file() and p not in {self.build / 'results.json', self.build / 'artifacts.json'}}
        write_json(self.build / 'artifacts.json', artifacts)
        require(all(sha(self.build / p) == value for p, value in artifacts.items()), 'Artifact closing verification failed')
        self.report.update(CompleteSuite=complete, Commands=len(self.commands), Python=sys.executable,
                           Tools={k: str(v) for k, v in self.tools.items()},
                           Counts=dict(HostRuns=sum(r['Kind'] == 'HOST-GUARDS' for r in self.rows),
                               HostChecks=sum(r.get('Checks', 0) for r in self.rows),
                               ArmCodegen=sum(r['Kind'] == 'ARM-CODEGEN' for r in self.rows),
                               MatchingLinks=sum(r['Kind'] == 'COHORT-MATCHING-LINK' for r in self.rows),
                               Controls=len(self.controls)), ArtifactsVerifiedBeforePass=True)
        if complete:
            self.check_inputs()
            assurance = {'COPIED-CLASSIFIER-CLOSING': 1, 'COMPILED-CAPTURE-SEQUENCE': 24,
                         'COMPILED-DERIVED-PREFIX': 32, 'COMPILED-DUPLICATE-HELPERS': 32,
                         'COMPILED-BYTE-COVERAGE': 40}
            require(len(self.assurance) == 129 and all(sum(r['Kind'] == kind for r in self.assurance) == count
                    for kind, count in assurance.items()), 'Incomplete exact scanner-assurance inventory')
            require(self.report['Counts'] == dict(HostRuns=35, HostChecks=238680, ArmCodegen=63,
                                                 MatchingLinks=56, Controls=214), 'Incomplete exact case inventory')
            expected = {'COMPILED-GUARD-MUTATION': 61, 'COMPILED-RAW-FAMILIES': 63,
                        'ACTUAL-RUNTIME-V1-V2-COHORT': 56, 'COMPILED-PRE-MRS-ANNOTATION-REMOVAL': 14,
                        'COMPILED-OLD-CM0-READBACK': 4, 'COMPILED-VFP-POISON-before-mrs': 8,
                        'COMPILED-VFP-POISON-transitive-helper': 8}
            observed = {kind: sum(c['Kind'] == kind for c in self.controls) for kind in expected}
            require(observed == expected, 'Incomplete exact compiled-control inventory')
            self.report['ControlCounts'] = observed
        if complete and not error and not self.report['InputDrift']:
            self.report['Verdict'] = 'PASS'
        write_json(self.build / 'results.json', self.report)
        return self.report['Verdict'] == 'PASS'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'gcc', 'cmsis', 'host-gcc', 'build'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    suite = Suite(args)
    try:
        suite.snapshot()
        for p in PROFILES:
            print('classic CONTROL ' + p[0], flush=True)
            suite.host_guards(p)
            for opt, lto in MODES:
                suite.codegen(p, opt, lto)
            for opt in ('O2', 'Os'):
                suite.codegen(p, opt, True, True)
        suite.copy_closing_control()
        require(suite.finish(True), 'Closing input drift or failed case')
    except Exception:
        error = traceback.format_exc()
        suite.finish(False, error)
        print(error, file=sys.stderr)
        return 1
    print('PASS classic MPU CONTROL ' + str(suite.build))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
