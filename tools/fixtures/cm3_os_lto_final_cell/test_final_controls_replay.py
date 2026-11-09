"""Actual-byte 34-control fixtures; no capture admission, tools or CLI replay."""

import argparse
from contextlib import contextmanager, ExitStack
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import traceback
from types import ModuleType
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / 'final_controls_replay.py'
CONTRACT = HERE / 'FINAL_CONTROL_REPLAY_CONTRACT.md'
METHODS = 30
BASE_PIN = 'E28820C84F32FC86FA6317D4BB06C9B0313F0C43D76238B9522E0B366CC69694'
CONTRACT_PIN = '0F58C38B4962B1AB4B2DD6D5797013205DBB86DCE12D99F82CD4A1396D251C00'
MUTATION_PINS = {
    'native_mutations': ('cm3_lto_roots/mutations.py',
        '32BDE6CA67B12EEC9975D24D6628C5576EA29F33121CD60310F1F010CF272353'),
    'reference_mutations': ('cm3_reference_lto_roots/mutations.py',
        'E20E55734138E5F9AE76019D3C3EF1260EE708FDF222DC72E5C8B5552E02029C'),
}
RECIPE_PINS = {
    'cm3_lto_protocol/witness.py': '39E1994A74DB225CD3BB2010AE07C49FD1DB2EE2006BCAD2FC59BD3092E6CF51',
    'cm3_reference_lto_protocol/witness.py': 'B3968C5C51BCB7DFF13425B6656715DB4FA9674C18503AA04FDE7EA0A0F89D5F',
}
BASE_HELPERS = ('abi', 'link_helpers', 'binding_helpers', 'native_roots', 'reference_roots',
    'native_protocol', 'reference_protocol', 'decoder', 'checker', 'os_join', 'join', 'guard',
    'original_replay', 'port_replay')
HELPERS = (*BASE_HELPERS, 'final_replacement_replay', 'native_mutations', 'reference_mutations')
FIELDS = frozenset(('Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'LTO', 'Cohort',
    'SourceInventorySha256', 'BatchRoot', 'BatchAuthority', 'PortProofSha256', 'OriginalProofSha256',
    'FinalProofSha256', 'Inputs', 'LedgerBytes', 'Baseline', 'Controls', 'DerivedBuffers', 'ReadInputs',
    'LogicalRoles', 'ReadFiles', 'DerivedRoleInstances', 'TransportControlsExecuted',
    'CanonicalControlsExecuted', 'FreshControlsExecuted', 'ImmutableInputsConsumed',
    'ToolInvocations', 'CompilerInvocations', 'RequiredCellsSatisfied', 'Nonclaims'))
NONCLAIMS = frozenset(('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'FullInstructionSemantics', 'SourceIRProof', 'SourceToIRSemanticProof',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'OrdinaryRootPreservationProven', 'HandlerRoutingProven', 'FinalReferenceParity',
    'InstructionEquivalence', 'PolicyEquivalence', 'ArbitraryCallbackSafetyProven',
    'AllProducerMutantsReexecuted', 'ProducerCompilersReexecuted', 'UnchangedOtherSixGeneratedBodies',
    'CompleteCellProof', 'WholeCellProof', 'RequiredCellSatisfied', 'CellContractSatisfied',
    'ArchiveQualification', 'HostedCIQualified', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified'))
ROLES = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'MachineDisassembly')
ROOTS = {'Native': ('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler'),
    'Reference': ('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler')}
NATIVE_CASES = (
    ('machine-nonrelocation-byte', 'LTO-PRESERVATION'), ('machine-bl-addend', 'LTO-RELOC'),
    ('machine-slot-addend', 'LTO-SLOT'), ('applied-slot-word', 'LTO-SLOT'),
    ('coherent-slot-in-bss', 'LTO-(ORIGIN|SYMBOL)'), ('globalized-slot', 'LTO-SYMBOL'),
    ('wrong-slot-section-target', 'LTO-SLOT'), ('function-alias', 'LTO-SYMBOL'),
    ('slot-object-alias', 'LTO-SYMBOL'), ('code-without-execute', 'LTO-SYMBOL'),
    ('callee-data-mapping', 'LTO-SYMBOL'), ('coherent-callee-entry', 'LTO-ORIGIN'),
    ('wrong-machine-section-size', '(LTO-)?ORIGIN'), ('foreign-map-provider', '(LTO-)?ORIGIN'),
    ('missing-root-reference', 'LTO-RELOC'), ('extra-root-reference', 'LTO-RELOC'))
REFERENCE_CASES = (
    ('machine-nonrelocation-byte', 'REF-LTO-PRESERVATION'), ('machine-bl-addend', 'REF-LTO-RELOC'),
    ('machine-slot-addend', 'REF-LTO-SLOT'), ('applied-slot-word', 'REF-LTO-SLOT'),
    ('coherent-slot-in-bss', 'REF-LTO-ORIGIN'), ('localized-slot', 'REF-LTO-SYMBOL'),
    ('wrong-slot-named-target', 'REF-LTO-RELOC'), ('function-alias', 'REF-LTO-SYMBOL'),
    ('slot-object-alias', 'REF-LTO-SYMBOL'), ('code-without-execute', 'REF-LTO-SYMBOL'),
    ('callee-data-mapping', 'REF-LTO-SYMBOL'), ('coherent-callee-entry', 'REF-LTO-ORIGIN'),
    ('wrong-machine-section-size', 'REF-LTO-ORIGIN'), ('foreign-map-provider', 'REF-LTO-ORIGIN'),
    ('missing-root-reference', 'REF-LTO-RELOC'), ('extra-root-reference', 'REF-LTO-RELOC'))
CATALOG = dict(Native=NATIVE_CASES, Reference=REFERENCE_CASES)
BUFFERS, FIXTURES, DATA, INPUTS = {}, {}, {}, {}
BATCH = PORT = ORIGINAL = FINAL = None
base = m = core = None
H, PARSER_MODULES = {}, {}
PARSER_FINDERS = []
FORBIDDEN_CALLS = []
ORIGINAL_EXERCISED = FINAL_EXERCISED = CONTROLS_EXERCISED = False


def need(value, label):
    if not value: raise ValueError('final-controls-tests: ' + label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def proof_hash(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
        allow_nan=False).encode('ascii'))


def token_hash(value):
    return sha(json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii'))


def retain(destination, path, raw):
    path = Path(path)
    need(type(raw) is bytes, 'literal first-seen bytes')
    if path in destination:
        need(destination[path] == raw, 'first-seen buffer collision/' + str(path))
    else:
        destination[path] = raw
    return raw


def snapshot(path, expected, destination):
    path = Path(path); raw = path.read_bytes()
    if expected is not None: need(sha(raw) == expected, 'source/fixture pin/' + str(path))
    return retain(destination, path, raw)


def merge(destination, incoming):
    for path, raw in incoming.items(): retain(destination, path, raw)


def absorb():
    current = base
    while current is not None:
        merge(BUFFERS, current.BUFFERS); merge(FIXTURES, current.FIXTURES)
        current = getattr(current, 'base', None)


def load(name, path, raw):
    module = ModuleType(name); module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def initialize(helpers=None):
    global base, m, core, H, BATCH, PORT, ORIGINAL, FINAL
    global ORIGINAL_EXERCISED, FINAL_EXERCISED
    if helpers is not None:
        need(type(helpers) is dict and set(helpers) == set(HELPERS), 'exact seventeen real helpers')
    first = base is None
    if first:
        before = list(sys.meta_path)
        path = HERE / 'test_final_replacement_replay.py'
        base = load('_final_controls_final_fixture', path, snapshot(path, BASE_PIN, BUFFERS))
        for path in (Path(__file__).resolve(), SUBJECT): snapshot(path, None, BUFFERS)
        snapshot(CONTRACT, CONTRACT_PIN, BUFFERS)
        mutation_modules = {name: load('_final_controls_' + name, HERE.parent / relative,
            snapshot(HERE.parent / relative, digest, BUFFERS))
            for name, (relative, digest) in MUTATION_PINS.items()}
        for relative, digest in RECIPE_PINS.items(): snapshot(HERE.parent / relative, digest, BUFFERS)
        # Retain the unpinned fixture envelope bytes before its initializer reads them.
        for path in (base.SUBJECT, HERE / 'FINAL_REPLACEMENT_REPLAY_CONTRACT.md'):
            snapshot(path, None, BUFFERS)
        base.initialize(None if helpers is None else {key: helpers[key] for key in BASE_HELPERS})
        core = base.core
        H = dict(base.H, final_replacement_replay=base.m, **mutation_modules)
        PARSER_FINDERS.extend(finder for finder in sys.meta_path if finder not in before)
    elif helpers is not None:
        base.initialize({key: helpers[key] for key in BASE_HELPERS})
    if helpers is not None: H = dict(helpers)
    if first or helpers is not None:
        absorb()
        BATCH, PORT, ORIGINAL = copy.deepcopy(base.BATCH), copy.deepcopy(base.PORT), copy.deepcopy(base.ORIGINAL)
        ORIGINAL_EXERCISED = True
        FINAL = base.Model().run(helpers={key: H[key] for key in BASE_HELPERS})
        FINAL_EXERCISED = True
        absorb()
        for group in ('Final', 'Reference', 'Ledgers'):
            value = copy.deepcopy(FINAL['Inputs'][group])
            need(group not in INPUTS or INPUTS[group] == value, 'stable fresh final bindings')
            if group not in INPUTS: INPUTS[group] = value
            for row in value.values():
                path = Path(row['Path'])
                need(path in base.DATA and sha(base.DATA[path]) == row['Sha256'], 'authenticated fourteen-byte fixture')
                retain(DATA, path, base.DATA[path]); retain(FIXTURES, path, base.DATA[path])
        need(len(DATA) == sum(map(len, INPUTS.values())) == 14, 'fourteen distinct explicit inputs')
        for name, module in sys.modules.items():
            if name != 'elftools' and not name.startswith('elftools.'): continue
            need(name not in PARSER_MODULES or PARSER_MODULES[name] is module, 'same captured parser module/' + name)
            if name not in PARSER_MODULES: PARSER_MODULES[name] = module
    if m is None: m = load('_final_controls_leaf', SUBJECT, BUFFERS[SUBJECT])


@contextmanager
def no_io():
    with base.no_io(), ExitStack() as stack:
        for name in ('is_file', 'is_dir', 'rmdir', 'symlink_to', 'hardlink_to'):
            stack.enter_context(patch.object(Path, name, side_effect=AssertionError('physical/write API forbidden/' + name)))
        yield


@contextmanager
def forbidden_runners():
    with ExitStack() as stack:
        spies = []
        for key in ('native_mutations', 'reference_mutations'):
            for name in ('mutate', 'run_cases', '_physical'):
                if hasattr(H[key], name):
                    def forbidden(*args, _key=key, _name=name, **kwargs):
                        FORBIDDEN_CALLS.append((_key, _name))
                        raise AssertionError('frozen filesystem recipe forbidden/' + _key + '/' + _name)
                    spies.append(stack.enter_context(patch.object(H[key], name,
                        side_effect=forbidden)))
        yield spies


@contextmanager
def detached():
    with no_io(), forbidden_runners(), ExitStack() as stack:
        for helper, name in (('abi', 'inspect'), ('original_replay', 'inspect'), ('port_replay', 'inspect'),
                ('final_replacement_replay', 'inspect'), ('os_join', 'check_join'), ('decoder', 'Object'),
                ('native_roots', 'NativeCM3LTOImage'), ('reference_roots', 'ReferenceCM3LTOImage')):
            stack.enter_context(patch.object(H[helper], name, side_effect=AssertionError('binary inspector forbidden/' + name)))
        for name in ('FinalImage', '_ELF', 'compare_load_images'):
            stack.enter_context(patch.object(core, name, side_effect=AssertionError('binary constructor forbidden/' + name)))
        yield


class Model:
    def __init__(self):
        self.batch, self.port, self.original, self.final = copy.deepcopy((BATCH, PORT, ORIGINAL, FINAL))
        self.files, self.allowed, self.reads = dict(DATA), set(DATA), []

    def read(self, path, expected=None):
        if not isinstance(path, Path) or path not in self.allowed:
            raise PermissionError('missing explicit control fixture role/' + str(path))
        self.reads.append((path, expected))
        return self.files[path]

    def run(self, **options):
        global CONTROLS_EXERCISED
        arguments = dict(core=core, read=self.read, batch=self.batch, port=self.port,
            original=self.original, final=self.final, helpers=H)
        arguments.update(options)
        with no_io(), forbidden_runners(): result = m.inspect(**arguments)
        CONTROLS_EXERCISED = True
        return result


def synthetic_result(helpers=None):
    """Fresh real-byte controls/final; pinned port metadata, never renewed admission."""
    previous = list(sys.meta_path)
    with patch.dict(sys.modules):
        try:
            if base is not None:
                sys.modules.update(PARSER_MODULES)
                sys.meta_path[:0] = [finder for finder in PARSER_FINDERS if finder not in sys.meta_path]
            initialize(helpers if helpers is not None else (H if base is not None else None))
            return Model().run()
        finally:
            sys.meta_path[:] = previous


def cases(proof):
    for side in ('Native', 'Reference'):
        for stage in ('Transport', 'Canonical'):
            for row in proof['Controls'][side][stage]: yield side, stage, row


def case(proof, side, name):
    return next(row for s, _, row in cases(proof) if s == side and row['Name'] == name)


def derived(proof, side, name, role):
    return next(row for row in proof['DerivedBuffers']
        if (row['Side'], row['Case'], row['Role']) == (side, name, role))


def before_bytes(row):
    raw = bytes.fromhex(row['Output']['Data'])
    for edit in reversed(row['Edits']):
        offset, before, after = edit['FileOffset'], bytes.fromhex(edit['Before']), bytes.fromhex(edit['After'])
        need(type(offset) is int and 0 <= offset <= len(raw) - len(after)
            and raw[offset:offset + len(after)] == after, 'independent reversed edit extent/data')
        raw = raw[:offset] + before + raw[offset + len(after):]
    return raw


def replace_output(row, raw):
    """Coherently alter recorded bytes/edits; this is a forged proof, not execution."""
    original = DATA[Path(row['Input']['Path'])]
    prefix = 0
    while prefix < min(len(original), len(raw)) and original[prefix] == raw[prefix]: prefix += 1
    suffix = 0
    while suffix < min(len(original), len(raw)) - prefix and original[-suffix - 1] == raw[-suffix - 1]: suffix += 1
    row['Edits'] = [] if original == raw else [dict(FileOffset=prefix,
        Before=original[prefix:len(original) - suffix if suffix else None].hex(),
        After=raw[prefix:len(raw) - suffix if suffix else None].hex())]
    row['Output'] = dict(Sha256=sha(raw), Bytes=len(raw), Data=raw.hex())


def symbol_field(raw, name):
    """Bounded independent ELF32 symbol coordinates, without constructing a parser."""
    need(raw[:6] == b'\x7fELF\x01\x01', 'ELF32 little-endian fixture')
    shoff = struct.unpack_from('<I', raw, 32)[0]
    extent, count = struct.unpack_from('<HH', raw, 46)
    need(extent == 40 and shoff + count * extent <= len(raw), 'bounded section table')
    found = []
    for index in range(count):
        header = shoff + index * extent
        if struct.unpack_from('<I', raw, header + 4)[0] != 2: continue
        offset, size, strings = struct.unpack_from('<III', raw, header + 16)
        entry = struct.unpack_from('<I', raw, header + 36)[0]
        need(entry == 16 and size % entry == 0 and offset + size <= len(raw) and strings < count, 'bounded symbols')
        table = shoff + strings * extent
        text, text_size = struct.unpack_from('<II', raw, table + 16)
        need(text + text_size <= len(raw), 'bounded strings')
        for position in range(offset, offset + size, entry):
            start = struct.unpack_from('<I', raw, position)[0]
            need(start < text_size, 'bounded symbol name')
            end = raw.find(b'\0', text + start, text + text_size)
            need(end >= 0, 'terminated symbol name')
            if raw[text + start:end].decode('ascii') != name: continue
            value, length = struct.unpack_from('<II', raw, position + 4)
            section = struct.unpack_from('<H', raw, position + 14)[0]
            need(0 < section < count, 'defined symbol')
            owner = shoff + section * extent
            address, file_offset, section_size = struct.unpack_from('<III', raw, owner + 12)
            found.append(dict(SymbolOffset=position, Value=value, Size=length, Section=section,
                Address=address, FileOffset=file_offset, SectionSize=section_size))
    need(len(found) == 1, 'one exact ELF symbol')
    return found[0]


def root_slice(raw, name):
    field = symbol_field(raw, name)
    offset = field['FileOffset'] + (field['Value'] & ~1) - field['Address']
    need(0 <= offset and offset + field['Size'] <= len(raw), 'bounded actual root slice')
    return offset, raw[offset:offset + field['Size']]


def rewrite_slice(row, offset, after):
    raw = bytes.fromhex(row['Output']['Data']); before = raw[offset:offset + len(after)]
    need(len(before) == len(after) and before != after, 'nonempty coordinated byte tamper')
    raw = raw[:offset] + after + raw[offset + len(after):]
    replace_output(row, raw)
    need(before_bytes(row) == DATA[Path(row['Input']['Path'])], 'forged edits still reconstruct admitted input')


def rehash_transport(row):
    body = bytearray(row['Size'])
    for item in row['Instructions'] + row['MappedData']:
        raw = bytes.fromhex(item['Bytes']); body[item['Offset']:item['Offset'] + len(raw)] = raw
    row['BodySha256'] = sha(body)
    for reference in row['References']:
        body[reference['Offset']:reference['Offset'] + 4] = bytes.fromhex(reference['OriginalBytes'])
    row['MachineBodySha256'] = sha(body)


class ControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model, cls.spies = Model(), {}
        cls.before = copy.deepcopy((cls.model.batch, cls.model.port, cls.model.original, cls.model.final))
        with ExitStack() as stack:
            for key, name in (('native_roots', 'NativeCM3LTOImage'), ('reference_roots', 'ReferenceCM3LTOImage'),
                    ('decoder', 'Object'), ('os_join', 'check_join'), ('checker', 'check_pair')):
                cls.spies[key] = stack.enter_context(patch.object(H[key], name, wraps=getattr(H[key], name)))
            cls.proof = cls.model.run()
        cls.forbidden_calls = tuple(FORBIDDEN_CALLS)

    def reject(self, proof, model=None, label=None):
        model = Model() if model is None else model
        with detached(), self.assertRaises((ValueError, RuntimeError)) as caught:
            m.require_result(proof, model.batch, model.port, model.original, model.final, H)
        if label is not None: self.assertRegex(str(caught.exception), label)

    def test_actual_34_controls_and_independent_catalog(self):
        p = self.proof
        self.assertEqual(set(p), FIELDS)
        self.assertEqual(p['Status'], 'CM3-OS-LTO-FINAL-CONTROLS-REPLAYED-NOT-QUALIFIED')
        self.assertEqual(p['Scope'], 'CM3_OS_LTO_SELECTED_FINAL_AND_REFERENCE_34_BUFFER_CONTROLS_ONLY')
        self.assertEqual((p['ReadFiles'], p['LogicalRoles'], p['DerivedRoleInstances']), (14, 14, 172))
        self.assertEqual((p['TransportControlsExecuted'], p['CanonicalControlsExecuted']), (32, 2))
        self.assertEqual(len(list(cases(p))), 34)
        for side in ROOTS:
            self.assertEqual([(row['Name'], row['Expected']) for row in p['Controls'][side]['Transport']], list(CATALOG[side]))
            self.assertEqual([(row['Name'], row['Expected']) for row in p['Controls'][side]['Canonical']],
                [('coherent-svc-immediate', 'CM3-CLOSED-ROOTS')])
        for side, stage, row in cases(p):
            self.assertEqual(row['Status'], 'PASS')
            self.assertEqual(row['Rejection']['Type'], 'CORE' if stage == 'Transport' else 'CHECKER')
            self.assertRegex(row['Rejection']['Message'], '^REJECT:' + (row['Expected'] + ':' if stage == 'Transport'
                else 'CM3-CLOSED-ROOTS:' + side + '/' + ROOTS[side][0] + '/'))

    def test_byte_records_replay_and_exact_reader_bindings(self):
        self.assertEqual(self.proof['Inputs'], INPUTS)
        self.assertEqual(len(self.model.reads), 14)
        self.assertEqual({path for path, _ in self.model.reads}, set(DATA))
        self.assertEqual(self.proof['ReadInputs'], [dict(Path=str(path), Sha256=sha(raw), Bytes=len(raw))
            for path, raw in sorted(DATA.items())])
        expected_order = []
        for side in ROOTS:
            for stage, catalog in (('Transport', CATALOG[side]), ('Canonical', [('coherent-svc-immediate', '')])):
                for name, _ in catalog:
                    expected_order.extend((side, stage, name, role) for role in (ROLES[:5] if stage == 'Transport' else ROLES))
        self.assertEqual([(r['Side'], r['Stage'], r['Case'], r['Role']) for r in self.proof['DerivedBuffers']], expected_order)
        for row in self.proof['DerivedBuffers']:
            source = DATA[Path(row['Input']['Path'])]; self.assertEqual(before_bytes(row), source)
            self.assertEqual(row['Input'], dict(Path=row['Input']['Path'], Sha256=sha(source), Bytes=len(source)))
            raw = source
            for edit in row['Edits']:
                position, before, after = edit['FileOffset'], bytes.fromhex(edit['Before']), bytes.fromhex(edit['After'])
                self.assertNotEqual(before, after); self.assertEqual(raw[position:position + len(before)], before)
                raw = raw[:position] + after + raw[position + len(before):]
            self.assertEqual(row['Output'], dict(Sha256=sha(raw), Bytes=len(raw), Data=raw.hex()))

    def test_baseline_adapters_decoders_and_join_are_fresh(self):
        for key, group in (('native_roots', 'Final'), ('reference_roots', 'Reference')):
            spy = self.spies[key]; self.assertGreaterEqual(spy.call_count, 18)
            self.assertEqual(spy.call_args_list[0].args,
                (core, *(Path(INPUTS[group][role]['Path']) for role in ('Machine', 'Final', 'Disassembly'))))
            self.assertEqual(spy.call_args_list[0].kwargs, dict(link_map=Path(INPUTS[group]['LinkMap']['Path']),
                provider_objects={INPUTS[group][role]['Path']: Path(INPUTS[group][role]['Path']) for role in ('Machine', 'Startup')}))
        self.assertGreaterEqual(self.spies['decoder'].call_count, 4)
        self.spies['os_join'].assert_called_once()
        self.assertGreaterEqual(self.spies['checker'].call_count, 1)
        self.assertEqual(self.proof['Baseline'], {key: FINAL[key] for key in
            ('TransportRoots', 'CanonicalJoin', 'PolicyDifferenceRationales')})

    def test_filesystem_runners_are_not_positive_predicates(self):
        self.assertTrue(CONTROLS_EXERCISED)
        self.assertEqual(self.forbidden_calls, ())
        self.assertFalse(self.proof['Baseline']['CanonicalJoin']['MutantsReexecuted'])
        for name, key in (('native_mutations', 'Native'), ('reference_mutations', 'Reference')):
            self.assertEqual(H[name].CASES, CATALOG[key])
        self.assertNotIn('PhysicalIdentity', json.dumps(self.proof['DerivedBuffers']))

    def test_exact_seventeen_helpers(self):
        self.assertEqual(set(H), set(HELPERS))
        for name in HELPERS:
            wrong = dict(H); del wrong[name]
            with self.subTest(missing=name), self.assertRaises(ValueError): Model().run(helpers=wrong)
            wrong = dict(H); wrong[name] = object()
            with self.subTest(api=name), self.assertRaises(ValueError): Model().run(helpers=wrong)
        for wrong in (dict(H, Foreign=object()), dict(H, final_replacement_replay=object()), []):
            with self.subTest(kind=type(wrong).__name__), self.assertRaises(ValueError): Model().run(helpers=wrong)
        for alias in ('native_mutations', 'reference_mutations'):
            with patch.object(H[alias], 'CASES', tuple(reversed(H[alias].CASES))), self.assertRaises(ValueError): Model().run()

    def test_all_fourteen_permissions_are_required(self):
        for path in DATA:
            model = Model(); model.allowed.remove(path)
            with self.subTest(path=str(path)), self.assertRaises(PermissionError): model.run()

    def test_all_fourteen_hashes_with_digest_ignoring_reader(self):
        for path, raw in DATA.items():
            model = Model(); model.files[path] = bytes([raw[0] ^ 1]) + raw[1:]
            with self.subTest(path=str(path)), self.assertRaises(ValueError): model.run()

    def test_nonbytes_are_not_admitted_buffers(self):
        path = Path(INPUTS['Final']['Machine']['Path'])
        for value in (bytearray(DATA[path]), memoryview(DATA[path]), 'not bytes', None):
            model = Model(); model.files[path] = value
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError): model.run()

    def test_closed_result_keys_and_literal_facts_and_counters(self):
        for key in FIELDS:
            bad = copy.deepcopy(self.proof); del bad[key]
            with self.subTest(missing=key): self.reject(bad)
        for key, value in (('Foreign', False), ('Mode', 'O2-lto'), ('LTO', 1), ('FreshControlsExecuted', 1),
                ('ImmutableInputsConsumed', 1), ('ReadFiles', True), ('LogicalRoles', 14.0),
                ('DerivedRoleInstances', 171), ('TransportControlsExecuted', True), ('CanonicalControlsExecuted', 1),
                ('ToolInvocations', False), ('CompilerInvocations', 1), ('RequiredCellsSatisfied', 1)):
            bad = copy.deepcopy(self.proof); bad[key] = value
            with self.subTest(field=key): self.reject(bad)

    def test_independent_nonclaim_names_and_literal_false(self):
        self.assertEqual(set(self.proof['Nonclaims']), NONCLAIMS)
        for key in NONCLAIMS:
            for value in (True, 0):
                bad = copy.deepcopy(self.proof); bad['Nonclaims'][key] = value
                with self.subTest(claim=key, value=value): self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['Nonclaims']['MutantsReexecuted'] = False; self.reject(bad)

    def test_closed_inputs_read_inventory_and_ledgers(self):
        for group, rows in INPUTS.items():
            for role in rows:
                for key, value in (('Path', 'C:/foreign-final-control.o'),
                        ('Sha256', rows[role]['Sha256'].lower()), ('Foreign', False)):
                    bad = copy.deepcopy(self.proof); bad['Inputs'][group][role][key] = value
                    with self.subTest(group=group, role=role, field=key): self.reject(bad)
        for name in ('Master', 'Policy'):
            bad = copy.deepcopy(self.proof); bad['LedgerBytes'][name] += '00'; self.reject(bad)
        for action in ('reverse', 'missing', 'duplicate', 'size', 'bool'):
            bad = copy.deepcopy(self.proof); rows = bad['ReadInputs']
            if action == 'reverse': rows.reverse()
            elif action == 'missing': rows.pop()
            elif action == 'duplicate': rows[-1] = copy.deepcopy(rows[0])
            else: rows[0]['Bytes'] = True if action == 'bool' else rows[0]['Bytes'] + 1
            with self.subTest(action=action): self.reject(bad)

    def test_full_component_hashes_and_batch_authority(self):
        for field, component in (('PortProofSha256', PORT), ('OriginalProofSha256', ORIGINAL), ('FinalProofSha256', FINAL)):
            self.assertEqual(self.proof[field], proof_hash(component))
            bad = copy.deepcopy(self.proof); bad[field] = '0' * 64; self.reject(bad)
        for name in ('port', 'original', 'final'):
            model = Model(); getattr(model, name)['Foreign'] = False
            with self.subTest(component=name): self.reject(copy.deepcopy(self.proof), model)
        bad = copy.deepcopy(self.proof); bad['BatchAuthority']['Receipt']['Sha256'] = '0' * 64; self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['BatchRoot'] = 'C:/foreign-batch'; self.reject(bad)

    def test_control_catalog_order_and_membership_are_exact(self):
        for side in ROOTS:
            for action in ('reverse', 'duplicate', 'missing', 'foreign', 'expected'):
                bad = copy.deepcopy(self.proof); rows = bad['Controls'][side]['Transport']
                if action == 'reverse': rows.reverse()
                elif action == 'duplicate': rows[-1] = copy.deepcopy(rows[0])
                elif action == 'missing': rows.pop()
                elif action == 'foreign': rows[0]['Name'] = 'invented-control'
                else: rows[0]['Expected'] = '.*'
                with self.subTest(side=side, action=action): self.reject(bad)

    def test_rejections_are_narrow_not_generic_error_strings(self):
        for side, stage, row in cases(self.proof):
            prefix, family, detail = row['Rejection']['Message'].split(':', 2)
            for field, value in (('Type', 'CHECKER' if stage == 'Transport' else 'CORE'),
                    ('Message', 'REJECT:UNRELATED:synthetic unrelated failure'), ('Message', 'PermissionError: outside buffers'),
                    ('Message', prefix + ':' + family + '-FORGED:' + detail)):
                bad = copy.deepcopy(self.proof); case(bad, side, row['Name'])['Rejection'][field] = value
                with self.subTest(side=side, case=row['Name'], field=field): self.reject(bad)

    def test_all_172_row_schemas_roles_and_input_bindings(self):
        for index in range(172):
            for field, value in (('Role', 'Foreign'), ('Foreign', False)):
                bad = copy.deepcopy(self.proof); bad['DerivedBuffers'][index][field] = value
                with self.subTest(index=index, field=field): self.reject(bad)
            for field, value in (('Sha256', '0' * 64), ('Bytes', True)):
                bad = copy.deepcopy(self.proof); bad['DerivedBuffers'][index]['Input'][field] = value
                with self.subTest(index=index, input=field): self.reject(bad)
            bad = copy.deepcopy(self.proof); row = bad['DerivedBuffers'][index]
            row['Input']['Bytes'] += 1
            next(item for item in bad['ReadInputs'] if item['Path'] == row['Input']['Path'])['Bytes'] += 1
            with self.subTest(index=index, input='coordinated-size'): self.reject(bad)

    def test_all_172_outputs_bind_actual_data_hash_and_size(self):
        for index in range(172):
            output = self.proof['DerivedBuffers'][index]['Output']
            for field, value in (('Sha256', '0' * 64), ('Bytes', output['Bytes'] + 1), ('Bytes', True),
                    ('Data', output['Data'] + '00')):
                bad = copy.deepcopy(self.proof); bad['DerivedBuffers'][index]['Output'][field] = value
                with self.subTest(index=index, field=field): self.reject(bad)

    def test_all_172_edit_lists_are_checked_not_trusted(self):
        for index in range(172):
            if not self.proof['DerivedBuffers'][index]['Edits']:
                bad = copy.deepcopy(self.proof); row = bad['DerivedBuffers'][index]
                raw = bytes.fromhex(row['Output']['Data'])
                row['Edits'] = [dict(FileOffset=0, Before=raw[:1].hex(), After=raw[:1].hex())]
                with self.subTest(index=index, edit='no-op'): self.reject(bad)
                continue
            for field in ('FileOffset', 'Before', 'After'):
                bad = copy.deepcopy(self.proof); row = bad['DerivedBuffers'][index]; edit = row['Edits'][0]
                if field == 'FileOffset': edit[field] = row['Output']['Bytes'] + 1
                else:
                    raw = bytes.fromhex(edit[field])
                    edit[field] = (bytes([raw[0] ^ 1]) + raw[1:]).hex() if raw else '00'
                with self.subTest(index=index, field=field): self.reject(bad)
        bad = copy.deepcopy(self.proof)
        next(row for row in bad['DerivedBuffers'] if row['Edits'])['Edits'][0]['FileOffset'] = True
        self.reject(bad)
        bad = copy.deepcopy(self.proof)
        row = next(row for row in bad['DerivedBuffers'] if row['Edits'])
        output = copy.deepcopy(row['Output']); raw = bytes.fromhex(output['Data'])
        original, changed = raw[:1].hex(), bytes([raw[0] ^ 1]).hex()
        row['Edits'].extend((dict(FileOffset=0, Before=original, After=changed),
            dict(FileOffset=0, Before=changed, After=original)))
        self.assertEqual(row['Output'], output)
        self.assertEqual(sha(raw), output['Sha256'])
        self.assertEqual(before_bytes(row), DATA[Path(row['Input']['Path'])])
        self.reject(bad, label='unique net edit')

    def test_baseline_transport_and_raw_tokens_cannot_be_substituted(self):
        for branch in ('TransportRoots', 'CanonicalJoin', 'PolicyDifferenceRationales'):
            bad = copy.deepcopy(self.proof); bad['Baseline'][branch]['Foreign'] = False
            with self.subTest(branch=branch): self.reject(bad)
        for side in ROOTS:
            bad = copy.deepcopy(self.proof); row = bad['Baseline']['CanonicalJoin']['Roots'][side][0]
            tokens = row['RawCanonicalTokens']; index = next(i for i, token in enumerate(tokens) if token[0] == 'svc')
            tokens[index] = ('svc', '72'); row['RawTokenSha256'] = token_hash(tokens)
            with self.subTest(side=side): self.reject(bad)

    def test_canonical_svc72_rehashed_tokens_cannot_claim_elf71(self):
        for side, immediate in (('Native', '72'), ('Reference', '2')):
            bad = copy.deepcopy(self.proof); coherence = case(bad, side, 'coherent-svc-immediate')['Coherence']
            tokens = coherence['CanonicalTokens']; index = next(i for i, token in enumerate(tokens) if token[0] == 'svc')
            tokens[index] = ('svc', immediate); coherence['CanonicalTokenSha256'] = token_hash(tokens)
            with self.subTest(side=side): self.reject(bad)

    def test_changed_transport_hash_provider_and_map_join_case_outputs(self):
        for side in ROOTS:
            for field in ('ProviderSha256', 'LinkMapSha256'):
                bad = copy.deepcopy(self.proof); row = case(bad, side, 'coherent-svc-immediate')['Coherence']['TransportRoots'][0]
                row['RootOrigin'][field] = '0' * 64
                with self.subTest(side=side, field=field): self.reject(bad)

    def test_self_consistent_changed_transport_body_still_joins_actual_bytes(self):
        for side in ROOTS:
            bad = copy.deepcopy(self.proof); row = case(bad, side, 'coherent-svc-immediate')['Coherence']['TransportRoots'][0]
            instruction = row['Instructions'][0]; raw = bytes.fromhex(instruction['Bytes'])
            instruction['Bytes'] = (bytes([raw[0] ^ 1]) + raw[1:]).hex(); rehash_transport(row)
            group = 'Final' if side == 'Native' else 'Reference'
            roles = copy.deepcopy(INPUTS[group])
            for role in ROLES:
                roles[role]['Sha256'] = derived(bad, side, 'coherent-svc-immediate', role)['Output']['Sha256']
            with detached(): H['original_replay']._require_transport(row, side, ROOTS[side][0], roles, H)
            with self.subTest(side=side): self.reject(bad)

    def test_slot_coordinated_metadata_still_joins_baseline_origins(self):
        for side in ROOTS:
            bad = copy.deepcopy(self.proof); c = case(bad, side, 'coherent-slot-in-bss')['Coherence']
            c['OriginalAddress'] += 4; c['MutatedAddress'] += 4
            for load in c['Loads']: load['Bytes'] = struct.pack('<I', c['MutatedAddress']).hex()
            if c['NeighborSwap'] is not None:
                c['NeighborSwap']['BeforeAddress'] += 4; c['NeighborSwap']['AfterAddress'] += 4
            self.assertEqual(c['MutatedAddress'], c['OriginalAddress'] - 4)
            with self.subTest(side=side): self.reject(bad)

    def test_slot_symbol_bytes_cannot_disagree_with_coherence_flags(self):
        for side, name in (('Native', 'fiber_internal_runtime_current_context_slot'), ('Reference', 'pxCurrentTCB')):
            bad = copy.deepcopy(self.proof); c = case(bad, side, 'coherent-slot-in-bss')['Coherence']
            row = derived(bad, side, 'coherent-slot-in-bss', 'Final')
            field = symbol_field(bytes.fromhex(row['Output']['Data']), name)
            rewrite_slice(row, field['SymbolOffset'] + 4, struct.pack('<I', c['OriginalAddress']))
            with self.subTest(side=side): self.reject(bad)

    def test_callee_coordinated_metadata_and_actual_bl_are_bound(self):
        for side in ROOTS:
            for mode in ('metadata', 'branch'):
                bad = copy.deepcopy(self.proof); c = case(bad, side, 'coherent-callee-entry')['Coherence']
                if mode == 'metadata':
                    c['OriginalSize'] += 2; c['MutatedSize'] += 2
                    self.assertEqual(c['MutatedSize'], c['OriginalSize'] - 2)
                else:
                    row = derived(bad, side, 'coherent-callee-entry', 'Final')
                    raw = bytes.fromhex(row['Output']['Data']); offset, _ = root_slice(raw, c['Root'])
                    origin = symbol_field(raw, c['Root'])['Value'] & ~1
                    wrong = H['native_mutations'].encode_bl(origin + c['RootRelativeOffset'], c['MutatedAddress'] + 2)
                    rewrite_slice(row, offset + c['RootRelativeOffset'], wrong)
                    c['BranchBytes'] = wrong.hex()
                with self.subTest(side=side, mode=mode): self.reject(bad)

    def test_canonical_flags_and_dump_bytes_are_not_self_attestations(self):
        for side in ROOTS:
            for key, value in (('TransportPreservationAccepted', 1), ('CanonicalRejected', False),
                    ('TwinComparisonExecuted', True), ('SourceAuthorityPreserved', True)):
                bad = copy.deepcopy(self.proof); case(bad, side, 'coherent-svc-immediate')['Coherence'][key] = value
                with self.subTest(side=side, flag=key): self.reject(bad)
            bad = copy.deepcopy(self.proof); row = derived(bad, side, 'coherent-svc-immediate', 'Disassembly')
            raw = bytes.fromhex(row['Output']['Data'])
            pattern = rb'(?m)(\bsvc\s+)' + (b'71' if side == 'Native' else b'1') + rb'(?=\s|$)'
            changed, count = re.subn(pattern, rb'\g<1>' + (b'72' if side == 'Native' else b'2'), raw)
            self.assertEqual(count, 1); replace_output(row, changed)
            self.assertEqual(before_bytes(row), DATA[Path(row['Input']['Path'])])
            with self.subTest(side=side, target='dump'): self.reject(bad)

    def test_detached_positive_needs_no_binary_inspectors_or_io(self):
        with detached(), patch.object(H['checker'], 'check_pair', wraps=H['checker'].check_pair) as check:
            result = m.require_result(copy.deepcopy(self.proof), BATCH, PORT, ORIGINAL, FINAL, H)
        self.assertIsNot(result, False); self.assertGreaterEqual(check.call_count, 1)

    def test_reader_escape_must_reject_at_the_leaf_facade(self):
        def escape(*args, **kwargs): return Path('C:/not-a-final-control-role.o').read_bytes()
        with patch.object(H['decoder'], 'Object', side_effect=escape), \
                self.assertRaisesRegex(ValueError, 'REJECT:CM3-OS-LTO-FINAL-CONTROLS:read outside current control buffers/'):
            Model().run()

    def test_unrelated_predicate_rejection_never_becomes_control_pass(self):
        real = H['native_roots'].NativeCM3LTOImage
        calls = []
        def unrelated(*args, **kwargs):
            calls.append(args)
            if len(calls) > 1: raise core.Rejected('REJECT:UNRELATED:deliberate noncatalog predicate failure')
            return real(*args, **kwargs)
        with patch.object(H['native_roots'], 'NativeCM3LTOImage', side_effect=unrelated), \
                self.assertRaises((ValueError, RuntimeError)):
            Model().run()
        self.assertGreaterEqual(len(calls), 2)

    def test_first_seen_buffers_and_input_objects_are_not_overwritten(self):
        self.assertEqual((self.model.batch, self.model.port, self.model.original, self.model.final), self.before)
        path = Path('C:/synthetic-first-seen.py'); buffers = {}
        retain(buffers, path, b'first'); retain(buffers, path, b'first')
        with self.assertRaisesRegex(ValueError, 'first-seen buffer collision'):
            merge(buffers, {path: b'changed'})
        self.assertEqual(buffers, {path: b'first'})

    def test_closed_coherence_records_do_not_accept_extra_claims(self):
        for side in ROOTS:
            for name in ('coherent-slot-in-bss', 'coherent-callee-entry', 'coherent-svc-immediate'):
                bad = copy.deepcopy(self.proof); case(bad, side, name)['Coherence']['Foreign'] = False
                with self.subTest(side=side, case=name): self.reject(bad)
        for side, _, row in cases(self.proof):
            for wrong in (True, row['BufferIndices'][-1]):
                bad = copy.deepcopy(self.proof); target = case(bad, side, row['Name'])
                target['BufferIndices'][0] = wrong
                with self.subTest(side=side, case=row['Name'], index=wrong): self.reject(bad)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv); output = args.output_dir.resolve(); temp = Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temp) or output.is_relative_to(ROOT):
        parser.error('fresh external TEMP output directory required')
    report = dict(Status='FAIL', Tests=0, ExpectedTests=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, FixtureHashes={}, SourceClosureVerified=False, FixtureClosureVerified=False,
        ActualOriginalBytePredicatesExercised=False, ActualFinalReplacementBytePredicatesExercised=False,
        ActualFinalControlBytePredicatesExercised=False, PortProofFromPinnedReceipt=True,
        PortComponentRecomputed=False, ActualCaptureAdmitted=False, ActualCombinedCLIReplay=False,
        CompilerInvocations=0, ToolInvocations=0, RequiredCellsSatisfied=0, Qualification=False, BoardExecution=False)
    previous = list(sys.meta_path)
    try:
        need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize,
            'fresh isolated unoptimized -I -S -B interpreter')
        with patch('subprocess.Popen', side_effect=AssertionError('no processes')), \
                patch('os.system', side_effect=AssertionError('no shell')):
            initialize()
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(ControlTests)
            need(suite.countTestCases() == METHODS and METHODS > 0, 'exact positive test method count')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            Details=[dict(Test=str(test), Error=error) for test, error in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped: report['Status'] = 'PASS'
    except BaseException:
        report.update(Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        sys.meta_path[:] = previous
    report.update(ActualOriginalBytePredicatesExercised=ORIGINAL_EXERCISED,
        ActualFinalReplacementBytePredicatesExercised=FINAL_EXERCISED,
        ActualFinalControlBytePredicatesExercised=CONTROLS_EXERCISED)
    for key, buffers in (('Source', BUFFERS), ('Fixture', FIXTURES)):
        report[key + 'Hashes'] = {str(path): sha(raw) for path, raw in buffers.items()}
        try: closed = bool(buffers) and all(path.read_bytes() == raw for path, raw in buffers.items())
        except BaseException: closed = False
        report[key + 'ClosureVerified'] = closed
        if not closed: report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False); raw = encoded(report); (output / 'results.json').write_bytes(raw)
    print(json.dumps({key: value for key, value in report.items() if key not in
        ('SourceHashes', 'FixtureHashes', 'Details', 'Error')}, sort_keys=True))
    print('ReceiptSha256=' + sha(raw))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
