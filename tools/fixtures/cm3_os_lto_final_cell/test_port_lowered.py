"""Bounded synthetic adapter controls with genuine frozen worker/census leafs."""

import argparse
from contextlib import ExitStack
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace as NS
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 20
PINS = {
    'port_runner': ('cm3_lto_port_policy/runner.py', 'E06E55AC26B3828EDA54333DC7D5E0982DCC791694A2E9FE64E2A31C3BBE9AAB'),
    'port_phase': ('cm3_os_lto_final_cell/port_policy_phase.py', '371821947E1F14E0C0DEBC5561EFD3EF8B539B20C9B00F288A8534143D29EB80'),
    'census': ('cm3_os_lto_final_cell/port_census.py', 'B3967886026A4082656380222ADB6451473F055E201E8383C6B9E555F9BC0D65'),
    'policy': ('cm3_lto_port_policy/policy.py', '8FC3AD729BF8903D716E34579700FC22D417040156EFCF0B434D2C43D75F0CA0'),
    'effects': ('cm3_os_lto_final_cell/common_effects.py', '800942F1CA34DCE0198258C13D85F5BA422DF6BF88726694360C16B39270C81D'),
    'attributes': ('cm3_lto_attributes/attributes.py', '93275A5903A67CB2DAEABB76BEF1431B052878BB478455E54343DB20881E83C0'),
    'transport': ('cm3_lto_transport/probe.py', 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626'),
    'port_model': ('cm3_lto_port_policy/test_policy.py', '34B4F6663E765D9D093789F9EFD441DEA657C64F718E3946BC8049097BDEC24D'),
    'stress_model': ('cm3_os_lto_final_cell/test_common_effects.py', '0387FAEA413970B821EC0D8439DFF61C2B2EE7742F9C621BE0B30CF0A085D0BB'),
}
API = M = H = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def arguments(values):
    return ('\n'.join(value.replace('\\', '\\\\') for value in values) + '\n').encode('ascii')


def elf_header(image):
    raw = bytearray(image.data)
    struct.pack_into('<I', raw, 32, len(raw))
    struct.pack_into('<H', raw, 40, 52)
    struct.pack_into('<HH', raw, 46, 40, 1)
    image.data = bytes(raw) + bytes(40)
    return image


class Fixture:
    def __init__(self):
        self.root = Path('C:/synthetic-port-lowered')
        self.raw, self.images, self.roles, self.plans = {}, {}, {}, []
        self.reads, self.parsed = [], []
        self.on_parse = None
        self.lto1 = Path('C:/synthetic-native/toolchain/libexec/lto1.exe')
        self.assembler = Path('C:/synthetic-native/toolchain/bin/as.exe')
        self.raw[self.lto1], self.raw[self.assembler] = b'lto1 authority', b'assembler authority'
        originals = [Path('C:/synthetic-native/objects') / ('%02d-native.o' % i) for i in range(9)]
        for path in originals:
            self.raw[path] = ('synthetic native object ' + path.name).encode('ascii')
        self.native = dict(Status='PASS', Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
            Sources=[dict(Object=str(p), ObjectSha256=sha(self.raw[p])) for p in originals],
            ResolvedWorkers={name: self.binding(path) for name, path in
                             (('lto1', self.lto1), ('as', self.assembler))})
        self.originals = originals
        selected = [self.root / 'port-policy/ir/selected' / (name + '.o')
                    for name in ('fiber_port', 'fiber_port_boot', 'fiber_port_exception')]
        self.surface = H['policy'].inspect_ir_definitions(M['port_model'].ir_rows())
        for index, group in enumerate(('selected', 'stress-supported', 'stress-raw', 'Final')):
            supported = index != 2
            output = self.root / 'port-policy/final-supported/image.elf' if index == 3 else self.root / 'port-policy/lowered' / group / 'aggregate.o'
            objects = selected if index == 0 else ([self.root / 'port-policy/ir' / group / 'stress.o'] if index < 3
                else originals[:3] + selected + originals[6:])
            for obj in objects:
                self.raw.setdefault(obj, ('synthetic slim IR ' + str(obj)).encode('ascii'))
            for suffix in API.SUFFIXES:
                self.raw[Path(str(output) + suffix)] = ('retained binding only ' + suffix).encode('ascii')
            self.raw[self.wrapper(output)] = b'retained wrapper bytes, not semantics'
            specs = self.root / 'port-policy/driver/no-auto-gcov.specs' if not supported else None
            if specs is not None:
                self.raw[specs] = b'authenticated adapted driver specs'
            for role in ('ELF', 'Machine') if index == 3 else ('Aggregate', 'Machine'):
                path = output if role != 'Machine' else Path(str(output) + '.ltrans0.ltrans.o')
                if index in (0, 3):
                    image = M['port_model'].SyntheticELF(final=role == 'ELF', whole=index == 3)
                    image.model_kind = 'port'
                    if image.final:
                        image.loads = [dict(Vaddr=s.header.sh_addr, FileSize=s.header.sh_size,
                            MemorySize=s.header.sh_size, Flags=5 if i == 1 else 4, Offset=s.header.sh_offset)
                            for i, s in enumerate(image.sections) if i]
                    dump = image.dis()
                else:
                    image = M['stress_model'].Image(stress=True, raw_stress=not supported)
                    image.model_kind = 'stress'
                    dump = ('Disassembly of section .text:\n' +
                            ''.join(' %x: bf00 nop\n' % i for i in range(0, 32, 2))).encode('ascii')
                self.images[path] = elf_header(image)
                self.raw[path] = image.data
                self.raw[Path(str(path) + '.dis')] = dump
            if index == 3:
                self.raw[output.with_suffix('.map')] = b'retained map bytes, not transfer semantics'
            flags = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os',
                     *M['port_phase'].RAW_FLAGS, *(M['port_phase'].COUNTER_FLAGS if supported else ())]
            lower = ['-flto-partition=one', '-flinker-output=exec' if index == 3 else '-flinker-output=nolto-rel']
            if index != 3:
                lower += ['-nostdlib', '-r']
            options = flags + lower + ([] if specs is None else ['-specs=' + str(specs)])
            intermediate = Path(str(output) + '.ltrans0.o')
            machine = Path(str(output) + '.ltrans0.ltrans.o')
            ir = [p for p in objects if p != originals[8]]
            self.raw[Path(str(output) + '.ltrans_args')] = arguments([*options, '-fwpa', *map(str, ir)])
            self.raw[Path(str(output) + '.ltrans0.ltrans_args')] = arguments(
                [*options, '-fltrans', '-o', str(machine), str(intermediate)])
            self.raw[Path(str(output) + '.wpa.args.0')] = arguments(list(map(str, ir)))
            self.raw[Path(str(output) + '.ltrans0.ltrans.args.0')] = arguments([str(intermediate)])
            self.raw[Path(str(output) + '.ltrans.out')] = ('1\n' + str(intermediate) + '\n').encode('ascii')
            invocations = [[str(self.lto1), *flags, '-fwpa', '@' + str(output) + '.wpa.args.0'],
                [str(self.lto1), *flags, '-fltrans', '-o', str(output) + '.ltrans0.ltrans.s',
                 '@' + str(output) + '.ltrans0.ltrans.args.0'],
                [str(self.assembler), '-o', str(machine), str(output) + '.ltrans0.ltrans.s']]
            diagnostic = self.root / ('commands/%03d.stderr' % (114, 121, 128, 131)[index])
            self.raw[diagnostic] = ''.join(' ' + ' '.join(row) + '\n' for row in invocations).encode('ascii')
            self.plans.append(dict(Component='PortPolicy', Group=group, Output=output,
                Objects=list(objects), Specs=specs, Diagnostics=self.raw[diagnostic],
                Supported=supported, StoredWorker={}))
            paths = (('Final/ELF', output), ('Final/Map', output.with_suffix('.map')),
                ('Final/Disassembly', Path(str(output) + '.dis')), ('Final/Machine', machine),
                ('Final/MachineDisassembly', Path(str(machine) + '.dis')), ('Final/Startup', originals[8])) if index == 3 else (
                (group + '/Aggregate', output), (group + '/AggregateDisassembly', Path(str(output) + '.dis')),
                (group + '/Machine', machine), (group + '/MachineDisassembly', Path(str(machine) + '.dis')))
            for role, path in paths:
                self.roles[role] = dict(Role=role, **self.binding(path))
        for plan in self.plans:
            plan['StoredWorker'] = H['port_runner'].worker_chain(self.view(), plan['Output'], plan['Objects'],
                plan['Diagnostics'], supported=plan['Supported'], specs=plan['Specs'])
        self.refresh()
        fixture = self

        class Parsed:
            def __init__(self, path, kind):
                fixture.parsed.append((Path(path), kind))
                if fixture.on_parse:
                    fixture.on_parse(Path(path))
                self.__dict__.update(copy.deepcopy(fixture.images[Path(path)].__dict__))
                self.data = Path(path).read_bytes()

            def mapping(self, section, position):
                cls = M['stress_model'].Image if self.model_kind == 'stress' else M['port_model'].SyntheticELF
                return cls.mapping(self, section, position)

            def section_read(self, section, offset, size):
                return M['port_model'].SyntheticELF.section_read(self, section, offset, size)

        def address_form(raw, place):
            return (M['stress_model'].address_form(raw, place) if len(raw) == 4
                    else M['port_model'].literal(raw, place))
        self.core = NS(_ELF=Parsed, _width=M['port_model'].width, _address_form=address_form)

    def wrapper(self, output):
        return self.root / (''.join(output.parts[1:]) + '.lto_wrapper_args')

    def binding(self, path):
        return dict(Path=str(path), Sha256=sha(self.raw[path]))

    def view(self):
        def read(path, digest=None):
            raw = self.raw[path]
            if digest is not None and sha(raw) != digest:
                raise ValueError('fixture hash mismatch')
            return raw
        return NS(watch=NS(read=read), api=NS(checked_path=lambda p: Path(p)),
            result=self.native, objects=self.originals, transport=H['transport'],
            modules={'policy': H['port_phase']}, admitted=NS(base=NS(stable_path=lambda p: Path(p))))

    def refresh(self):
        for row in self.roles.values():
            row['Sha256'] = sha(self.raw[Path(row['Path'])])
        self.raw[self.root / 'artifacts.json'] = encoded(dict(Artifacts={
            path.relative_to(self.root).as_posix(): sha(raw) for path, raw in self.raw.items()
            if path.is_relative_to(self.root) and path != self.root / 'artifacts.json'}))

    def read(self, path, digest=None):
        if not isinstance(path, Path) or path not in self.raw:
            raise ValueError('fixture read outside explicit authority')
        self.reads.append((path, digest))
        if digest is not None and sha(self.raw[path]) != digest:
            raise ValueError('fixture hash mismatch')
        return self.raw[path]

    def run(self, **kwargs):
        return API.inspect(self.core, kwargs.pop('read', self.read), self.plans, self.native,
                           kwargs.pop('helpers', H), roles=self.roles, ir_definitions=self.surface, **kwargs)


class LoweredTests(unittest.TestCase):
    def reject(self, fixture, **kwargs):
        with self.assertRaises(ValueError):
            fixture.run(**kwargs)

    def test_four_real_chains_eight_real_os_censuses_and_strict_return(self):
        f = Fixture()
        with patch.object(H['port_runner'], 'worker_chain', wraps=H['port_runner'].worker_chain) as chains, \
                patch.object(H['census'], 'inspect_lowered', wraps=H['census'].inspect_lowered) as selected, \
                patch.object(H['census'], 'inspect_stress', wraps=H['census'].inspect_stress) as stress, \
                patch.object(H['census'], 'inspect_final', wraps=H['census'].inspect_final) as final:
            proof = f.run()
        self.assertEqual((chains.call_count, selected.call_count, stress.call_count, final.call_count), (4, 3, 4, 1))
        self.assertEqual(len(f.parsed), 8)
        self.assertEqual([kind for _, kind in f.parsed], ['ET_REL'] * 6 + ['ET_EXEC', 'ET_REL'])
        self.assertEqual(len(f.reads), len({p for p, _ in f.reads}))
        self.assertEqual(proof['ReadFiles'], len(f.reads))
        self.assertIs(API.require_result(proof, H), proof)
        self.assertEqual(json.loads(encoded(proof)), proof)

    def test_non_alphabetic_symbol_order_is_valid_but_reordering_is_not(self):
        p = Fixture().run()
        rows = p['Machines'][0]['Images'][0]['Proof']['FunctionEvidence']
        self.assertNotEqual([r['Name'] for r in rows], sorted(r['Name'] for r in rows))
        self.assertEqual([r['Symbol']['index'] for r in rows], sorted(r['Symbol']['index'] for r in rows))
        rows[0], rows[1] = rows[1], rows[0]
        with self.assertRaisesRegex(ValueError, 'symbol-table function order'):
            API.require_result(p, H)

    def test_exact_helpers_no_o2_predicates_flag_builders_or_binder(self):
        for key in H:
            f = Fixture()
            self.reject(f, helpers={k: v for k, v in H.items() if k != key})
            self.assertFalse(f.reads)
        f = Fixture()
        self.reject(f, helpers=dict(H, worker_bindings=NS()))
        with ExitStack() as s:
            for key, names in (('policy', ('supported_flags', 'require_effective_options', 'inspect_lowered', 'inspect_final', 'inspect_stress')),
                    ('port_phase', ('flags_for', 'final_arguments', 'command_plan')),
                    ('port_runner', ('flags_for', 'policy_flags', 'inspect_outputs', 'link_final'))):
                for name in names:
                    s.enter_context(patch.object(M[key], name, side_effect=AssertionError('not a neutral API')))
            self.assertEqual(Fixture().run()['Status'], API.PASS)

    def test_plan_membership_order_types_and_support_are_not_inferred(self):
        for defect in ('missing', 'extra', 'order', 'field', 'component', 'supported', 'str-path', 'diagnostics'):
            f = Fixture()
            if defect == 'missing': f.plans.pop()
            elif defect == 'extra': f.plans.append(copy.deepcopy(f.plans[0]))
            elif defect == 'order': f.plans.reverse()
            elif defect == 'field': f.plans[0]['Claim'] = True
            elif defect == 'component': f.plans[0]['Component'] = 'CommonAttributes'
            elif defect == 'supported': f.plans[0]['Supported'] = 1
            elif defect == 'str-path': f.plans[0]['Output'] = str(f.plans[0]['Output'])
            else: f.plans[0]['Diagnostics'] = bytearray(f.plans[0]['Diagnostics'])
            with self.subTest(defect=defect): self.reject(f)

    def test_exact_eighteen_roles_and_independent_fixed_paths(self):
        for role in Fixture().roles:
            for defect in ('missing', 'path', 'role', 'field'):
                f = Fixture()
                if defect == 'missing': f.roles.pop(role)
                elif defect == 'path': f.roles[role]['Path'] = 'C:/foreign/forged.o'
                elif defect == 'role': f.roles[role]['Role'] = 'foreign'
                else: f.roles[role]['Claim'] = True
                with self.subTest(role=role, defect=defect): self.reject(f)
        f = Fixture(); f.roles['foreign'] = dict(f.roles['Final/ELF']); self.reject(f)

    def test_lexical_paths_hash_types_and_reader_byte_contract(self):
        for value in ('relative.o', 'C:relative.o', '//host/share/a.o', 'C:/a/../aggregate.o',
                      'C:/a/./aggregate.o', 'C:/a//aggregate.o', 'C:/a./aggregate.o', 'C:/a\0/aggregate.o'):
            f = Fixture(); f.plans[0]['Output'] = Path(value) if value == 'relative.o' else value
            self.reject(f)
        for value in (None, 1, 'a' * 64, 'A' * 63):
            f = Fixture(); f.roles['selected/Aggregate']['Sha256'] = value; self.reject(f)
        for value in (None, '', bytearray(b'{}'), b''):
            self.reject(Fixture(), read=lambda *args, value=value: value)
        f = Fixture(); path = Path(f.roles['Final/Startup']['Path']); f.raw[path] += b'changed'; self.reject(f)

    def test_manifest_grammar_membership_and_no_unbound_saved_inputs(self):
        for defect in ('duplicate', 'traversal', 'missing-response', 'two-wrappers', 'bad-hash'):
            f = Fixture(); path = f.root / 'artifacts.json'
            if defect == 'duplicate': f.raw[path] = b'{"Artifacts":{},"Artifacts":{}}'
            else:
                manifest = json.loads(f.raw[path])
                if defect == 'traversal': manifest['Artifacts']['../escape.o'] = 'A' * 64
                elif defect == 'missing-response': manifest['Artifacts'].pop('port-policy/lowered/selected/aggregate.o.wpa.args.0')
                elif defect == 'bad-hash': manifest['Artifacts']['port-policy/lowered/selected/aggregate.o.res'] = 0
                else: manifest['Artifacts']['port-policy/lowered/selected/aggregate.o.lto_wrapper_args'] = 'A' * 64
                f.raw[path] = encoded(manifest)
            with self.subTest(defect=defect): self.reject(f)
        f = Fixture(); optional = Path(str(f.plans[2]['Output']) + '.wpa.gcno')
        f.raw[optional] = b'bound optional coverage notes'; f.refresh()
        self.assertIn(str(optional), {x['Path'] for x in f.run()['ReadInputs']})

    def test_native_authority_final_cohort_and_metadata_only_originals(self):
        for key, value in (('Status', 'FAIL'), ('Mode', 'O2-lto'), ('Profile', 'CM0'), ('Linkage', 'archive'), ('LTO', 1)):
            f = Fixture(); f.native[key] = value; self.reject(f)
        for defect in ('object-order', 'startup', 'worker-hash', 'worker-alias', 'object-hash'):
            f = Fixture()
            if defect == 'object-order': f.plans[-1]['Objects'].reverse()
            elif defect == 'startup': f.roles['Final/Startup']['Path'] = str(f.originals[7])
            elif defect == 'worker-hash': f.native['ResolvedWorkers']['as']['Sha256'] = 'A' * 64
            elif defect == 'worker-alias': f.native['ResolvedWorkers']['as'] = dict(f.native['ResolvedWorkers']['lto1'])
            else: f.native['Sources'][0]['ObjectSha256'] = 'A' * 64
            self.reject(f)
        f = Fixture(); p = f.run(); reads = {Path(r['Path']) for r in p['ReadInputs']}
        self.assertEqual([i for i, path in enumerate(f.originals) if path in reads], [0, 1, 2, 6, 7, 8])
        self.assertEqual(len(p['NativeObjects']), 9)

    def test_specs_only_raw_stress_and_actual_worker_not_authority(self):
        for index in (0, 1, 3):
            f = Fixture(); f.plans[index]['Specs'] = f.plans[2]['Specs']; self.reject(f)
        f = Fixture(); f.plans[2]['Specs'] = None; self.reject(f)
        f = Fixture(); f.plans[0]['StoredWorker']['MachineSha256'] = 'A' * 64
        with patch.object(H['port_runner'], 'worker_chain', wraps=H['port_runner'].worker_chain) as called:
            self.reject(f)
        called.assert_called_once()

    def test_saved_os_options_stage_and_late_override_rejections(self):
        for extra in ('-O2', '-finstrument-functions', '-mfpu=fpv4-sp-d16', '-mno-general-regs-only', '-fltrans'):
            f = Fixture(); path = Path(str(f.plans[0]['Output']) + '.ltrans_args')
            f.raw[path] += (extra + '\n').encode('ascii'); f.refresh()
            self.reject(f)
        f = Fixture(); path = Path(str(f.plans[2]['Output']) + '.ltrans_args')
        f.raw[path] += b'-fno-profile-arcs\n'; f.refresh(); self.reject(f)

    def test_response_order_partition_and_native_startup_exclusion(self):
        for suffix, raw in (('.wpa.args.0', b'C:\\foreign.o\n'), ('.ltrans0.ltrans.args.0', b'C:\\foreign.o\n'),
                            ('.ltrans.out', b'1\nC:\\foreign.o\n')):
            f = Fixture(); f.raw[Path(str(f.plans[0]['Output']) + suffix)] = raw; f.refresh(); self.reject(f)
        f = Fixture(); output = f.plans[-1]['Output']; path = Path(str(output) + '.wpa.args.0')
        f.raw[path] += arguments([str(f.originals[8])]); f.refresh(); self.reject(f)
        p = Fixture().run()
        self.assertEqual(len(p['WorkerChains'][-1]['Proof']['WpaInputs']), 8)

    def test_diagnostic_stages_options_responses_and_assembler_bindings(self):
        for old, new in ((b'-fwpa', b'-fltrans'), (b'-Os', b'-O2'), (b'lto1.exe', b'other.exe'),
                         (b'.wpa.args.0', b'.foreign.args'), (b'as.exe', b'unknown.exe'),
                         (b'.ltrans.s', b'.foreign.s')):
            f = Fixture(); path = f.root / 'commands/114.stderr'
            f.raw[path] = f.raw[path].replace(old, new, 1)
            f.plans[0]['Diagnostics'] = f.raw[path]; f.refresh(); self.reject(f)

    def test_parser_must_consume_bound_bytes_and_actual_final_kind(self):
        for defect in ('bytes', 'kind'):
            f = Fixture()
            if defect == 'bytes': f.images[Path(f.roles['selected/Aggregate']['Path'])].data += b'foreign'
            else: f.images[Path(f.roles['Final/ELF']['Path'])].final = False
            if defect == 'bytes':
                original = f.core._ELF
                class Forged(original):
                    def __init__(self, path, kind):
                        super().__init__(path, kind); self.data += b'forged parser bytes'
                f.core._ELF = Forged
            self.reject(f)

    def test_local_buffer_escape_and_no_physical_or_module_fallback(self):
        f = Fixture(); original = Path.read_bytes
        with ExitStack() as s:
            for name in ('stat', 'lstat', 'open', 'exists', 'resolve', 'iterdir', 'glob', 'rglob'):
                s.enter_context(patch.object(Path, name, side_effect=AssertionError('physical API disabled')))
            for name in ('builtins.open', 'os.open', 'os.stat', 'os.lstat', 'importlib.util.spec_from_file_location'):
                s.enter_context(patch(name, side_effect=AssertionError('physical/module API disabled')))
            self.assertEqual(f.run()['Status'], API.PASS)
            f.on_parse = lambda p: Path('C:/outside/unadmitted.py').read_bytes()
            self.reject(f)
        self.assertIs(Path.read_bytes, original)

    def test_disassembly_and_selected_definition_surface_reject_mutation(self):
        for role in ('selected/AggregateDisassembly', 'Final/Disassembly'):
            f = Fixture(); path = Path(f.roles[role]['Path'])
            f.raw[path] = f.raw[path].replace(b'bf00', b'0000', 1); f.refresh(); self.reject(f)
        for defect in ('missing', 'claim', 'kind', 'bool'):
            f = Fixture()
            if defect == 'missing': f.surface['Definitions'].pop()
            elif defect == 'claim': f.surface['FullIRSemantics'] = True
            elif defect == 'kind': f.surface['Definitions'][0]['Kind'] = 'D'
            else: f.surface['PublicFunctions'] = True
            self.reject(f)

    def test_vector_scope_map_startup_hashes_and_literal_outer_nonclaims(self):
        p = Fixture().run()
        self.assertEqual(p['Machines'][-1]['Images'][0]['Proof']['FinalRootVectorBindings']['Words'], 256)
        for key in API.NONCLAIMS:
            for value in (True, 0):
                q = copy.deepcopy(p); q[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError): API.require_result(q, H)
        for role in ('Final/Map', 'Final/Startup'):
            q = copy.deepcopy(p); q['Inputs'][role]['Sha256'] = 'A' * 64
            with self.assertRaises(ValueError): API.require_result(q, H)

    def test_returned_worker_deep_fields_types_controls_and_comparison(self):
        p = Fixture().run()
        for defect in ('field', 'header-bool', 'header-bounds', 'input', 'response', 'options',
                       'assembler', 'control', 'stored', 'support'):
            q = copy.deepcopy(p); worker = q['WorkerChains'][0]['Proof']
            if defect == 'field': worker['Qualification'] = True
            elif defect == 'header-bool': worker['MachineHeader']['SectionCount'] = True
            elif defect == 'header-bounds': worker['MachineHeader']['SectionOffset'] = 10**9
            elif defect == 'input': worker['WpaInputs'].reverse()
            elif defect == 'response': worker['Execution']['WorkerInvocations'][0]['ResponseSha256'] = 'A' * 64
            elif defect == 'options': worker['WpaOptions']['EffectiveOptionsVerified'] = 1
            elif defect == 'assembler': worker['Execution']['Assembler']['Argv'][-1] = 'C:/foreign.s'
            elif defect == 'control': q['ControlBytes'][next(iter(q['ControlBytes']))] += '00'
            elif defect == 'stored': q['Plans'][0]['StoredWorker']['MachineSha256'] = 'A' * 64
            else: worker['SupportedPolicy'] = 1
            with self.subTest(defect=defect), self.assertRaises(ValueError): API.require_result(q, H)

    def test_returned_census_closed_fields_projections_and_vector_nonclaims(self):
        p = Fixture().run()
        for defect in ('field', 'body', 'reference', 'owner', 'projection', 'count', 'symbol', 'vector', 'order'):
            q = copy.deepcopy(p); leaf = q['Machines'][0]['Images'][0]['Proof']
            if defect == 'field': leaf['IndependentDecoderValidated'] = True
            elif defect == 'body': leaf['FunctionEvidence'][0]['BodySha256'] = 'bad'
            elif defect == 'reference': leaf['References'][0]['AppliedDestinationValidated'] = True
            elif defect == 'owner': leaf['References'][0]['Owner'] = 'foreign'
            elif defect == 'projection': leaf['FunctionEvidence'][0]['References'].append(dict(leaf['References'][0]))
            elif defect == 'count': leaf['FunctionsAudited'] = True
            elif defect == 'symbol': leaf['FunctionEvidence'][0]['Symbol']['SourceProof'] = True
            elif defect == 'vector': q['Machines'][-1]['Images'][0]['Proof']['FinalRootVectorBindings']['CanonicalRootProtocolsValidated'] = True
            else: q['Machines'].reverse()
            with self.subTest(defect=defect), self.assertRaises(ValueError): API.require_result(q, H)

    def test_returned_stress_effects_and_full_local_read_membership(self):
        p = Fixture().run()
        for defect in ('field', 'root', 'counter', 'projection', 'clean', 'import', 'extra-read', 'bool-count'):
            q = copy.deepcopy(p); leaf = q['Machines'][2]['Images'][0]['Proof']
            if defect == 'field': leaf['Effects']['FullInstructionSemantics'] = True
            elif defect == 'root': leaf['Effects']['RootEvidence'][0]['WholePolicy'] = True
            elif defect == 'counter': leaf['Effects']['StressCounterEvidence']['Definition']['kind'] = 'STT_FUNC'
            elif defect == 'projection': leaf['Effects']['StressCounterEvidence']['References'] = []
            elif defect == 'clean': leaf['CleanPredicateRejected'] = False
            elif defect == 'import': leaf['Effects']['CompilerImports'] = []
            elif defect == 'extra-read': q['ReadInputs'].append(dict(Path='C:/foreign.bin', Sha256='A'*64, Bytes=1)); q['ReadFiles'] += 1
            else: q['ReadFiles'] = True
            with self.subTest(defect=defect), self.assertRaises(ValueError): API.require_result(q, H)

    def test_no_caller_or_callback_mutation_and_failure_restores_local_patch(self):
        f = Fixture(); before = copy.deepcopy((f.plans, f.roles, f.surface, f.native, f.raw))
        callback, physical = M['policy'].require_effective_options, Path.read_bytes
        p = f.run(); self.assertEqual(before, (f.plans, f.roles, f.surface, f.native, f.raw))
        p['Plans'][0]['StoredWorker']['MachineSha256'] = 'A' * 64
        self.assertEqual(before, (f.plans, f.roles, f.surface, f.native, f.raw))
        f.on_parse = lambda p: (_ for _ in ()).throw(RuntimeError('synthetic constructor failure'))
        with self.assertRaises(RuntimeError): f.run()
        self.assertIs(M['policy'].require_effective_options, callback)
        self.assertIs(Path.read_bytes, physical)


def main(argv=None):
    global API, M, H
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    output, temp = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temp) or output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
        parser.error('fresh external TEMP receipt directory required')
    paths = dict(subject=HERE / 'port_lowered.py', tests=Path(__file__).resolve())
    paths.update({name: ROOT / 'tools/fixtures' / row[0] for name, row in PINS.items()})
    buffers = {name: path.read_bytes() for name, path in paths.items()}
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_OS_PORT_LOWERED_ADAPTER', Tests=0,
        ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={str(paths[name]): sha(raw) for name, raw in buffers.items()}, SourceDrift=[],
        SourceClosureVerified=False, SyntheticELFMetadata=True, ActualELFParsed=False,
        ActualCaptureRead=False, ActualOsCodegenValidated=False, ExternalToolsExecuted=0,
        Qualification=False, CpuExecution=False, BoardExecution=False, RequiredCellsSatisfied=0)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('fresh unoptimized -I -S -B interpreter required')
        for name, row in PINS.items():
            if sha(buffers[name]) != row[1]:
                raise ValueError('frozen pure helper/model source pin/' + name)
        with patch('subprocess.Popen', side_effect=AssertionError('synthetic suite cannot start processes')), \
                patch('os.system', side_effect=AssertionError('synthetic suite cannot execute shell')):
            M = {}
            for name, raw in buffers.items():
                if name == 'tests':
                    continue
                module = ModuleType('_os_port_lowered_test_' + name)
                module.__file__ = str(paths[name])
                exec(compile(raw, str(paths[name]), 'exec'), module.__dict__)
                M[name] = module
            API = M['subject']
            policy_names = ('ROLES', 'FORWARD', 'NAKED', 'LOCAL', 'UNDEFINED', 'FINAL_WORKER_UNDEFINED',
                'FORBIDDEN', 'FORBIDDEN_FORMS', '_header', '_symbols', '_forms', '_disassembly', 'inspect_ir_definitions')
            attribute_names = ('_header', '_functions', '_symbol_fields', '_walk', '_resolved', 'Rejected',
                'PROTECTED', 'FORWARD', 'THREAD', 'THREAD_SECTION', 'COLD', 'SETTER', 'PANIC', 'STRESS',
                'MUTATIONS', 'HOOKS', 'COLD_IMPORTS', 'STRESS_FAMILIES')
            H = dict(port_runner=M['port_runner'], port_phase=M['port_phase'], census=M['census'],
                effects=M['effects'], transport=NS(require_elf32le=M['transport'].require_elf32le),
                policy=NS(**{name: getattr(M['policy'], name) for name in policy_names}),
                attributes=NS(**{name: getattr(M['attributes'], name) for name in attribute_names}))
            tests = unittest.defaultTestLoader.loadTestsFromTestCase(LoweredTests)
            if tests.countTestCases() != METHODS:
                raise ValueError('exact method count/' + str(tests.countTestCases()))
            result = unittest.TextTestRunner(verbosity=2).run(tests)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), Details=[dict(Test=str(case), Error=error)
                for case, error in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except BaseException:
        report.update(Errors=report['Errors'] + 1, Error=traceback.format_exc())
    for path, expected in report['SourceHashes'].items():
        try:
            if sha(Path(path).read_bytes()) != expected:
                report['SourceDrift'].append(path)
        except OSError:
            report['SourceDrift'].append(path)
    report['SourceClosureVerified'] = len(report['SourceHashes']) == len(PINS) + 2 and not report['SourceDrift']
    if not report['SourceClosureVerified']:
        report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes((json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
