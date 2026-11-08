"""Bounded synthetic adapter controls using both actual frozen slot helpers."""

import argparse
from contextlib import ExitStack
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 20
PINS = {
    'os_slot': (HERE / 'slot.py', 'B47B8ACF2F98172D79509BC60DF42D4603F3FAF7CEC9F1BA29995057621F7F9F'),
    'neutral': (HERE.parent / 'cm3_lto_isolation/slot.py', '669F294A622B076984E36F6FA9C73235BD0D3F778AA4A36F496051D49DE822B3'),
    'fixture': (HERE / 'test_slot.py', 'EC6EC3F2ADFB25747897927FCFE587F2F7C0DCBECD6A602C6C75B4425E4330C2'),
}
m = os_slot = neutral = fixture = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


class Model:
    def __init__(self):
        self.roles, self.files, self.calls, self.reads = {}, {}, [], []
        self.fixtures = {kind: fixture.Fixture() for kind in ('Original', 'Isolated')}
        for name in m.ROLES:
            path = Path('C:/synthetic-os-slots/producer') / (name + '.bin')
            self.files[path] = ('role/' + name).encode('ascii')
            self.roles[name] = dict(Role=name, Path=str(path), Sha256=sha(self.files[path]))
        self.dump = Path('C:/synthetic-os-slots/normal/original-final.dis')
        self.files[self.dump] = b'fresh dump: r10,r11\n'
        self.files[self.path('OriginalDisassembly')] = b'producer dump: sl,fp\n'
        self.refresh()
        f = self.fixtures['Original']
        self.core = types.SimpleNamespace(FinalImage=self.construct, _width=f.core._width,
            _address_form=f.core._address_form)

    def path(self, name):
        return Path(self.roles[name]['Path'])

    def refresh(self):
        for kind, f in self.fixtures.items():
            self.files[self.path(kind + 'Machine')] = f.machine.data
            self.files[self.path(kind + 'EmitELF')] = f.final.data
            self.files[self.path(kind + 'Assembly')] = f.assembly
        self.files[self.path('PortSource')] = self.fixtures['Original'].source
        for row in self.roles.values():
            row['Sha256'] = sha(self.files[Path(row['Path'])])

    def change(self, role, raw):
        self.files[self.path(role)] = raw
        self.roles[role]['Sha256'] = sha(raw)

    def read(self, path, expected):
        if not isinstance(path, Path) or path not in self.files:
            raise AssertionError('unowned read/' + str(path))
        if expected != sha(self.files[path]):
            raise AssertionError('wrong expected hash/' + str(path))
        self.reads.append((path, expected))
        return self.files[path]

    def construct(self, machine, final, disassembly, *, provider_objects, link_map, float_abi):
        kind = next(kind for kind in m.KINDS if self.path(kind + 'Machine') == machine)
        expected_dump = self.dump if kind == 'Original' else self.path('IsolatedDisassembly')
        assert (final, disassembly, link_map, float_abi) == (
            self.path(kind + 'EmitELF'), expected_dump, self.path(kind + 'Map'), 'soft')
        startup = self.path('StartupObject')
        assert provider_objects == {str(machine): machine, str(startup): startup}
        for path in (machine, final, disassembly, link_map, startup):
            assert path.read_bytes() == self.files[path]
        self.calls.append((kind, machine, final, disassembly, dict(provider_objects)))
        f = self.fixtures[kind]
        identity = str(machine).replace('\\', '/').casefold()
        f.image.providers = {identity: f.machine,
            str(startup).replace('\\', '/').casefold(): types.SimpleNamespace(
                data=self.files[startup], final=False, sections=[], symbols=[], relocations={})}
        f.image.placements = {(identity, section): placement
            for (_, section), placement in f.image.placements.items()}
        f.image.hashes = dict(PrelinkSha256=sha(self.files[machine]),
            FinalSha256=sha(self.files[final]), DisassemblySha256=sha(self.files[disassembly]))
        f.image.link_map_hash = sha(self.files[link_map])
        return f.image

    def run(self, **changes):
        kwargs = dict(core=self.core, read=self.read, roles=self.roles,
            os_slot=os_slot, neutral_slot=neutral, original_dump=(self.dump, self.files[self.dump]))
        kwargs.update(changes)
        return m.inspect(**kwargs)


class AdapterTests(unittest.TestCase):
    def test_two_actual_os_predicates_and_nineteen_bound_reads(self):
        model = Model()
        with patch.object(neutral, 'inspect', side_effect=AssertionError('no O2 verdict')), \
                patch.object(os_slot, 'inspect', wraps=os_slot.inspect) as inspect, \
                patch.object(os_slot, 'require_result', wraps=os_slot.require_result) as require:
            proof = model.run()
        self.assertIs(m.require_result(proof), proof)
        self.assertEqual(inspect.call_count, 2)
        self.assertGreaterEqual(require.call_count, 2)
        self.assertEqual([x[0] for x in model.calls], ['Original', 'Isolated'])
        self.assertEqual(len(model.reads), 19)
        self.assertEqual(len({p for p, _ in model.reads}), 19)
        self.assertEqual(proof['InputRoles'], 18)
        self.assertEqual(proof['ReadFiles'], 19)
        for kind in m.KINDS:
            self.assertEqual(proof['SlotProofs'][kind]['CommonBytes'], 272)
            self.assertEqual(proof['SlotProofs'][kind]['AppliedSlotReferences'], 8)

    def test_exact_role_membership_before_reads(self):
        for name in m.ROLES:
            model = Model()
            del model.roles[name]
            with self.subTest(name=name), self.assertRaises(m.Rejected):
                model.run()
            self.assertEqual(model.reads, [])
        model = Model()
        model.roles['Foreign'] = copy.deepcopy(model.roles['PortSource'])
        with self.assertRaises(m.Rejected):
            model.run()
        self.assertEqual(model.reads, [])

    def test_role_records_types_hashes_and_extra_fields(self):
        for field, value in (('Role', True), ('Role', 'other'), ('Path', Path('C:/x')),
                ('Sha256', 'a' * 64), ('Sha256', True), ('Sha256', 'F' * 63), ('Extra', False)):
            model = Model()
            model.roles['PortSource'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(m.Rejected):
                model.run()
        for roles in ([], None, True):
            with self.subTest(roles=roles), self.assertRaises(m.Rejected):
                Model().run(roles=roles)

    def test_lexical_paths_reject_traversal_unc_and_aliases(self):
        for path in ('relative.c', 'C:relative.c', '//server/share/a', 'C:/x/../a',
                'C:/x/./a', 'C:/x//a', 'C:/x/a.', 'C:/x/a ', 'C:/x/a:stream', 'C:/x/a\n'):
            model = Model()
            model.roles['PortSource']['Path'] = path
            with self.subTest(path=path), self.assertRaises(m.Rejected):
                model.run()

    def test_distinct_paths_allow_identical_bytes_not_aliased_roles(self):
        model = Model()
        self.assertEqual(model.roles['OriginalMachine']['Sha256'], model.roles['IsolatedMachine']['Sha256'])
        model.run()
        model = Model()
        model.roles['IsolatedMachine']['Path'] = model.roles['OriginalMachine']['Path']
        with self.assertRaisesRegex(m.Rejected, 'distinct role paths'):
            model.run()

    def test_all_role_bytes_are_verified_even_unused_ir_and_plain_images(self):
        for name in m.ROLES:
            model = Model()
            wrong = model.path(name)
            def read(path, digest):
                raw = model.read(path, digest)
                return raw + b'wrong' if path == wrong else raw
            with self.subTest(name=name), self.assertRaisesRegex(m.Rejected, 'immutable reader bytes'):
                model.run(read=read)
            self.assertEqual(model.calls, [])
        for raw in (None, bytearray(b'x'), 'bytes'):
            with self.subTest(raw=raw), self.assertRaises(m.Rejected):
                Model().run(read=lambda path, digest: raw)

    def test_fresh_original_dump_differs_and_is_the_constructor_input(self):
        model = Model()
        self.assertNotEqual(model.files[model.dump], model.files[model.path('OriginalDisassembly')])
        proof = model.run()
        self.assertEqual(model.calls[0][3], model.dump)
        self.assertEqual(model.calls[1][3], model.path('IsolatedDisassembly'))
        self.assertEqual(proof['OriginalDump'], dict(Path=str(model.dump), Sha256=sha(model.files[model.dump])))
        self.assertIn(model.path('OriginalDisassembly'), dict(model.reads))

    def test_fresh_dump_shape_distinctness_and_callback_bytes(self):
        model = Model()
        for pair in (None, [], [model.dump, b'x'], ('C:/x', b'x'), (model.dump, bytearray(b'x')),
                     (model.dump, b''), (model.path('OriginalDisassembly'), b'x')):
            with self.subTest(pair=pair), self.assertRaises(m.Rejected):
                model.run(original_dump=pair)
        for value in (b'foreign', bytearray(model.files[model.dump])):
            def read(path, digest):
                return value if path == model.dump else model.read(path, digest)
            with self.subTest(value=value), self.assertRaises(m.Rejected):
                model.run(read=read)

    def test_constructor_cannot_read_available_but_unowned_buffer(self):
        model = Model()
        extra = Path('C:/synthetic-os-slots/available-not-a-role.bin')
        model.files[extra] = b'available'
        def construct(*args, **kwargs):
            extra.read_bytes()
        with self.assertRaisesRegex(m.Rejected, 'outside local role buffers'):
            model.run(core=types.SimpleNamespace(FinalImage=construct))

    def test_constructor_text_decode_is_strict_and_local(self):
        model = Model()
        original = model.construct
        def construct(*args, **kwargs):
            self.assertEqual(model.dump.read_text(encoding='ascii'), model.files[model.dump].decode('ascii'))
            with self.assertRaises(m.Rejected):
                model.dump.read_text(encoding='utf-16')
            with self.assertRaises(m.Rejected):
                model.dump.read_text(errors='ignore')
            with self.assertRaises(m.Rejected):
                Path('C:/unowned.txt').read_text()
            return original(*args, **kwargs)
        model.core.FinalImage = construct
        model.run()

    def test_exact_machine_final_parser_bytes_and_literal_final_flags(self):
        for target, field, value in (('prelink', 'data', b'foreign'), ('final', 'data', b'foreign'),
                ('prelink', 'final', 0), ('final', 'final', 1)):
            model = Model()
            original = model.construct
            def construct(*args, **kwargs):
                image = original(*args, **kwargs)
                setattr(getattr(image, target), field, value)
                return image
            model.core.FinalImage = construct
            with self.subTest(target=target, field=field), self.assertRaisesRegex(m.Rejected, 'exact parsed image bytes'):
                model.run()

    def test_provider_membership_and_startup_bytes_cannot_be_forged(self):
        for defect in ('missing', 'extra', 'startup-data', 'startup-final'):
            model = Model()
            original = model.construct
            def construct(*args, **kwargs):
                image = original(*args, **kwargs)
                startup = str(model.path('StartupObject')).replace('\\', '/').casefold()
                if defect == 'missing':
                    del image.providers[startup]
                elif defect == 'extra':
                    image.providers['C:/foreign.o'] = image.prelink
                elif defect == 'startup-data':
                    image.providers[startup].data = b'foreign'
                else:
                    image.providers[startup].final = True
                return image
            model.core.FinalImage = construct
            with self.subTest(defect=defect), self.assertRaisesRegex(m.Rejected, 'exact explicit provider bytes'):
                model.run()

    def test_map_and_constructor_hashes_must_bind_admitted_buffers(self):
        for field in ('link_map_hash', 'PrelinkSha256', 'FinalSha256', 'DisassemblySha256'):
            model = Model()
            original = model.construct
            def construct(*args, **kwargs):
                image = original(*args, **kwargs)
                if field == 'link_map_hash':
                    image.link_map_hash = 'F' * 64
                else:
                    image.hashes[field] = 'F' * 64
                return image
            model.core.FinalImage = construct
            with self.subTest(field=field), self.assertRaisesRegex(m.Rejected, 'parsed image input hashes'):
                model.run()

    def test_rebound_source_and_assembly_mutants_reach_real_os_predicate(self):
        for role in ('PortSource', 'OriginalAssembly', 'IsolatedAssembly'):
            model = Model()
            model.change(role, b'foreign source\n')
            with self.subTest(role=role), self.assertRaises(os_slot.Rejected):
                model.run()

    def test_rebound_machine_mutant_is_not_saved_proof_authority(self):
        for kind in m.KINDS:
            model = Model()
            f = model.fixtures[kind]
            f.machine.write(4, 0, b'\x00\xbf')
            model.refresh()
            with self.subTest(kind=kind), self.assertRaises(os_slot.Rejected):
                model.run()

    def test_forged_helper_result_hash_provider_and_extra_claim_reject(self):
        for defect in ('hash', 'provider', 'extra'):
            model = Model()
            original = os_slot.inspect
            def forged(*args, **kwargs):
                proof = original(*args, **kwargs)
                if defect == 'hash':
                    proof['SourceSha256'] = 'F' * 64
                elif defect == 'provider':
                    proof['SlotOrigin']['Provider'] = 'foreign.o'
                else:
                    proof['Qualified'] = False
                return proof
            supplied = types.SimpleNamespace(inspect=forged, require_result=os_slot.require_result)
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):
                model.run(os_slot=supplied)

    def test_returned_closed_schema_typed_counts_and_nonclaims(self):
        baseline = Model().run()
        for key in m.COUNTS:
            proof = copy.deepcopy(baseline)
            proof[key] = True
            with self.subTest(key=key), self.assertRaises(m.Rejected):
                m.require_result(proof)
        for key in m.NONCLAIMS:
            proof = copy.deepcopy(baseline)
            proof[key] = 0
            with self.subTest(key=key), self.assertRaises(m.Rejected):
                m.require_result(proof)
        for key in m.FACTS:
            proof = copy.deepcopy(baseline)
            proof[key] = 1
            with self.subTest(key=key), self.assertRaises(m.Rejected):
                m.require_result(proof)
        with self.assertRaises(m.Rejected):
            m.require_result(dict(baseline, Qualified=True))

    def test_returned_nested_proofs_and_read_closure_cannot_be_forged(self):
        for defect in ('missing', 'duplicate', 'hash', 'dump', 'proof-hash', 'claim', 'body-provider',
                'body-count', 'reference-kind', 'reference-offset', 'raw-symbol', 'handler-count',
                'handler-pair', 'source-pair', 'generated-pair'):
            proof = Model().run()
            slot = proof['SlotProofs']['Original']
            if defect == 'missing':
                proof['ReadInputs'].pop()
            elif defect == 'duplicate':
                proof['ReadInputs'][1] = proof['ReadInputs'][0]
            elif defect == 'hash':
                proof['ReadInputs'][0]['Sha256'] = 'F' * 64
            elif defect == 'dump':
                proof['OriginalDump']['Path'] = proof['Inputs']['OriginalDisassembly']['Path']
            elif defect == 'proof-hash':
                slot['MachineSha256'] = 'F' * 64
            elif defect == 'claim':
                slot['CompleteHandlerBodiesValidated'] = True
            elif defect == 'body-provider':
                slot['CommonBodies'][0]['Origin']['Provider'] = 'foreign.o'
            elif defect == 'body-count':
                slot['CommonBodies'][0]['Size'] = True
            elif defect == 'reference-kind':
                slot['CommonBodies'][0]['References'][0]['Kind'] = True
            elif defect == 'reference-offset':
                slot['CommonBodies'][0]['References'][0]['InputOffset'] = False
            elif defect == 'raw-symbol':
                slot['CommonBodies'][0]['References'][0]['OriginalRelocationSymbol']['size'] = True
            elif defect == 'handler-count':
                slot['HandlerLoads'][0]['MachineLiteralLoads'] = True
            elif defect == 'handler-pair':
                slot['HandlerLoads'][0]['DereferenceOffset'] += 2
            elif defect == 'source-pair':
                slot['SourcePairs'][0]['Register'] = 'r7'
            else:
                slot['GeneratedPairs'][0]['Owner'] = 'foreign'
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):
                m.require_result(proof)

    def test_no_filesystem_process_or_loader_and_patch_restoration(self):
        model = Model()
        with ExitStack() as stack:
            for name in ('open', 'resolve', 'absolute', 'stat', 'lstat', 'exists', 'is_file', 'is_dir', 'iterdir', 'glob', 'rglob'):
                stack.enter_context(patch.object(Path, name, side_effect=AssertionError('physical/' + name)))
            stack.enter_context(patch('builtins.open', side_effect=AssertionError('open')))
            stack.enter_context(patch.object(subprocess, 'Popen', side_effect=AssertionError('process')))
            stack.enter_context(patch.object(os, 'system', side_effect=AssertionError('shell')))
            stack.enter_context(patch.object(importlib.util, 'spec_from_file_location', side_effect=AssertionError('loader')))
            model.run()
        previous_bytes, previous_text = Path.read_bytes, Path.read_text
        def fail(*args, **kwargs):
            raise RuntimeError('constructor failure')
        with self.assertRaisesRegex(RuntimeError, 'constructor failure'):
            Model().run(core=types.SimpleNamespace(FinalImage=fail))
        self.assertIs(Path.read_bytes, previous_bytes)
        self.assertIs(Path.read_text, previous_text)

    def test_no_input_or_helper_global_mutation_and_no_output_aliases(self):
        model = Model()
        before = copy.deepcopy((model.roles, model.files))
        programs = copy.deepcopy(os_slot.PROGRAMS)
        helper_globals = dict(neutral.__dict__)
        proof = model.run()
        self.assertEqual((model.roles, model.files), before)
        self.assertEqual(os_slot.PROGRAMS, programs)
        self.assertEqual(neutral.__dict__, helper_globals)
        proof['Inputs']['PortSource']['Role'] = 'foreign'
        proof['SlotProofs']['Original']['SlotOrigin']['Name'] = 'foreign'
        self.assertEqual(model.roles['PortSource']['Role'], 'PortSource')
        self.assertEqual(model.fixtures['Original'].machine.symbol(fixture.SLOT)['name'], fixture.SLOT)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.absolute()
    temporary = Path(tempfile.gettempdir()).absolute()
    if output.exists() or output.is_relative_to(ROOT) or not output.is_relative_to(temporary):
        parser.error('fresh external TEMP output required')
    paths = dict(subject=HERE / 'isolation_slots.py', test=Path(__file__).resolve(),
        **{name: row[0] for name, row in PINS.items()})
    buffers = {name: path.read_bytes() for name, path in paths.items()}
    opening = {str(paths[name]): sha(raw) for name, raw in buffers.items()}
    for name, (_, digest) in PINS.items():
        if sha(buffers[name]) != digest:
            raise ValueError('frozen fixture/helper pin/' + name)
    if not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode or sys.flags.optimize:
        raise ValueError('fresh unoptimized -I -S -B required')
    modules = {}
    for name in ('neutral', 'os_slot', 'fixture', 'subject'):
        module = types.ModuleType('_isolation_slots_test_' + name)
        module.__file__ = str(paths[name])
        exec(compile(buffers[name], str(paths[name]), 'exec'), module.__dict__)
        modules[name] = module
    global m, os_slot, neutral, fixture
    m, os_slot, neutral, fixture = (modules[name] for name in ('subject', 'os_slot', 'neutral', 'fixture'))
    fixture.helper, fixture.subject = neutral, os_slot
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AdapterTests)
    if suite.countTestCases() != METHODS:
        raise ValueError('exact bounded method count')
    with patch.object(subprocess, 'Popen', side_effect=AssertionError('pure test process')):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    closing = {str(path): sha(path.read_bytes()) for path in paths.values()}
    report = dict(Status='PASS' if result.wasSuccessful() and result.testsRun == METHODS
        and not result.skipped and opening == closing else 'FAIL', Tests=result.testsRun,
        ExpectedTests=METHODS, Failures=len(result.failures), Errors=len(result.errors),
        Skipped=len(result.skipped), SourceHashes=opening, SourceDrift=opening != closing,
        ClosingFilesVerified=len(closing), SyntheticModels=True, FrozenOsPredicatesExecuted=True,
        ActualELFParsed=False, ToolInvocations=0, CompilerInvocations=0, RequiredCellsSatisfied=0,
        Qualification=False, FullABIProof=False, CpuExecution=False, BoardExecution=False,
        Details=[dict(Test=str(test), Detail=detail) for test, detail in result.failures + result.errors])
    output.mkdir(parents=True)
    receipt = output / 'results.json'
    receipt.write_bytes((json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
