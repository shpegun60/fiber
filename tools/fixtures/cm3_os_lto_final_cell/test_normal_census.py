"""Synthetic normal census wiring/forgery controls, not actual ELF evidence."""

import argparse
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 22
m = LOADED = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


class Model:
    """Invented metadata and dictionary reads; core/census calls are synthetic."""
    def __init__(self):
        self.root = Path('C:/synthetic-normal-census/batch')
        self.native_root = self.root.parent / 'native'
        self.seed = self.root.parent / 'seed'
        self.gcc = self.native_root / 'toolchain/bin/arm-none-eabi-gcc.exe'
        self.nm = self.gcc.with_name('arm-none-eabi-nm.exe')
        self.plugin = self.native_root / 'toolchain/lib/gcc/arm-none-eabi/14.3.1/liblto_plugin.dll'
        self.files, self.streams, self.reads, self.calls = {}, {}, [], []
        self.put(self.nm, b'synthetic admitted nm executable')
        self.put(self.plugin, b'synthetic admitted plugin')
        header = dict(Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
                      Cohort=m.COHORT, SourceInventorySha256=m.SOURCE)
        self.batch = dict(header, Status='BUILT-PENDING-READER', Commands=[], PortPolicyCompilations=[],
                          NativeCapture=dict(Build=str(self.native_root)))
        self.native = dict(header, Status='PASS', CapturedCompiler=str(self.gcc), Sources=[],
                           LTOPlugin=dict(Path=str(self.plugin), Sha256=sha(self.files[self.plugin])))
        for index in range(134):
            self.journal(index, 'unused synthetic command', ['synthetic-unused'])
        for index in range(9):
            stem = m.STEMS[index - 3] if 3 <= index <= 5 else 'other_' + str(index)
            source = self.seed / 'source/fiber/port/ARM_CM3' / (stem + '.c')
            obj = self.native_root / 'objects' / ('%02d-' % index + stem + '.o')
            self.put(source, ('synthetic original source/' + stem).encode('ascii'))
            self.put(obj, ('synthetic original IR/' + stem).encode('ascii'))
            self.native['Sources'].append(dict(Source=str(source), SourceSha256=sha(self.files[source]),
                                               Object=str(obj), ObjectSha256=sha(self.files[obj])))
        p = LOADED['policy']
        names = (dict.fromkeys(p.RUNTIME, 'T'), dict.fromkeys(p.BOOT, 'T'), dict.fromkeys(p.EXCEPTION, 'T'))
        names[0].update({p.PRIVATE: 'D', p.STORAGE: 'D'})
        names[1]['fiber_fallback_initial_msp'] = 'W'
        grouped = {}
        for position, (role, stem, index, first, number) in enumerate(zip(
                m.ROLES, m.STEMS, (3, 4, 5), (99, 104, 109), (103, 108, 113))):
            obj = self.root / 'port-policy/ir/selected' / (stem + '.o')
            self.put(obj, ('synthetic supported-policy IR/' + stem).encode('ascii'))
            stdout = ''.join('%s %s 0 \r\n' % item for item in names[position].items()).encode('ascii')
            definitions = LOADED['port_runner'].parse_ir_definitions(stdout)
            grouped[role] = definitions
            original = self.native['Sources'][index]
            self.batch['PortPolicyCompilations'].append(dict(Group='selected', TemplateIndex=index,
                Source=original['Source'], SourceSha256=original['SourceSha256'], Object=str(obj),
                ObjectSha256=sha(self.files[obj]), SupportedPolicy=True, IRDefinitions=definitions,
                CommandIndices=list(range(first, number + 1))))
            self.journal(number, 'definitions selected ' + stem,
                [str(self.nm), '--plugin', str(self.plugin), '-P', '-S', '--defined-only', str(obj)], stdout=stdout)
        self.batch['PortPolicyCompilations'] += [dict(Group='stress-supported'), dict(Group='stress-raw')]
        self.batch['PortPolicyIRDefinitionSurface'] = p.inspect_ir_definitions(grouped)
        links = []
        for kind in ('ordinary', 'emit-relocs'):
            final = self.native_root / kind / 'image.elf'
            machine = Path(str(final) + '.ltrans0.ltrans.o')
            self.put(final, ('synthetic original final/' + kind).encode('ascii'))
            self.put(machine, ('synthetic original worker/' + kind).encode('ascii'))
            links.append(dict(Kind=kind, Path=str(final), Sha256=sha(self.files[final]),
                              Machine=str(machine), MachineSha256=sha(self.files[machine])))
        self.native['Links'] = links
        words = [0] * 256
        words[0], words[1], words[11], words[14] = 0x20010000, 0x08000101, 0x08000201, 0x08000301
        self.vector = struct.pack('<256I', *words)
        self.native['TwinLoadImages'] = dict(Identical=True, Entry=words[1], VectorAddress=0x08000000,
            VectorBytes=self.vector.hex(), Segments=[dict(Vaddr=0x08000000, FileSize=1024, MemorySize=1024,
                                                        Flags=5, BytesSha256=sha(self.vector))])
        self.dumps = {role: (self.root.parent / 'new-cli/inspection' / (role + '.stdout'),
                             ('synthetic zero-inclusive dump/' + role).encode('ascii')) for role in ('Machine', 'Final')}
        self.bad_parser = self.bad_census = self.bad_twins = None
        self.core = SimpleNamespace(_ELF=self.image, compare_load_images=self.twins)
        self.helpers = dict(census=SimpleNamespace(inspect_lowered=self.lowered, inspect_final=self.final),
                            policy=p, port_runner=LOADED['port_runner'], guard=LOADED['guard'])
        self.seal()

    def put(self, path, raw):
        self.files[Path(path)] = raw

    def journal(self, number, label, argv, stdout=b'', stderr=b''):
        prefix = 'commands/%03d' % number
        row = dict(Label=label, Argv=argv, Cwd=str(self.root), State='TERMINAL', Status='PASS',
                   Exit=0, ExpectedExit=0, TimedOut=False, Seconds=0.125,
                   Stdout=prefix + '.stdout', Stderr=prefix + '.stderr', StdoutSha256=sha(stdout), StderrSha256=sha(stderr))
        if number == len(self.batch['Commands']):
            self.batch['Commands'].append(row)
        else:
            self.batch['Commands'][number] = row
        self.streams[number] = stdout, stderr

    def seal(self):
        for index, row in enumerate(self.batch['Commands']):
            self.files[self.root / ('commands/%03d.json' % index)] = encoded(row)
            for suffix, raw in zip(('.stdout', '.stderr'), self.streams[index]):
                self.files[self.root / ('commands/%03d%s' % (index, suffix))] = raw
        self.files[self.root / 'commands.json'] = encoded(self.batch['Commands'])
        self.batch['CommandsSha256'] = sha(self.files[self.root / 'commands.json'])
        self.catalog()

    def catalog(self):
        manifest = self.root / 'artifacts.json'
        self.files[manifest] = encoded(dict(Artifacts={path.relative_to(self.root).as_posix(): sha(raw)
            for path, raw in self.files.items() if path.is_relative_to(self.root) and path != manifest}))
        self.batch['InputHashes'] = {str(path): sha(raw) for path, raw in self.files.items() if path != manifest}

    def read(self, path, expected):
        if not isinstance(path, Path) or path not in self.files:
            raise AssertionError('unadmitted synthetic read/' + str(path))
        if expected is None and path != self.root / 'artifacts.json':
            raise AssertionError('only the caller-admitted manifest permits no explicit digest')
        raw = self.files[path]
        if expected is not None and sha(raw) != expected:
            raise ValueError('synthetic read hash mismatch')
        self.reads.append((path, expected))
        return raw

    def image(self, path, kind):
        self.calls.append(('image', path, kind))
        return SimpleNamespace(data=self.files[path] + (b'foreign bytes' if self.bad_parser == 'bytes' else b''),
                               final=(1 if self.bad_parser == 'type' else kind == 'ET_EXEC'))

    def census(self, image, dump, surface, *, final):
        self.calls.append(('census', final, dump, copy.deepcopy(surface)))
        if self.bad_census == 'reject':
            raise ValueError('synthetic unchanged predicate rejection')
        result = dict(Status='CM3-OS-LTO-PORT-CENSUS-PASS', Scope='CM3_OS_LTO_PORT_MACHINE_CENSUS_ONLY',
            Profile='CM3', Mode='Os-lto', ObjectSha256=sha(image.data), DisassemblySha256=sha(dump), FinalELF=final,
            DefinitionSurface=copy.deepcopy(surface), DefinitionsFromIR=[dict(name=x['Name']) for x in surface['Definitions']],
            FunctionsAudited=1, FunctionEvidence=[dict(Name='synthetic_function', Instructions=1, DataBytes=0,
                BodySha256=sha(b'synthetic function'), Symbol={}, References=[])],
            ExecutableInstructionBytes=2, ExecutableMappedDataBytes=0, CompleteExecutableCensus=True,
            ForbiddenDependenciesAbsent=True, RecognizedForbiddenFormsAbsent=True,
            Undefined=[] if final else sorted(LOADED['policy'].FINAL_WORKER_UNDEFINED), RequiredCellsSatisfied=0,
            **dict.fromkeys(m.CENSUS_NONCLAIMS, False))
        if final:
            result['FinalRootVectorBindings'] = dict(Words=256, VectorSha256=sha(self.vector),
                Entry=0x08000101, SVC=0x08000201, PendSV=0x08000301, AllocatedFileBackedLoadValidated=True,
                CanonicalRootProtocolsValidated=False)
        if self.bad_census == 'mode':
            result['Mode'] = 'O2-lto'
        if self.bad_census == 'hash':
            result['ObjectSha256'] = '0' * 64
        return result

    def lowered(self, image, core, dump, surface, policy, *, whole_image):
        if whole_image is not True or image.final is not False:
            raise AssertionError('original whole-image worker role required')
        return self.census(image, dump, surface, final=False)

    def final(self, image, core, dump, surface, policy):
        if image.final is not True:
            raise AssertionError('original final role required')
        return self.census(image, dump, surface, final=True)

    def twins(self, ordinary, emitted):
        self.calls.append(('twins', ordinary, emitted))
        result = copy.deepcopy(self.native['TwinLoadImages'])
        if self.bad_twins:
            result['Identical'] = False
        return result

    def run(self, **kwargs):
        args = dict(batch=self.batch, native=self.native, root=self.root, core=self.core,
                    helpers=self.helpers, read=self.read, dumps=self.dumps)
        args.update(kwargs)
        return m.inspect(**args)


class NormalTests(unittest.TestCase):
    def test_complete_typed_original_composition_and_nonclaims(self):
        model = Model()
        proof = model.run()
        self.assertIs(m.require_result(proof), proof)
        self.assertEqual(proof['Status'], m.STATUS)
        self.assertEqual([x['DefinitionCommandIndex'] for x in proof['SourceCohort']], [103, 108, 113])
        self.assertEqual([x['Role'] for x in proof['SourceCohort']], list(m.ROLES))
        self.assertEqual(len(proof['DefinitionSurface']['Definitions']), 31)
        self.assertEqual(len(proof['ReadInputs']), 23)
        for field in m.NONCLAIMS:
            self.assertIs(proof[field], False)
        self.assertEqual(proof['RequiredCellsSatisfied'], 0)

    def test_no_filesystem_process_loading_or_input_mutation(self):
        model = Model()
        before = copy.deepcopy((model.batch, model.native, model.files, model.dumps))
        with ExitStack() as stack:
            for field in ('read_bytes', 'read_text', 'open', 'resolve', 'absolute', 'stat', 'lstat', 'exists',
                          'is_file', 'is_dir', 'samefile', 'iterdir', 'glob', 'rglob'):
                stack.enter_context(patch.object(Path, field, side_effect=AssertionError('filesystem/' + field)))
            for field in ('stat', 'lstat', 'scandir', 'listdir', 'system', 'getcwd'):
                stack.enter_context(patch.object(os, field, side_effect=AssertionError('physical/' + field)))
            stack.enter_context(patch.object(subprocess, 'Popen', side_effect=AssertionError('process execution')))
            stack.enter_context(patch.object(importlib.util, 'spec_from_file_location', side_effect=AssertionError('module loading')))
            stack.enter_context(patch('builtins.open', side_effect=AssertionError('file access')))
            proof = model.run()
        self.assertEqual(before, (model.batch, model.native, model.files, model.dumps))
        proof['DefinitionSurface']['Definitions'].clear()
        self.assertEqual(len(model.batch['PortPolicyIRDefinitionSurface']['Definitions']), 31)

    def test_real_plugin_grammar_and_surface_used_not_o2_verdicts(self):
        model = Model()
        with patch.object(LOADED['policy'], 'supported_flags', side_effect=AssertionError('no O2 flag builder')), \
                patch.object(LOADED['port_runner'], 'succeeded', side_effect=AssertionError('no O2 verdict')):
            result = model.run()
        self.assertTrue(result['SelectedIRDefinitionProvenanceValidated'])
        self.assertTrue(all(item['Value'] == 0 and item['Size'] is None for item in result['DefinitionSurface']['Definitions']))

    def test_per_command_only_json_corruption_is_rejected(self):
        for index in (103, 108, 113):
            model = Model(); path = model.root / ('commands/%03d.json' % index)
            value = json.loads(model.files[path]); value['Exit'] = False
            model.files[path] = encoded(value); model.catalog()
            with self.subTest(index=index), self.assertRaisesRegex(m.Rejected, 'per-command definition journal'):
                model.run()

    def test_json_float_overflow_rejected_before_journal_comparison(self):
        for raw in (b'1e999', b'-1e999', b'{"Seconds":1e999}', b'[0.125,-1e999]'):
            with self.subTest(raw=raw), self.assertRaisesRegex(m.Rejected, 'nonfinite JSON number'):
                m._json(raw)
        for raw in (b'Infinity', b'-Infinity', b'NaN'):
            with self.subTest(raw=raw), self.assertRaisesRegex(m.Rejected, 'nonfinite JSON/'):
                m._json(raw)
        self.assertEqual(m._json(b'{"Seconds":1.25,"Large":1e308,"Small":1e-999}'),
                         dict(Seconds=1.25, Large=1e308, Small=0.0))
        self.assertEqual(m._json(b'"1e999"'), '1e999')
        model = Model(); path = model.root / 'commands/103.json'
        original = model.files[path]
        model.files[path] = original.replace(b'"Seconds": 0.125', b'"Seconds": 1e999')
        self.assertNotEqual(model.files[path], original)
        model.catalog()
        with self.assertRaisesRegex(m.Rejected, 'nonfinite JSON number'):
            model.run()

    def test_both_journal_copies_foreign_tool_plugin_object_or_flags_rejected(self):
        for index in (103, 108, 113):
            for defect in ('tool', 'plugin', 'object', 'flags', 'label', 'cwd'):
                model = Model(); row = model.batch['Commands'][index]
                if defect in ('tool', 'plugin', 'object'):
                    position = {'tool': 0, 'plugin': 2, 'object': -1}[defect]
                    row['Argv'][position] = 'C:/foreign-input'
                elif defect == 'flags':
                    row['Argv'].remove('--defined-only')
                elif defect == 'label':
                    row['Label'] = 'definitions foreign'
                else:
                    row['Cwd'] = 'C:/foreign'
                model.seal()
                with self.subTest(index=index, defect=defect), self.assertRaises(m.Rejected):
                    model.run()

    def test_terminal_status_types_and_clean_streams(self):
        for field, value in (('Exit', False), ('ExpectedExit', False), ('TimedOut', 0), ('Seconds', True),
                             ('Seconds', -1), ('State', 'ATTEMPT'), ('Status', 'FAIL'), ('JournalErrors', ['error'])):
            model = Model(); model.batch['Commands'][103][field] = value; model.seal()
            with self.subTest(field=field, value=value), self.assertRaises(m.Rejected):
                model.run()
        for defect in ('stderr', 'stdout-empty', 'stream-path', 'stream-hash'):
            model = Model(); row = model.batch['Commands'][103]
            if defect == 'stderr':
                model.streams[103] = model.streams[103][0], b'warning'
                row['StderrSha256'] = sha(b'warning')
            elif defect == 'stdout-empty':
                model.streams[103] = b'', b''; row['StdoutSha256'] = sha(b'')
            elif defect == 'stream-path':
                row['Stdout'] = 'commands/108.stdout'
            else:
                row['StdoutSha256'] = '0' * 64
            model.seal()
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):
                model.run()

    def test_forged_stored_surface_is_comparison_only(self):
        for target in ('surface', 'rows', 'both'):
            model = Model()
            if target != 'rows': model.batch['PortPolicyIRDefinitionSurface']['PublicFunctions'] = 28
            if target != 'surface': model.batch['PortPolicyCompilations'][0]['IRDefinitions'].pop()
            with self.subTest(target=target), self.assertRaises(m.Rejected): model.run()

    def test_corrupt_nm_bytes_and_matching_claims_cannot_change_fixed_surface(self):
        for defect in ('missing', 'duplicate', 'foreign-name', 'nonzero', 'size', 'malformed'):
            model = Model(); lines = model.streams[103][0].decode('ascii').splitlines()
            if defect == 'missing': lines.pop()
            elif defect == 'duplicate': lines.append(lines[0])
            elif defect == 'foreign-name': lines[0] = 'foreign_provider D 0 '
            elif defect == 'nonzero': lines[0] = lines[0].replace(' 0 ', ' 1 ', 1)
            elif defect == 'size': lines[0] += '4'
            else: lines[0] = 'not a plugin row'
            stdout = ('\r\n'.join(lines) + '\r\n').encode('ascii')
            model.streams[103] = stdout, b''; model.batch['Commands'][103]['StdoutSha256'] = sha(stdout)
            if defect != 'malformed':
                model.batch['PortPolicyCompilations'][0]['IRDefinitions'] = LOADED['port_runner'].parse_ir_definitions(stdout)
            model.seal()
            with self.subTest(defect=defect), self.assertRaises(m.Rejected): model.run()

    def test_selected_paths_source_hashes_and_fixed_record_ranges(self):
        for field, value in (('Object', 'C:/foreign.o'), ('ObjectSha256', '0' * 64), ('Source', 'C:/foreign.c'),
                             ('SourceSha256', '0' * 64), ('TemplateIndex', 4), ('SupportedPolicy', 1),
                             ('Group', 'stress-supported'), ('CommandIndices', [103])):
            model = Model(); model.batch['PortPolicyCompilations'][0][field] = value
            with self.subTest(field=field), self.assertRaises(m.Rejected): model.run()

    def test_admitted_object_source_and_plugin_identities_required(self):
        for role in ('selected', 'native-object', 'source', 'plugin', 'nm'):
            model = Model()
            path = {'selected': Path(model.batch['PortPolicyCompilations'][0]['Object']),
                    'native-object': Path(model.native['Sources'][3]['Object']),
                    'source': Path(model.native['Sources'][3]['Source']), 'plugin': model.plugin, 'nm': model.nm}[role]
            del model.batch['InputHashes'][str(path)]
            if role == 'selected':
                manifest = json.loads(model.files[model.root / 'artifacts.json'])
                del manifest['Artifacts'][path.relative_to(model.root).as_posix()]
                model.files[model.root / 'artifacts.json'] = encoded(manifest)
            with self.subTest(role=role), self.assertRaises(m.Rejected): model.run()

    def test_original_targets_derived_not_replacement_final(self):
        model = Model(); proof = model.run()
        self.assertEqual([call[1] for call in model.calls if call[0] == 'image'],
                         [Path(model.native['Links'][1]['Machine']), Path(model.native['Links'][1]['Path'])])
        self.assertEqual([call for call in model.calls if call[0] == 'twins'],
                         [('twins', Path(model.native['Links'][0]['Path']), Path(model.native['Links'][1]['Path']))])
        self.assertFalse(proof['ReplacementGeneratedBodyIdentity'])
        for field in ('Machine', 'Path', 'Sha256', 'MachineSha256'):
            model = Model(); model.native['Links'][1][field] = 'C:/replacement' if not field.endswith('Sha256') else '0' * 64
            with self.subTest(field=field), self.assertRaises(m.Rejected): model.run()

    def test_content_only_dump_pairs_are_not_read_from_filesystem(self):
        model = Model(); result = model.run()
        self.assertFalse(any(path in [pair[0] for pair in model.dumps.values()] for path, _ in model.reads))
        self.assertTrue(result['CallerOwnsDumpJournalBinding']); self.assertFalse(result['DumpCollectionProvenanceValidated'])
        for defect in ('missing', 'extra', 'string-path', 'mutable-bytes', 'empty', 'same-path'):
            model = Model(); dumps = dict(model.dumps)
            if defect == 'missing': del dumps['Final']
            elif defect == 'extra': dumps['Replacement'] = dumps['Final']
            elif defect == 'string-path': dumps['Final'] = str(dumps['Final'][0]), dumps['Final'][1]
            elif defect == 'mutable-bytes': dumps['Final'] = dumps['Final'][0], bytearray(dumps['Final'][1])
            elif defect == 'empty': dumps['Final'] = dumps['Final'][0], b''
            else: dumps['Final'] = dumps['Machine'][0], dumps['Final'][1]
            with self.subTest(defect=defect), self.assertRaises(m.Rejected): model.run(dumps=dumps)

    def test_parser_exact_bytes_and_boolean_role_required(self):
        for defect in ('bytes', 'type'):
            model = Model(); model.bad_parser = defect
            with self.subTest(defect=defect), self.assertRaises(m.Rejected): model.run()

    def test_census_rejection_o2_result_and_foreign_hash_fail_closed(self):
        for defect in ('reject', 'mode', 'hash'):
            model = Model(); model.bad_census = defect
            with self.subTest(defect=defect), self.assertRaises(m.Rejected): model.run()

    def test_twins_recomputed_not_trusted_and_vector_consistency_enforced(self):
        model = Model(); model.bad_twins = True
        with self.assertRaises(m.Rejected): model.run()
        for defect in ('Identical', 'Entry', 'VectorBytes', 'Segments'):
            proof = Model().run()
            proof['Twins'][defect] = {'Identical': 1, 'Entry': False, 'VectorBytes': '00', 'Segments': []}[defect]
            with self.subTest(defect=defect), self.assertRaises(m.Rejected): m.require_result(proof)

    def test_result_literal_counts_and_nonclaims_are_strict(self):
        baseline = Model().run()
        for field in ('DefinitionCommands', 'SelectedSources', 'OriginalMachineRoles', 'TwinImages', 'RequiredCellsSatisfied'):
            for value in (True, 1, '0'):
                proof = copy.deepcopy(baseline); proof[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(m.Rejected): m.require_result(proof)
        for field in m.NONCLAIMS:
            for value in (True, 0):
                proof = copy.deepcopy(baseline); proof[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(m.Rejected): m.require_result(proof)
        proof = copy.deepcopy(baseline); proof['WholeCellProof'] = True
        with self.assertRaises(m.Rejected): m.require_result(proof)

    def test_result_census_fields_cannot_be_narrowed_or_promoted(self):
        baseline = Model().run()
        for role in ('OriginalLtrans', 'OriginalFinal'):
            for field, value in (('CompleteExecutableCensus', 1), ('FunctionsAudited', True), ('FunctionEvidence', []),
                    ('ObjectSha256', '0' * 64), ('DisassemblySha256', '0' * 64), ('FinalELF', 1),
                    ('RequiredCellsSatisfied', False), ('Undefined', ['foreign']), ('ExecutableInstructionBytes', False)):
                proof = copy.deepcopy(baseline); proof[role][field] = value
                with self.subTest(role=role, field=field), self.assertRaises(m.Rejected): m.require_result(proof)
            for field in m.CENSUS_NONCLAIMS:
                proof = copy.deepcopy(baseline); proof[role][field] = True
                with self.subTest(role=role, field=field), self.assertRaises(m.Rejected): m.require_result(proof)

    def test_result_cohort_surface_and_read_accounting_are_closed(self):
        baseline = Model().run()
        for defect in ('cohort', 'bool-index', 'surface', 'reads', 'read-hash', 'extra-read', 'original'):
            proof = copy.deepcopy(baseline)
            if defect == 'cohort': proof['SourceCohort'].reverse()
            elif defect == 'bool-index': proof['SourceCohort'][0]['Definitions'][0]['Value'] = False
            elif defect == 'surface': proof['DefinitionSurface']['PublicFunctions'] = True
            elif defect == 'reads': proof['ReadInputs'].pop()
            elif defect == 'read-hash':
                target = proof['SourceCohort'][0]['Source']
                next(x for x in proof['ReadInputs'] if x['Path'] == target)['Sha256'] = '0' * 64
            elif defect == 'extra-read': proof['ReadInputs'][0]['Path'] = 'C:/foreign-read'
            else: proof['OriginalInputs']['OriginalLtrans']['Path'] = 'C:/foreign-worker.o'
            with self.subTest(defect=defect), self.assertRaises(m.Rejected): m.require_result(proof)

    def test_reader_wrong_bytes_or_mutable_bytes_and_malformed_manifest(self):
        for defect in ('bytes', 'type', 'duplicate-json', 'manifest-traversal', 'commands'):
            model = Model()
            if defect == 'duplicate-json': model.files[model.root / 'artifacts.json'] = b'{"Artifacts":{},"Artifacts":{}}'
            elif defect == 'manifest-traversal':
                value = json.loads(model.files[model.root / 'artifacts.json']); value['Artifacts']['../foreign'] = '0' * 64
                model.files[model.root / 'artifacts.json'] = encoded(value)
            elif defect == 'commands':
                value = copy.deepcopy(model.batch['Commands']); value[103]['Exit'] = False
                model.files[model.root / 'commands.json'] = encoded(value)
                model.batch['CommandsSha256'] = sha(model.files[model.root / 'commands.json']); model.catalog()
            def read(path, expected):
                value = model.read(path, expected)
                if path == model.root / 'commands/103.stdout':
                    if defect == 'bytes': return value + b'foreign'
                    if defect == 'type': return bytearray(value)
                return value
            with self.subTest(defect=defect), self.assertRaises(m.Rejected): model.run(read=read)

    def test_no_implicit_helpers_foreign_mode_or_unadmitted_scope(self):
        for defect in ('helper', 'batch-mode', 'native-mode', 'bool-lto', 'root', 'reader'):
            model = Model(); kwargs = {}
            if defect == 'helper': kwargs['helpers'] = dict(model.helpers, implicit_runner=object())
            elif defect == 'batch-mode': model.batch['Mode'] = 'O2-lto'
            elif defect == 'native-mode': model.native['Mode'] = 'O2-lto'
            elif defect == 'bool-lto': model.batch['LTO'] = 1
            elif defect == 'root': kwargs['root'] = Path('relative')
            else: kwargs['read'] = None
            with self.subTest(defect=defect), self.assertRaises(m.Rejected): model.run(**kwargs)

    def test_source_objects_and_definitions_trace_own_bytes(self):
        model = Model(); proof = model.run()
        reads = dict(model.reads)
        for row in proof['SourceCohort']:
            for field in ('Source', 'NativeObject', 'SelectedObject'):
                self.assertEqual(reads[Path(row[field])], row[field + 'Sha256'])
            stdout = model.root / ('commands/%03d.stdout' % row['DefinitionCommandIndex'])
            self.assertEqual(reads[stdout], row['DefinitionStdoutSha256'])
        self.assertIsNone(reads[model.root / 'artifacts.json'])
        self.assertTrue(all(expected is not None for path, expected in model.reads if path != model.root / 'artifacts.json'))


def main():
    global m, LOADED
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.absolute()
    if output.exists() or output == ROOT or ROOT in output.parents:
        raise SystemExit('fresh external output directory required')
    paths = dict(leaf=HERE / 'normal_census.py', policy=ROOT / 'tools/fixtures/cm3_lto_port_policy/policy.py',
                 port_runner=ROOT / 'tools/fixtures/cm3_lto_port_policy/runner.py', guard=HERE / 'batch_guard.py')
    sources = (Path(__file__).resolve(), *paths.values())
    buffers = {path: path.read_bytes() for path in sources}
    opening = {str(path): sha(value) for path, value in buffers.items()}
    LOADED = {}
    for name, path in paths.items():
        spec = importlib.util.spec_from_file_location('_normal_census_test_' + name, path)
        module = importlib.util.module_from_spec(spec)
        exec(compile(buffers[path], str(path), 'exec'), module.__dict__)
        LOADED[name] = module
    m = LOADED['leaf']
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NormalTests))
    closing = {str(path): sha(path.read_bytes()) for path in sources}
    report = dict(Status='PASS' if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped
                  and opening == closing else 'FAIL', Tests=result.testsRun, Errors=len(result.errors),
                  Failures=len(result.failures), Skipped=len(result.skipped), SourceHashes=opening,
                  SourceDrift=opening != closing, SyntheticControlsOnly=True, ActualMachineBytesValidated=False,
                  CompilerExecuted=False, SourceToIRSemanticProof=False, SourceToMachineSemanticProof=False,
                  Qualification=False, RequiredCellsSatisfied=0)
    output.mkdir(parents=True)
    (output / 'results.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n', encoding='ascii')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
