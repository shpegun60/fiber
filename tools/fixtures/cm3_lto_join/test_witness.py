"""Pure synthetic CM3 LTO join-witness admission/closure, not ELF qualification.

Qualified parser/root execution is mocked. Role, artifact and edit bytes below
are in-memory synthetic metadata fixtures, never actual target/tool outputs.
"""
import argparse
import ast
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
WITNESS = HERE / 'witness.py'
UTILITY = HERE.parent / 'cm3_lto_transport/probe.py'
MUTATORS = {'Native': HERE.parent / 'cm3_lto_roots/mutations.py',
            'Reference': HERE.parent / 'cm3_reference_lto_roots/mutations.py'}
NATIVE_ROOTS = ('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')
REFERENCE_ROOTS = ('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler')
w = p = None
SOURCE_BYTES = {}


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def module(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    exec(compile(data, str(path), 'exec'), result.__dict__)
    return result


def record(side):
    names = NATIVE_ROOTS if side == 'Native' else REFERENCE_ROOTS
    roots = [dict(Name=name, Synthetic=True) for name in names]
    proof = dict(Status='NATIVE-CANONICAL-PASS-NOT-REFERENCE-QUALIFIED' if side == 'Native'
                 else 'REFERENCE-CANONICAL-PASS-NOT-PAIRED-QUALIFIED',
        CanonicalProtocolValidated=True, ClosedBodies=3, Roots=copy.deepcopy(roots),
        MatchEvidence=[dict(Name=name, Side=side, TailNops=0) for name in names])
    rows = [dict(Name='synthetic-control-%02d' % index, Status='PASS', ImmutableInputBuffersConsumed=True,
                 ClosingFilesVerified=5, Files=[dict(Synthetic=True) for _ in range(5)], Edits=[dict(Synthetic=True)])
            for index in range(16)]
    result = dict(Status='MACHINE-ROOT-WITNESS-PASS-NOT-QUALIFIED' if side == 'Native'
                  else 'REFERENCE-MACHINE-ROOT-PASS-NOT-QUALIFIED', Error=None,
        Scope=side.upper() + '_CM3_O2_LTO_MACHINE_AND_CANONICAL_PROTOCOL_COMPOSITION_ONLY',
        RequiredCellsSatisfied=0, NativeCommandsExecuted=0, UnexpectedOutputMembers=[], MissingDeclaredOutputMembers=[],
        ProtocolProof=proof, Roots=[roots[1], roots[2], roots[0]] if side == 'Native' else roots,
        Mutants=rows, ProtocolControls=[dict(Name='synthetic-canonical-control',
            Status='PASS', TransportPreservationAccepted=True, ImmutableInputBuffersConsumed=True,
            ClosingFilesVerified=6, Files=[dict(Synthetic=True) for _ in range(6)],
            TwinComparisonExecuted=False, SourceAuthorityPreserved=False)])
    for key in ('InputClosureVerified', 'OutputSealVerified', 'ImmutablePositiveInputsConsumed', 'CanonicalProtocolValidated'):
        result[key] = True
    for key in ('Qualification', 'FinalReferenceParity', 'FullABIProof', 'SourceToMachineSemanticProof',
                'CompleteObjectProof', 'PolicyEquivalence', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified'):
        result[key] = False
    return result


class Memory:
    def __init__(self):
        self.base = Path(tempfile.gettempdir()).resolve() / 'cm3-lto-join-witness-memory-only'
        self.output = self.base / 'output'
        self.buffers, self.mkdir_calls, self.save_statuses = {}, [], []
        self.save_attempts, self.on_save = {}, None
        self.identities = {}
        self.api = SimpleNamespace(regular=self.regular, files_under=self.files, save=self.save,
                                   same=p.same, unique_object=p.unique_object)
        self.watch = p.Closure()

    def regular(self, path):
        path = Path(path)
        if path not in self.buffers:
            raise FileNotFoundError(str(path))
        return path

    def files(self, root):
        return {path.relative_to(root).as_posix(): path for path in self.buffers if path.is_relative_to(root)}

    def stat(self, path, *args, **kwargs):
        path = self.regular(path)
        if path not in self.identities:
            self.identities[path] = len(self.identities) + 1
        return SimpleNamespace(st_dev=7, st_ino=self.identities[path], st_nlink=1)

    def save(self, path, value):
        path = Path(path)
        self.save_attempts[path] = self.save_attempts.get(path, 0) + 1
        attempt = self.save_attempts[path]
        if path == self.output / 'results.json':
            self.save_statuses.append(value['Status'])
        if self.on_save:
            self.on_save('before', path, attempt, self.buffers)
        self.buffers[path] = encoded(value)
        if self.on_save:
            self.on_save('after', path, attempt, self.buffers)

    @contextmanager
    def active(self):
        with patch.object(p, 'regular', side_effect=self.regular), \
                patch.object(p, 'checked_path', side_effect=lambda path, must_exist=True: Path(os.path.abspath(path))), \
                patch.object(p, 'files_under', side_effect=self.files), \
                patch.object(Path, 'read_bytes', lambda path: self.buffers[self.regular(path)]), \
                patch.object(Path, 'stat', lambda path, *args, **kwargs: self.stat(path)), \
                patch.object(Path, 'iterdir', lambda path: iter(child for child in self.buffers if child.parent == path)), \
                patch.object(Path, 'mkdir', lambda path, *args, **kwargs: self.mkdir_calls.append(Path(path))), \
                patch('subprocess.Popen', side_effect=AssertionError('pure controls forbid processes')):
            yield

    def witness(self):
        result = object.__new__(w.Witness)
        result.api, result.watch, result.output = self.api, self.watch, self.output
        result.expected = {'results.json', 'artifacts.json'}
        result.buffers = {}
        result.report = dict(Status='FAIL', Error=None, SyntheticQualifiedStageStub=True, Qualification=False,
            FinalReferenceParity=False, FullABIProof=False, PolicyEquivalence=False, SourceToMachineSemanticProof=False,
            OriginalTranslationUnitOwnership=False, CompleteObjectProof=False, CpuExecution=False, BoardExecution=False,
            GlobalFreezeQualified=False, RequiredCellsSatisfied=0, ProducerCompilersReexecuted=False,
            MutantsReexecuted=False, NativeCommandsExecuted=0)
        return result

    def role_fixture(self, side='Native'):
        root, capture = self.base / (side + '-prior'), self.base / (side + '-capture')
        emit = capture / 'emit-relocs'
        source_count = 9 if side == 'Native' else 4
        sources = [dict(Object=str(capture / 'objects' / ('%02d-source.o' % index))) for index in range(source_count)]
        paths = dict(Machine=emit / 'image.elf.ltrans0.ltrans.o', Final=emit / 'image.elf',
            Disassembly=emit / 'image.elf.dis', LinkMap=emit / 'image.map', Startup=Path(sources[-1]['Object']),
            Plain=capture / 'ordinary/image.elf', MachineDisassembly=emit / 'image.elf.ltrans0.ltrans.o.dis')
        rows, artifacts = [], {}
        for index, (role, original) in enumerate(paths.items()):
            copied = root / 'copies' / (role + original.suffix)
            data = ('synthetic-%s-%s-%d' % (side, role, index)).encode('ascii')
            self.buffers[original] = self.buffers[copied] = data
            artifacts[copied.relative_to(root).as_posix()] = sha(data)
            rows.append(dict(Role=role, Original=str(original), Captured=str(copied), Sha256=sha(data)))
        r = dict(BinaryInputs=rows[:-1], MachineDisassemblyInput=rows[-1])
        return self.witness(), root, artifacts, r, capture, dict(Sources=sources)

    def control_fixture(self, side):
        witness, root, artifacts, role_record, capture, captured = self.role_fixture(side)
        before, after = (bytes.fromhex('46df'), bytes.fromhex('47df')) if side == 'Native' else (bytes.fromhex('00df'), bytes.fromhex('01df'))
        for row in [*role_record['BinaryInputs'], role_record['MachineDisassemblyInput']]:
            if row['Role'] in ('Machine', 'Final'):
                data = b'xx' + before + b'synthetic binary'
                self.buffers[Path(row['Original'])] = self.buffers[Path(row['Captured'])] = data
                row['Sha256'] = artifacts[Path(row['Captured']).relative_to(root).as_posix()] = sha(data)
        with self.active():
            roles = witness._roles(root, artifacts, role_record, capture, captured)
        tree = ast.parse(SOURCE_BYTES[MUTATORS[side]], filename=str(MUTATORS[side]))
        catalog_node = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                            and any(isinstance(target, ast.Name) and target.id == 'CASES' for target in node.targets))
        catalog = ast.literal_eval(catalog_node)
        witness.buffers[MUTATORS[side]] = SOURCE_BYTES[MUTATORS[side]]
        result = record(side)
        result['Mutants'] = []

        def private(rows, directory, selected, canonical=False):
            for role in selected:
                path = directory / (role + roles[role]['Path'].suffix)
                if canonical and role in ('Machine', 'Final'):
                    data = b'xx' + after + b'synthetic binary'
                elif canonical and role in ('Disassembly', 'MachineDisassembly'):
                    data = ('synthetic changed ' + role).encode('ascii')
                else:
                    data = roles[role]['Bytes']
                self.buffers[path] = data
                artifacts[path.relative_to(root).as_posix()] = sha(data)
                info = self.stat(path)
                rows.append(dict(Role=role, Path=str(path), Sha256=sha(data),
                                 PhysicalIdentity=dict(Device=info.st_dev, FileId=info.st_ino, Links=info.st_nlink)))

        for name, expected in catalog:
            guard = 'LTO-ORIGIN' if expected in ('LTO-(ORIGIN|SYMBOL)', '(LTO-)?ORIGIN') else expected
            row = dict(Name=name, Expected=expected, Rejection='REJECT:' + guard + ':synthetic intended guard',
                Status='PASS', ImmutableInputBuffersConsumed=True, ClosingFilesVerified=5,
                ImmutableOriginControlCoherenceChecked=True, Files=[], Edits=[dict(Synthetic=True)])
            private(row['Files'], root / 'mutants' / name, w.ROLES[:5])
            result['Mutants'].append(row)
        first = NATIVE_ROOTS[0] if side == 'Native' else REFERENCE_ROOTS[0]
        control = result['ProtocolControls'][0]
        control.update(Name='coherent-svc-immediate', Expected='CM3-CLOSED-ROOTS',
            Rejection='REJECT:CM3-CLOSED-ROOTS:' + side + '/' + first + '/token-'
            + str(27 if side == 'Native' else 8) + '/complete protocol mismatch', Files=[], Edits=[])
        private(control['Files'], root / 'protocol-mutants/coherent-svc-immediate', (*w.ROLES[:5], 'MachineDisassembly'), True)
        for role in ('Machine', 'Final', 'Disassembly', 'MachineDisassembly'):
            if role in ('Machine', 'Final'):
                control['Edits'].append(dict(Role=role, FileOffset=2, Before=before.hex(), After=after.hex()))
            else:
                row = next(item for item in control['Files'] if item['Role'] == role)
                control['Edits'].append(dict(Role=role, BeforeSha256=roles[role]['Sha256'], AfterSha256=row['Sha256']))
        return witness, dict(Root=root, Artifacts=artifacts, Result=result, Roles=roles)


class RecordTests(unittest.TestCase):
    def check(self, side, row):
        w.Witness._require_record(SimpleNamespace(), side, row)

    def test_both_literal_three_root_synthetic_envelopes_pass_record_layer_only(self):
        for side in ('Native', 'Reference'):
            with self.subTest(side=side):
                self.check(side, record(side))

    def test_literal_true_and_false_phase_markers_cannot_be_numeric_aliases(self):
        true_keys = ('InputClosureVerified', 'OutputSealVerified', 'ImmutablePositiveInputsConsumed', 'CanonicalProtocolValidated')
        false_keys = ('Qualification', 'FinalReferenceParity', 'FullABIProof', 'SourceToMachineSemanticProof',
                      'CompleteObjectProof', 'PolicyEquivalence', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified')
        for side in ('Native', 'Reference'):
            for keys, value in ((true_keys, 1), (false_keys, 0)):
                for key in keys:
                    row = record(side)
                    row[key] = value
                    with self.subTest(side=side, key=key), self.assertRaises(ValueError):
                        self.check(side, row)

    def test_status_scope_error_and_zero_counters_are_exact(self):
        for side in ('Native', 'Reference'):
            for key, value in (('Status', 'PASS'), ('Scope', 'unrelated'), ('Error', ''),
                               ('RequiredCellsSatisfied', False), ('RequiredCellsSatisfied', 0.0),
                               ('NativeCommandsExecuted', False), ('NativeCommandsExecuted', 0.0),
                               ('UnexpectedOutputMembers', ['foreign']), ('MissingDeclaredOutputMembers', ['missing'])):
                row = record(side)
                row[key] = value
                with self.subTest(side=side, key=key, value=value), self.assertRaises(ValueError):
                    self.check(side, row)


class BindingTests(unittest.TestCase):
    def test_seven_fixed_roles_bind_original_and_copied_bytes_for_both_sides(self):
        for side in ('Native', 'Reference'):
            memory = Memory()
            witness, root, artifacts, row, capture, captured = memory.role_fixture(side)
            with memory.active(), self.subTest(side=side):
                roles = witness._roles(root, artifacts, row, capture, captured)
            self.assertEqual(tuple(roles), w.ROLES)
            self.assertEqual(len(memory.watch.hashes), 14)
            self.assertEqual(memory.mkdir_calls, [])

    def test_role_membership_original_path_and_copied_containment_are_exact(self):
        for change in ('missing', 'duplicate', 'unknown', 'original', 'outside'):
            memory = Memory()
            witness, root, artifacts, row, capture, captured = memory.role_fixture()
            if change == 'missing':
                row['BinaryInputs'].pop()
            elif change == 'duplicate':
                row['BinaryInputs'][1]['Role'] = 'Machine'
            elif change == 'unknown':
                row['BinaryInputs'][1]['Role'] = 'Foreign'
            elif change == 'original':
                row['BinaryInputs'][0]['Original'] = row['BinaryInputs'][1]['Original']
            else:
                original = Path(row['BinaryInputs'][0]['Captured'])
                outside = memory.base / 'outside/copy.o'
                memory.buffers[outside] = memory.buffers[original]
                row['BinaryInputs'][0]['Captured'] = str(outside)
            with memory.active(), self.subTest(change=change), self.assertRaises(ValueError):
                witness._roles(root, artifacts, row, capture, captured)

    def test_each_role_hash_manifest_original_and_captured_bytes_are_independently_bound(self):
        for change in ('hash', 'original', 'captured'):
            memory = Memory()
            witness, root, artifacts, row, capture, captured = memory.role_fixture('Reference')
            selected = row['BinaryInputs'][0]
            if change == 'hash':
                selected['Sha256'] = '0' * 64
            else:
                memory.buffers[Path(selected['Original' if change == 'original' else 'Captured'])] += b'changed'
            with memory.active(), self.subTest(change=change), self.assertRaises(ValueError):
                witness._roles(root, artifacts, row, capture, captured)

    def tree(self):
        memory = Memory()
        root = memory.base / 'evidence'
        memory.buffers[root / 'results.json'] = encoded(dict(Status='PASS', Synthetic=True))
        memory.buffers[root / 'input.bin'] = b'synthetic nested input'
        members = {path.relative_to(root).as_posix(): sha(data) for path, data in memory.buffers.items()}
        memory.buffers[root / 'artifacts.json'] = encoded(dict(Artifacts=members))
        return memory, memory.witness(), root, sha(memory.buffers[root / 'results.json']), sha(memory.buffers[root / 'artifacts.json'])

    def test_nested_evidence_tree_binds_receipt_manifest_and_full_membership(self):
        memory, witness, root, receipt, manifest = self.tree()
        with memory.active():
            witness._evidence_tree(root, receipt, manifest)
            memory.watch.close()
        self.assertEqual(memory.watch.memberships[root], {'results.json', 'input.bin', 'artifacts.json'})
        self.assertEqual(memory.mkdir_calls, [])

    def test_nested_tree_wrong_hash_binding_extra_missing_and_duplicate_json_reject(self):
        for change in ('caller', 'binding', 'extra', 'missing', 'duplicate-json'):
            memory, witness, root, receipt, manifest = self.tree()
            if change == 'caller':
                manifest = '0' * 64
            elif change == 'binding':
                value = json.loads(memory.buffers[root / 'artifacts.json'])
                value['Artifacts']['results.json'] = '0' * 64
                memory.buffers[root / 'artifacts.json'] = encoded(value)
                manifest = sha(memory.buffers[root / 'artifacts.json'])
            elif change == 'extra':
                memory.buffers[root / 'extra.bin'] = b'unlisted'
            elif change == 'missing':
                memory.buffers.pop(root / 'input.bin')
            else:
                memory.buffers[root / 'artifacts.json'] = b'{"Artifacts":{},"Artifacts":{}}'
                manifest = sha(memory.buffers[root / 'artifacts.json'])
            with memory.active(), self.subTest(change=change), self.assertRaises(ValueError):
                witness._evidence_tree(root, receipt, manifest)


class ControlTests(unittest.TestCase):
    def test_exact_pinned_source_catalog_and_synthetic_file_edit_bindings_pass_both_sides(self):
        for side in ('Native', 'Reference'):
            memory = Memory()
            witness, group = memory.control_fixture(side)
            with memory.active(), self.subTest(side=side):
                witness._require_controls(side, group)
            self.assertEqual(memory.mkdir_calls, [])

    def test_catalog_rejection_role_path_hash_missing_members_and_physical_identity_reject(self):
        for side in ('Native', 'Reference'):
            for change in ('name', 'expected', 'rejection', 'coherence', 'role', 'path', 'hash', 'missing-file', 'extra-member', 'physical'):
                if change == 'physical' and side != 'Reference':
                    continue
                memory = Memory()
                witness, group = memory.control_fixture(side)
                first = group['Result']['Mutants'][0]
                if change == 'name':
                    first['Name'] = 'arbitrary-control'
                elif change == 'expected':
                    first['Expected'] = 'UNRELATED'
                elif change == 'rejection':
                    first['Rejection'] = 'REJECT:UNRELATED:other failure'
                elif change == 'coherence':
                    coherent = next(row for row in group['Result']['Mutants'] if row['Name'] == 'coherent-slot-in-bss')
                    coherent['ImmutableOriginControlCoherenceChecked'] = 1
                elif change == 'role':
                    first['Files'][1]['Role'] = first['Files'][0]['Role']
                elif change == 'path':
                    first['Files'][0]['Path'] = first['Files'][1]['Path']
                elif change == 'hash':
                    first['Files'][0]['Sha256'] = '0' * 64
                elif change == 'missing-file':
                    first['Files'].pop()
                elif change == 'extra-member':
                    memory.buffers[Path(first['Files'][0]['Path']).parent / 'unexpected'] = b'extra private file'
                else:
                    first['Files'][0]['PhysicalIdentity']['FileId'] += 1
                with memory.active(), self.subTest(side=side, change=change), self.assertRaises(ValueError):
                    witness._require_controls(side, group)

    def test_canonical_exact_diagnostic_six_roles_and_all_four_edit_fields_are_bound(self):
        for side in ('Native', 'Reference'):
            for change in ('name', 'expected', 'diagnostic', 'file-role', 'file-hash', 'edit-role',
                           'binary-before', 'binary-after', 'offset-bool', 'original-bytes', 'private-bytes', 'dis-before', 'dis-after'):
                memory = Memory()
                witness, group = memory.control_fixture(side)
                control = group['Result']['ProtocolControls'][0]
                if change == 'name':
                    control['Name'] = 'unrelated'
                elif change == 'expected':
                    control['Expected'] = 'OTHER'
                elif change == 'diagnostic':
                    control['Rejection'] = control['Rejection'].replace('/token-', '/token-1')
                elif change == 'file-role':
                    control['Files'][1]['Role'] = control['Files'][0]['Role']
                elif change == 'file-hash':
                    control['Files'][0]['Sha256'] = '0' * 64
                elif change == 'edit-role':
                    control['Edits'][1]['Role'] = control['Edits'][0]['Role']
                elif change == 'binary-before':
                    control['Edits'][0]['Before'] = '0000'
                elif change == 'binary-after':
                    control['Edits'][0]['After'] = 'ffff'
                elif change == 'offset-bool':
                    control['Edits'][0]['FileOffset'] = False
                elif change == 'original-bytes':
                    group['Roles']['Machine']['Bytes'] = b'xxxx' + group['Roles']['Machine']['Bytes'][4:]
                elif change == 'private-bytes':
                    row = next(row for row in control['Files'] if row['Role'] == 'Machine')
                    path = Path(row['Path'])
                    memory.buffers[path] = b'xxxx' + memory.buffers[path][4:]
                    row['Sha256'] = group['Artifacts'][path.relative_to(group['Root']).as_posix()] = sha(memory.buffers[path])
                else:
                    control['Edits'][2]['BeforeSha256' if change == 'dis-before' else 'AfterSha256'] = '0' * 64
                with memory.active(), self.subTest(side=side, change=change), self.assertRaises(ValueError):
                    witness._require_controls(side, group)


class CallbackTests(unittest.TestCase):
    def callbacks(self, snapshots):
        tree = ast.parse(SOURCE_BYTES[WITNESS], filename=str(WITNESS))
        owner = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == '_read')
        selected = [copy.deepcopy(node) for node in owner.body if isinstance(node, ast.FunctionDef)
                    and node.name in ('fixed_read', 'fixed_text')]
        self.assertEqual([node.name for node in selected], ['fixed_read', 'fixed_text'])
        namespace = dict(w.__dict__, snapshots=snapshots)
        exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])), str(WITNESS), 'exec'), namespace)
        return namespace['fixed_read'], namespace['fixed_text']

    def test_immutable_binary_and_text_lookups_normalize_lexically_without_disk_or_resolution(self):
        path = Path(tempfile.gettempdir()).absolute() / 'cm3-join-lookup/source.py'
        read, text = self.callbacks({path: b'captured immutable bytes'})
        with patch.object(Path, 'resolve', side_effect=AssertionError('callback must not resolve')), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('disk fallback forbidden')), \
                patch.object(Path, 'read_text', side_effect=AssertionError('disk fallback forbidden')):
            for selected in (path, path.parent / 'absent' / '..' / path.name):
                self.assertEqual(read(selected), b'captured immutable bytes')
                self.assertEqual(text(selected, encoding='ascii'), 'captured immutable bytes')

    def test_unknown_binary_and_text_inputs_fail_closed_without_fallback(self):
        path = Path(tempfile.gettempdir()).absolute() / 'cm3-join-lookup/source.py'
        read, text = self.callbacks({path: b'immutable'})
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('disk fallback forbidden')), \
                patch.object(Path, 'read_text', side_effect=AssertionError('disk fallback forbidden')):
            for callback in (read, text):
                with self.subTest(callback=callback.__name__), self.assertRaisesRegex(ValueError, 'unknown join reader input'):
                    callback(path.parent / 'unknown.py')

    def test_text_callback_only_accepts_exact_strict_utf8_or_ascii_decoding(self):
        path = Path(tempfile.gettempdir()).absolute() / 'cm3-join-lookup/source.py'
        _, text = self.callbacks({path: b'immutable'})
        for kwargs in (dict(encoding='latin-1'), dict(errors='ignore'), dict(newline='')):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, 'exact join text decoding'):
                text(path, **kwargs)


class RootRecordTests(unittest.TestCase):
    def check(self, side, row):
        w.Witness._require_record(SimpleNamespace(), side, row)

    def test_duplicate_reordered_or_foreign_top_and_protocol_root_names_reject(self):
        for side in ('Native', 'Reference'):
            for target in ('top', 'protocol', 'matched'):
                for change in ('duplicate', 'reverse', 'foreign'):
                    row = record(side)
                    roots = row['Roots'] if target == 'top' else row['ProtocolProof']['Roots' if target == 'protocol' else 'MatchEvidence']
                    if change == 'duplicate':
                        roots[1]['Name'] = roots[0]['Name']
                    elif change == 'reverse':
                        roots.reverse()
                    else:
                        roots[0]['Name'] = 'wrong-side-root'
                    with self.subTest(side=side, target=target, change=change), self.assertRaises(ValueError):
                        self.check(side, row)

    def test_protocol_status_closed_count_tail_types_and_completeness_reject(self):
        for side in ('Native', 'Reference'):
            for change in ('status', 'claim', 'count', 'tail-bool', 'tail-one', 'missing-root', 'missing-match'):
                row = record(side)
                proof = row['ProtocolProof']
                if change == 'status':
                    proof['Status'] = 'PASS'
                elif change == 'claim':
                    proof['CanonicalProtocolValidated'] = 1
                elif change == 'count':
                    proof['ClosedBodies'] = 3.0
                elif change == 'tail-bool':
                    proof['MatchEvidence'][0]['TailNops'] = False
                elif change == 'tail-one':
                    proof['MatchEvidence'][0]['TailNops'] = 1
                elif change == 'missing-root':
                    proof['Roots'].pop()
                else:
                    proof['MatchEvidence'].pop()
                with self.subTest(side=side, change=change), self.assertRaises(ValueError):
                    self.check(side, row)


    def test_transport_control_count_unique_names_files_edits_and_integer_closing_count(self):
        for side in ('Native', 'Reference'):
            for change in ('missing', 'duplicate', 'status', 'immutable', 'files', 'edits', 'closing-float'):
                row = record(side)
                controls, first = row['Mutants'], row['Mutants'][0]
                if change == 'missing':
                    controls.pop()
                elif change == 'duplicate':
                    controls[1]['Name'] = first['Name']
                elif change == 'status':
                    first['Status'] = 'FAIL'
                elif change == 'immutable':
                    first['ImmutableInputBuffersConsumed'] = 1
                elif change == 'files':
                    first['Files'].pop()
                elif change == 'edits':
                    first['Edits'].clear()
                else:
                    first['ClosingFilesVerified'] = 5.0
                with self.subTest(side=side, change=change), self.assertRaises(ValueError):
                    self.check(side, row)

    def test_one_canonical_control_requires_six_files_literal_flags_and_integer_counter(self):
        for side in ('Native', 'Reference'):
            for change in ('missing', 'extra', 'files', 'closing-float', 'claim', 'transport', 'twins', 'authority'):
                row = record(side)
                controls, first = row['ProtocolControls'], row['ProtocolControls'][0]
                if change == 'missing':
                    controls.clear()
                elif change == 'extra':
                    controls.append(copy.deepcopy(first))
                elif change == 'files':
                    first['Files'].pop()
                elif change == 'closing-float':
                    first['ClosingFilesVerified'] = 6.0
                else:
                    key = dict(claim='ImmutableInputBuffersConsumed', transport='TransportPreservationAccepted',
                               twins='TwinComparisonExecuted', authority='SourceAuthorityPreserved')[change]
                    first[key] = 1 if change in ('claim', 'transport') else 0
                with self.subTest(side=side, change=change), self.assertRaises(ValueError):
                    self.check(side, row)


class ClosingTests(unittest.TestCase):
    def run_witness(self, memory, *, stage_error=None, after_stage=None, on_close=None):
        witness = memory.witness()
        original = memory.base / 'immutable-input.py'
        memory.buffers[original] = b'synthetic watched input'
        with memory.active():
            witness.watch.read(original, sha(memory.buffers[original]))

            def stage():
                if stage_error is not None:
                    raise stage_error
                witness.report['JoinProof'] = dict(SyntheticQualifiedStageStub=True)
                watched = memory.output / 'synthetic-stage.json'
                witness.declare(watched)
                memory.save(watched, dict(SyntheticQualifiedStageStub=True))
                witness.watch.read(watched, sha(memory.buffers[watched]))
                diagnostic = memory.output / 'side-report.json'
                witness.declare(diagnostic)
                memory.save(diagnostic, dict(SyntheticDiagnostic=True))
                if after_stage:
                    after_stage(witness, memory)

            close, calls = witness.watch.close, 0

            def closing():
                nonlocal calls
                calls += 1
                if on_close:
                    on_close(calls, memory)
                close()

            with patch.object(witness, '_read', side_effect=stage) as reader, \
                    patch.object(witness.watch, 'close', side_effect=closing):
                passed = witness.run()
            reader.assert_called_once()
        return passed, witness

    def receipt(self, memory, status, *, sealed=True):
        row = json.loads(memory.buffers[memory.output / 'results.json'])
        self.assertEqual(row['Status'], status)
        self.assertIs(row['OutputSealVerified'], sealed)
        for key in ('Qualification', 'FinalReferenceParity', 'FullABIProof', 'PolicyEquivalence', 'SourceToMachineSemanticProof',
                    'OriginalTranslationUnitOwnership', 'CompleteObjectProof', 'CpuExecution', 'BoardExecution',
                    'GlobalFreezeQualified', 'ProducerCompilersReexecuted', 'MutantsReexecuted'):
            self.assertIs(row[key], False)
        self.assertIs(type(row['RequiredCellsSatisfied']), int)
        self.assertEqual(row['RequiredCellsSatisfied'], 0)
        self.assertEqual(row['NativeCommandsExecuted'], 0)
        if sealed:
            expected = {path.relative_to(memory.output).as_posix(): sha(data) for path, data in memory.buffers.items()
                        if path.is_relative_to(memory.output) and path != memory.output / 'artifacts.json'}
            self.assertEqual(json.loads(memory.buffers[memory.output / 'artifacts.json']), dict(Artifacts=expected))
        return row

    def test_mocked_stage_success_seals_exact_outputs_without_parser_or_qualification(self):
        memory = Memory()
        passed, witness = self.run_witness(memory)
        self.assertIs(passed, True)
        row = self.receipt(memory, w.PASS)
        self.assertIs(row['InputClosureVerified'], True)
        self.assertEqual(row['UnexpectedOutputMembers'], [])
        self.assertEqual(row['MissingDeclaredOutputMembers'], [])
        self.assertEqual(row['ClosingFilesVerified'], len(witness.watch.hashes))
        self.assertEqual(memory.mkdir_calls, [memory.output])

    def test_stage_rejection_and_baseexception_cannot_finalize_success(self):
        for error in (ValueError('synthetic qualified-stage rejection'), KeyboardInterrupt('synthetic interruption')):
            memory = Memory()
            with self.subTest(error=error):
                passed, _ = self.run_witness(memory, stage_error=error)
                self.assertIs(passed, False)
                row = self.receipt(memory, 'FAIL')
                self.assertIn(str(error), row['Error'])
                self.assertEqual(set(memory.save_statuses), {'FAIL'})

    def test_preseal_foreign_missing_or_watched_drift_cannot_become_success(self):
        for change in ('extra', 'missing', 'watched'):
            memory = Memory()

            def fault(witness, data):
                if change == 'extra':
                    data.buffers[data.output / 'foreign'] = b'unplanned output'
                elif change == 'missing':
                    witness.declare(data.output / 'declared-missing')
                else:
                    data.buffers[data.output / 'synthetic-stage.json'] += b'changed'

            with self.subTest(change=change):
                passed, _ = self.run_witness(memory, after_stage=fault)
                self.assertIs(passed, False)
                row = self.receipt(memory, 'FAIL')
                self.assertIs(row['InputClosureVerified'], False)
                self.assertIn('input hash mismatch' if change == 'watched' else 'predetermined join output membership', row['Error'])

    def test_output_add_change_delete_during_manifest_write_downgrades_and_reseals(self):
        for change in ('add', 'change', 'delete'):
            memory = Memory()

            def fault(phase, path, attempt, buffers):
                if phase == 'after' and path == memory.output / 'artifacts.json' and attempt == 1:
                    if change == 'add':
                        buffers[memory.output / 'late-extra'] = b'late output'
                    elif change == 'change':
                        buffers[memory.output / 'side-report.json'] += b'changed'
                    else:
                        del buffers[memory.output / 'side-report.json']

            memory.on_save = fault
            with self.subTest(change=change):
                passed, _ = self.run_witness(memory)
                self.assertIs(passed, False)
                row = self.receipt(memory, 'FAIL')
                self.assertIn('post-manifest output closure', row['Error'])
                self.assertIn(w.PASS, memory.save_statuses)

    def test_written_manifest_dictionary_and_unique_json_keys_are_mandatory(self):
        for contents in (encoded(dict(Artifacts={})), b'{"Artifacts":{},"Artifacts":{}}'):
            memory = Memory()

            def fault(phase, path, attempt, buffers):
                if phase == 'after' and path == memory.output / 'artifacts.json' and attempt == 1:
                    buffers[path] = contents

            memory.on_save = fault
            with self.subTest(contents=contents):
                passed, _ = self.run_witness(memory)
                self.assertIs(passed, False)
                row = self.receipt(memory, 'FAIL')
                self.assertIn('written join manifest value' if contents.startswith(b'{\n') else 'duplicate JSON key', row['Error'])

    def test_one_time_and_permanent_manifest_storage_failures_never_leave_success(self):
        for permanent in (False, True):
            memory = Memory()

            def fault(phase, path, attempt, buffers):
                if phase == 'before' and path == memory.output / 'artifacts.json' and (permanent or attempt == 1):
                    raise OSError('synthetic manifest storage failure')

            memory.on_save = fault
            with self.subTest(permanent=permanent):
                passed, _ = self.run_witness(memory)
                self.assertIs(passed, False)
                row = self.receipt(memory, 'FAIL', sealed=not permanent)
                self.assertIn('synthetic manifest storage failure', row['Error'])

    def test_late_output_input_and_manifest_drift_downgrade_persisted_success(self):
        for change in ('add', 'change', 'delete', 'input', 'manifest'):
            memory = Memory()

            def fault(count, data):
                if count == 2:
                    if change == 'add':
                        data.buffers[data.output / 'late-extra'] = b'late output'
                    elif change == 'delete':
                        del data.buffers[data.output / 'side-report.json']
                    else:
                        path = data.base / 'immutable-input.py' if change == 'input' else data.output / (
                            'artifacts.json' if change == 'manifest' else 'side-report.json')
                        data.buffers[path] += b' \n'

            with self.subTest(change=change):
                passed, _ = self.run_witness(memory, on_close=fault)
                self.assertIs(passed, False)
                row = self.receipt(memory, 'FAIL')
                message = 'input hash mismatch' if change == 'input' else 'late join manifest drift' if change == 'manifest' else 'late join output closure'
                self.assertIn(message, row['Error'])

    def test_duplicate_or_escaped_output_declarations_fail_without_creating_directories(self):
        memory = Memory()
        witness = memory.witness()
        witness.declare(memory.output / 'new.json')
        for path in (memory.output / 'new.json', memory.output / 'results.json', memory.base / 'outside.json'):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'declared output|duplicate declared'):
                witness.declare(path)
        self.assertEqual(memory.mkdir_calls, [])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output.exists() or output.is_relative_to(REPO) or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        parser.error('fresh external TEMP output directory required')
    report = dict(Status='FAIL', Tests=0, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        Scope='PURE_SYNTHETIC_CM3_LTO_JOIN_WITNESS_ENVELOPE_ONLY', SyntheticInputs=True,
        FullConstructorTested=False, PhysicalIdentityValidated=False, ActualELFTested=False,
        QualifiedCapturedParserExecuted=False, ActualMutationCasesTested=False,
        ToolInvocations=0, NativeCommandsExecuted=0, FinalReferenceParity=False, FullABIProof=False,
        SourceToMachineSemanticProof=False, CanonicalProtocolValidated=False, PolicyEquivalence=False,
        CpuExecution=False, BoardExecution=False, RequiredCellsSatisfied=0, GlobalFreezeQualified=False)
    paths = [Path(__file__).resolve(), WITNESS, UTILITY, *MUTATORS.values()]
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('optimized Python unsupported')
        global SOURCE_BYTES, w, p
        SOURCE_BYTES = {path: path.read_bytes() for path in paths}
        report['SourceHashes'] = {str(path): sha(data) for path, data in SOURCE_BYTES.items()}
        with patch('subprocess.Popen', side_effect=AssertionError('pure controls forbid processes')):
            w = module('pure_cm3_lto_join_witness', WITNESS, SOURCE_BYTES[WITNESS])
            p = module('pure_cm3_lto_join_closure_utilities', UTILITY, SOURCE_BYTES[UTILITY])
            suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
            count = suite.countTestCases()
            if not count:
                raise ValueError('nonempty pure witness controls required')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        report['SourceDrift'] = [str(path) for path in paths if not path.is_file() or sha(path.read_bytes()) != report['SourceHashes'][str(path)]]
        if result.wasSuccessful() and result.testsRun == count > 0 and not result.skipped and not report['SourceDrift']:
            report['Status'] = 'PASS'
    except Exception:
        report.update(Status='FAIL', Error=traceback.format_exc(), Errors=report['Errors'] + 1)
    output.mkdir(parents=True, exist_ok=False)
    target = output / 'results.json'
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='ascii')
    print('Receipt:', target, sha(target.read_bytes()))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
