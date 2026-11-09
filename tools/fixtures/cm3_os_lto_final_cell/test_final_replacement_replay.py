"""Actual 23-input byte fixtures; no capture admission or combined CLI replay."""

import argparse
from contextlib import contextmanager, ExitStack
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import ModuleType
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / 'final_replacement_replay.py'
METHODS = 25
BASE_PIN = 'F1D443F37869258C53A1FF211EA545F038FEF8100836A2CF5B9FF3E1C003D6BC'
ORIGINAL_PIN = 'BF15568AE1EF2D5A67FC63573965D36AA0A9D31308A57C1B2FC860310E0DA645'
PORT_PIN = 'C88995AC5343B376AC1E73F0570F8AF9F025144820BD88556CF0A57814B8DE94'
RECEIPT = ('C:/fzosoriginal-census-20261109-e1/results.json',
    'F72CFBB8E8A9184797341220A220DB3B45B026D66E58F5ED6CDC0139114F532E')
HELPERS = ('abi', 'link_helpers', 'binding_helpers', 'native_roots', 'reference_roots',
    'native_protocol', 'reference_protocol', 'decoder', 'checker', 'os_join', 'join', 'guard',
    'original_replay', 'port_replay')
FIELDS = frozenset(('Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'LTO', 'Cohort',
    'SourceInventorySha256', 'BatchRoot', 'BatchAuthority', 'OriginalProofSha256', 'PortProofSha256',
    'Inputs', 'ControlBytes', 'ByteComparisons', 'LoadImageComparison', 'TransportRoots', 'CanonicalJoin',
    'PolicyDifferenceRationales', 'ReadInputs', 'ReadFiles', 'LogicalRoles',
    'FreshFinalCanonicalRootsRecomputed', 'OwnFinalInputsBound', 'ToolInvocations',
    'CompilerInvocations', 'RequiredCellsSatisfied', 'Nonclaims'))
FINAL_ROLES = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'MachineDisassembly')
CONTROL = ('BatchReceipt', 'BatchManifest', 'NativeReceipt', 'NativeManifest',
    'ReferenceReceipt', 'ReferenceManifest', 'MasterLedger', 'PolicyLedger')
NONCLAIMS = frozenset(('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'FullInstructionSemantics', 'SourceIRProof', 'SourceToIRSemanticProof',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'OrdinaryRootPreservationProven', 'HandlerRoutingProven', 'FinalReferenceParity',
    'InstructionEquivalence', 'PolicyEquivalence', 'ArbitraryCallbackSafetyProven',
    'MutantsReexecuted', 'ProducerCompilersReexecuted', 'UnchangedOtherSixGeneratedBodies',
    'CompleteCellProof', 'WholeCellProof', 'RequiredCellSatisfied', 'CellContractSatisfied',
    'ArchiveQualification', 'HostedCIQualified', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified'))
BUFFERS, FIXTURES, DATA, INPUTS = {}, {}, {}, {}
BATCH = PORT = ORIGINAL = None
base = m = core = None
H = {}
ORIGINAL_EXERCISED = FINAL_EXERCISED = False


def need(value, message):
    if not value: raise ValueError('final-replacement-tests: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def proof_hash(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
        allow_nan=False).encode('ascii'))


def load(name, path, raw):
    module = ModuleType(name); module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def snapshot(path, expected, destination):
    path = Path(path); raw = path.read_bytes()
    need(sha(raw) == expected, 'fixed fixture/source drift/' + str(path))
    need(path not in destination or destination[path] == raw, 'buffer collision')
    destination[path] = raw
    return raw


def initialize(helpers=None):
    global base, m, core, H, BATCH, PORT, ORIGINAL, ORIGINAL_EXERCISED
    if m is not None:
        if helpers is not None:
            need(type(helpers) is dict and set(helpers) == set(HELPERS), 'exact 14 real helpers')
            H = dict(helpers)
            ORIGINAL = base.Model().run(helpers={k: H[k] for k in base.HELPERS})
            ORIGINAL_EXERCISED = True
        return
    base_path = HERE / 'test_original_replay.py'
    raw = snapshot(base_path, BASE_PIN, BUFFERS)
    base = load('_final_replacement_original_fixture', base_path, raw)
    base.initialize(); core = base.core
    BUFFERS.update(base.BUFFERS); FIXTURES.update(base.FIXTURES)
    for path in (Path(__file__).resolve(), SUBJECT, HERE / 'FINAL_REPLACEMENT_REPLAY_CONTRACT.md'):
        BUFFERS[path] = path.read_bytes()
    port_path, original_path = HERE / 'port_replay.py', HERE / 'original_replay.py'
    snapshot(original_path, ORIGINAL_PIN, BUFFERS)
    port_module = load('_final_replacement_port_rules', port_path, snapshot(port_path, PORT_PIN, BUFFERS))
    H = dict(base.H, original_replay=base.m, port_replay=port_module)
    if helpers is not None:
        need(type(helpers) is dict and set(helpers) == set(HELPERS), 'exact 14 real helpers')
        H = dict(helpers)
    ORIGINAL = base.Model().run(helpers={k: H[k] for k in base.HELPERS})
    ORIGINAL_EXERCISED = True
    receipt = base.structured(snapshot(RECEIPT[0], RECEIPT[1], FIXTURES))
    PORT = copy.deepcopy(receipt['PortPolicyComponent'])
    H['port_replay'].require_result(PORT)
    descriptor = receipt['Batch']; root = Path(descriptor['Build'])
    result = base.structured(snapshot(root / 'results.json', descriptor['ReceiptSha256'], FIXTURES))
    artifacts = base.structured(snapshot(root / 'artifacts.json', descriptor['ArtifactsSha256'], FIXTURES))['Artifacts']
    BATCH = dict(Root=str(root), Result=result, Artifacts=artifacts,
        ReceiptSha256=descriptor['ReceiptSha256'], ManifestSha256=descriptor['ArtifactsSha256'])
    final_map = dict(Machine='Final/Machine', Final='Final/ELF', Disassembly='Final/Disassembly',
        LinkMap='Final/Map', Startup='Final/Startup', MachineDisassembly='Final/MachineDisassembly')
    INPUTS.update(Final={k: {f: PORT['Inputs'][v][f] for f in ('Path', 'Sha256')} for k, v in final_map.items()},
        Reference={k: copy.deepcopy(ORIGINAL['Inputs']['Reference'][k]) for k in FINAL_ROLES},
        OriginalNative=dict(Machine=copy.deepcopy(ORIGINAL['Inputs']['NativeEmitted']['Machine']),
            Emitted=copy.deepcopy(ORIGINAL['Inputs']['NativeEmitted']['Final']),
            Ordinary=copy.deepcopy(ORIGINAL['Inputs']['NativeOrdinary']['Final'])),
        Ledgers=copy.deepcopy(ORIGINAL['Inputs']['Ledgers']),
        Authorities=dict(BatchReceipt=dict(Path=str(root / 'results.json'), Sha256=descriptor['ReceiptSha256']),
            BatchManifest=dict(Path=str(root / 'artifacts.json'), Sha256=descriptor['ArtifactsSha256'])))
    for side in ('Native', 'Reference'):
        for kind in ('Receipt', 'Manifest'):
            INPUTS['Authorities'][side + kind] = copy.deepcopy(ORIGINAL['Authorities'][side][kind])
    for group in INPUTS.values():
        for row in group.values():
            path = Path(row['Path']); snapshot(path, row['Sha256'], DATA)
    need(len(DATA) == 23 and sum(map(len, INPUTS.values())) == 23, '23 logical and distinct byte inputs')
    FIXTURES.update(DATA)
    m = load('_final_replacement_leaf', SUBJECT, BUFFERS[SUBJECT])


@contextmanager
def no_io():
    with base.no_io(), ExitStack() as stack:
        for name in ('write_bytes', 'write_text', 'mkdir', 'unlink', 'rename', 'replace', 'touch'):
            stack.enter_context(patch.object(Path, name, side_effect=AssertionError('write forbidden/' + name)))
        yield


@contextmanager
def detached():
    with no_io(), ExitStack() as stack:
        for helper, name in (('abi', 'inspect'), ('original_replay', 'inspect'), ('port_replay', 'inspect'),
                ('os_join', 'check_join'), ('decoder', 'Object'), ('native_roots', 'NativeCM3LTOImage'),
                ('reference_roots', 'ReferenceCM3LTOImage')):
            stack.enter_context(patch.object(H[helper], name, side_effect=AssertionError('binary inspector forbidden/' + name)))
        stack.enter_context(patch.object(core, 'FinalImage', side_effect=AssertionError('binary constructor forbidden')))
        stack.enter_context(patch.object(core, '_ELF', side_effect=AssertionError('ELF constructor forbidden')))
        stack.enter_context(patch.object(core, 'compare_load_images', side_effect=AssertionError('load inspector forbidden')))
        yield


class Model:
    def __init__(self):
        self.batch, self.port, self.original = copy.deepcopy(BATCH), copy.deepcopy(PORT), copy.deepcopy(ORIGINAL)
        self.files, self.allowed, self.reads = dict(DATA), set(DATA), []

    def read(self, path, expected=None):
        if not isinstance(path, Path) or path not in self.allowed:
            raise PermissionError('missing explicit fixture read role/' + str(path))
        self.reads.append((path, expected))
        return self.files[path]

    def run(self, **options):
        global FINAL_EXERCISED
        arguments = dict(core=core, read=self.read, batch=self.batch, port=self.port, original=self.original, helpers=H)
        arguments.update(options)
        with no_io(): result = m.inspect(**arguments)
        FINAL_EXERCISED = True
        return result

    def reseal(self):
        root = Path(self.batch['Root']); raw = encoded(self.batch['Result'])
        self.files[root / 'results.json'] = raw; self.batch['ReceiptSha256'] = sha(raw)
        self.batch['Artifacts']['results.json'] = sha(raw)
        raw = encoded(dict(Artifacts=self.batch['Artifacts']))
        self.files[root / 'artifacts.json'] = raw; self.batch['ManifestSha256'] = sha(raw)


def synthetic_result(helpers):
    """Fresh actual-byte leaf result; port is pinned metadata, never renewed admission."""
    previous = list(sys.meta_path)
    with patch.dict(sys.modules):
        if m is None:
            for name in tuple(sys.modules):
                if name == 'elftools' or name.startswith('elftools.'): del sys.modules[name]
        try:
            initialize(helpers)
            return Model().run()
        finally:
            sys.meta_path[:] = previous


class FinalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proof = Model().run()

    def reject(self, proof, *, model=None):
        model = Model() if model is None else model
        with detached(), self.assertRaises((ValueError, RuntimeError)):
            m.require_result(proof, model.batch, model.port, model.original, H)

    def test_actual_final_inputs_and_full_prior_proof_hashes(self):
        with patch.object(H['native_roots'], 'NativeCM3LTOImage', wraps=H['native_roots'].NativeCM3LTOImage) as native, \
                patch.object(H['reference_roots'], 'ReferenceCM3LTOImage', wraps=H['reference_roots'].ReferenceCM3LTOImage) as reference, \
                patch.object(H['decoder'], 'Object', wraps=H['decoder'].Object) as decoder, \
                patch.object(H['os_join'], 'check_join', wraps=H['os_join'].check_join) as join, \
                patch.object(H['checker'], 'check_pair', wraps=H['checker'].check_pair) as checker, \
                patch.object(core, 'compare_load_images', wraps=core.compare_load_images) as load_images:
            p = Model().run()
        for spy, group in ((native, 'Final'), (reference, 'Reference')):
            spy.assert_called_once()
            row = INPUTS[group]
            self.assertEqual(spy.call_args.args, (core, *(Path(row[k]['Path']) for k in ('Machine', 'Final', 'Disassembly'))))
            self.assertEqual(spy.call_args.kwargs, dict(link_map=Path(row['LinkMap']['Path']),
                provider_objects={row[k]['Path']: Path(row[k]['Path']) for k in ('Machine', 'Startup')}))
        self.assertEqual([call.args for call in decoder.call_args_list], [
            (Path(INPUTS[group]['Machine']['Path']), Path(INPUTS[group]['MachineDisassembly']['Path']))
            for group in ('Final', 'Reference')])
        join.assert_called_once(); self.assertGreaterEqual(checker.call_count, 1)
        load_images.assert_called_once_with(Path(INPUTS['OriginalNative']['Ordinary']['Path']), Path(INPUTS['Final']['Final']['Path']))
        self.assertEqual(set(p), FIELDS)
        self.assertEqual(p['Status'], 'CM3-OS-LTO-FINAL-REPLACEMENT-REPLAYED-NOT-QUALIFIED')
        self.assertEqual(p['Scope'], 'CM3_OS_LTO_SELECTED_REPLACEMENT_FINAL_AND_SIX_ROOTS_ONLY')
        self.assertEqual(p['Inputs'], INPUTS)
        self.assertEqual((p['ReadFiles'], p['LogicalRoles']), (23, 23))
        self.assertEqual(p['OriginalProofSha256'], proof_hash(ORIGINAL))
        self.assertEqual(p['PortProofSha256'], proof_hash(PORT))
        self.assertEqual(len(p['CanonicalJoin']['ProtocolProof']['RootEvidence']), 6)

    def test_exact_helpers_missing_extra_and_uncallable(self):
        for name in HELPERS:
            helpers = dict(H); del helpers[name]
            with self.subTest(name=name), self.assertRaises(ValueError): Model().run(helpers=helpers)
        for helpers in (dict(H, Foreign=object()), dict(H, original_replay=object()), []):
            with self.subTest(helpers=type(helpers).__name__), self.assertRaises(ValueError): Model().run(helpers=helpers)

    def test_every_path_requires_its_own_authorization(self):
        for path in DATA:
            model = Model(); model.allowed.remove(path)
            with self.subTest(path=str(path)), self.assertRaises(PermissionError): model.run()

    def test_ignoring_reader_cannot_bypass_any_byte_hash(self):
        for path, raw in DATA.items():
            model = Model(); model.files[path] = bytes([raw[0] ^ 1]) + raw[1:]
            with self.subTest(path=str(path)), self.assertRaises(ValueError): model.run()

    def test_batch_descriptor_controls_are_closed_and_reread(self):
        for key in ('Root', 'Result', 'Artifacts', 'ReceiptSha256', 'ManifestSha256'):
            model = Model(); del model.batch[key]
            with self.subTest(missing=key), self.assertRaises(ValueError): model.run()
        for key, value in (('Foreign', False), ('ReceiptSha256', 'F' * 64), ('ManifestSha256', 'F' * 64),
                ('Result', []), ('Artifacts', []), ('Root', 'C:/foreign-batch')):
            model = Model(); model.batch[key] = value
            with self.subTest(field=key), self.assertRaises((ValueError, PermissionError)): model.run()

    def test_final_roles_do_not_accept_original_or_reference_substitutes(self):
        aliases = dict(Machine='Final/Machine', Final='Final/ELF', Disassembly='Final/Disassembly',
            LinkMap='Final/Map', Startup='Final/Startup', MachineDisassembly='Final/MachineDisassembly')
        for role, key in aliases.items():
            for group in ('Reference', 'NativeEmitted'):
                model = Model(); replacement = model.original['Inputs'][group][role]
                model.port['Inputs'][key] = dict(Role=key, **replacement)
                if role == 'Startup' and group == 'NativeEmitted':
                    self.assertEqual(model.port['Inputs'][key], PORT['Inputs'][key])
                    model.run()
                    continue
                with self.subTest(role=role, side=group), self.assertRaises(ValueError): model.run()

    def test_final_manifest_membership_and_hashes_are_independent(self):
        root = Path(BATCH['Root'])
        for role in ('Machine', 'Final', 'Disassembly', 'LinkMap', 'MachineDisassembly'):
            relative = Path(INPUTS['Final'][role]['Path']).relative_to(root).as_posix()
            for remove in (True, False):
                model = Model()
                if remove: del model.batch['Artifacts'][relative]
                else: model.batch['Artifacts'][relative] = 'F' * 64
                model.reseal()
                with self.subTest(role=role, remove=remove), self.assertRaises(ValueError): model.run()

    def test_whole_file_identity_is_recomputed_from_actual_buffers(self):
        for role in ('Final', 'Machine'):
            model = Model(); path = Path(INPUTS['Final'][role]['Path']); raw = model.files[path] + b'\0'
            model.files[path] = raw
            actual_sha = m.sha
            # Simulated digest collision isolates byte equality from checksum gates.
            def misleading_sha(value):
                return INPUTS['Final'][role]['Sha256'] if value == raw else actual_sha(value)
            with self.subTest(role=role), patch.object(m, 'sha', side_effect=misleading_sha), \
                    self.assertRaisesRegex(ValueError, 'actual whole-file equality/' + role):
                model.run()

    def test_duplicate_control_json_is_not_hidden_by_descriptor_mismatch(self):
        for filename, leading in (('results.json', b'{"Profile":"CM3",'), ('artifacts.json', b'{"Artifacts":{},')):
            model = Model(); root = Path(model.batch['Root']); original = model.files[root / filename]
            raw = leading + original[1:]
            self.assertEqual(json.loads(raw), json.loads(original))
            model.files[root / filename] = raw
            if filename == 'results.json':
                model.batch['ReceiptSha256'] = sha(raw); model.batch['Artifacts']['results.json'] = sha(raw)
                manifest = encoded(dict(Artifacts=model.batch['Artifacts']))
                model.files[root / 'artifacts.json'] = manifest; model.batch['ManifestSha256'] = sha(manifest)
            else: model.batch['ManifestSha256'] = sha(raw)
            with self.subTest(file=filename), self.assertRaises(ValueError): model.run()

    def test_explicit_reader_facade_has_no_physical_fallback(self):
        def escape(*args, **kwargs): return Path('C:/not-authorized-final.o').read_bytes()
        with patch.object(H['decoder'], 'Object', side_effect=escape), \
                self.assertRaisesRegex(ValueError, 'constructor read outside final replacement roles'):
            Model().run()

    def test_final_predicates_do_not_invent_readelf_or_replay_prior_binaries(self):
        with patch.object(H['abi'], 'inspect', side_effect=AssertionError('no final readelf/ABI inspection')), \
                patch.object(H['original_replay'], 'inspect', side_effect=AssertionError('no invented capture replay')), \
                patch.object(H['port_replay'], 'inspect', side_effect=AssertionError('no port compiler replay')):
            Model().run()

    def test_detached_validator_allows_tokens_but_no_binary_inspectors(self):
        with detached(), patch.object(H['checker'], 'check_pair', wraps=H['checker'].check_pair) as check:
            result = m.require_result(copy.deepcopy(self.proof), BATCH, PORT, ORIGINAL, H)
        self.assertIsNot(result, False)
        self.assertGreaterEqual(check.call_count, 1)

    def test_full_component_hashes_reject_metadata_substitution(self):
        for name in ('OriginalProofSha256', 'PortProofSha256'):
            bad = copy.deepcopy(self.proof); bad[name] = '0' * 64
            with self.subTest(hash=name): self.reject(bad)
        for name in ('port', 'original'):
            model = Model(); value = getattr(model, name); value['Foreign'] = False
            with self.subTest(component=name): self.reject(copy.deepcopy(self.proof), model=model)

    def test_result_keys_identity_facts_and_counters_are_literal(self):
        for key in FIELDS:
            bad = copy.deepcopy(self.proof); del bad[key]
            with self.subTest(missing=key): self.reject(bad)
        for key, value in (('Foreign', False), ('LTO', 1), ('FreshFinalCanonicalRootsRecomputed', 1),
                ('OwnFinalInputsBound', 1), ('ReadFiles', True), ('LogicalRoles', 23.0),
                ('ToolInvocations', False), ('CompilerInvocations', 1), ('RequiredCellsSatisfied', 1),
                ('Mode', 'O2-lto'), ('BatchRoot', 'C:/foreign-batch')):
            bad = copy.deepcopy(self.proof); bad[key] = value
            with self.subTest(field=key): self.reject(bad)

    def test_independent_nonclaim_catalog_and_literal_false_values(self):
        self.assertEqual(set(self.proof['Nonclaims']), NONCLAIMS)
        for name in NONCLAIMS:
            for value in (True, 0):
                bad = copy.deepcopy(self.proof); bad['Nonclaims'][name] = value
                with self.subTest(name=name, value=value): self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['Nonclaims']['SelectedReplacementBodiesIdentical'] = False; self.reject(bad)

    def test_inputs_closed_bindings_reject_foreign_paths_and_extra_fields(self):
        for group, rows in INPUTS.items():
            for role in rows:
                for value in (dict(Path='C:/foreign.o', Sha256='F' * 64), dict(rows[role], Foreign=False)):
                    bad = copy.deepcopy(self.proof); bad['Inputs'][group][role] = value
                    with self.subTest(group=group, role=role): self.reject(bad)

    def test_all_eight_control_bytes_and_read_sizes_are_bound(self):
        self.assertEqual(set(self.proof['ControlBytes']), set(CONTROL))
        for name in CONTROL:
            bad = copy.deepcopy(self.proof); raw = bytes.fromhex(bad['ControlBytes'][name])
            bad['ControlBytes'][name] = (bytes([raw[0] ^ 1]) + raw[1:]).hex()
            with self.subTest(control=name): self.reject(bad)
        for change in ('reverse', 'duplicate', 'missing', 'extra', 'boolbytes'):
            bad = copy.deepcopy(self.proof); rows = bad['ReadInputs']
            if change == 'reverse': rows.reverse()
            elif change == 'duplicate': rows[-1] = copy.deepcopy(rows[0])
            elif change == 'missing': rows.pop()
            elif change == 'extra': rows.append(dict(Path='C:/foreign', Sha256='F' * 64, Bytes=1))
            else: rows[0]['Bytes'] = True
            with self.subTest(change=change): self.reject(bad)

    def test_both_byte_comparisons_have_complete_typed_bindings(self):
        self.assertEqual(set(self.proof['ByteComparisons']), {'Final', 'Machine'})
        for name in ('Final', 'Machine'):
            row = self.proof['ByteComparisons'][name]
            self.assertEqual(set(row), {'Left', 'Right', 'Bytes', 'Sha256', 'Identical'})
            for key, value in (('Identical', 1), ('Bytes', True), ('Sha256', '0' * 64),
                    ('Left', row['Right']), ('Foreign', False)):
                bad = copy.deepcopy(self.proof); bad['ByteComparisons'][name][key] = value
                with self.subTest(comparison=name, field=key): self.reject(bad)

    def test_transports_cannot_borrow_original_native_paths_or_promote_claims(self):
        for side in ('Native', 'Reference'):
            for key, value in (('BodySha256', '0' * 64), ('CanonicalProtocolValidated', True), ('InstructionCount', True)):
                bad = copy.deepcopy(self.proof); bad['TransportRoots'][side][0][key] = value
                with self.subTest(side=side, field=key): self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['TransportRoots']['Native'] = copy.deepcopy(ORIGINAL['TransportRoots']['Native'])
        self.reject(bad)

    def test_canonical_tokens_and_ledger_evidence_are_revalidated(self):
        for side in ('Native', 'Reference'):
            for key, value in (('RawTokenSha256', '0' * 64), ('RawCanonicalTokens', []), ('Foreign', False)):
                bad = copy.deepcopy(self.proof); bad['CanonicalJoin']['Roots'][side][0][key] = value
                with self.subTest(side=side, field=key): self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['PolicyDifferenceRationales'] = {}; self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['CanonicalJoin']['MutantsReexecuted'] = True; self.reject(bad)

    def test_nested_schemas_and_own_load_image_comparison_reject_tampering(self):
        for target in ('BatchAuthority', 'Inputs', 'ByteComparisons', 'LoadImageComparison', 'TransportRoots', 'CanonicalJoin'):
            bad = copy.deepcopy(self.proof); bad[target]['Foreign'] = False
            with self.subTest(target=target): self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['LoadImageComparison']['Entry'] ^= 2; self.reject(bad)

    def test_reference_and_original_sizes_join_original_inventory(self):
        for group, role in (('Reference', 'Machine'), ('OriginalNative', 'Ordinary')):
            bad = copy.deepcopy(self.proof); path = bad['Inputs'][group][role]['Path']
            next(row for row in bad['ReadInputs'] if row['Path'] == path)['Bytes'] += 1
            with self.subTest(group=group, role=role): self.reject(bad)

    def test_final_auxiliary_sizes_join_port_inventory(self):
        for role in ('LinkMap', 'Disassembly', 'MachineDisassembly', 'Startup'):
            bad = copy.deepcopy(self.proof); path = bad['Inputs']['Final'][role]['Path']
            next(row for row in bad['ReadInputs'] if row['Path'] == path)['Bytes'] += 1
            with self.subTest(role=role): self.reject(bad)

    def test_coordinated_comparison_sizes_cannot_replace_prior_authority(self):
        for name in ('Final', 'Machine'):
            bad = copy.deepcopy(self.proof); comparison = bad['ByteComparisons'][name]
            comparison['Bytes'] += 1
            paths = {comparison[side]['Path'] for side in ('Left', 'Right')}
            for row in bad['ReadInputs']:
                if row['Path'] in paths: row['Bytes'] += 1
            with self.subTest(comparison=name): self.reject(bad)

    def test_exact_read_inventory_and_inputs_are_not_mutated(self):
        model = Model(); before = copy.deepcopy((model.batch, model.port, model.original))
        result = model.run()
        self.assertEqual((model.batch, model.port, model.original), before)
        self.assertEqual(len(model.reads), 23); self.assertEqual({p for p, _ in model.reads}, set(DATA))
        self.assertEqual(result['ReadInputs'], [dict(Path=str(p), Sha256=sha(raw), Bytes=len(raw)) for p, raw in sorted(DATA.items())])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv); output = args.output_dir.resolve(); temp = Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temp) or output.is_relative_to(ROOT):
        parser.error('fresh external TEMP output directory required')
    report = dict(Status='FAIL', Tests=0, ExpectedTests=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, FixtureHashes={}, SourceClosureVerified=False, FixtureClosureVerified=False,
        ActualOriginalBytePredicatesExercised=False, ActualFinalReplacementBytePredicatesExercised=False,
        PortProofFromPinnedReceipt=True, PortComponentRecomputed=False, ActualCaptureAdmitted=False,
        ActualCombinedCLIReplay=False, CompilerInvocations=0, ToolInvocations=0,
        Qualification=False, BoardExecution=False, RequiredCellsSatisfied=0)
    previous = list(sys.meta_path)
    try:
        need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize,
            'fresh isolated unoptimized -I -S -B interpreter')
        with patch('subprocess.Popen', side_effect=AssertionError('no processes')), patch('os.system', side_effect=AssertionError('no shell')):
            initialize()
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(FinalTests)
            need(suite.countTestCases() == METHODS, 'exact test method count')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            Details=[dict(Test=str(case), Error=error) for case, error in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped: report['Status'] = 'PASS'
    except BaseException:
        report.update(Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        sys.meta_path[:] = previous
    report.update(ActualOriginalBytePredicatesExercised=ORIGINAL_EXERCISED,
        ActualFinalReplacementBytePredicatesExercised=FINAL_EXERCISED)
    for key, buffers in (('Source', BUFFERS), ('Fixture', FIXTURES)):
        report[key + 'Hashes'] = {str(p): sha(raw) for p, raw in buffers.items()}
        try: closed = bool(buffers) and all(p.read_bytes() == raw for p, raw in buffers.items())
        except BaseException: closed = False
        report[key + 'ClosureVerified'] = closed
        if not closed: report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False); raw = encoded(report); (output / 'results.json').write_bytes(raw)
    print(json.dumps({k: v for k, v in report.items() if k not in ('SourceHashes', 'FixtureHashes', 'Details', 'Error')}, sort_keys=True))
    print('ReceiptSha256=' + sha(raw))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
