"""Bounded original-byte fixtures and independent controls; no capture admission."""

import argparse
from contextlib import contextmanager, ExitStack
import copy
import hashlib
import importlib.abc
import importlib.util
import json
import math
import os
from pathlib import Path
import struct
import sys
import tempfile
import traceback
from types import ModuleType
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / 'original_replay.py'
HELPERS = ('abi', 'link_helpers', 'binding_helpers', 'native_roots', 'reference_roots',
    'native_protocol', 'reference_protocol', 'decoder', 'checker', 'os_join', 'join', 'guard')
TOP = frozenset(('Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'LTO', 'Cohort',
    'SourceInventorySha256', 'Authorities', 'Inputs', 'NativeBindings', 'LoadImageComparisons',
    'TransportRoots', 'CanonicalJoin', 'PolicyDifferenceRationales', 'ControlBytes', 'ReadInputs',
    'ReadFiles', 'LogicalRoles', 'UniqueEvidencePaths', 'ToolInvocations', 'CompilerInvocations',
    'RequiredCellsSatisfied', 'Nonclaims'))
ORDINARY = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'Attributes', 'MachineAttributes')
EMITTED = (*ORDINARY, 'MachineDisassembly')
REFERENCE = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'Plain', 'MachineDisassembly')
CONTROL = ('NativeReceipt', 'NativeManifest', 'ReferenceReceipt', 'ReferenceManifest',
    'NativeLoadImages', 'ReferenceLoadImages', 'MasterLedger', 'PolicyLedger')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'FullInstructionSemantics', 'SourceIRProof', 'SourceToIRSemanticProof',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'OrdinaryRootPreservationProven', 'HandlerRoutingProven', 'FinalReferenceParity',
    'InstructionEquivalence', 'PolicyEquivalence', 'ArbitraryCallbackSafetyProven',
    'MutantsReexecuted', 'ProducerCompilersReexecuted', 'SelectedReplacementBodiesIdentical',
    'CompleteCellProof', 'WholeCellProof', 'RequiredCellSatisfied', 'CellContractSatisfied',
    'ArchiveQualification', 'HostedCIQualified', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified')
CAPTURES = {
    'Native': ('C:/fz-current-cm3-lto-capture-20261106-e3/native-Os-lto',
        'D8BBA48B5EBEA3555226A9BA2E9D65D7B5E7EFED44A817902A11A23E0A6317B4',
        '422958DE9A8F5BB0F43C7EABC763A0FAF7EEEC796CFAB946D7275EA8761E2F9E'),
    'Reference': ('C:/fz-current-cm3-lto-capture-20261106-e3/reference-Os-lto',
        'B7D7D82EAF35E1B73BFC788B204EF998E45B9FDA077D583201362E7B2EBBE246',
        'F527A4D21B4CC77C91F7C3314B9D83DBCDC2B208A4A83CEC11180DFDF2226785'),
}
PINS = {
    'abi': ('cm3_os_lto_final_cell/abi.py', 'D0471869CA413901AB51016BDA662683FAED60231FB87CD9F9BA14BFD121A73E'),
    'link_helpers': ('cm3_lto_link_contract/audit.py', '9D6B4E1694A8C0A2D7F2E1C7B6D108B58B103131DD7C19D45CD08238E4CED759'),
    'binding_helpers': ('cm3_lto_runtime_bindings/bindings.py', 'A8C994427DDE61619AB789D62E198B24DEC0B05EF8D1EE8E1C28BE86536E4C3B'),
    'native_roots': ('cm3_lto_roots/native.py', 'D4BA0378FA50E11A570D40180149794B16EB0807E36DC902C19840E32D1AF05D'),
    'reference_roots': ('cm3_reference_lto_roots/reference.py', '3E53C4C0C5030B973A599FBDD0CB0B7FDECC625DEFD8C204A8C9691C5F6A616D'),
    'native_protocol': ('cm3_lto_protocol/protocol.py', 'BA3B630BB1FEA67C81D2EE18C84F6D2A47DE9802E8763F52EE55DB34CD65F419'),
    'reference_protocol': ('cm3_reference_lto_protocol/protocol.py', '200B277D03DF4236FE887907F732BC2A26898D8C15C1544D917B3DC3CF6BF798'),
    'decoder': ('cm55_tfm_parity/elf.py', '394BA0549C2325BC5BB988EB1A6EBA89263CAF3E351189582931C59A64D5752D'),
    'checker': ('cm3_freeze_parity/check.py', 'F0D9CD4F48912FB6E5455AA365BF73FFCF356BAFAD922B3A73ACA992A616A11A'),
    'os_join': ('cm3_os_lto_join/compose.py', '359BB0E7463F4514F5964529702DDC07CCED773927970AC3C246A1B7E845367E'),
    'join': ('cm3_lto_join/join.py', 'F4EF2402495FF90C6D781762EC2B85A458F7DA702F14B2C6A1581D9E09343CE3'),
    'guard': ('cm3_os_lto_final_cell/batch_guard.py', '1281084AF70A6AADEA9590E4839311D3F3FA813B17ED06EEE5CD402F4E69BAFD'),
    'core': ('classic_final_image/elf.py', '3A8F4E42B42189CDDAE44DE6AFA4468F24781B6EDFD13F02491C96C1E0729809'),
}
OLD_PROOFS = {
    'bindings': ('cm3-os-lto-bindings-20261106-e2/results.json',
        '369526F5CE2DEA3B1A496AEF5437A8EF25FBB0F131D38C71E5696509CE0D12A9'),
    'join': ('cm3-current-os-protected-replay-20261106-e2/results.json',
        'F74E17BE8B55C0359F807E968ED7D7EFC42FA495F2E2AF37A4ED78B69EF2A57A'),
}
MASTER_SHA = '0C8903A49C927D4E807E75C3619DD4D43AF81663672421A6A3DF4BB28892B2B9'
POLICY_SHA = '778B098F80EAE5EE641B323B4F8D60441C2F725921B506AEDA90B487D3EB5019'
BUFFERS, FIXTURES, DATA, DESCRIPTORS, ROLES, LEDGERS, PRIOR = {}, {}, {}, {}, {}, {}, {}
H, PARSER = {}, {}
m = core = None


def need(value, detail):
    if not value:
        raise ValueError('original-replay-tests: ' + detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def unique(rows):
    result = {}
    for key, value in rows:
        need(key not in result, 'duplicate fixture JSON key')
        result[key] = value
    return result


def finite(value):
    result = float(value)
    need(math.isfinite(result), 'nonfinite fixture JSON')
    return result


def structured(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_float=finite,
        parse_constant=lambda value: need(False, 'nonfinite constant/' + value))


def snapshot(path, expected, destination):
    path = Path(path)
    raw = path.read_bytes()
    need(sha(raw) == expected, 'fixed input drift/' + str(path))
    need(path not in destination or destination[path] == raw, 'input collision')
    destination[path] = raw
    return raw


def prepare_inputs():
    DATA.clear(); DESCRIPTORS.clear(); ROLES.clear(); LEDGERS.clear(); PRIOR.clear()
    for side, (folder, receipt, manifest) in CAPTURES.items():
        root = Path(folder)
        result = structured(snapshot(root / 'results.json', receipt, DATA))
        artifacts = structured(snapshot(root / 'artifacts.json', manifest, DATA))['Artifacts']
        need(artifacts['results.json'] == receipt, 'capture fixture receipt/manifest')
        DESCRIPTORS[side] = dict(Root=str(root), Result=result, Artifacts=artifacts,
            ReceiptSha256=receipt, ManifestSha256=manifest)

        def role(path):
            path = Path(path)
            need(path.is_relative_to(root), 'fixture role outside capture')
            digest = artifacts[path.relative_to(root).as_posix()]
            snapshot(path, digest, DATA)
            return dict(Path=str(path), Sha256=digest)

        links = {row['Kind']: row for row in result['Links']}
        for kind in (('ordinary', 'emit-relocs') if side == 'Native' else ('emit-relocs',)):
            link = links[kind]; final, machine = Path(link['Path']), Path(link['Machine'])
            paths = dict(Machine=machine, Final=final, Disassembly=Path(str(final) + '.dis'),
                LinkMap=Path(link['Map']), Startup=Path(result['Sources'][-1]['Object']))
            if side == 'Native':
                paths.update(Attributes=Path(str(final) + '.readelf'), MachineAttributes=Path(str(machine) + '.readelf'))
                if kind == 'emit-relocs': paths['MachineDisassembly'] = Path(str(machine) + '.dis')
                group = 'NativeOrdinary' if kind == 'ordinary' else 'NativeEmitted'
            else:
                paths.update(Plain=Path(links['ordinary']['Path']), MachineDisassembly=Path(str(machine) + '.dis'))
                group = 'Reference'
            ROLES[group] = {name: role(path) for name, path in paths.items()}
        ROLES.setdefault('LoadImages', {})[side] = role(root / 'load-image.json')
        need(ROLES['LoadImages'][side]['Sha256'] == result['TwinLoadImagesSha256'], 'load-image fixture binding')
    n, r = (DESCRIPTORS[side]['Result'] for side in ('Native', 'Reference'))
    need(type(n['SourceInventoryReceipt']) is str and n['SourceInventoryReceipt'] == r['SourceInventoryReceipt'], 'shared inventory STRING')
    master = Path(n['SourceInventoryReceipt']) / 'inputs/FREERTOS_ASM_PARITY.md'
    need(n['InputHashes'][str(master)] == r['InputHashes'][str(master)] == MASTER_SHA, 'shared captured master authority')
    policy = ROOT / 'tools/fixtures/cm3_final_join/POLICY_DIFFERENCES.md'
    for key, path, digest in (('Master', master, MASTER_SHA), ('Policy', policy, POLICY_SHA)):
        snapshot(path, digest, DATA); LEDGERS[key] = dict(Path=str(path), Sha256=digest)
    need(len(DATA) == 29, 'exact 29 byte fixtures')
    FIXTURES.update(DATA)
    for key, (relative, digest) in OLD_PROOFS.items():
        path = Path(tempfile.gettempdir()) / relative
        PRIOR[key] = structured(snapshot(path, digest, FIXTURES))


class CapturedParser(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        if fullname != 'elftools' and not fullname.startswith('elftools.'):
            return None
        need(fullname in PARSER and target is None, 'unenrolled parser import/' + fullname)
        source, package = PARSER[fullname]
        spec = importlib.util.spec_from_loader(fullname, self, origin=str(source), is_package=package)
        if package: spec.submodule_search_locations = [str(source.parent)]
        return spec

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        path, package = PARSER[module.__name__]
        module.__file__ = str(path)
        exec(compile(BUFFERS[path], str(path), 'exec'), module.__dict__)


def load(name, path):
    module = ModuleType(name); module.__file__ = str(path)
    exec(compile(BUFFERS[path], str(path), 'exec'), module.__dict__)
    return module


def initialize(helpers=None):
    global m, core, H
    if m is not None:
        if helpers is not None: H = {key: helpers[key] for key in HELPERS}
        return
    need(not any(k == 'elftools' or k.startswith('elftools.') for k in sys.modules), 'fresh captured parser namespace')
    prepare_inputs()
    for path in (Path(__file__).resolve(), SUBJECT, HERE / 'ORIGINAL_REPLAY_CONTRACT.md'):
        BUFFERS[path] = path.read_bytes()
    for key, (relative, digest) in PINS.items():
        snapshot(HERE.parent / relative, digest, BUFFERS)
    seed = DESCRIPTORS['Native']['Result']['SeedAuthority']
    package_root = Path(seed['Build'])
    manifest_path = package_root / 'artifacts.json'
    manifest = structured(snapshot(manifest_path, seed['ArtifactsSha256'], FIXTURES))['Artifacts']
    for name, digest in manifest.items():
        if name.startswith('python/elftools/') and name.endswith('.py'):
            path = package_root / name; snapshot(path, digest, BUFFERS)
            parts = list(path.relative_to(package_root / 'python').with_suffix('').parts)
            package = parts[-1] == '__init__'
            if package: parts.pop()
            PARSER['.'.join(parts)] = path, package
    need(len(PARSER) == 52, 'closed captured parser package')
    sys.meta_path.insert(0, CapturedParser())
    H = {key: load('_original_test_' + key, HERE.parent / PINS[key][0]) for key in HELPERS}
    core = load('_original_test_core', HERE.parent / PINS['core'][0])
    m = load('_original_test_leaf', SUBJECT)
    if helpers is not None:
        need(type(helpers) is dict and set(HELPERS) <= set(helpers), 'actual composition helper subset')
        H = {key: helpers[key] for key in HELPERS}


@contextmanager
def no_io():
    with ExitStack() as stack:
        for name in ('read_bytes', 'read_text', 'open', 'stat', 'lstat', 'exists', 'iterdir', 'glob', 'rglob', 'resolve'):
            stack.enter_context(patch.object(Path, name, side_effect=AssertionError('physical I/O forbidden/' + name)))
        for name in ('builtins.open', 'os.open', 'os.stat', 'os.lstat', 'subprocess.Popen', 'os.system'):
            stack.enter_context(patch(name, side_effect=AssertionError('physical/process I/O forbidden/' + name)))
        yield


class Model:
    def __init__(self):
        self.native, self.reference = (copy.deepcopy(DESCRIPTORS[side]) for side in ('Native', 'Reference'))
        self.roles, self.ledgers = copy.deepcopy(ROLES), copy.deepcopy(LEDGERS)
        self.files, self.allowed, self.reads = dict(DATA), set(DATA), []

    def read(self, path, expected=None):
        if not isinstance(path, Path) or path not in self.allowed:
            raise PermissionError('reader role not explicitly authorized/' + str(path))
        raw = self.files[path]
        if expected is not None and sha(raw) != expected:
            raise ValueError('test reader expected digest mismatch')
        self.reads.append((path, expected))
        return raw

    def reseal(self, side):
        descriptor = self.native if side == 'Native' else self.reference
        root = Path(descriptor['Root']); raw = encoded(descriptor['Result'])
        self.files[root / 'results.json'] = raw
        descriptor['ReceiptSha256'] = sha(raw)
        descriptor['Artifacts']['results.json'] = sha(raw)
        raw = encoded(dict(Artifacts=descriptor['Artifacts']))
        self.files[root / 'artifacts.json'] = raw
        descriptor['ManifestSha256'] = sha(raw)

    def run(self, **options):
        arguments = dict(core=core, read=self.read, native=self.native, reference=self.reference,
            helpers=H, roles=self.roles, ledgers=self.ledgers)
        arguments.update(options)
        with no_io(): return m.inspect(**arguments)


def synthetic_result(helpers):
    """Inspect actual byte fixtures without capture admission or CLI credit."""
    initialize(helpers)
    return Model().run()


class OriginalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proof = Model().run()

    def reject(self, proof):
        with no_io(), self.assertRaises((ValueError, RuntimeError, KeyError, TypeError)):
            m.require_result(proof, H)

    def test_actual_twins_six_roots_and_prior_comparisons(self):
        proof = self.proof
        self.assertEqual(set(proof), TOP)
        self.assertEqual((proof['ReadFiles'], proof['LogicalRoles'], proof['UniqueEvidencePaths']), (29, 30, 25))
        self.assertEqual(proof['NativeBindings'], {('Ordinary' if r['Kind'] == 'ordinary' else 'Emitted'): r['Proof']
            for r in PRIOR['bindings']['Links']})
        self.assertEqual(proof['CanonicalJoin'], PRIOR['join']['JoinProof'])
        self.assertEqual(proof['PolicyDifferenceRationales'], PRIOR['join']['PolicyDifferenceRationales'])
        self.assertEqual(len(proof['CanonicalJoin']['ProtocolProof']['RootEvidence']), 6)

    def test_exact_helper_set_and_callable_surface(self):
        for name in HELPERS:
            helpers = dict(H); del helpers[name]
            with self.subTest(missing=name), self.assertRaises((ValueError, RuntimeError)):
                Model().run(helpers=helpers)
        with self.assertRaises((ValueError, RuntimeError)):
            Model().run(helpers=dict(H, foreign=object()))

    def test_role_and_ledger_bindings_are_closed_not_hashless(self):
        for group, names in (('NativeOrdinary', ORDINARY), ('NativeEmitted', EMITTED), ('Reference', REFERENCE)):
            for name in names:
                for value in (Path(ROLES[group][name]['Path']), ROLES[group][name]['Path'],
                              dict(ROLES[group][name], Foreign=True)):
                    model = Model(); model.roles[group][name] = value
                    with self.subTest(group=group, role=name, value=type(value).__name__), self.assertRaises((ValueError, RuntimeError)):
                        model.run()
        for name in LEDGERS:
            model = Model(); model.ledgers[name] = Path(LEDGERS[name]['Path'])
            with self.subTest(ledger=name), self.assertRaises((ValueError, RuntimeError)): model.run()

    def test_each_reader_role_is_required(self):
        for path in DATA:
            model = Model(); model.allowed.remove(path)
            with self.subTest(path=str(path)), self.assertRaises((ValueError, PermissionError, RuntimeError)): model.run()

    def test_each_byte_input_is_hash_bound(self):
        for path in DATA:
            model = Model(); raw = model.files[path]; model.files[path] = bytes([raw[0] ^ 1]) + raw[1:]
            # The reader intentionally ignores expected hashes: the leaf must reject.
            with self.subTest(path=str(path)), self.assertRaisesRegex(ValueError, 'immutable byte/hash binding'):
                model.run(read=lambda p, expected=None: model.files[p])

    def test_wrong_side_maps_startup_and_machine_reject(self):
        for role in ('Machine', 'Final', 'LinkMap', 'Startup', 'Disassembly', 'MachineDisassembly'):
            model = Model(); model.roles['NativeEmitted'][role] = copy.deepcopy(model.roles['Reference'][role])
            with self.subTest(role=role), self.assertRaises((ValueError, RuntimeError)): model.run()

    def test_descriptor_keys_receipt_hash_and_inventory_types(self):
        for field, value in (('LTO', 1), ('Mode', 'O2-lto'), ('SourceInventoryReceipt', {}),
                             ('SourceInventorySha256', 'F' * 64)):
            model = Model(); model.native['Result'][field] = value; model.reseal('Native')
            with self.subTest(field=field), self.assertRaises((ValueError, RuntimeError)): model.run()
        model = Model(); model.native['ReceiptSha256'] = '0' * 64
        with self.assertRaises((ValueError, RuntimeError)): model.run()
        model = Model(); model.native['Foreign'] = True
        with self.assertRaises((ValueError, RuntimeError)): model.run()

    def test_duplicate_and_nonfinite_json_reject_after_hash_rebinding(self):
        original = DATA[Path(DESCRIPTORS['Native']['Root']) / 'results.json']
        duplicate = b'{"Profile":"CM3",' + original[1:]
        self.assertEqual(json.loads(duplicate), json.loads(original))
        for raw in (duplicate, b'{"Value":NaN}', b'{"Value":1e999}'):
            model = Model(); root = Path(model.native['Root']); model.files[root / 'results.json'] = raw
            digest = sha(raw); model.native['ReceiptSha256'] = digest; model.native['Artifacts']['results.json'] = digest
            manifest = encoded(dict(Artifacts=model.native['Artifacts']))
            model.files[root / 'artifacts.json'] = manifest; model.native['ManifestSha256'] = sha(manifest)
            with self.subTest(raw=raw), self.assertRaises((ValueError, RuntimeError)): model.run()
            with self.subTest(parser=raw[:32]), self.assertRaises(ValueError): m._json(raw)

    def test_external_startup_symbols_and_defined_provider_boundaries(self):
        for twin in ('Ordinary', 'Emitted'):
            for i in (1, 2):
                symbol = self.proof['NativeBindings'][twin]['StartupVectors'][i]['OriginalRelocationSymbol']
                self.assertEqual((symbol['section'], symbol['kind'], symbol['value'], symbol['size']),
                                 ('SHN_UNDEF', 'STT_NOTYPE', 0, 0))
                for key, value in (('name', 'Reset_Handler'), ('section', 1), ('size', 1), ('value', 1),
                                   ('kind', 'STT_FUNC'), ('binding', 'STB_WEAK')):
                    bad = copy.deepcopy(self.proof)
                    bad['NativeBindings'][twin]['StartupVectors'][i]['OriginalRelocationSymbol'][key] = value
                    with self.subTest(twin=twin, slot=i, field=key): self.reject(bad)
            bad = copy.deepcopy(self.proof)
            bad['NativeBindings'][twin]['ReverseReferences'][0]['OriginalRelocationSymbol']['section'] = 'SHN_UNDEF'
            self.reject(bad)

    def test_top_schema_identity_and_literal_counters(self):
        for key in TOP:
            bad = copy.deepcopy(self.proof); del bad[key]
            with self.subTest(missing=key): self.reject(bad)
        for key in ('ReadFiles', 'LogicalRoles', 'UniqueEvidencePaths', 'ToolInvocations', 'CompilerInvocations', 'RequiredCellsSatisfied'):
            bad = copy.deepcopy(self.proof); bad[key] = True
            with self.subTest(counter=key): self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['Foreign'] = False; self.reject(bad)

    def test_all_nonclaims_are_closed_and_literal_false(self):
        self.assertEqual(set(self.proof['Nonclaims']), set(NONCLAIMS))
        for name in self.proof['Nonclaims']:
            for value in (True, 0):
                bad = copy.deepcopy(self.proof); bad['Nonclaims'][name] = value
                with self.subTest(claim=name, value=value): self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['Nonclaims']['Foreign'] = False; self.reject(bad)

    def test_each_control_buffer_and_size_is_bound(self):
        for name in CONTROL:
            bad = copy.deepcopy(self.proof); raw = bytes.fromhex(bad['ControlBytes'][name])
            bad['ControlBytes'][name] = (bytes([raw[0] ^ 1]) + raw[1:]).hex()
            with self.subTest(control=name): self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['ReadInputs'][0]['Bytes'] = True; self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['ReadInputs'].reverse(); self.reject(bad)

    def test_native_abi_and_nested_unknown_fields_reject(self):
        for branch in ('Ordinary', 'Emitted'):
            for target in ('proof', 'link', 'symbol'):
                bad = copy.deepcopy(self.proof); row = bad['NativeBindings'][branch]
                row = row if target == 'proof' else row['LinkContract'] if target == 'link' else row['MandatoryDefinitions']['SVC_Handler']
                row['Foreign'] = True
                with self.subTest(branch=branch, target=target): self.reject(bad)

    def test_load_images_are_joined_to_saved_control_records(self):
        for side in ('Native', 'Reference'):
            bad = copy.deepcopy(self.proof); bad['LoadImageComparisons'][side]['Entry'] ^= 2
            with self.subTest(side=side): self.reject(bad)

    def test_root_byte_hashes_and_transport_nonclaims_reject(self):
        for side in ('Native', 'Reference'):
            for key, value in (('BodySha256', '0' * 64), ('CanonicalProtocolValidated', True), ('InstructionCount', True)):
                bad = copy.deepcopy(self.proof); bad['TransportRoots'][side][0][key] = value
                with self.subTest(side=side, field=key): self.reject(bad)

    def test_canonical_tokens_hashes_and_ledger_rationales_reject(self):
        for key, value in (('RawTokenSha256', '0' * 64), ('RawCanonicalTokens', []), ('Foreign', False)):
            bad = copy.deepcopy(self.proof); bad['CanonicalJoin']['Roots']['Native'][0][key] = value
            with self.subTest(field=key): self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['CanonicalJoin']['MutantsReexecuted'] = True; self.reject(bad)
        bad = copy.deepcopy(self.proof); bad['PolicyDifferenceRationales'] = {}; self.reject(bad)

    def test_final_validator_uses_no_binary_inspectors(self):
        with ExitStack() as stack:
            for helper, name in (('abi', 'inspect'), ('os_join', 'check_join'), ('decoder', 'Object'),
                                 ('native_roots', 'NativeCM3LTOImage'), ('reference_roots', 'ReferenceCM3LTOImage')):
                stack.enter_context(patch.object(H[helper], name, side_effect=AssertionError('binary inspector forbidden')))
            stack.enter_context(patch.object(core, 'FinalImage', side_effect=AssertionError('binary constructor forbidden')))
            with no_io(): m.require_result(copy.deepcopy(self.proof), H)

    def test_inspect_does_not_mutate_inputs_and_consumes_exact_29(self):
        model = Model(); before = copy.deepcopy((model.native, model.reference, model.roles, model.ledgers))
        model.run()
        self.assertEqual(before, (model.native, model.reference, model.roles, model.ledgers))
        self.assertEqual(len(model.reads), 29); self.assertEqual({p for p, _ in model.reads}, set(DATA))

    def test_no_physical_fallback_for_unauthorized_binary_read(self):
        def escape(*args, **kwargs): return Path('C:/NOT-ADMITTED.o').read_bytes()
        helpers = dict(H); helpers['decoder'] = ModuleType('escaping_decoder'); helpers['decoder'].Object = escape
        with self.assertRaisesRegex(ValueError, 'binary constructor read escapes admitted roles'):
            Model().run(helpers=helpers)

    def test_startup_allowed_names_cannot_be_swapped_or_used_as_defined_origin(self):
        for twin in ('Ordinary', 'Emitted'):
            for index in (1, 2):
                bad = copy.deepcopy(self.proof); row = bad['NativeBindings'][twin]['StartupVectors'][index]
                row['OriginalRelocationSymbol']['name'] = 'PendSV_Handler' if index == 1 else 'SVC_Handler'
                self.reject(bad)
                bad = copy.deepcopy(self.proof); row = bad['NativeBindings'][twin]['StartupVectors'][index]
                row['TargetOrigin']['Original'] = copy.deepcopy(row['OriginalRelocationSymbol']); self.reject(bad)

    def test_defined_handlers_must_be_strong_even_when_all_copies_agree(self):
        def weaken(value, name):
            if type(value) is dict:
                if value.get('name') == name and type(value.get('section')) is int: value['binding'] = 'STB_WEAK'
                for child in value.values(): weaken(child, name)
            elif type(value) is list:
                for child in value: weaken(child, name)
        for twin in ('Ordinary', 'Emitted'):
            for name in ('SVC_Handler', 'PendSV_Handler'):
                bad = copy.deepcopy(self.proof); weaken(bad['NativeBindings'][twin], name); self.reject(bad)

    def test_vector_original_bytes_are_zero_addends(self):
        for twin in ('Ordinary', 'Emitted'):
            for index in range(3):
                bad = copy.deepcopy(self.proof)
                bad['NativeBindings'][twin]['StartupVectors'][index]['OriginalBytes'] = '01000000'; self.reject(bad)

    def test_vector_placement_matches_startup_vector_origin(self):
        for twin in ('Ordinary', 'Emitted'):
            for field, value in (('InputSection', '.foreign'), ('SectionSize', 1025), ('SectionAddress', 4),
                                 ('InputSectionIndex', 999), ('OutputSection', '.foreign'), ('OutputSectionIndex', 999)):
                bad = copy.deepcopy(self.proof)
                bad['NativeBindings'][twin]['StartupVectors'][1]['InputPlacement'][field] = value
                with self.subTest(twin=twin, field=field): self.reject(bad)

    def test_captured_master_is_not_live_documentation(self):
        model = Model(); model.ledgers['Master']['Path'] = str(ROOT / 'FREERTOS_ASM_PARITY.md')
        with self.assertRaises((ValueError, RuntimeError)): model.run()


def main(argv=None):
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize,
         'fresh isolated unoptimized -I -S -B interpreter')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv); output = args.output_dir.resolve(); temporary = Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temporary) or output.is_relative_to(ROOT):
        parser.error('fresh external TEMP receipt directory required')
    initialize()
    sources, fixtures = {str(p): sha(raw) for p, raw in BUFFERS.items()}, {str(p): sha(raw) for p, raw in FIXTURES.items()}
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(OriginalTests); expected = 24
    need(suite.countTestCases() == expected, 'exact method count')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    closing = {name: sha(Path(name).read_bytes()) for name in sources}
    fixture_closing = {name: sha(Path(name).read_bytes()) for name in fixtures}
    report = dict(Status='PASS' if result.wasSuccessful() and result.testsRun == expected and not result.skipped
        and sources == closing and fixtures == fixture_closing else 'FAIL', Tests=result.testsRun, ExpectedTests=expected,
        Errors=len(result.errors), Failures=len(result.failures), Skipped=len(result.skipped), SourceHashes=sources,
        FixtureHashes=fixtures, SourceClosureVerified=sources == closing, FixtureClosureVerified=fixtures == fixture_closing,
        ActualOriginalBytePredicatesExercised=True, ActualCaptureAdmitted=False, ActualCombinedCLIReplay=False,
        CompilerInvocations=0, ToolInvocations=0, Qualification=False, BoardExecution=False, RequiredCellsSatisfied=0)
    output.mkdir(parents=True); raw = encoded(report); (output / 'results.json').write_bytes(raw)
    print(json.dumps({key: value for key, value in report.items() if key not in ('SourceHashes', 'FixtureHashes')}, sort_keys=True))
    print('ReceiptSha256=' + sha(raw))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
