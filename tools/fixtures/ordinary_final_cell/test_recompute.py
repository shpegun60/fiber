"""Synthetic orchestration/closure controls, not ELF or compiler qualification."""
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SUBJECT = HERE / 'recompute.py'
RAW = SUBJECT.read_bytes()


def load(name, path, raw):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


with patch.object(subprocess, 'Popen', side_effect=AssertionError('pure tests cannot launch processes')):
    r = load('_ordinary_recompute_controls', SUBJECT, RAW)
    PROFILE_RAW = (HERE / 'profiles.py').read_bytes()
    if r.sha(PROFILE_RAW) != r.PROFILES_SHA:
        raise AssertionError('fixed independent profile source drift')
    profiles = load('_ordinary_recompute_control_profiles', HERE / 'profiles.py', PROFILE_RAW)
    POLICY_RAW = (r.ROOT / r.POLICY).read_bytes()
    if r.sha(POLICY_RAW) != r.POLICY_SHA:
        raise AssertionError('fixed classic policy supplement drift')

BASE = Path(HERE.anchor) / '_ordinary_recompute_synthetic'


def same(actual, expected, label):
    if r.encoded(actual) != r.encoded(expected):
        raise ValueError(label)


def receipt(contract, root, side):
    reference = side == 'Reference'
    flags = [*contract['CompileFlags'], '-' + contract['Mode'], '-std=gnu11', '-g0', '-ffreestanding']
    definitions = contract['CohortArtifact']['upstream_defines' if reference else 'defines']
    flags += ['-D' + key + '=' + definitions[key] for key in sorted(definitions)]
    flags += ['-I' + str(root / 'include')]
    result = dict(Profile=contract['Profile'], Mode=contract['Mode'], Cohort=contract['Cohort'],
        SourceGroup=contract['SourceGroup'], CohortArtifact=copy.deepcopy(contract['CohortArtifact']),
        SourceInventorySha256=contract['SourceInventorySha256'], Linkage='direct', LTO=False,
        CompileFlags=flags, Sources=[], Links=[dict(Kind=kind, Path=str(root / (kind + '.elf')))
                                            for kind in ('ordinary', 'emit-relocs')])
    for index, relative in enumerate(contract['ReferenceSourceOrder' if reference else 'SourceOrder']):
        source = root / ('freertos' if reference and relative.startswith('portable/') else 'source') / relative
        source_flags = (contract['ReferenceStartupFlags' if reference else 'StartupFlags'] if source.suffix == '.S'
                        else flags + ([] if reference else ['-I' + str(source.parent)]))
        result['Sources'].append(dict(Source=str(source), Object=str(root / 'objects' / ('%02d-' % index + source.stem + '.o')),
            SourceSha256='A' * 64, ObjectSha256='B' * 64, CompileFlags=list(source_flags)))
    if reference:
        result['ReferenceCommit'] = contract['ReferenceCommit']
        if contract['Profile'] in ('CM4', 'CM7'):
            result['FPCCRPolicy'] = dict(DeclaredNativePolicy='eager', ReferencePolicy='upstream-lazy',
                ReferenceASPEN=1, ReferenceLSPEN=1, ReferenceBits=0xC0000000, DifferenceId=r.POLICY_ID,
                PolicyEquivalenceProven=False, HardwareEffectsProven=False)
        else:
            result.update(DeclaredVTOR=contract['Target']['vtor'],
                FixtureHandlerInstallationCheck=contract['ReferenceHandlerInstallationCheck'],
                FPPolicy='NOT-APPLICABLE-NO-FPU', SchedulerThreshold=(
                    'BASEPRI-NOT-APPLICABLE;PRIMASK-ENVELOPE' if contract['SourceGroup'] == 'CM0' else 16))
    return result


class Watch:
    def __init__(self, buffers=None, output=None):
        self.buffers = {} if buffers is None else dict(buffers)
        self.hashes, self.copies, self.reads = {}, {}, []
        self.output, self.closed, self.fail_close = output, 0, False

    def read(self, path, expected=None):
        path = Path(path)
        raw = self.buffers[path]
        digest = r.sha(raw)
        if expected is not None and digest != expected:
            raise ValueError('watched hash')
        if path in self.hashes and self.hashes[path] != digest:
            raise ValueError('watched drift')
        self.hashes[path] = digest
        self.reads.append(path)
        return raw

    def close(self):
        self.closed += 1
        if self.fail_close:
            raise ValueError('joined closure failed')
        for path, digest in self.hashes.items():
            self.read(path, digest)


class Harness:
    """Fake gate stages only; these fixtures assert routing, not ELF semantics."""
    def __init__(self, profile='CM0', mode='O2'):
        self.contract = profiles.profile(profile, mode)
        self.family = r.FAMILIES[profile]
        self.output = BASE / 'output'
        self.inventory = BASE / 'inventory'
        self.active = self.family != 'cm3'
        self.events = []
        self.groups, self.prepared, self.selection = {}, {}, dict(Route=self.contract['Route'])
        native_tokens = [dict(Side='Native', Name=name, Tokens=[['synthetic', index]])
            for index, name in enumerate(('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler'))]
        reference_names = (('vStartFirstTask', 'SVC_Handler', 'vPortSVCHandler_C', 'vRestoreContextOfFirstTask', 'PendSV_Handler')
            if self.family == 'cm0' else ('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler'))
        reference_tokens = [dict(Side='Reference', Name=name, Tokens=[['synthetic', index]])
                            for index, name in enumerate(reference_names)]
        ids = [x for x in self.contract['DifferenceIds'] if x != r.POLICY_ID]
        self.proof = dict(DifferenceIds=ids, RootEvidence=[*native_tokens, *reference_tokens],
            Mechanisms=[dict(Name=name, DifferenceIds=part) for name, part in
                        zip(('first-start', 'first-restore', 'PendSV'), (ids[:2], ids[2:4], ids[4:]))])
        for side in ('Native', 'Reference'):
            root = BASE / side
            result = receipt(self.contract, root, side)
            result['PrelinkNativeRoots' if side == 'Native' else 'PrelinkReferenceRoots'] = copy.deepcopy(
                native_tokens if side == 'Native' else reference_tokens)
            descriptor = dict(Build=str(root), ReceiptSha256=('C' if side == 'Native' else 'D') * 64,
                              ArtifactsSha256=('E' if side == 'Native' else 'F') * 64)
            group = dict(Root=root, Result=result, Artifacts={'synthetic.o': 'B' * 64}, Descriptor=descriptor,
                         ReceiptSha256=descriptor['ReceiptSha256'], ManifestSha256=descriptor['ArtifactsSha256'])
            self.groups[side] = group
            self.selection[side] = descriptor
            owner = dict(PrelinkNativeRoots=copy.deepcopy(native_tokens), PrelinkOwners={'synthetic': 'owner'}) if side == 'Native' else {}
            self.prepared[side] = dict(group, Inventory=self.inventory, MechanismObject=object(),
                Roots=[dict(Name=row['Name'], Complete=True, RawBytesSha256='1' * 64) for row in (native_tokens if side == 'Native' else reference_tokens)],
                Twins=dict(Identical=True, Segments=['synthetic']), UniqueImageInputs=len(result['Sources']) + 4,
                Prelinks=[dict(Path=str(root / 'objects/prelink.o'), Sha256='B' * 64)],
                Prelink=str(root / 'objects/prelink.o'), PrelinkSha256='B' * 64, ReplayedOwnerEvidence=owner)
        self.ledger = ('# Captured master\n\n' + ''.join('### ' + identity + '\n\nIndependent source rationale.\n\n' for identity in ids)).encode('ascii')
        previous = dict(ProtocolProof=copy.deepcopy(self.proof), ClosedBodies=8 if self.family == 'cm0' else 6,
            Mechanisms=copy.deepcopy(self.proof['Mechanisms']), SourceInventorySha256=self.contract['SourceInventorySha256'],
            ReferenceCommit=self.contract['ReferenceCommit'], LedgerSha256=r.sha(self.ledger), ProducerBindings=[])
        for side in ('Native', 'Reference'):
            group = self.prepared[side]
            previous[side + 'FinalRoots'] = copy.deepcopy(group['Roots'])
            previous[side + 'Twins'] = copy.deepcopy(group['Twins'])
            previous[side + 'ArtifactsSha256'] = self.selection[side]['ArtifactsSha256']
            binding = dict(Side=side, Build=str(group['Root']), ReceiptSha256=group['ReceiptSha256'],
                           UniqueImageInputs=group['UniqueImageInputs'])
            if self.family == 'cm0':
                binding['Prelinks'] = copy.deepcopy(group['Prelinks'])
            else:
                binding['PrelinkSha256'] = group['PrelinkSha256']
            if self.family == 'cm3':
                binding.update(ArtifactsSha256=group['ManifestSha256'], Prelink=group['Prelink'],
                               OwnerEvidence=copy.deepcopy(group['ReplayedOwnerEvidence']))
            previous['ProducerBindings'].append(binding)
        if self.family == 'cm3':
            previous.update(DifferenceRationales={'synthetic': {'Text': 'checked by unchanged ledger API'}},
                HashDomains=dict(PrelinkProtocol='SHA256-JSON-TOKENS', FinalRoot='SHA256-APPLIED-ELF-FUNCTION-BYTES',
                                 Ledger='SHA256-CAPTURED-LEDGER-BYTES'),
                FrameContract=dict(NativeCoreSlots=9, NativeExcReturn='PER-CONTEXT-SAVED-LR', ReferenceCoreSlots=8,
                                   ReferenceFirstRestoreExcReturn='ORR-LR-13', EquivalenceProven=False),
                ExecutedSourceBuffers=[dict(Path='synthetic captured helper', Sha256='2' * 64)])
        if self.family == 'classic':
            previous.update(FPSetupDifferenceId=r.POLICY_ID, PolicySupplementSha256=r.sha(POLICY_RAW))
        self.groups['PriorJoin'] = dict(Root=BASE / 'prior', Result=previous)
        self.current = dict(Bundle=dict(Root=self.inventory), Manifest={'synthetic': 'manifest'},
                            SourceInventorySha256=self.contract['SourceInventorySha256'])
        self.gate_path = r.ROOT / self.contract['Gate']
        self.gate_raw = b'# synthetic gate source, never executed\n'
        self.watch = Watch({r.ROOT / r.PROFILES: PROFILE_RAW, self.gate_path: self.gate_raw,
                            self.inventory / 'inputs/FREERTOS_ASM_PARITY.md': self.ledger, r.ROOT / r.POLICY: POLICY_RAW})
        self.joined = Watch(output=self.output / 'recomputed')
        self.api = SimpleNamespace(same=same, SOURCE_PINS={self.contract['Gate']: r.sha(self.gate_raw)})
        self.helpers = dict(checker=SimpleNamespace(check_pair=self.check_pair),
            attributes=SimpleNamespace(require_proof=self.require_proof), inventory=SimpleNamespace(require_proof=self.require_proof),
            native=object(), final=object(), ExecutedSourceBuffers=copy.deepcopy(previous.get('ExecutedSourceBuffers', [])))
        self.join = SimpleNamespace(Watch=self.new_watch, load_api=self.load_api, prepare_group=self.prepare_group,
            _authenticate=self.authenticate, require_pairings=self.require_pairings,
            require_cross_side_inputs=self.cross_side, require_mechanisms=self.require_mechanisms,
            expected_mechanisms=lambda: self.proof['Mechanisms'], require_ledger=self.require_ledger)
        self.binding_status = 'PASS'
        self.bindings = SimpleNamespace(inspect=self.inspect_bindings)

    def assert_active(self):
        if not self.active:
            raise AssertionError('operation escaped frozen loader context')

    def new_watch(self, output):
        same(str(output), str(self.joined.output), 'copy root')
        return self.joined

    def authenticate(self, watch, root, receipt_hash, manifest_hash):
        side = next(side for side in ('Native', 'Reference') if self.groups[side]['Root'] == root)
        same([receipt_hash, manifest_hash], [self.selection[side]['ReceiptSha256'], self.selection[side]['ArtifactsSha256']], 'caller hashes')
        self.events.append(('authenticate', side))
        return copy.deepcopy(self.groups[side])

    @contextmanager
    def scope(self):
        self.events.append(('enter',))
        self.active = True
        try:
            yield self.helpers
        finally:
            self.active = False
            self.events.append(('exit',))

    def load_api(self, *args):
        if self.family == 'cm3':
            same(len(args), 3, 'CM3 context loader arity')
            same([str(args[1]['Root']), str(args[2]['Root'])],
                 [str(self.groups['Native']['Root']), str(self.groups['Reference']['Root'])], 'CM3 groups')
            return self.scope()
        same(len(args), 2, 'ordinary loader arity')
        same(str(args[1]), str(self.groups['Native']['Root']), 'native parser authority')
        return self.helpers

    def prepare_group(self, *args):
        self.assert_active()
        if self.family == 'cm3':
            watch, group, side, profile, mode, helpers = args
        else:
            watch, root, expected, side, profile, mode, helpers = args
            same(str(root), str(self.groups[side]['Root']), 'prepared root')
            same(expected, self.selection[side]['ReceiptSha256'], 'prepared receipt')
        same([profile, mode], [self.contract['Profile'], self.contract['Mode']], 'selected target/mode')
        self.events.append(('prepare', side))
        return self.prepared[side]

    def check_pair(self, *args):
        self.assert_active()
        expected = [self.prepared['Native']['MechanismObject'], self.prepared['Reference']['MechanismObject']]
        if self.family != 'cm3':
            expected.append(self.contract['Mode' if self.family == 'cm0' else 'Profile'])
        if len(args) != len(expected) or any(a is not b for a, b in zip(args[:2], expected[:2])) or args[2:] != tuple(expected[2:]):
            raise AssertionError('wrong family checker API or object identity')
        self.events.append(('check',))
        return copy.deepcopy(self.proof)

    def require_proof(self, proof, *args):
        self.assert_active()
        expected = (self.contract['Profile'], self.contract['Mode']) if self.family == 'classic' else (self.contract['Mode'],)
        same(list(args), list(expected), 'family proof validator signature')
        same(proof, self.proof, 'complete proof passed unchanged')
        self.events.append(('require_proof',))

    def require_pairings(self, proof, profile):
        self.assert_active()
        same(profile, self.contract['Profile'], 'pairing profile')
        self.events.append(('pairings',))

    def cross_side(self, native, reference):
        self.assert_active()
        self.events.append(('cross_side',))

    def require_mechanisms(self, proof):
        self.assert_active()
        self.events.append(('mechanisms',))

    def require_ledger(self, text, proof):
        self.assert_active()
        same(text, self.ledger.decode('ascii'), 'captured master, not policy text')
        return copy.deepcopy(self.groups['PriorJoin']['Result']['DifferenceRationales'])

    def inspect_bindings(self, contract, result, root, final):
        self.assert_active()
        same(contract, self.contract, 'independent private/storage contract')
        same(result, self.groups['Native']['Result'], 'native binding receipt')
        same(str(root), str(self.groups['Native']['Root']), 'native binding root')
        if final is not self.helpers['final']:
            raise AssertionError('wrong final reader')
        self.events.append(('bindings',))
        return dict(Status=self.binding_status)

    def recheck(self, group, native, final, attributes, manifest, profile, mode):
        self.assert_active()
        same([profile, mode], [self.contract['Profile'], self.contract['Mode']], 'native replay mode/profile')
        if manifest is not self.current['Manifest']:
            raise AssertionError('wrong current manifest')
        self.events.append(('pilot',))
        return dict(Sources=copy.deepcopy(group['Result']['Sources']), CompleteSyntheticPredicateReplay=True)

    def run(self):
        def modules(name, path, raw):
            if path == r.ROOT / r.PROFILES:
                same(r.sha(raw), r.PROFILES_SHA, 'profile buffer')
                return profiles
            same([str(path), r.sha(raw)], [str(self.gate_path), r.sha(self.gate_raw)], 'fixed gate buffer')
            return self.join
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('no child processes')), \
             patch.object(r, 'module', modules), patch.object(r, 'recheck_pilot', self.recheck):
            return r.recompute(self.api, self.watch, self.output, self.selection, self.groups,
                               self.current, self.contract, self.bindings)


class RecomputeTests(unittest.TestCase):
    def test_all_thirty_routes_use_exact_family_signatures_and_zero_credit(self):
        for profile in r.FAMILIES:
            for mode in r.MODES:
                with self.subTest(profile=profile, mode=mode):
                    h = Harness(profile, mode)
                    before = r.encoded([h.selection, {k: v['Result'] for k, v in h.groups.items()}, h.contract])
                    facts, joined, copies = h.run()
                    self.assertIs(joined, h.joined)
                    self.assertEqual(joined.closed, 1)
                    self.assertEqual(copies, {})
                    self.assertEqual((facts['Profile'], facts['Mode']), (profile, mode))
                    self.assertIs(facts['MechanismParityWithDeclaredDifferences'], True)
                    self.assertEqual(facts['NativePredicates']['Sources'], h.groups['Native']['Result']['Sources'])
                    self.assertEqual(facts['Bindings']['Status'], 'PASS')
                    self.assertIs(type(facts['RequiredCellsSatisfied']), int)
                    self.assertEqual(facts['RequiredCellsSatisfied'], 0)
                    for key in ('FullABIProof', 'FullSemanticABIProof', 'InstructionEquivalence', 'PolicyEquivalence',
                                'SourceIRProof', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified'):
                        self.assertIs(facts[key], False)
                    self.assertEqual(before, r.encoded([h.selection, {k: v['Result'] for k, v in h.groups.items()}, h.contract]))
                    self.assertEqual(('pilot',) in h.events, profile != 'CM3')
                    if profile == 'CM3':
                        self.assertLess(h.events.index(('bindings',)), h.events.index(('exit',)))

    def test_contract_route_source_inventory_and_gate_are_independently_fixed(self):
        for field, value in (('PrivateSymbol', 'foreign'), ('StorageSymbol', 'foreign'), ('Gate', 'foreign.py'),
                             ('Mode', 'O2-lto'), ('Profile', 'CM33'), ('LTO', 0)):
            h = Harness()
            h.contract[field] = value
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError)):
                h.run()
        h = Harness()
        h.selection['Route'] = 'CM0/Og/direct'
        with self.assertRaises(ValueError):
            h.run()
        h = Harness()
        h.current['SourceInventorySha256'] = '0' * 64
        with self.assertRaises(ValueError):
            h.run()

    def test_native_and_reference_source_metadata_guards_reject_flags_and_bool_aliases(self):
        for side in ('Native', 'Reference'):
            for change in ('mode', 'artifact', 'flags', 'source'):
                h = Harness('CM7', 'O3')
                result = h.groups[side]['Result']
                if change == 'mode':
                    result['Mode'] = 'O2'
                elif change == 'artifact':
                    result['CohortArtifact']['target']['nvic_prio_bits'] = True
                elif change == 'flags':
                    result['Sources'][0]['CompileFlags'].append('-flto')
                else:
                    result['Sources'][0]['Source'] += '.foreign'
                with self.subTest(side=side, change=change), self.assertRaises(ValueError):
                    h.run()

    def test_prepared_receipts_and_inventory_cannot_change_after_outer_admission(self):
        for profile in ('CM0PLUS', 'CM3', 'CM4'):
            for side in ('Native', 'Reference'):
                for field in ('Result', 'Inventory'):
                    h = Harness(profile, 'Og')
                    if field == 'Result':
                        h.prepared[side]['Result'] = dict(h.prepared[side]['Result'], Foreign=True)
                    else:
                        h.prepared[side]['Inventory'] = BASE / 'different-snapshot'
                    with self.subTest(profile=profile, side=side, field=field), self.assertRaises(ValueError):
                        h.run()

    def test_full_prior_protocol_roots_twins_mechanisms_and_producer_fields_are_compared(self):
        for profile in ('CM0', 'CM3', 'CM7'):
            for field in ('ProtocolProof', 'ClosedBodies', 'Mechanisms', 'ProducerBindings', 'NativeFinalRoots',
                          'ReferenceFinalRoots', 'NativeTwins', 'ReferenceTwins', 'LedgerSha256', 'ReferenceCommit',
                          'SourceInventorySha256', 'NativeArtifactsSha256', 'ReferenceArtifactsSha256'):
                h = Harness(profile)
                h.groups['PriorJoin']['Result'][field] = {'forged': True}
                with self.subTest(profile=profile, field=field), self.assertRaises(ValueError):
                    h.run()
        h = Harness()
        h.groups['PriorJoin']['Result']['ClosedBodies'] = 8.0
        with self.assertRaises(ValueError):
            h.run()

    def test_cm3_additional_domains_frame_sources_and_authentication_are_bound(self):
        for field in ('HashDomains', 'FrameContract', 'ExecutedSourceBuffers'):
            h = Harness('CM3')
            h.groups['PriorJoin']['Result'][field] = []
            with self.subTest(field=field), self.assertRaises(ValueError):
                h.run()
        h = Harness('CM3')
        original = h.join._authenticate
        def forged(*args):
            group = original(*args)
            group['Artifacts']['injected'] = '0' * 64
            return group
        h.join._authenticate = forged
        with self.assertRaises(ValueError):
            h.run()

    def test_cm3_protocol_root_records_cannot_be_partial_or_different(self):
        for side, field in (('Native', 'PrelinkNativeRoots'), ('Reference', 'PrelinkReferenceRoots')):
            h = Harness('CM3')
            h.groups[side]['Result'][field] = []
            with self.subTest(side=side), self.assertRaises(ValueError):
                h.run()

    def test_cm3_emits_independent_fresh_executed_source_snapshot(self):
        for mode in r.MODES:
            with self.subTest(mode=mode):
                h = Harness('CM3', mode)
                fresh = h.helpers['ExecutedSourceBuffers']
                previous = h.groups['PriorJoin']['Result']['ExecutedSourceBuffers']
                expected = copy.deepcopy(fresh)
                facts, _, _ = h.run()
                emitted = facts['ExecutedSourceBuffers']
                self.assertTrue(emitted)
                self.assertEqual(emitted, expected)
                self.assertIsNot(emitted, fresh)
                self.assertIsNot(emitted, previous)
                self.assertIsNot(emitted[0], fresh[0])
                self.assertIsNot(emitted[0], previous[0])
                fresh[0]['Sha256'] = '0' * 64
                fresh.append(dict(Path='later load', Sha256='3' * 64))
                previous.clear()
                self.assertEqual(emitted, expected)
        for profile in ('CM0', 'CM0PLUS', 'CM0PLUSVTOR', 'CM4', 'CM7'):
            with self.subTest(profile=profile):
                facts, _, _ = Harness(profile).run()
                self.assertNotIn('ExecutedSourceBuffers', facts)

    def test_cm3_cross_side_proof_and_mechanism_rejections_propagate(self):
        for method in ('require_cross_side_inputs', 'require_mechanisms', 'require_ledger'):
            h = Harness('CM3')
            def rejected(*args):
                raise ValueError('fixed predicate rejected')
            setattr(h.join, method, rejected)
            with self.subTest(method=method), self.assertRaisesRegex(ValueError, 'fixed predicate rejected'):
                h.run()
            self.assertEqual(h.events[-1], ('exit',))

    def test_proof_validator_and_pairing_failures_propagate_for_both_other_families(self):
        for profile in ('CM0PLUSVTOR', 'CM4'):
            for stage in ('proof', 'pairings'):
                h = Harness(profile)
                def rejected(*args):
                    raise ValueError('unchanged predicate rejection')
                if stage == 'proof':
                    h.helpers['attributes'].require_proof = rejected
                else:
                    h.join.require_pairings = rejected
                with self.subTest(profile=profile, stage=stage), self.assertRaisesRegex(ValueError, 'unchanged predicate rejection'):
                    h.run()

    def test_difference_inventory_rejects_empty_missing_extra_and_duplicate_ids(self):
        for ids in ([], ['foreign'], ['FAP-COMMON-START'] * 2):
            h = Harness()
            h.proof['DifferenceIds'] = ids
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                h.run()
        h = Harness()
        h.proof['DifferenceIds'].pop()
        with self.assertRaises(ValueError):
            h.run()

    def test_master_rationale_requires_unique_heading_visible_text_and_ascii(self):
        identifier = 'FAP-TEST'
        for raw in (b'', b'### FAP-TEST\n<!-- invisible text -->\n',
                    b'### FAP-TEST\n\n### unrelated\nOther text.\n',
                    b'### FAP-TEST\nText.\n### FAP-TEST\nText.\n',
                    b'## FAP-TEST\nText.\n', b'### FAP-TEST\n\xff'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                r.rationale_facts(raw, [identifier])
        result = r.rationale_facts(b'# master\r\n### FAP-TEST\r\n\r\nReason.\r\n', [identifier])
        self.assertEqual(result, [dict(Id=identifier, RationaleSha256=r.sha(b'Reason.'))])

    def test_fp_policy_supplement_is_separate_pinned_and_nonpromoting(self):
        for profile in ('CM4', 'CM7'):
            h = Harness(profile)
            facts, _, _ = h.run()
            self.assertNotIn(r.POLICY_ID, [row['Id'] for row in facts['Rationales']])
            self.assertEqual(facts['FPPolicySupplement']['Rationales'][0]['Id'], r.POLICY_ID)
            self.assertIs(facts['FPPolicySupplement']['PolicyEquivalence'], False)
            self.assertIs(facts['FPPolicySupplement']['HardwareEffectsProven'], False)
            for field in ('PolicySupplementSha256', 'FPSetupDifferenceId'):
                broken = Harness(profile)
                broken.groups['PriorJoin']['Result'][field] = 'foreign'
                with self.subTest(profile=profile, field=field), self.assertRaises(ValueError):
                    broken.run()
        h = Harness('CM4')
        h.watch.buffers[r.ROOT / r.POLICY] += b'changed'
        with self.assertRaisesRegex(ValueError, 'watched hash'):
            h.run()

    def test_bindings_and_native_source_authority_must_pass(self):
        h = Harness('CM7')
        h.binding_status = 'FAIL'
        with self.assertRaises(ValueError):
            h.run()
        h = Harness('CM4')
        h.recheck = lambda *args: dict(Sources=[])
        with self.assertRaises(ValueError):
            h.run()

    def test_joined_watch_and_capture_aliases_transfer_to_outer_watch(self):
        h = Harness()
        original = BASE / 'actual retained input.o'
        copied = h.output / 'recomputed/inputs/0000-input.o'
        raw = b'unchanged authenticated bytes'
        h.joined.buffers[original] = raw
        h.joined.hashes[original] = r.sha(raw)
        h.joined.copies[original] = copied
        h.watch.buffers[original] = h.watch.buffers[copied] = raw
        _, joined, copies = h.run()
        self.assertEqual(copies, {'recomputed/inputs/0000-input.o': r.sha(raw)})
        self.assertEqual(h.watch.hashes[original], r.sha(raw))
        self.assertEqual(h.watch.hashes[copied], r.sha(raw))

    def test_closing_failure_and_copy_mutation_cannot_return_facts(self):
        h = Harness()
        h.joined.fail_close = True
        with self.assertRaisesRegex(ValueError, 'joined closure failed'):
            h.run()
        h = Harness()
        original, copied = BASE / 'input', h.output / 'recomputed/inputs/0000-input'
        h.joined.hashes[original] = r.sha(b'original')
        h.joined.buffers[original] = h.watch.buffers[original] = b'original'
        h.joined.copies[original] = copied
        h.watch.buffers[copied] = b'mutated'
        with self.assertRaisesRegex(ValueError, 'watched hash'):
            h.run()

    def test_subject_and_dependency_buffers_are_unchanged(self):
        self.assertEqual(SUBJECT.read_bytes(), RAW)
        self.assertEqual((HERE / 'profiles.py').read_bytes(), PROFILE_RAW)
        self.assertEqual((r.ROOT / r.POLICY).read_bytes(), POLICY_RAW)


class PilotReplayTests(unittest.TestCase):
    def fixture(self, profile, mode):
        contract = profiles.profile(profile, mode)
        root = BASE / 'native-pilot'
        result = receipt(contract, root, 'Native')
        result['PrelinkOwners'] = {'one': ['actual provider']}
        result['PrelinkNativeRoots'] = [{'Name': 'complete synthetic record'}]
        calls = []
        testcase = self
        class Pilot:
            def prelink(pilot):
                testcase.assertEqual((pilot.profile, pilot.mode, pilot.root), (profile, mode, root / 'source'))
                testcase.assertEqual(pilot.sources, [Path(row['Source']) for row in result['Sources']])
                testcase.assertEqual(pilot.objects, [Path(row['Object']) for row in result['Sources']])
                testcase.assertEqual(pilot.object_hashes, tuple((row['Object'], row['ObjectSha256']) for row in result['Sources']))
                testcase.assertEqual(pilot.fixture_copy, root / 'source/tools/fixtures/classic_final_image')
                testcase.assertEqual(pilot.storage, contract['StorageSymbol'])
                testcase.assertEqual(pilot.artifact, contract['CohortArtifact'])
                testcase.assertEqual(pilot.report['Sources'], result['Sources'])
                pilot.report.update(PrelinkOwners=copy.deepcopy(result['PrelinkOwners']),
                                    PrelinkNativeRoots=copy.deepcopy(result['PrelinkNativeRoots']))
                calls.append('prelink')

            def audit_final(pilot, path):
                calls.append(path)
        manifest = {'canonical': 'current manifest'}
        def selection(name, opt):
            same([name, opt], [profile, mode], 'exact native selection')
            return contract['Cohort'], 'port', contract['StorageSymbol']
        def require_manifest(value, name, opt, admission):
            testcase.assertIs(value, manifest)
            same([name, opt], [profile, mode], 'manifest profile/mode')
            return contract['CohortArtifact']
        native = SimpleNamespace(Pilot=Pilot, selection=selection, require_manifest_selection=require_manifest)
        return dict(Result=result, Root=root), native, manifest, calls

    def test_actual_profile_mode_sources_manifest_and_both_final_predicates(self):
        for profile in ('CM0', 'CM0PLUS', 'CM0PLUSVTOR', 'CM4', 'CM7'):
            for mode in r.MODES:
                with self.subTest(profile=profile, mode=mode):
                    group, native, manifest, calls = self.fixture(profile, mode)
                    before = copy.deepcopy(group['Result'])
                    proof = r.recheck_pilot(group, native, object(), object(), manifest, profile, mode)
                    self.assertEqual(calls, ['prelink', *(Path(row['Path']) for row in group['Result']['Links'])])
                    self.assertEqual(proof['Sources'], group['Result']['Sources'])
                    self.assertEqual(group['Result'], before)

    def test_changed_full_prelink_evidence_and_final_predicate_rejection_propagate(self):
        group, native, manifest, _ = self.fixture('CM4', 'Os')
        original = native.Pilot.prelink
        def changed(pilot):
            original(pilot)
            pilot.report['PrelinkOwners']['one'].append('foreign provider')
        native.Pilot.prelink = changed
        with self.assertRaisesRegex(ValueError, 'complete native prelink'):
            r.recheck_pilot(group, native, object(), object(), manifest, 'CM4', 'Os')
        group, native, manifest, _ = self.fixture('CM0PLUSVTOR', 'Og')
        native.Pilot.audit_final = lambda *_: (_ for _ in ()).throw(ValueError('fixed final rejection'))
        with self.assertRaisesRegex(ValueError, 'fixed final rejection'):
            r.recheck_pilot(group, native, object(), object(), manifest, 'CM0PLUSVTOR', 'Og')


if __name__ == '__main__':
    with patch.object(subprocess, 'Popen', side_effect=AssertionError('pure tests cannot launch processes')):
        unittest.main(verbosity=2)
