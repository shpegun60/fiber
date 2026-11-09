"""Nine-component driver controls with real-byte fixtures and lifecycle doubles.

The byte factory executes original/final/control predicates without admission.
Earlier port metadata is pinned; reader wiring is checked structurally and
lifecycle replay is doubled. No test grants combined admission or qualification.
"""

import argparse
import ast
from contextlib import ExitStack, contextmanager, nullcontext, redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 28
ENTRY = HERE / 'final_controls_census_attempt.py'
PREVIOUS = (HERE / 'test_final_replacement_census_attempt.py',
    '1628377C5929A26B799657F168FD33AA0B694711E2C51B494100EB06B8226695')
CONTROL_FIXTURE = (HERE / 'test_final_controls_replay.py',
    '428C43F7DC99F90E652DB6CC74CC59CED67A7D2C9286E1EC7970474961510E71')
LEAF = (HERE / 'final_controls_replay.py',
    'C507CBCFBB593E78C5E6F5CC6710DF0C7436FEDACF119375429080A40CEEAD11')
CONTRACT = (HERE / 'FINAL_CONTROL_REPLAY_CONTRACT.md',
    '0F58C38B4962B1AB4B2DD6D5797013205DBB86DCE12D99F82CD4A1396D251C00')
RECIPES = {
    'tools/fixtures/cm3_lto_roots/mutations.py':
        '32BDE6CA67B12EEC9975D24D6628C5576EA29F33121CD60310F1F010CF272353',
    'tools/fixtures/cm3_reference_lto_roots/mutations.py':
        'E20E55734138E5F9AE76019D3C3EF1260EE708FDF222DC72E5C8B5552E02029C',
    'tools/fixtures/cm3_lto_protocol/witness.py':
        '39E1994A74DB225CD3BB2010AE07C49FD1DB2EE2006BCAD2FC59BD3092E6CF51',
    'tools/fixtures/cm3_reference_lto_protocol/witness.py':
        'B3968C5C51BCB7DFF13425B6656715DB4FA9674C18503AA04FDE7EA0A0F89D5F',
}
COMPONENTS = ('OriginalCensus', 'DeferredABI', 'ABIControls', 'IsolationComponent',
    'CommonAttributes', 'PortPolicyComponent', 'OriginalComponent', 'FinalReplacementComponent',
    'FinalControlComponent')
INSPECTORS = ('normal', 'abi_replay', 'controls_replay', 'isolation_replay', 'common_replay',
    'port_replay', 'original_replay', 'final_replacement_replay', 'final_controls_replay')
BUFFERS, FIXTURES, FIRST_READS = {}, {}, {}
subject = previous = leaf_fixture = prepared = proof = None
BYTE_PREDICATES_EXERCISED = False
RETENTION_DIRECTORY = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def proof_hash(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
        allow_nan=False).encode('ascii'))


def retain(destination, path, raw):
    if not isinstance(path, Path) or type(raw) is not bytes:
        raise ValueError('literal source/fixture snapshot')
    if path in destination and destination[path] != raw:
        raise ValueError('first-seen source/fixture collision/' + str(path))
    if path not in destination:
        destination[path] = raw


def merge(destination, incoming):
    for path, raw in incoming.items():
        retain(destination, path, raw)


def module(name, path, raw):
    value = ModuleType(name)
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def clear_parser():
    for name in list(sys.modules):
        if name == 'elftools' or name.startswith('elftools.'):
            del sys.modules[name]


def control_helpers(helpers):
    return subject.final_control_helpers(helpers)


def credits():
    return (*subject.COUNTERS, *subject.CONTROL_COUNTERS)


def parent_alias():
    matches = [name for name, row in subject.PINS.items()
        if row[0] == 'tools/fixtures/cm3_os_lto_final_cell/final_replacement_census_attempt.py']
    if len(matches) != 1:
        raise ValueError('one explicitly pinned published eight-component composition')
    return matches[0]


def pin_locations(relative):
    matches = []
    for name in ('PINS', 'DOCUMENTS', 'RECIPE_PINS'):
        registry = getattr(subject, name, {})
        for key, row in registry.items():
            path = row[0] if name != 'DOCUMENTS' else key
            if path == relative:
                matches.append((name, key))
    if not matches:
        raise ValueError('new source absent from explicit bootstrap registries/' + relative)
    return matches


@contextmanager
def bootstrap(case, *, bad_path=None, missing=None, zero=None, late=False):
    state = NS(constructed=False, reads=[], enrolled={}, events=[])
    physical_read, real_load = Path.read_bytes, subject.load

    def read(path):
        if state.constructed:
            raise AssertionError('late physical bootstrap read')
        state.reads.append(path)
        return b'corrupt authenticated source' if path == bad_path else physical_read(path)

    def construct(args):
        state.constructed = True
        state.events.append('witness')
        return NS(SyntheticWitness=True)

    constructor = Mock(side_effect=construct)

    def factory(legacy, capture, *, extra_sources):
        state.enrolled = dict(extra_sources)
        for path, raw in extra_sources.items():
            case.assertEqual(raw, BUFFERS[path])
        case.assertEqual(state.events, ['transport'])
        return constructor

    state.factory = Mock(side_effect=factory)

    def load(name, path, raw):
        value = real_load(name, path, raw)
        if name.endswith('_admission_admission'):
            value.witness_type = state.factory
        if name.endswith('_bootstrap_transport'):
            state.events.append('transport')
        if late and name.endswith('_bootstrap_final_controls_replay'):
            (ROOT / 'tools/unadmitted-final-control.py').read_bytes()
        return value

    changes = {}
    for relative, omit in ((missing, True), (zero, False)):
        if relative is None:
            continue
        for registry_name, key in pin_locations(relative):
            registry = changes.setdefault(registry_name, dict(getattr(subject, registry_name)))
            if omit:
                del registry[key]
            elif registry_name == 'DOCUMENTS':
                registry[key] = '0' * 64
            else:
                registry[key] = (registry[key][0], '0' * 64)
    with ExitStack() as stack:
        stack.enter_context(patch.dict(sys.modules))
        for name, value in changes.items():
            stack.enter_context(patch.object(subject, name, value))
        stack.enter_context(patch.object(Path, 'read_bytes', read))
        stack.enter_context(patch.object(subject, 'load', side_effect=load))
        clear_parser()
        yield state, constructor


@contextmanager
def detached():
    # Guards use the valid dictionary, so missing-helper tests cannot pass in setup.
    helpers = prepared[3]
    with previous.fixture.detached(helpers), ExitStack() as stack:
        for key in ('final_replacement_replay', 'final_controls_replay'):
            stack.enter_context(patch.object(helpers[key], 'inspect',
                side_effect=AssertionError('binary inspector disabled/' + key)))
        for module_value in control_helpers(helpers).values():
            for name in ('mutate', 'run_cases', '_physical'):
                if hasattr(module_value, name):
                    stack.enter_context(patch.object(module_value, name,
                        side_effect=AssertionError('physical recipe disabled/' + name)))
        yield


def validate(value, helpers=None):
    with detached():
        return subject.require_result(value, prepared[3] if helpers is None else helpers)


class BootstrapTests(unittest.TestCase):
    def test_first_seen_source_and_fixture_bytes_cannot_be_replaced(self):
        path = Path('C:/first-seen-final-controls.py')
        saved = {}
        retain(saved, path, b'first')
        retain(saved, path, b'first')
        with self.assertRaisesRegex(ValueError, 'first-seen'):
            merge(saved, {path: b'changed'})
        self.assertEqual(saved, {path: b'first'})

    def test_original35_and_four_recipe_sources_precede_witness(self):
        with bootstrap(self) as (state, constructor):
            result = subject.prepare(NS())
        self.assertEqual(result[4], prepared[4])
        self.assertEqual(result[4], previous.prepared[4])
        self.assertEqual(len(result[4]), 35)
        self.assertEqual(result[5], state.enrolled)
        self.assertEqual(set(state.reads), set(state.enrolled))
        self.assertEqual(state.events, ['transport', 'witness'])
        for relative, digest in RECIPES.items():
            self.assertEqual(sha(state.enrolled[ROOT / relative]), digest)
        self.assertIn(parent_alias(), result[3])
        self.assertIn('final_controls_replay', result[3])
        self.assertEqual(set(control_helpers(result[3])), set(leaf_fixture.HELPERS))
        constructor.assert_called_once()

    def test_corrupt_leaf_parent_contract_or_recipe_never_constructs_witness(self):
        paths = [LEAF[0], CONTRACT[0], ROOT / subject.PINS[parent_alias()][0]]
        paths.extend(ROOT / relative for relative in RECIPES)
        for path in paths:
            with self.subTest(path=str(path)), bootstrap(self, bad_path=path) as (state, constructor):
                with self.assertRaises(ValueError):
                    subject.prepare(NS())
            state.factory.assert_not_called()
            constructor.assert_not_called()

    def test_missing_leaf_parent_or_each_recipe_pin_is_not_optional(self):
        paths = [LEAF[0].relative_to(ROOT).as_posix(), subject.PINS[parent_alias()][0], *RECIPES]
        for relative in paths:
            with self.subTest(path=relative), bootstrap(self, missing=relative) as (state, constructor):
                with self.assertRaises((KeyError, ValueError)):
                    subject.prepare(NS())
            state.factory.assert_not_called()
            constructor.assert_not_called()

    def test_zero_pins_and_initial_parser_fail_before_witness(self):
        for relative in (LEAF[0].relative_to(ROOT).as_posix(), *RECIPES):
            with self.subTest(path=relative), bootstrap(self, zero=relative) as (state, constructor):
                with self.assertRaises(ValueError):
                    subject.prepare(NS())
            constructor.assert_not_called()
        with bootstrap(self) as (state, constructor), patch.dict(sys.modules, {'elftools': ModuleType('elftools')}):
            with self.assertRaisesRegex(ValueError, 'initially unimported parser'):
                subject.prepare(NS())
        self.assertEqual(state.reads, [])
        constructor.assert_not_called()

    def test_no_parent_prepare_or_postwitness_physical_helper_load(self):
        tree = ast.parse(BUFFERS[ENTRY])
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare')
        self.assertFalse(any(isinstance(n, ast.Attribute) and n.attr in ('prepare', 'run', 'replay')
            for n in ast.walk(node)))
        with bootstrap(self, late=True) as (state, constructor):
            with self.assertRaisesRegex(ValueError, 'outside first-seen enrolled buffers'):
                subject.prepare(NS())
        constructor.assert_called_once()
        self.assertNotIn(ROOT / 'tools/unadmitted-final-control.py', state.reads)


class BoundaryTests(unittest.TestCase):
    def test_admission_delegates_to_published_eight_component_helper(self):
        model, run, _ = LifecycleTests.model(self)
        run()
        model.admission.assert_called_once_with(model.args, model.runner, model.environment,
            model.batch_root, model.batch, model.roles, model.helpers)

    def test_fourteen_control_roles_already_have_explicit_reader_permissions(self):
        rows = proof['FinalControlComponent']['ReadInputs']
        self.assertEqual(len(rows), 14)
        for row in rows:
            self.assertIn(row['Path'], previous.proof['ImmutableReader']['Reads'])
            self.assertEqual(previous.proof['InputHashes'][row['Path']], row['Sha256'])

    def test_source_wires_all_nine_inspectors_inside_one_reader(self):
        tree = ast.parse(BUFFERS[ENTRY])
        replay = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'replay')
        readers = [n for n in ast.walk(replay) if isinstance(n, ast.With) and any(
            isinstance(i.context_expr, ast.Call) and isinstance(i.context_expr.func, ast.Attribute)
            and i.context_expr.func.attr == 'reader' for i in n.items)]
        self.assertEqual(len(readers), 1)
        calls = [n for n in ast.walk(readers[0]) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and n.func.attr == 'inspect'
            and isinstance(n.func.value, ast.Subscript)]
        names = [n.func.value.slice.value for n in calls if isinstance(n.func.value.slice, ast.Constant)]
        self.assertEqual(sorted(names), sorted(INSPECTORS))
        for call in calls:
            self.assertEqual(sum(isinstance(a, ast.Name) and a.id == 'core' for a in call.args), 1)
            self.assertEqual(sum(isinstance(a, ast.Attribute) and a.attr == 'read'
                and isinstance(a.value, ast.Attribute) and a.value.attr == 'watch' for a in call.args), 1)
        control = next(n for n in calls if n.func.value.slice.value == 'final_controls_replay')
        self.assertEqual([a.id for a in control.args[3:6]], ['port', 'original', 'final'])


class ValidatorTests(unittest.TestCase):
    def test_real_returned_bootstrap_helpers_validate_all_nine(self):
        self.assertIsNot(validate(copy.deepcopy(proof)), False)
        self.assertEqual(len(subject.FACTS), 13)
        self.assertIs(proof['FinalControlComponentReplayed'], True)
        self.assertEqual(tuple(proof[k] for k, _ in credits()), (41, 12, 45, 36, 32, 2))
        self.assertEqual(tuple(proof[k] for k in ('ToolInvocations', 'CompilerInvocations', 'RequiredCellsSatisfied')), (0, 0, 0))
        self.assertIs(proof['CanonicalProtocolValidated'], False)

    def test_each_control_helper_is_required_by_real_final_validator(self):
        projection = control_helpers(prepared[3])
        for name, value in projection.items():
            aliases = [key for key, candidate in prepared[3].items() if candidate is value]
            self.assertTrue(aliases, name)
            helpers = {key: candidate for key, candidate in prepared[3].items() if key not in aliases}
            with self.subTest(missing=name), self.assertRaises((KeyError, ValueError)):
                validate(copy.deepcopy(proof), helpers)
        helpers = dict(prepared[3])
        del helpers['final_controls_replay']
        with self.assertRaises((KeyError, ValueError)):
            validate(copy.deepcopy(proof), helpers)

    def test_thirteen_facts_nonclaims_and_six_counters_are_literal(self):
        self.assertEqual((len(subject.FACTS), len(subject.NONCLAIMS), len(credits())), (13, 41, 6))
        changes = [(key, 1) for key in subject.FACTS] + [(key, 0) for key in subject.NONCLAIMS]
        changes += [(key, True) for key, _ in credits()]
        changes += [('RecordedInspectionInvocations', True), ('RequiredCellsSatisfied', 1)]
        for key, value in changes:
            bad = copy.deepcopy(proof)
            bad[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                validate(bad)

    def test_complete_port_original_and_final_hashes_bind_controls(self):
        for key, component in (('Port', 'PortPolicyComponent'), ('Original', 'OriginalComponent'),
                ('Final', 'FinalReplacementComponent')):
            self.assertEqual(proof['FinalControlComponent'][key + 'ProofSha256'], proof_hash(proof[component]))
            bad = copy.deepcopy(proof)
            bad['FinalControlComponent'][key + 'ProofSha256'] = 'F' * 64
            with self.subTest(component=component), self.assertRaises(ValueError):
                validate(bad)
        for key in ('ReceiptSha256', 'ArtifactsSha256'):
            bad = copy.deepcopy(proof)
            bad['Batch'][key] = 'F' * 64
            with self.subTest(authority=key), self.assertRaises(ValueError):
                validate(bad)

    def test_each_control_input_keeps_own_final_reference_and_ledger_roles(self):
        for group, rows in proof['FinalControlComponent']['Inputs'].items():
            for role in rows:
                bad = copy.deepcopy(proof)
                bad['FinalControlComponent']['Inputs'][group][role]['Path'] = 'C:/foreign-control-input.o'
                with self.subTest(group=group, role=role), self.assertRaises(ValueError):
                    validate(bad)

    def test_nested_controls_counters_and_derived_bytes_are_not_outer_markers(self):
        for key, value in (('TransportControlsExecuted', 31), ('CanonicalControlsExecuted', True),
                ('FreshControlsExecuted', 1), ('DerivedRoleInstances', 171)):
            bad = copy.deepcopy(proof)
            bad['FinalControlComponent'][key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                validate(bad)
        bad = copy.deepcopy(proof)
        bad['FinalControlComponent']['DerivedBuffers'][0]['Output']['Bytes'] += 1
        with self.assertRaises(ValueError):
            validate(bad)

    def test_prior_authorities_and_exact_pending_projection_remain_enforced(self):
        for side in ('Native', 'Reference'):
            bad = copy.deepcopy(proof)
            next(r for r in bad['ProducerBindings'] if r['Side'] == side)['ReceiptSha256'] = 'F' * 64
            with self.subTest(side=side), self.assertRaises(ValueError):
                validate(bad)
        for key, value in (('Status', subject.PENDING), ('CommonAttributionClosed', False), ('UnresolvedAttribution', [{}])):
            bad = copy.deepcopy(proof)
            bad[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                validate(bad)

    def test_outer_authority_joins_survive_new_leaf_validator_bypass(self):
        for key, value in (('BatchRoot', 'C:/foreign-batch'), ('BatchAuthority', dict(Foreign=True))):
            bad = copy.deepcopy(proof)
            bad['FinalReplacementComponent'][key] = value
            with self.subTest(field=key), \
                    patch.object(prepared[3]['final_controls_replay'], 'require_result', return_value=None), \
                    patch.object(prepared[3]['final_replacement_replay'], 'require_result', return_value=None), \
                    self.assertRaisesRegex(ValueError, 'shared'):
                validate(bad)

    def test_real_old_common_port_and_final_validators_keep_transport_helper(self):
        helpers = prepared[3]
        with detached():
            helpers['common_composition'].common_result(proof['CommonAttributes'], helpers)
            previous.subject.port_result(proof['PortPolicyComponent'], helpers)
        broken = dict(helpers)
        del broken['transport']
        with detached(), self.assertRaises((KeyError, ValueError)):
            helpers['common_composition'].common_result(proof['CommonAttributes'], broken)
        validate(copy.deepcopy(proof))


class LifecycleTests(unittest.TestCase):
    def model(self, *, fault=None, final_failure=False, replay_failure=False, pending=None):
        model = previous.fixture.prior_fixture.Model(self)
        model.fault = fault
        parent = prepared[3][parent_alias()]
        model.helpers[parent_alias()] = parent
        model.admission = Mock(return_value=(model.handoff_root, model.handoff, model.targets,
            model.inspection_tool, len(model.project)))
        returned = tuple(dict(SyntheticOnly=name) for name in ('census', 'abi', 'controls', 'isolation'))
        returned += (dict(LoweredProofs=dict(UnresolvedAttribution=[] if pending is None else pending)),)
        returned += tuple(dict(SyntheticOnly=name) for name in ('port', 'original', 'final', 'final-controls', 'reader'))

        def final(report, helpers):
            self.assertIs(report['FinalControlComponentReplayed'], True)
            self.assertEqual(tuple(report[key] for key, _ in credits()), (41, 12, 45, 36, 32, 2))
            if final_failure:
                raise ValueError('synthetic postseal controls validation')

        validation = Mock(side_effect=final)
        replay = Mock(side_effect=ValueError('synthetic ninth replay') if replay_failure else None, return_value=returned)

        def run():
            with redirect_stdout(io.StringIO()), patch.object(parent, 'admit_normal', model.admission), \
                    patch.object(subject, 'replay', replay), patch.object(subject, 'require_result', validation):
                return subject.run(model.args, model.runner, model.environment,
                    previous.fixture.prior_fixture.fixture.builder, model.helpers, {}, {})
        return model, run, validation

    def revoked(self, model, *, persisted=True):
        report = json.loads((model.output / 'results.json').read_bytes()) if persisted else model.suite.report
        self.assertEqual(report['Status'], 'FAIL')
        for key in (*subject.FACTS, *subject.NONCLAIMS):
            self.assertIs(report[key], False, key)
        for key, _ in credits():
            self.assertIs(type(report[key]), int, key)
            self.assertEqual(report[key], 0, key)
        self.assertIs(report['CommonAttributionClosed'], False)
        return report

    def test_success_credits_thirteen_facts_and_32_plus_two_without_commands(self):
        model, run, validation = self.model()
        result = run()
        self.assertEqual(result['Status'], subject.PASS)
        for key in subject.FACTS:
            self.assertIs(result[key], True)
        for key in subject.NONCLAIMS:
            self.assertIs(result[key], False)
        self.assertEqual(tuple(result[key] for key, _ in credits()), (41, 12, 45, 36, 32, 2))
        self.assertEqual(result['Commands'], [])
        model.suite.command.assert_not_called()
        model.runner.seal.assert_called_once()
        validation.assert_called_once()

    def test_common_pending_projection_is_not_failure_or_qualification(self):
        pending = [dict(Group='positive', Evidence=[dict(Function='bounded-inline')])]
        model, run, _ = self.model(pending=pending)
        result = run()
        self.assertEqual(result['Status'], subject.PENDING)
        self.assertEqual(result['UnresolvedAttribution'], pending)
        self.assertIs(result['CommonAttributionClosed'], False)
        for key in subject.FACTS:
            self.assertIs(result[key], True)
        for key in subject.NONCLAIMS:
            self.assertIs(result[key], False)

    def test_ninth_replay_failure_never_seals_or_credits_controls(self):
        model, run, validation = self.model(replay_failure=True)
        with self.assertRaisesRegex(ValueError, 'synthetic ninth replay'):
            run()
        validation.assert_not_called()
        model.runner.seal.assert_not_called()
        model.runner.recover.assert_called_once()
        self.revoked(model)

    def test_object_output_seal_and_manifest_failure_revoke_all_six_credits(self):
        for fault in ('objects', 'output', 'seal', 'manifest'):
            model, run, validation = self.model(fault=fault)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                run()
            validation.assert_not_called()
            model.runner.recover.assert_called_once()
            self.revoked(model)

    def test_witness_close_failure_revokes_before_output_seal(self):
        model, run, validation = self.model()
        model.witness.close.side_effect = ValueError('synthetic witness close')
        with self.assertRaisesRegex(ValueError, 'synthetic witness close'):
            run()
        validation.assert_not_called()
        model.runner.seal.assert_not_called()
        self.revoked(model)

    def test_postseal_validator_failure_revokes_every_fact_and_credit(self):
        model, run, validation = self.model(final_failure=True)
        with self.assertRaisesRegex(ValueError, 'synthetic postseal controls validation'):
            run()
        model.runner.seal.assert_called_once()
        validation.assert_called_once()
        model.runner.recover.assert_called_once()
        self.revoked(model)

    def test_summary_failure_revokes_after_real_postseal_callback(self):
        model, run, validation = self.model()
        with patch('builtins.print', side_effect=BrokenPipeError('synthetic summary')), \
                self.assertRaisesRegex(BrokenPipeError, 'synthetic summary'):
            run()
        validation.assert_called_once()
        model.runner.recover.assert_called_once()
        self.revoked(model)

    def test_recovery_failure_never_recredits_or_replaces_primary_failure(self):
        model, run, validation = self.model(final_failure=True)
        model.runner.recover.side_effect = ValueError('synthetic recovery failure')
        with self.assertRaisesRegex(ValueError, 'synthetic postseal controls validation'):
            run()
        validation.assert_called_once()
        report = self.revoked(model, persisted=False)
        self.assertIn('synthetic postseal controls validation', report['PrimaryError'])
        self.assertTrue(any('synthetic recovery failure' in text for text in report['ClosingErrors']))
        model.runner.recover.assert_called_once()

    def test_foreign_output_identity_is_preserved_without_recovery(self):
        model, run, _ = self.model()

        def substitute():
            model.output.rename(model.root / 'retired-controls')
            model.put(model.output / 'foreign', b'untouched')

        model.suite.verify_objects.side_effect = substitute
        with self.assertRaises(ValueError):
            run()
        model.runner.recover.assert_not_called()
        self.assertEqual((model.output / 'foreign').read_bytes(), b'untouched')
        self.revoked(model, persisted=False)

    def test_cli_process_guards_include_diagnostic_failure_and_no_abbreviations(self):
        with patch.object(subject, 'prepare') as prepare, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            subject.main(['--batch-b', 'x'])
        prepare.assert_not_called()
        argv = [value for key in subject.ARGUMENTS for value in ('--' + key, 'synthetic')]
        for name in ('subprocess.Popen', 'os.system'):
            def attempt(*args, _name=name, **kwargs):
                if _name == 'os.system':
                    import os
                    return os.system('NEVER')
                import subprocess
                return subprocess.Popen(['NEVER'])

            with self.subTest(api=name, phase='bootstrap'), patch.object(subject, 'prepare', side_effect=attempt), \
                    patch(name) as external, redirect_stderr(io.StringIO()):
                self.assertEqual(subject.main(argv), 1)
                external.assert_not_called()
            with self.subTest(api=name, phase='diagnostic'), \
                    patch.object(subject, 'prepare', side_effect=ValueError('synthetic startup failure')), \
                    patch('builtins.print', side_effect=attempt), patch(name) as external:
                self.assertEqual(subject.main(argv), 1)
                external.assert_not_called()


def retained_fixture(value):
    """Build disclosed synthetic reader records from real first-seen source bytes."""
    global RETENTION_DIRECTORY
    RETENTION_DIRECTORY = Path(tempfile.mkdtemp(prefix='cm3-final-controls-driver-source-fixture-'))
    copies = RETENTION_DIRECTORY / 'source-buffers'
    copies.mkdir()
    bootstrap_rows = {row['Path']: dict(row) for row in value['BootstrapSources']}
    captured_rows = {row['Original']: dict(row) for row in value['CapturedSources']}
    prior_source_paths = set(captured_rows)
    for index, (path, raw) in enumerate(sorted(prepared[5].items())):
        name, digest = str(path), sha(raw)
        if name in value['InputHashes'] and value['InputHashes'][name] != digest:
            raise ValueError('published/prepared source conflict/' + name)
        value['InputHashes'][name] = digest
        physical = path.lstat()
        value['InputPhysicalIdentities'][name] = [physical.st_dev, physical.st_ino, physical.st_nlink]
        bootstrap_rows[name] = dict(Path=name, Sha256=digest)
        if name in captured_rows:
            if captured_rows[name]['Sha256'] != digest:
                raise ValueError('published/first-seen retained source conflict/' + name)
        else:
            copied = copies / ('%04d-%s%s' % (index, digest, path.suffix))
            copied.write_bytes(raw)
            retain(FIXTURES, copied, raw)
            captured_rows[name] = dict(Original=name, Captured=str(copied), Sha256=digest)
    value['BootstrapSources'] = [bootstrap_rows[name] for name in sorted(bootstrap_rows, key=Path)]
    value['CapturedSources'] = [captured_rows[name] for name in sorted(captured_rows, key=Path)]
    value['ClosingFilesVerified'] = len(value['InputHashes'])
    reader = value['ImmutableReader']
    reader['SourceBuffers'] = len(captured_rows)
    reader['InputPaths'] = max(reader['InputPaths'] + len(set(captured_rows) - prior_source_paths), len(captured_rows))
    executed = reader['ExecutedSourceBuffers']
    existing = {row['Path'] for row in executed}
    for name, helper in dict(control_helpers(prepared[3]),
            final_controls_replay=prepared[3]['final_controls_replay']).items():
        path = str(Path(helper.__file__))
        if path not in existing:
            executed.append(dict(Name='_synthetic_retained_control_' + name, Path=path,
                Sha256=value['InputHashes'][path]))
            existing.add(path)
    return value


def initialize():
    global subject, previous, leaf_fixture, prepared, proof, BYTE_PREDICATES_EXERCISED
    physical_read = Path.read_bytes

    def read(path):
        raw = physical_read(path)
        retain(FIRST_READS, path, raw)
        return raw

    with patch.object(Path, 'read_bytes', read):
        for path in (Path(__file__).resolve(), ENTRY, PREVIOUS[0], CONTROL_FIXTURE[0], LEAF[0], CONTRACT[0]):
            retain(BUFFERS, path, path.read_bytes())
        for path, digest in (PREVIOUS, CONTROL_FIXTURE, LEAF, CONTRACT):
            if sha(BUFFERS[path]) != digest:
                raise ValueError('fixed source/fixture pin/' + str(path))
        previous = module('_control_driver_previous_fixture', PREVIOUS[0], BUFFERS[PREVIOUS[0]])
        previous.initialize()
        merge(BUFFERS, previous.BUFFERS)
        merge(FIXTURES, previous.FIXTURES)
        subject = module('_control_driver_subject', ENTRY, BUFFERS[ENTRY])
        real_load = subject.load

        def collecting(name, path, raw):
            retain(FIRST_READS, path, raw)
            retain(BUFFERS, path, raw)
            value = real_load(name, path, raw)
            if name.endswith('_admission_admission'):
                value.witness_type = lambda legacy, capture, *, extra_sources: (lambda args: NS(SyntheticWitness=True))
            return value

        with patch.dict(sys.modules), patch.object(subject, 'load', side_effect=collecting):
            clear_parser()
            prepared = subject.prepare(NS())
        merge(BUFFERS, prepared[5])
        leaf_fixture = module('_control_driver_byte_fixture', CONTROL_FIXTURE[0], BUFFERS[CONTROL_FIXTURE[0]])
        with patch.dict(sys.modules):
            clear_parser()
            controls = leaf_fixture.synthetic_result(control_helpers(prepared[3]))
        merge(BUFFERS, leaf_fixture.BUFFERS)
        merge(FIXTURES, leaf_fixture.FIXTURES)
        proof = copy.deepcopy(previous.proof)
        for key, component in (('PortPolicyComponent', leaf_fixture.PORT), ('OriginalComponent', leaf_fixture.ORIGINAL),
                ('FinalReplacementComponent', leaf_fixture.FINAL)):
            if proof[key] != component:
                raise ValueError('fresh control dependencies differ from eight-component fixture/' + key)
        proof.update(Status=subject.PASS, Scope=subject.SCOPE, FinalControlComponent=controls,
            FinalControlComponentReplayed=True, **dict(credits()))
        retained_fixture(proof)
        BYTE_PREDICATES_EXERCISED = True
    for path, raw in FIRST_READS.items():
        retain(BUFFERS if path in BUFFERS else FIXTURES, path, raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    output, temp = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temp) or output.is_relative_to(ROOT):
        parser.error('fresh external TEMP output required')
    report = dict(Status='FAIL', Tests=0, ExpectedTests=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, FixtureHashes={}, SourceClosureVerified=False, FixtureClosureVerified=False,
        ActualOriginalFinalControlBytePredicatesExercised=False, PortProofFromPinnedReceipt=True,
        PortComponentRecomputed=False, LifecycleReplayDoubles=True, ReaderOrchestrationAstOnly=True,
        SyntheticReaderRetentionRecords=True, MaterializedSourceCopies=True,
        ActualCaptureAdmitted=False, ActualCombinedCLIReplay=False, CompilerInvocations=0,
        ToolInvocations=0, RequiredCellsSatisfied=0, Qualification=False, BoardExecution=False)
    saved_meta = list(sys.meta_path)
    with patch('subprocess.Popen', side_effect=AssertionError('no producer processes')), \
            patch('os.system', side_effect=AssertionError('no shell')):
        try:
            if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
                raise ValueError('fresh isolated unoptimized -I -S -B interpreter required')
            initialize()
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                for case in (BootstrapTests, BoundaryTests, ValidatorTests, LifecycleTests))
            if suite.countTestCases() != METHODS:
                raise ValueError('exact method count/' + str(suite.countTestCases()))
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
                Details=[dict(Test=str(case), Error=error) for case, error in result.failures + result.errors])
            if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
                report['Status'] = 'PASS'
        except BaseException:
            report.update(Errors=report['Errors'] + 1, Error=traceback.format_exc())
        finally:
            sys.meta_path[:] = saved_meta
        report['ActualOriginalFinalControlBytePredicatesExercised'] = BYTE_PREDICATES_EXERCISED
        report['SourceRetentionFixtureRoot'] = str(RETENTION_DIRECTORY) if RETENTION_DIRECTORY else None
        for label, buffers in (('Source', BUFFERS), ('Fixture', FIXTURES)):
            report[label + 'Hashes'] = {str(path): sha(raw) for path, raw in buffers.items()}
            try:
                closed = bool(buffers) and all(path.read_bytes() == raw for path, raw in buffers.items())
            except BaseException:
                closed = False
            report[label + 'ClosureVerified'] = closed
            if not closed:
                report['Status'] = 'FAIL'
        output.mkdir(parents=True, exist_ok=False)
        raw = encoded(report)
        (output / 'results.json').write_bytes(raw)
        print(json.dumps({key: value for key, value in report.items() if key not in
            ('SourceHashes', 'FixtureHashes', 'Details', 'Error')}, sort_keys=True))
        print('ReceiptSha256=' + sha(raw))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
