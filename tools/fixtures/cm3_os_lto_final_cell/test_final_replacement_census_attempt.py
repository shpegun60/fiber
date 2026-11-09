"""Final composition controls: actual byte predicates, explicit lifecycle doubles.

These tests neither admit a combined capture nor grant a required cell. The
fresh eight-component CLI remains a separate post-test obligation.
"""

import argparse
import ast
from contextlib import contextmanager, nullcontext, redirect_stderr, redirect_stdout
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
METHODS = 22
PRIOR_FIXTURE = ('tools/fixtures/cm3_os_lto_final_cell/test_original_census_attempt.py',
    '5AB78AA6BF02BA26A864A0C9318506B9AF3B91D8E348641EAB8137F66DF0FBA8')
PRIOR = ('C:/fzosoriginal-census-20261109-e1/results.json',
    'F72CFBB8E8A9184797341220A220DB3B45B026D66E58F5ED6CDC0139114F532E')
BUFFERS, FIXTURES = {}, {}
subject = fixture = leaf_fixture = prepared = proof = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def retain(buffers, path, raw):
    if not isinstance(path, Path) or type(raw) is not bytes:
        raise ValueError('literal source/fixture snapshot')
    if path in buffers and buffers[path] != raw:
        raise ValueError('conflicting first-seen source/fixture snapshot/' + str(path))
    buffers[path] = raw


def merge(buffers, additional):
    for path, raw in additional.items(): retain(buffers, path, raw)


def module(name, path, raw):
    value = ModuleType(name); value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def clear_parser():
    for name in list(sys.modules):
        if name == 'elftools' or name.startswith('elftools.'): del sys.modules[name]


@contextmanager
def bootstrap(case, *, bad=None, missing=None, zero=False, late=False):
    state = NS(constructed=False, reads=[], enrolled={}, events=[])
    physical_read, real_load = Path.read_bytes, subject.load
    bad_path = ROOT / (subject.PINS[bad][0] if bad in subject.PINS else next(iter(subject.DOCUMENTS))) if bad else None
    def read(path):
        if state.constructed: raise AssertionError('late physical bootstrap read')
        state.reads.append(path)
        return b'corrupt source' if path == bad_path else physical_read(path)
    def construct(args):
        state.constructed = True; state.events.append('witness'); return NS(SyntheticWitness=True)
    constructor = Mock(side_effect=construct)
    def factory(legacy, capture, *, extra_sources):
        state.enrolled = dict(extra_sources)
        for path, raw in extra_sources.items(): case.assertEqual(raw, BUFFERS[path])
        case.assertEqual(state.events, ['transport'])
        return constructor
    state.factory = Mock(side_effect=factory)
    def load(name, path, raw):
        result = real_load(name, path, raw)
        if name == '_os_final_replacement_census_admission_admission': result.witness_type = state.factory
        if name == '_os_final_replacement_census_bootstrap_transport': state.events.append('transport')
        if name == '_os_final_replacement_census_bootstrap_final_replacement_replay' and late:
            (ROOT / 'tools/unadmitted-final-replacement.py').read_bytes()
        return result
    pins = dict(subject.PINS)
    if missing: del pins[missing]
    if zero: pins['final_replacement_replay'] = (pins['final_replacement_replay'][0], '0' * 64)
    with patch.dict(sys.modules), patch.object(subject, 'PINS', pins), patch.object(Path, 'read_bytes', read), \
            patch.object(subject, 'load', side_effect=load):
        clear_parser()
        yield state, constructor


def validate(value, helpers=None):
    helpers = prepared[3] if helpers is None else helpers
    with fixture.detached(helpers): subject.require_result(value, helpers)


class BootstrapTests(unittest.TestCase):
    def test_first_seen_executed_snapshot_cannot_be_overwritten(self):
        path = Path('C:/first-seen.py'); buffers = {}
        retain(buffers, path, b'first'); retain(buffers, path, b'first')
        with self.assertRaisesRegex(ValueError, 'first-seen'): merge(buffers, {path: b'changed'})
        self.assertEqual(buffers, {path: b'first'})

    def test_original35_and_all_new_sources_precede_witness(self):
        with bootstrap(self) as (state, constructor): result = subject.prepare(NS())
        self.assertEqual(len(result[4]), 35); self.assertEqual(result[4], prepared[4])
        self.assertEqual(state.enrolled, result[5]); self.assertEqual(set(state.reads), set(result[5]))
        self.assertEqual(state.events, ['transport', 'witness']); constructor.assert_called_once()
        self.assertTrue({'original_composition', 'final_replacement_replay'} <= set(result[3]))

    def test_corrupt_new_leaf_parent_or_contract_fails_before_witness(self):
        for name in ('original_composition', 'final_replacement_replay', 'contract'):
            with self.subTest(role=name), bootstrap(self, bad=name) as (state, constructor), self.assertRaises(ValueError):
                subject.prepare(NS())
            state.factory.assert_not_called(); constructor.assert_not_called()

    def test_missing_new_helpers_and_zero_pin_fail_closed(self):
        for name in ('original_composition', 'final_replacement_replay'):
            with self.subTest(role=name), bootstrap(self, missing=name) as (state, constructor), self.assertRaises(ValueError):
                subject.prepare(NS())
            constructor.assert_not_called()
        with bootstrap(self, zero=True) as (state, constructor), self.assertRaises(ValueError): subject.prepare(NS())
        constructor.assert_not_called()

    def test_late_physical_fallback_rejects(self):
        with bootstrap(self, late=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'outside authenticated'):
            subject.prepare(NS())
        constructor.assert_called_once(); self.assertNotIn(ROOT / 'tools/unadmitted-final-replacement.py', state.reads)

    def test_no_parent_prepare_run_replay_or_initial_parser(self):
        tree = ast.parse(BUFFERS[Path(subject.__file__)])
        prepare = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare')
        self.assertFalse(any(isinstance(n, ast.Attribute) and n.attr in ('prepare', 'run', 'replay') for n in ast.walk(prepare)))
        with bootstrap(self) as (state, constructor), patch.dict(sys.modules, {'elftools': ModuleType('elftools')}), \
                self.assertRaisesRegex(ValueError, 'initially unimported parser'):
            subject.prepare(NS())
        self.assertEqual(state.reads, []); constructor.assert_not_called()


class BoundaryTests(unittest.TestCase):
    def test_previous_admission_is_delegated_not_relabelled(self):
        marker = object(); delegate = Mock(return_value=marker)
        args = tuple(object() for _ in range(6)); helpers = dict(original_composition=NS(admit_normal=delegate))
        self.assertIs(subject.admit_normal(*args, helpers), marker)
        delegate.assert_called_once_with(*args, helpers)

    def test_all23_paths_are_explicit_previous_reader_permissions(self):
        previous = json.loads(FIXTURES[Path(PRIOR[0])])
        rows = proof['FinalReplacementComponent']['ReadInputs']
        self.assertEqual(len(rows), 23)
        for row in rows:
            self.assertIn(row['Path'], previous['ImmutableReader']['Reads'])
            self.assertEqual(previous['InputHashes'][row['Path']], row['Sha256'])


class ValidatorTests(unittest.TestCase):
    def test_real_returned_bootstrap_helpers_validate_all_eight(self):
        validate(copy.deepcopy(proof))
        self.assertIs(proof['FinalReplacementComponentReplayed'], True)
        self.assertIs(proof['CanonicalProtocolValidated'], False)
        self.assertEqual(tuple(proof[k] for k, _ in subject.COUNTERS), (41, 12, 45, 36))

    def test_each_missing_final_helper_rejects(self):
        for name in (*subject.ORIGINAL_ALIASES.values(), 'original_replay', 'port_replay', 'final_replacement_replay'):
            helpers = dict(prepared[3]); del helpers[name]
            with self.subTest(missing=name), self.assertRaises((KeyError, ValueError)): validate(copy.deepcopy(proof), helpers)

    def test_batch_authority_and_proof_hash_substitutions_reject(self):
        cases = [('OriginalProofSha256', 'F' * 64), ('PortProofSha256', 'F' * 64), ('BatchRoot', 'C:/foreign')]
        for key, value in cases:
            changed = copy.deepcopy(proof); changed['FinalReplacementComponent'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): validate(changed)
        for key in ('ReceiptSha256', 'ArtifactsSha256'):
            changed = copy.deepcopy(proof); changed['Batch'][key] = 'F' * 64
            with self.subTest(key=key), self.assertRaises(ValueError): validate(changed)

    def test_own_final_roles_cannot_be_swapped_for_original_or_reference(self):
        for name in ('Machine', 'Final', 'LinkMap', 'Disassembly', 'Startup', 'MachineDisassembly'):
            changed = copy.deepcopy(proof); component = changed['FinalReplacementComponent']
            component['Inputs']['Final'][name] = copy.deepcopy(component['Inputs']['Reference'][name])
            with self.subTest(role=name), self.assertRaises(ValueError): validate(changed)

    def test_all_twelve_facts_41_nonclaims_and_four_credits_are_literal(self):
        self.assertEqual((len(subject.FACTS), len(subject.NONCLAIMS)), (12, 41))
        for key, value in ([(k, 1) for k in subject.FACTS] + [(k, 0) for k in subject.NONCLAIMS]
                + [(k, True) for k, _ in subject.COUNTERS] + [('RequiredCellsSatisfied', 1)]):
            changed = copy.deepcopy(proof); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): validate(changed)

    def test_previous_authorities_and_pending_projection_stay_enforced(self):
        for side in ('Native', 'Reference'):
            changed = copy.deepcopy(proof); next(r for r in changed['ProducerBindings'] if r['Side'] == side)['ReceiptSha256'] = 'F' * 64
            with self.subTest(side=side), self.assertRaises(ValueError): validate(changed)
        for key, value in (('Status', subject.PENDING), ('CommonAttributionClosed', False), ('UnresolvedAttribution', [{}])):
            changed = copy.deepcopy(proof); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): validate(changed)

    def test_nested_transport_token_and_control_byte_tampering_rejects(self):
        for field in ('TransportRoots', 'CanonicalJoin', 'ControlBytes'):
            changed = copy.deepcopy(proof); changed['FinalReplacementComponent'][field]['Foreign'] = True
            with self.subTest(field=field), self.assertRaises(ValueError): validate(changed)

    def test_outer_join_rejects_final_authority_even_if_leaf_is_bypassed(self):
        for key, value in (('BatchRoot', 'C:/foreign'), ('BatchAuthority', dict(Foreign=True))):
            changed = copy.deepcopy(proof); changed['FinalReplacementComponent'][key] = value
            helpers = dict(prepared[3], final_replacement_replay=NS(require_result=lambda *args: None))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'result shared'): validate(changed, helpers)


class LifecycleTests(unittest.TestCase):
    def model(self, *, fault=None, late=False, pending=None):
        model = fixture.prior_fixture.Model(self); model.fault = fault
        records = tuple(dict(SyntheticOnly=name) for name in ('census', 'abi', 'controls', 'isolation'))
        returned = (*records, dict(LoweredProofs=dict(UnresolvedAttribution=[] if pending is None else pending)),
            dict(SyntheticOnly='port'), dict(SyntheticOnly='original'), dict(SyntheticOnly='final'), dict(SyntheticOnly='reader'))
        def final(report, helpers):
            self.assertIs(report['FinalReplacementComponentReplayed'], True)
            if late: raise ValueError('postseal final failure')
        def run():
            with redirect_stdout(io.StringIO()), patch.object(subject, 'admit_normal', return_value=(
                    model.handoff_root, model.handoff, model.targets, model.inspection_tool, len(model.project))), \
                    patch.object(subject, 'replay', return_value=returned), patch.object(subject, 'require_result', side_effect=final):
                return subject.run(model.args, model.runner, model.environment, fixture.prior_fixture.fixture.builder,
                    model.helpers, {}, {})
        return model, run

    def test_success_sets_twelve_facts_without_new_commands(self):
        model, run = self.model(); result = run()
        self.assertEqual(result['Status'], subject.PASS)
        for name in subject.FACTS: self.assertIs(result[name], True)
        for name in subject.NONCLAIMS: self.assertIs(result[name], False)
        model.suite.command.assert_not_called()

    def test_pending_projection_is_preserved_without_qualification(self):
        pending = [dict(Group='positive', Evidence=[dict(Function='bounded-inline')])]
        model, run = self.model(pending=pending); result = run()
        self.assertEqual(result['Status'], subject.PENDING)
        self.assertEqual(result['UnresolvedAttribution'], pending)
        self.assertIs(result['CommonAttributionClosed'], False)
        for name in subject.NONCLAIMS: self.assertIs(result[name], False)

    def test_postseal_failure_revokes_every_fact_and_credit(self):
        model, run = self.model(late=True)
        with self.assertRaisesRegex(ValueError, 'postseal final'): run()
        model.runner.recover.assert_called_once()
        result = json.loads((model.output / 'results.json').read_bytes())
        for name in subject.FACTS + subject.NONCLAIMS: self.assertIs(result[name], False)
        for name, _ in subject.COUNTERS: self.assertEqual(result[name], 0)

    def test_object_output_seal_and_summary_failures_revoke(self):
        for fault in ('objects', 'output', 'seal', 'summary'):
            model, run = self.model(fault=None if fault == 'summary' else fault)
            printer = patch('builtins.print', side_effect=BrokenPipeError('summary')) if fault == 'summary' else nullcontext()
            with self.subTest(fault=fault), printer, self.assertRaises((ValueError, BrokenPipeError)): run()
            model.runner.recover.assert_called_once()
            for name in subject.FACTS: self.assertIs(model.suite.report[name], False)

    def test_foreign_output_identity_is_never_recovered(self):
        model, run = self.model()
        def substitute():
            model.output.rename(model.root / 'retired'); model.put(model.output / 'foreign', b'untouched')
        model.suite.verify_objects.side_effect = substitute
        with self.assertRaises(ValueError): run()
        model.runner.recover.assert_not_called(); self.assertEqual((model.output / 'foreign').read_bytes(), b'untouched')

    def test_cli_process_guards_and_no_abbreviations(self):
        with patch.object(subject, 'prepare') as prepare, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            subject.main(['--batch-b', 'x'])
        prepare.assert_not_called()
        for name in ('subprocess.Popen', 'os.system'):
            def attempt(*args):
                if name == 'os.system':
                    import os
                    os.system('NEVER')
                else:
                    import subprocess
                    subprocess.Popen(['NEVER'])
            argv = [v for key in subject.ARGUMENTS for v in ('--' + key, 'synthetic')]
            with self.subTest(name=name), patch.object(subject, 'prepare', side_effect=attempt), patch(name) as external, redirect_stderr(io.StringIO()):
                self.assertEqual(subject.main(argv), 1); external.assert_not_called()


def initialize():
    global subject, fixture, leaf_fixture, prepared, proof
    own, entry, parent = Path(__file__).resolve(), HERE / 'final_replacement_census_attempt.py', ROOT / PRIOR_FIXTURE[0]
    for path in (own, entry, parent, HERE / 'test_final_replacement_replay.py'): retain(BUFFERS, path, path.read_bytes())
    if sha(BUFFERS[parent]) != PRIOR_FIXTURE[1]: raise ValueError('published original fixture pin')
    fixture = module('_final_driver_original_fixture', parent, BUFFERS[parent]); fixture.initialize()
    merge(BUFFERS, fixture.BUFFERS); merge(FIXTURES, fixture.FIXTURES)
    subject = module('_final_driver_subject', entry, BUFFERS[entry]); real_load = subject.load
    def collecting(name, path, raw):
        retain(BUFFERS, path, raw); value = real_load(name, path, raw)
        if name == '_os_final_replacement_census_admission_admission':
            value.witness_type = lambda legacy, capture, *, extra_sources: (lambda args: NS(SyntheticWitness=True))
        return value
    with patch.dict(sys.modules), patch.object(subject, 'load', side_effect=collecting):
        clear_parser(); prepared = subject.prepare(NS())
    merge(BUFFERS, prepared[5])
    leaf_path = HERE / 'test_final_replacement_replay.py'
    leaf_fixture = module('_final_driver_byte_fixture', leaf_path, BUFFERS[leaf_path])
    with patch.dict(sys.modules):
        clear_parser(); final = leaf_fixture.synthetic_result(subject.final_helpers(prepared[3]))
    merge(BUFFERS, leaf_fixture.BUFFERS); merge(FIXTURES, leaf_fixture.FIXTURES)
    path = Path(PRIOR[0]); raw = path.read_bytes()
    if sha(raw) != PRIOR[1]: raise ValueError('recorded seven-component control pin')
    retain(FIXTURES, path, raw); proof = json.loads(raw)
    proof.update(Status=subject.PASS, Scope=subject.SCOPE, FinalReplacementComponent=final, FinalReplacementComponentReplayed=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv); output = args.output_dir.resolve(); temp = Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temp) or output.is_relative_to(ROOT): parser.error('fresh external TEMP output required')
    report = dict(Status='FAIL', Tests=0, ExpectedTests=METHODS, Errors=0, Failures=0, Skipped=0,
        SourceHashes={}, FixtureHashes={}, SourceClosureVerified=False, FixtureClosureVerified=False,
        ActualCaptureAdmitted=False, ActualCombinedCLIReplay=False, LifecycleReplayDoubles=True,
        ActualFinalBytePredicatesExercised=False, ToolInvocations=0, CompilerInvocations=0,
        RequiredCellsSatisfied=0, Qualification=False, BoardExecution=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('fresh isolated unoptimized -I -S -B interpreter required')
        initialize(); report['ActualFinalBytePredicatesExercised'] = True
        with patch('subprocess.Popen', side_effect=AssertionError('no producer processes')), patch('os.system', side_effect=AssertionError('no shell')):
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                for c in (BootstrapTests, BoundaryTests, ValidatorTests, LifecycleTests))
            if suite.countTestCases() != METHODS: raise ValueError('exact method count/' + str(suite.countTestCases()))
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Errors=len(result.errors), Failures=len(result.failures), Skipped=len(result.skipped),
            Details=[dict(Test=str(case), Error=error) for case, error in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped: report['Status'] = 'PASS'
    except BaseException:
        report.update(Errors=report['Errors'] + 1, Error=traceback.format_exc())
    for label, buffers in (('Source', BUFFERS), ('Fixture', FIXTURES)):
        report[label + 'Hashes'] = {str(p): sha(raw) for p, raw in buffers.items()}
        report[label + 'ClosureVerified'] = bool(buffers) and all(p.read_bytes() == raw for p, raw in buffers.items())
        if not report[label + 'ClosureVerified']: report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False); raw = encoded(report); (output / 'results.json').write_bytes(raw)
    print(json.dumps({k: v for k, v in report.items() if k not in ('SourceHashes', 'FixtureHashes', 'Details', 'Error')}, sort_keys=True))
    print('ReceiptSha256=' + sha(raw))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
