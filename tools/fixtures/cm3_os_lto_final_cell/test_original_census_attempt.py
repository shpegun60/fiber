"""Original composition controls, not an admitted combined replay or qualification.

Driver lifecycle tests use explicit replay doubles. Detached-validator tests use
recorded six-component controls plus freshly evaluated original byte fixtures.
The real combined CLI must still run separately with capture admission.
"""

import argparse
import ast
from contextlib import ExitStack, contextmanager, nullcontext, redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 23
PORT_FIXTURE = ('tools/fixtures/cm3_os_lto_final_cell/test_port_census_attempt.py',
    'C7DCA1CEFD65267A7FD3C5FCC6C2FD95C4DEABC49625ECA1C58C3E30F98848F3')
PRIOR = ('C:/fzosport-census-20261108-e1/results.json',
    '0D51EBE5F1F4C34829C4352981E96DCC11E3A2365AB819A8338CE05EF4DA4516')
BATCH_CONTROL = ('C:/fzosbatch-20261107-e1/results.json',
    '3DCE7C453AF909B6B917B9A3EED552F1725D70ED9420CEA74A36797ADB12EEC7')
BUFFERS, FIXTURES = {}, {}
subject = prior_fixture = leaf_fixture = prepared = proof = batch = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def module(name, path, raw):
    return prior_fixture.module_from_bytes(name, path, raw)


@contextmanager
def bootstrap(case, *, bad=None, missing=None, zero=False, late=False, mismatch=False):
    state = NS(constructed=False, reads=[], enrolled={}, events=[])
    real_read, real_load = Path.read_bytes, subject.load
    path_bad = ROOT / (subject.PINS[bad][0] if bad in subject.PINS else next(iter(subject.DOCUMENTS))) if bad else None
    def read(path):
        if state.constructed:
            raise AssertionError('late physical bootstrap read')
        state.reads.append(path)
        return b'corrupt source' if path == path_bad else real_read(path)
    def construct(args):
        state.constructed = True; state.events.append('witness')
        return NS(SyntheticWitness=True)
    constructor = Mock(side_effect=construct)
    def factory(legacy, capture, *, extra_sources):
        state.enrolled = dict(extra_sources)
        for path, raw in extra_sources.items(): case.assertEqual(raw, BUFFERS[path])
        case.assertEqual(state.events, ['transport'])
        return constructor
    state.factory = Mock(side_effect=factory)
    def load(name, path, raw):
        result = real_load(name, path, raw)
        if name == '_os_original_census_admission_admission': result.witness_type = state.factory
        if name == '_os_original_census_admission_capture' and mismatch:
            result.PINS = dict(result.PINS, api=(result.PINS['api'][0], 'F' * 64))
        if name == '_os_original_census_bootstrap_transport': state.events.append('transport')
        if name == '_os_original_census_bootstrap_original_replay' and late:
            (ROOT / 'tools/unadmitted-original.py').read_bytes()
        return result
    pins = dict(subject.PINS)
    if missing: del pins[missing]
    if zero: pins['original_replay'] = (pins['original_replay'][0], '0' * 64)
    with patch.dict(sys.modules), patch.object(subject, 'PINS', pins), patch.object(Path, 'read_bytes', read), \
            patch.object(subject, 'load', side_effect=load):
        for name in list(sys.modules):
            if name == 'elftools' or name.startswith('elftools.'): del sys.modules[name]
        yield state, constructor


@contextmanager
def detached(helpers):
    with prior_fixture.validators_only(helpers), ExitStack() as stack:
        for key, name in (('original_abi', 'inspect'), ('original_os_join', 'check_join'),
                ('original_decoder', 'Object'), ('original_native_roots', 'NativeCM3LTOImage'),
                ('original_reference_roots', 'ReferenceCM3LTOImage')):
            stack.enter_context(patch.object(helpers[key], name, side_effect=AssertionError('binary predicate disabled')))
        yield


def validated(value, helpers=None):
    helpers = prepared[3] if helpers is None else helpers
    with detached(helpers): subject.require_result(value, helpers)


class BootstrapTests(unittest.TestCase):
    def test_original_35_and_all_new_aliases_authenticated_before_witness(self):
        with bootstrap(self) as (state, constructor): result = subject.prepare(NS())
        runner, environment, builder, helpers, opening, buffers = result
        self.assertEqual(len(opening), 35)
        self.assertEqual(opening, prepared[4]); self.assertEqual(buffers, state.enrolled)
        self.assertEqual(set(state.reads), set(buffers)); self.assertEqual(state.events, ['transport', 'witness'])
        self.assertTrue(set(subject.ORIGINAL_ALIASES.values()) <= set(helpers))
        for name, alias in subject.ORIGINAL_ALIASES.items():
            if name in ('abi', 'link_helpers', 'binding_helpers'):
                self.assertEqual(environment['HelperPlans'][alias], runner.PINS[name])
        constructor.assert_called_once()

    def test_each_new_helper_and_contract_corruption_fails_before_witness(self):
        for name in (*subject.PINS, 'contract'):
            with self.subTest(role=name), bootstrap(self, bad=name) as (state, constructor), self.assertRaises(ValueError):
                subject.prepare(NS())
            state.factory.assert_not_called(); constructor.assert_not_called()

    def test_each_missing_original_helper_and_zero_pin_fails_before_witness(self):
        for name in subject.PINS:
            if not name.startswith('original_'): continue
            with self.subTest(missing=name), bootstrap(self, missing=name) as (state, constructor), self.assertRaises(ValueError):
                subject.prepare(NS())
            state.factory.assert_not_called(); constructor.assert_not_called()
        with bootstrap(self, zero=True) as (state, constructor), self.assertRaises(ValueError): subject.prepare(NS())
        constructor.assert_not_called()

    def test_transport_mismatch_and_late_physical_read_reject(self):
        with bootstrap(self, mismatch=True) as (state, constructor), self.assertRaises(ValueError): subject.prepare(NS())
        constructor.assert_not_called()
        with bootstrap(self, late=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'outside authenticated'):
            subject.prepare(NS())
        constructor.assert_called_once(); self.assertNotIn(ROOT / 'tools/unadmitted-original.py', state.reads)

    def test_no_parent_execution_or_preimported_parser(self):
        tree = ast.parse(BUFFERS[Path(subject.__file__)])
        prepare = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare')
        self.assertFalse(any(isinstance(n, ast.Attribute) and n.attr in ('prepare', 'run', 'replay') for n in ast.walk(prepare)))
        from types import ModuleType
        with bootstrap(self) as (state, constructor), patch.dict(sys.modules, {'elftools': ModuleType('elftools')}), \
                self.assertRaisesRegex(ValueError, 'initially unimported parser'):
            subject.prepare(NS())
        self.assertEqual(state.reads, []); constructor.assert_not_called()


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.native, self.reference = (copy.deepcopy(leaf_fixture.DESCRIPTORS[side]) for side in ('Native', 'Reference'))
        self.roles, self.ledgers, self.hashes = subject.original_inputs(self.native, self.reference)

    def witness(self):
        groups = {side: dict(Root=Path(row['Root']), **{k: v for k, v in row.items() if k != 'Root'})
                  for side, row in (('Native', self.native), ('Reference', self.reference))}
        result = NS(groups=groups, watch=NS(read=Mock(side_effect=lambda p, h: leaf_fixture.DATA[p])), close=Mock())
        return result

    def test_exact_30_logical_29_distinct_inputs_and_22_new_reader_roles(self):
        self.assertEqual(len(self.hashes), 29)
        self.assertEqual(set(self.hashes), set(leaf_fixture.DATA))
        bindings, ledgers = subject.original_call_inputs(self.roles, self.ledgers, self.hashes)
        self.assertEqual(bindings, leaf_fixture.ROLES); self.assertEqual(ledgers, leaf_fixture.LEDGERS)
        previous = {self.roles['NativeOrdinary']['Final'], self.roles['NativeEmitted']['Final'],
            self.roles['NativeEmitted']['Machine'], self.roles['NativeEmitted']['LinkMap'],
            self.roles['NativeEmitted']['Disassembly'], self.roles['NativeEmitted']['Startup'],
            Path(self.native['Root']) / 'results.json'}
        self.assertEqual(len(set(self.hashes) - previous), 22)

    def test_all_roles_retain_sealed_hash_and_physical_identity_before_close(self):
        witness, roles, retain = self.witness(), {}, Mock()
        subject.admit_original_roles(witness, batch, roles, dict(machine=NS(retain_identity=retain)))
        self.assertEqual(roles, self.hashes); self.assertEqual(retain.call_count, 29)
        self.assertEqual(witness.watch.read.call_count, 29); witness.close.assert_called_once()
        for call in retain.call_args_list:
            self.assertEqual(call.args[2], batch['InputPhysicalIdentities'][str(call.args[1])])

    def test_each_missing_batch_hash_or_physical_identity_rejects(self):
        for path in self.hashes:
            for key in ('InputHashes', 'InputPhysicalIdentities'):
                changed = copy.deepcopy(batch); del changed[key][str(path)]
                with self.subTest(path=str(path), missing=key), self.assertRaises(ValueError):
                    subject.admit_original_roles(self.witness(), changed, {}, dict(machine=NS(retain_identity=Mock())))

    def test_conflicting_reader_role_or_identity_failure_does_not_close(self):
        path = next(iter(self.hashes)); witness = self.witness()
        with self.assertRaises(ValueError):
            subject.admit_original_roles(witness, batch, {path: 'F' * 64}, dict(machine=NS(retain_identity=Mock())))
        witness.close.assert_not_called()
        witness = self.witness()
        with self.assertRaisesRegex(ValueError, 'physical drift'):
            subject.admit_original_roles(witness, batch, {}, dict(machine=NS(retain_identity=Mock(side_effect=ValueError('physical drift')))))
        witness.close.assert_not_called()

    def test_capture_link_hash_source_count_and_alias_invariants_reject(self):
        for key, value in (('Sha256', 'F' * 64), ('MachineSha256', 'F' * 64), ('MapSha256', 'F' * 64)):
            bad = copy.deepcopy(self.native); bad['Result']['Links'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): subject.original_inputs(bad, self.reference)
        bad = copy.deepcopy(self.native); bad['Result']['Sources'].pop()
        with self.assertRaises(ValueError): subject.original_inputs(bad, self.reference)
        bad = copy.deepcopy(self.reference); bad['Result']['TwinLoadImagesPath'] = self.native['Result']['TwinLoadImagesPath']
        with self.assertRaises(ValueError): subject.original_inputs(self.native, bad)


class ValidatorTests(unittest.TestCase):
    def test_real_bootstrap_helpers_validate_all_seven_detached_components(self):
        validated(copy.deepcopy(proof))
        self.assertIs(proof['OriginalComponentReplayed'], True)
        self.assertIs(proof['CanonicalProtocolValidated'], False)
        self.assertEqual(tuple(proof[k] for k, _ in subject.COUNTERS), (41, 12, 45, 36))

    def test_missing_each_original_helper_rejects(self):
        for name in (*subject.ORIGINAL_ALIASES.values(), 'original_replay'):
            helpers = dict(prepared[3]); del helpers[name]
            with self.subTest(missing=name), self.assertRaises((KeyError, ValueError)): validated(copy.deepcopy(proof), helpers)

    def test_outer_authorities_native_and_reference_cannot_be_substituted(self):
        for side in ('Native', 'Reference'):
            for key in ('Build', 'ReceiptSha256', 'ArtifactsSha256'):
                changed = copy.deepcopy(proof)
                row = next(r for r in changed['ProducerBindings'] if r['Side'] == side)
                row[key] = 'C:/foreign' if key == 'Build' else 'F' * 64
                with self.subTest(side=side, field=key), self.assertRaises(ValueError): validated(changed)
        changed = copy.deepcopy(proof); changed['ProducerBindings'].append(copy.deepcopy(changed['ProducerBindings'][0]))
        with self.assertRaises(ValueError): validated(changed)

    def test_every_original_cross_component_join_is_repeated_by_outer_validator(self):
        cases = [(None, key) for key in ('Cohort', 'SourceInventorySha256')]
        cases += [('Authorities', key) for key in ('Native', 'Reference')]
        cases += [('Inputs', key) for key in ('NativeOrdinary', 'NativeEmitted')]
        cases += [('LoadImageComparisons', 'Native')]
        for group, key in cases:
            changed = copy.deepcopy(proof); target = changed['OriginalComponent']
            (target if group is None else target[group])[key] = dict(Foreign=True)
            helpers = dict(prepared[3], original_replay=NS(require_result=lambda p, h: None))
            with self.subTest(group=group, key=key), self.assertRaises((KeyError, ValueError)): validated(changed, helpers)

    def test_each_native_startup_map_dump_machine_and_image_join_rejects(self):
        cases = [('NativeOrdinary', 'Final'), ('NativeEmitted', 'Final'), ('NativeEmitted', 'Machine'),
            ('NativeEmitted', 'LinkMap'), ('NativeEmitted', 'Disassembly'),
            ('NativeOrdinary', 'Startup'), ('NativeEmitted', 'Startup')]
        for group, key in cases:
            changed = copy.deepcopy(proof)
            changed['OriginalComponent']['Inputs'][group][key] = dict(Path='C:/foreign.o', Sha256='F' * 64)
            helpers = dict(prepared[3], original_replay=NS(require_result=lambda p, h: None))
            with self.subTest(group=group, key=key), self.assertRaisesRegex(ValueError, 'result shared'):
                validated(changed, helpers)

    def test_all_facts_nonclaims_and_counters_are_literal(self):
        for key, value in ([(k, 1) for k in subject.FACTS] + [(k, 0) for k in subject.NONCLAIMS]
                + [(k, True) for k, _ in subject.COUNTERS] + [('ToolInvocations', False), ('RequiredCellsSatisfied', 1)]):
            changed = copy.deepcopy(proof); changed[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError): validated(changed)
        self.assertEqual(len(subject.FACTS), 11); self.assertEqual(len(subject.NONCLAIMS), 41)

    def test_pending_is_exact_projection_and_never_original_root_promotion(self):
        for key, value in (('Status', subject.PENDING), ('CommonAttributionClosed', False), ('UnresolvedAttribution', [{}])):
            changed = copy.deepcopy(proof); changed[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError): validated(changed)

    def test_nested_claims_reject_even_if_all_outer_facts_are_true(self):
        for path in (('Nonclaims', 'Qualification'), ('CanonicalJoin', 'MutantsReexecuted')):
            changed = copy.deepcopy(proof); target = changed['OriginalComponent']
            target[path[0]][path[1]] = True
            with self.subTest(path=path), self.assertRaises(ValueError): validated(changed)


class LifecycleTests(unittest.TestCase):
    def run_double(self, case, *, fault=None, bad_final=False):
        model = prior_fixture.Model(case)
        model.fault = fault
        components = tuple(dict(SyntheticOnly=name) for name in ('census', 'abi', 'controls', 'isolation'))
        common = dict(LoweredProofs=dict(UnresolvedAttribution=[]))
        returned = (*components, common, dict(SyntheticOnly='port'), dict(SyntheticOnly='original'), dict(SyntheticOnly='reader'))
        def final(report, helpers):
            case.assertIs(report['OriginalComponentReplayed'], True)
            case.assertEqual(tuple(report[k] for k, _ in subject.COUNTERS), (41, 12, 45, 36))
            if bad_final: raise ValueError('postseal validator failure')
        def run():
            with redirect_stdout(io.StringIO()), patch.object(subject, 'admit_normal', return_value=(
                    model.handoff_root, model.handoff, model.targets, model.inspection_tool, len(model.project))), \
                    patch.object(subject, 'replay', return_value=returned), patch.object(subject, 'require_result', side_effect=final):
                return subject.run(model.args, model.runner, model.environment, prior_fixture.fixture.builder, model.helpers, {}, {})
        return model, run

    def test_success_publishes_eleven_facts_only_after_replay(self):
        model, run = self.run_double(self); report = run()
        self.assertEqual(report['Status'], subject.PASS)
        for key in subject.FACTS: self.assertIs(report[key], True)
        for key in subject.NONCLAIMS: self.assertIs(report[key], False)
        model.suite.command.assert_not_called(); model.runner.seal.assert_called_once()

    def test_postseal_validator_failure_revokes_every_credit(self):
        model, run = self.run_double(self, bad_final=True)
        with self.assertRaisesRegex(ValueError, 'postseal validator'): run()
        model.runner.recover.assert_called_once()
        report = json.loads((model.output / 'results.json').read_bytes())
        for key in subject.FACTS + subject.NONCLAIMS: self.assertIs(report[key], False)
        for key, _ in subject.COUNTERS: self.assertEqual(report[key], 0)

    def test_object_output_seal_and_summary_failure_revoke(self):
        for fault in ('objects', 'output', 'seal', 'summary'):
            model, run = self.run_double(self, fault=None if fault == 'summary' else fault)
            printer = patch('builtins.print', side_effect=BrokenPipeError('summary')) if fault == 'summary' else nullcontext()
            with self.subTest(fault=fault), printer, self.assertRaises((ValueError, BrokenPipeError)): run()
            model.runner.recover.assert_called_once()
            report = json.loads((model.output / 'results.json').read_bytes())
            for key in subject.FACTS: self.assertIs(report[key], False)
            for key, _ in subject.COUNTERS: self.assertEqual(report[key], 0)

    def test_output_identity_substitution_is_not_recovered_over_foreign_data(self):
        model, run = self.run_double(self)
        def substitute():
            model.output.rename(model.root / 'retired'); model.put(model.output / 'foreign', b'untouched')
        model.suite.verify_objects.side_effect = substitute
        with self.assertRaises(ValueError): run()
        self.assertEqual((model.output / 'foreign').read_bytes(), b'untouched')
        model.runner.recover.assert_not_called()

    def test_cli_guards_processes_from_bootstrap_and_rejects_abbreviations(self):
        from contextlib import redirect_stderr
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
            with self.subTest(name=name), patch.object(subject, 'prepare', side_effect=attempt), patch(name) as external, \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(subject.main(argv), 1); external.assert_not_called()


def initialize():
    global subject, prior_fixture, leaf_fixture, prepared, proof, batch
    own, entry, old = Path(__file__).resolve(), HERE / 'original_census_attempt.py', ROOT / PORT_FIXTURE[0]
    for path in (own, entry, old, HERE / 'test_original_replay.py'): BUFFERS[path] = path.read_bytes()
    if sha(BUFFERS[old]) != PORT_FIXTURE[1]: raise ValueError('published port fixture pin')
    # The published fixture supplies independently owned synthetic lifecycle machinery.
    from types import ModuleType
    prior_fixture = ModuleType('_original_prior_fixture'); prior_fixture.__file__ = str(old)
    exec(compile(BUFFERS[old], str(old), 'exec'), prior_fixture.__dict__)
    prior_fixture.initialize(); BUFFERS.update(prior_fixture.BUFFERS)
    FIXTURES.update(prior_fixture.FIXTURE_BUFFERS)
    subject = module('_original_driver_subject', entry, BUFFERS[entry])
    # Authenticate every bootstrap dependency through prepare before tests use it.
    paths = dict(BUFFERS)
    real_load = subject.load
    def collecting(name, path, raw):
        BUFFERS[path] = raw
        result = real_load(name, path, raw)
        if name == '_os_original_census_admission_admission':
            result.witness_type = lambda legacy, capture, *, extra_sources: (lambda args: NS(SyntheticWitness=True))
        return result
    with patch.dict(sys.modules), patch.object(subject, 'load', side_effect=collecting): prepared = subject.prepare(NS())
    BUFFERS.update(prepared[5]); BUFFERS.update(paths)
    leaf_path = HERE / 'test_original_replay.py'
    leaf_fixture = module('_original_driver_byte_fixture', leaf_path, BUFFERS[leaf_path])
    original = leaf_fixture.synthetic_result(subject.original_helpers(prepared[3]))
    BUFFERS.update(leaf_fixture.BUFFERS); FIXTURES.update(leaf_fixture.FIXTURES)
    for name, digest in (PRIOR, BATCH_CONTROL):
        path = Path(name); raw = path.read_bytes()
        if sha(raw) != digest: raise ValueError('fixed control receipt pin')
        FIXTURES[path] = raw
    proof = json.loads(FIXTURES[Path(PRIOR[0])]); batch = json.loads(FIXTURES[Path(BATCH_CONTROL[0])])
    proof.update(Status=subject.PASS, Scope=subject.SCOPE, OriginalComponent=original, OriginalComponentReplayed=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv); output = args.output_dir.resolve(); temp = Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temp) or output.is_relative_to(ROOT):
        parser.error('fresh external TEMP directory required')
    report = dict(Status='FAIL', Tests=0, ExpectedTests=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, FixtureHashes={}, SourceClosureVerified=False, FixtureClosureVerified=False,
        ActualCaptureAdmitted=False, ActualCombinedCLIReplay=False, LifecycleReplayDoubles=True,
        ActualOriginalBytePredicatesExercised=False, ToolInvocations=0, CompilerInvocations=0,
        Qualification=False, RequiredCellsSatisfied=0, BoardExecution=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('fresh isolated unoptimized -I -S -B interpreter required')
        initialize(); report['ActualOriginalBytePredicatesExercised'] = True
        with patch('subprocess.Popen', side_effect=AssertionError('suite cannot start processes')), \
                patch('os.system', side_effect=AssertionError('suite cannot execute shell')):
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                for c in (BootstrapTests, AdmissionTests, ValidatorTests, LifecycleTests))
            if suite.countTestCases() != METHODS: raise ValueError('exact method count/' + str(suite.countTestCases()))
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            Details=[dict(Test=str(case), Error=error) for case, error in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped: report['Status'] = 'PASS'
    except BaseException:
        report.update(Errors=report['Errors'] + 1, Error=traceback.format_exc())
    for key, sources in (('Source', BUFFERS), ('Fixture', FIXTURES)):
        report[key + 'Hashes'] = {str(p): sha(raw) for p, raw in sources.items()}
        report[key + 'ClosureVerified'] = bool(sources) and all(p.read_bytes() == raw for p, raw in sources.items())
        if not report[key + 'ClosureVerified']: report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False); raw = encoded(report); (output / 'results.json').write_bytes(raw)
    print(json.dumps({k: v for k, v in report.items() if k not in ('SourceHashes', 'FixtureHashes', 'Details', 'Error')}, sort_keys=True))
    print('ReceiptSha256=' + sha(raw))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
