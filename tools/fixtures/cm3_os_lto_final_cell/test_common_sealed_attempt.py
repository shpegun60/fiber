"""Bootstrap regression and inherited controls; no actual producer replay.

The hash-pinned failed receipt is only a structural validator fixture. Its
original FAIL disposition, bytes and revoked credit are never changed.
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
METHODS = 35
INHERITED_METHODS = 19
FIXTURE_PIN = '6CCAA547AA06004085D5B3C904C7F3542F6D96C0336BAAB3AE2357FDFCF60401'
FAILURE_FIXTURES = {
    'C:/fzoscommon-census-20261108-e1/results.json':
        'A9407CE1B0C30E97A2D267CC9E922516837D57E328BBB00408B7FF303FEB398C',
    'C:/fzoscommon-census-20261108-e1/artifacts.json':
        '1400ED75666684A566C481EDAC75627DA35971BD76BE489AA718A55551E7A506',
}
BUFFERS, FIXTURE_BUFFERS = {}, {}
subject = fixture = failure = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def module_from_bytes(name, path, raw):
    module = ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


@contextmanager
def bootstrap(case, *, bad=None, zero=False, capture_mismatch=False, late=False):
    """Execute real authenticated modules; replace only witness construction."""
    state = NS(constructed=False, reads=[], enrolled={}, loaded={}, events=[])
    physical_read, real_load = Path.read_bytes, subject.load
    bad_paths = dict(base=ROOT / subject.BASE[0], transport=ROOT / subject.PINS['transport'][0],
        contract=ROOT / next(iter(subject.DOCUMENTS)),
        leaf=ROOT / fixture.subject.PINS['common_replay'][0])

    def read(path):
        if state.constructed:
            raise AssertionError('physical bootstrap read after witness')
        state.reads.append(path)
        if bad is not None and path == bad_paths[bad]:
            return b'corrupted synthetic authenticated source'
        return physical_read(path)

    def construct(args):
        state.events.append('witness')
        state.constructed = True
        return NS(SyntheticWitness=True)

    constructor = Mock(side_effect=construct)

    def factory(legacy, capture, *, extra_sources):
        state.enrolled = dict(extra_sources)
        required = {ROOT / subject.BASE[0], Path(subject.__file__).resolve(),
                    ROOT / subject.PINS['transport'][0], *(ROOT / p for p in subject.DOCUMENTS)}
        case.assertTrue(required <= set(extra_sources))
        for path, raw in extra_sources.items():
            case.assertEqual(raw, BUFFERS[path])
        case.assertIn('transport', state.events)
        case.assertEqual(capture.PINS['api'], subject.PINS['transport'])
        return constructor

    state.factory = Mock(side_effect=factory)

    def load(name, path, raw):
        module = real_load(name, path, raw)
        state.loaded[name] = module
        if name == '_os_common_sealed_admission_admission':
            module.witness_type = state.factory
        if name == '_os_common_sealed_admission_capture' and capture_mismatch:
            module.PINS = dict(module.PINS, api=(module.PINS['api'][0], 'F' * 64))
        if name == '_os_common_sealed_bootstrap_transport':
            case.assertFalse(state.constructed)
            state.events.append('transport')
        if name == '_os_common_sealed_bootstrap_machine' and late:
            (ROOT / 'tools/unadmitted-common-sealed.py').read_bytes()
        return module

    pins = dict(subject.PINS)
    if zero:
        pins['transport'] = (pins['transport'][0], '0' * 64)
    with patch.dict(sys.modules), patch.object(subject, 'PINS', pins), \
            patch.object(Path, 'read_bytes', read), patch.object(subject, 'load', side_effect=load):
        yield state, constructor


@contextmanager
def validator_only(helpers):
    with ExitStack() as stack:
        for name in ('read_bytes', 'read_text', 'open', 'stat', 'lstat', 'exists',
                     'iterdir', 'glob', 'rglob', 'resolve'):
            stack.enter_context(patch.object(Path, name, side_effect=AssertionError('validator filesystem disabled')))
        for name in ('builtins.open', 'os.open', 'os.stat', 'os.lstat'):
            stack.enter_context(patch(name, side_effect=AssertionError('validator filesystem disabled')))
        for name in ('subprocess.Popen', 'os.system'):
            stack.enter_context(patch(name, side_effect=AssertionError('validator process/shell disabled')))
        seen = set()
        for helper in helpers.values():
            if id(helper) in seen:
                continue
            seen.add(id(helper))
            for name in ('inspect', 'inspect_lowered', 'inspect_final', 'inspect_stress',
                         'inspect_sources', 'inspect_ir_undefined', 'worker_chain'):
                if callable(getattr(helper, name, None)):
                    stack.enter_context(patch.object(helper, name,
                        side_effect=AssertionError('producer predicate disabled/' + name)))
        yield


class BootstrapTests(unittest.TestCase):
    def test_exact_original_35_and_expanded_sources_precede_witness(self):
        with bootstrap(self) as (state, constructor):
            base, runner, environment, builder, helpers, opening, buffers = subject.prepare(NS())
        metadata = fixture.literals(BUFFERS[ROOT / builder.METADATA[0]])
        expected = {ROOT / subject.BATCH[0], ROOT / builder.METADATA[0], HERE / 'runner.py'}
        for registry in (metadata['PINS'], metadata['LEAF_PINS'], builder.PINS, runner.PINS):
            expected.update(ROOT / row[0] for row in registry.values())
        for registry in (metadata['DOCUMENTS'], runner.DOCUMENTS):
            expected.update(ROOT / p for p in registry)
        self.assertEqual(len(opening), 35)
        self.assertEqual(opening, {str(p): sha(BUFFERS[p]) for p in expected})
        self.assertEqual(buffers, state.enrolled)
        self.assertEqual(set(state.reads), set(buffers))
        self.assertNotIn(str(ROOT / subject.BASE[0]), opening)
        self.assertNotIn(str(Path(subject.__file__).resolve()), opening)
        self.assertEqual(environment['HelperPlans']['transport'], subject.PINS['transport'])
        self.assertEqual(state.events, ['transport', 'witness'])
        state.factory.assert_called_once()
        constructor.assert_called_once()

    def test_returned_bootstrap_transport_is_real_pre_witness_module(self):
        with bootstrap(self) as (state, constructor):
            base, runner, environment, builder, helpers, opening, buffers = subject.prepare(NS())
        transport = helpers['transport']
        self.assertIs(transport, state.loaded['_os_common_sealed_bootstrap_transport'])
        self.assertEqual(transport.__file__, str(ROOT / subject.PINS['transport'][0]))
        self.assertTrue(callable(transport.require_elf32le))
        self.assertTrue(callable(transport.section_records))
        self.assertEqual(environment['HelperPlans']['transport'], environment['Modules']['capture'].PINS['api'])
        self.assertTrue(set(base.LOWERED_HELPERS) <= set(helpers))
        self.assertTrue(set(base.COMMON_HELPERS) <= set(helpers))

    def test_corrupt_parent_transport_leaf_and_contract_reject_before_witness(self):
        for role in ('base', 'transport', 'leaf', 'contract'):
            with self.subTest(role=role), bootstrap(self, bad=role) as (state, constructor), \
                    self.assertRaisesRegex(ValueError, 'source pin'):
                subject.prepare(NS())
            state.factory.assert_not_called()
            constructor.assert_not_called()

    def test_zero_transport_pin_rejects_before_witness(self):
        with bootstrap(self, zero=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'source pin'):
            subject.prepare(NS())
        state.factory.assert_not_called()
        constructor.assert_not_called()

    def test_capture_api_disagreement_rejects_before_witness(self):
        with bootstrap(self, capture_mismatch=True) as (state, constructor), \
                self.assertRaisesRegex(ValueError, 'same authenticated capture transport'):
            subject.prepare(NS())
        state.factory.assert_not_called()
        constructor.assert_not_called()

    def test_unadmitted_helper_read_has_no_late_physical_fallback(self):
        with bootstrap(self, late=True) as (state, constructor), \
                self.assertRaisesRegex(ValueError, 'bootstrap helper outside authenticated opening buffers'):
            subject.prepare(NS())
        constructor.assert_called_once()
        self.assertNotIn(ROOT / 'tools/unadmitted-common-sealed.py', state.reads)

    def test_already_loaded_parser_rejects_before_sources_or_witness(self):
        with bootstrap(self) as (state, constructor), patch.dict(sys.modules, {'elftools': ModuleType('elftools')}), \
                self.assertRaisesRegex(ValueError, 'initially unimported parser'):
            subject.prepare(NS())
        self.assertEqual(state.reads, [])
        state.factory.assert_not_called()
        constructor.assert_not_called()

    def test_parent_predicates_globals_and_cli_are_unchanged(self):
        with bootstrap(self) as (state, constructor):
            base, *prepared = subject.prepare(NS())
        self.assertEqual(base.PINS, fixture.subject.PINS)
        self.assertEqual(base.DOCUMENTS, fixture.subject.DOCUMENTS)
        self.assertEqual(base.ARGUMENTS, subject.ARGUMENTS)
        for name in ('run', 'replay', 'require_result', 'common_result'):
            actual, expected = getattr(base, name), getattr(fixture.subject, name)
            self.assertEqual(actual.__code__.co_code, expected.__code__.co_code)
            self.assertEqual(actual.__code__.co_filename, str(ROOT / subject.BASE[0]))
        tree = ast.parse(BUFFERS[Path(subject.__file__).resolve()])
        self.assertFalse(any(isinstance(n, ast.Attribute) and n.attr == 'prepare' for n in ast.walk(tree)))
        self.assertEqual(sha(BUFFERS[ROOT / subject.BASE[0]]), subject.BASE[1])


class RealValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        case = unittest.TestCase()
        with bootstrap(case):
            cls.prepared = subject.prepare(NS())

    def test_failed_fixture_remains_failed_without_inherited_credit(self):
        base = self.prepared[0]
        self.assertEqual(failure['Status'], 'FAIL')
        self.assertEqual(failure['Error'], "KeyError: 'transport'")
        self.assertIsNotNone(failure['ImmutableReader'])
        self.assertEqual(failure['CommonAttributes']['CommandsReplayed'], 45)
        self.assertEqual(failure['CommonAttributes']['LoweredProofs']['UnresolvedAttribution'], [])
        for key in base.FACTS:
            self.assertIs(failure[key], False)
        for key, _ in base.COUNTERS:
            self.assertIs(type(failure[key]), int)
            self.assertEqual(failure[key], 0)

    def test_real_common_result_accepts_actual_returned_bootstrap_helpers(self):
        base, runner, environment, builder, helpers, opening, buffers = self.prepared
        with validator_only(helpers):
            self.assertEqual(base.common_result(copy.deepcopy(failure['CommonAttributes']), helpers), [])

    def test_missing_transport_reproduces_exact_postseal_keyerror(self):
        base, runner, environment, builder, helpers, opening, buffers = self.prepared
        missing = dict(helpers)
        del missing['transport']
        with validator_only(helpers), self.assertRaises(KeyError) as caught:
            base.common_result(copy.deepcopy(failure['CommonAttributes']), missing)
        self.assertEqual(caught.exception.args, ('transport',))

    def test_real_outer_validator_reaches_same_helpers_after_synthetic_fact_setup(self):
        base, runner, environment, builder, helpers, opening, buffers = self.prepared
        # This copy only tests schema/control flow, not admission or proof credit.
        report = copy.deepcopy(failure)
        report.update(Status=base.PASS, Error=None, PrimaryError=None, ClosingErrors=[],
            CommonAttributionClosed=True, **dict.fromkeys(base.FACTS, True), **dict(base.COUNTERS))
        with validator_only(helpers):
            base.require_result(report, helpers)
            missing = dict(helpers)
            del missing['transport']
            with self.assertRaises(KeyError) as caught:
                base.require_result(report, missing)
            self.assertEqual(caught.exception.args, ('transport',))
        self.assertEqual(failure['Status'], 'FAIL')

    def test_real_detailed_validator_still_rejects_nested_foreign_claims(self):
        base, runner, environment, builder, helpers, opening, buffers = self.prepared
        for key, value in (('ForeignClaim', True), ('Qualification', True),
                           ('FullInstructionSemantics', True), ('CommonAttributionClosed', False)):
            proof = copy.deepcopy(failure['CommonAttributes'])
            proof['LoweredProofs'][key] = value
            with self.subTest(key=key), validator_only(helpers), self.assertRaises(ValueError):
                base.common_result(proof, helpers)

    def test_postseal_missing_transport_revokes_all_nine_facts_and_three_counters(self):
        model = fixture.Model(self)
        del model.helpers['transport']
        with self.assertRaises(KeyError) as caught:
            model.run()
        self.assertEqual(caught.exception.args, ('transport',))
        model.runner.seal.assert_called_once()
        model.runner.recover.assert_called_once()
        report = model.failed()
        self.assertIsNotNone(report['CommonAttributes'])
        self.assertIsNotNone(report['ImmutableReader'])


class CliTests(unittest.TestCase):
    def test_main_delegates_unmodified_base_run_with_prepared_arguments(self):
        model = fixture.Model(self)
        base = fixture.subject
        argv = [value for name in subject.ARGUMENTS for value in ('--' + name,
            str(getattr(model.args, name.replace('-', '_'), 'synthetic')))]
        prepared = (base, model.runner, model.environment, fixture.builder, model.helpers, {}, {})
        with model.frozen(), patch.object(subject, 'prepare', return_value=prepared) as prepare, \
                patch.object(base, 'run', wraps=base.run) as run, patch.object(base, 'prepare') as old_prepare, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(subject.main(argv), 0)
        prepare.assert_called_once()
        run.assert_called_once()
        old_prepare.assert_not_called()
        self.assertEqual(run.call_args.args[1:], prepared[1:])
        self.assertEqual(model.suite.report['Status'], base.PASS)

    def test_cli_guards_bootstrap_through_failure_diagnostics_without_abbreviations(self):
        with patch.object(subject, 'prepare') as prepare, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            subject.main(['--batch-b', 'synthetic'])
        prepare.assert_not_called()
        for stage in ('prepare', 'admission', 'reader', 'close', 'seal', 'summary'):
            for kind in ('process', 'shell'):
                model = fixture.Model(self)

                def attempt(*args, **kwargs):
                    if kind == 'process':
                        import subprocess
                        subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
                    else:
                        import os
                        os.system('SYNTHETIC-NEVER-EXECUTED')

                def prepare(args):
                    if stage == 'prepare':
                        attempt()
                    return fixture.subject, model.runner, model.environment, fixture.builder, model.helpers, {}, {}

                @contextmanager
                def reader(*args):
                    attempt()
                    yield None

                if stage == 'admission': model.facade.admit_batch.side_effect = attempt
                elif stage == 'reader': model.runner.reader = reader
                elif stage == 'close': model.witness.close.side_effect = attempt
                elif stage == 'seal': model.runner.seal.side_effect = attempt
                argv = [value for name in subject.ARGUMENTS for value in ('--' + name,
                    str(getattr(model.args, name.replace('-', '_'), 'synthetic')))]
                printer = patch('builtins.print', side_effect=attempt) if stage == 'summary' else nullcontext()
                with self.subTest(stage=stage, kind=kind), model.frozen(), printer, \
                        patch.object(subject, 'prepare', side_effect=prepare), patch('subprocess.Popen') as process, \
                        patch('os.system') as shell, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(subject.main(argv), 1)
                    process.assert_not_called()
                    shell.assert_not_called()


def initialize():
    global subject, fixture, failure
    own = Path(__file__).resolve()
    child = HERE / 'common_sealed_attempt.py'
    frozen_fixture = HERE / 'test_common_census_attempt.py'
    for path in (own, child, frozen_fixture):
        BUFFERS[path] = path.read_bytes()
    if sha(BUFFERS[frozen_fixture]) != FIXTURE_PIN:
        raise ValueError('frozen parent fixture pin')
    fixture = module_from_bytes('_common_sealed_frozen_fixture', frozen_fixture, BUFFERS[frozen_fixture])
    fixture.initialize()
    BUFFERS.update(fixture.BUFFERS)
    subject = module_from_bytes('_common_sealed_subject', child, BUFFERS[child])
    for relative, digest in (subject.BASE, subject.BATCH, *subject.PINS.values(), *subject.DOCUMENTS.items()):
        path = ROOT / relative
        raw = BUFFERS[path] if path in BUFFERS else path.read_bytes()
        BUFFERS[path] = raw
        if digest == '0' * 64 or sha(raw) != digest:
            raise ValueError('final bootstrap source pin/' + relative)
    for relative, digest in (*fixture.subject.PINS.values(), *fixture.subject.DOCUMENTS.items()):
        if digest == '0' * 64 or sha(BUFFERS[ROOT / relative]) != digest:
            raise ValueError('final frozen common source pin/' + relative)
    for name, digest in FAILURE_FIXTURES.items():
        path = Path(name)
        raw = path.read_bytes()
        if sha(raw) != digest:
            raise ValueError('fixed failed receipt/manifest fixture pin/' + name)
        FIXTURE_BUFFERS[path] = raw
    failure = fixture.normal.structured(FIXTURE_BUFFERS[Path(next(iter(FAILURE_FIXTURES)))])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temporary) or output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
        parser.error('fresh external TEMP receipt directory required')
    report = dict(Status='FAIL', Scope='SYNTHETIC_COMMON_SEALED_BOOTSTRAP_AND_RESULT_VALIDATOR_ONLY',
        Tests=0, ExpectedTestMethods=METHODS, InheritedDriverMethods=INHERITED_METHODS,
        Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[], SourceClosureVerified=False,
        FixtureHashes={}, FixtureDrift=[], FixtureClosureVerified=False, FinalPinsVerified=False,
        ActualCaptureAdmitted=False, ActualProducerPredicatesReplayed=False, ExternalToolsExecuted=0,
        Qualification=False, RequiredCellsSatisfied=0, BoardExecution=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('fresh unoptimized -I -S -B interpreter required')
        initialize()
        report.update(FinalPinsVerified=True, SourceHashes={str(p): sha(raw) for p, raw in BUFFERS.items()},
                      FixtureHashes={str(p): sha(raw) for p, raw in FIXTURE_BUFFERS.items()})
        inherited = type('InheritedDriverTests', (fixture.DriverTests,), {})
        with patch('subprocess.Popen', side_effect=AssertionError('synthetic suite cannot start processes')), \
                patch('os.system', side_effect=AssertionError('synthetic suite cannot execute shell')):
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                for c in (BootstrapTests, RealValidatorTests, CliTests, inherited))
            if unittest.defaultTestLoader.loadTestsFromTestCase(inherited).countTestCases() != INHERITED_METHODS:
                raise ValueError('exact inherited test count')
            if suite.countTestCases() != METHODS:
                raise ValueError('exact test count')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), Details=[dict(Test=str(case), Error=error) for case, error in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except BaseException:
        report.update(Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        for buffers, key in ((BUFFERS, 'SourceDrift'), (FIXTURE_BUFFERS, 'FixtureDrift')):
            for path, raw in buffers.items():
                try:
                    if path.read_bytes() != raw:
                        report[key].append(str(path))
                except OSError:
                    report[key].append(str(path))
        report['SourceClosureVerified'] = bool(report['SourceHashes']) and not report['SourceDrift']
        report['FixtureClosureVerified'] = bool(report['FixtureHashes']) and not report['FixtureDrift']
        if not report['SourceClosureVerified'] or not report['FixtureClosureVerified']:
            report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes(encoded(report))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
