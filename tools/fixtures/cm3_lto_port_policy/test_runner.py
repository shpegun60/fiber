"""Host-only synthetic controls for the selected-port policy runner."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / 'runner.py'
S = None
A = None
P = None
D = 'A' * 64
EXPECTED_METHODS = 13


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(path, raw, name):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def flags():
    return ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-O2', '-std=gnu11',
        '-ffreestanding', '-I/cmsis', '-I/source/fiber/port/ARM_CM3', '-include',
        '/source/tools/fixtures/classic_final_image/main.h', '-flto', '-fno-fat-lto-objects']


def option_proof(supported=True):
    return dict(SupportedPolicy=supported, EffectiveOptionsVerified=True, AttributeEffectsValidated=False,
        Counters=list(S.COUNTER_FLAGS) if supported else [], RawPresent=list(S.RAW_FLAGS), CanonicalizedRawAbsent=[])


def worker(supported=True):
    return dict(Machine='machine.o', MachineSha256=D, SupportedPolicy=supported,
        EffectiveOptionsVerified=True, WpaOptions=option_proof(supported), LtransOptions=option_proof(supported),
        Execution=dict(CompilerReportedWorkerExecutionVerified=True, OsProcessTraceVerified=False,
            TranscriptSha256=D, EffectiveOptions=[option_proof(supported), option_proof(supported)],
            WorkerInvocations=[dict(Stage=marker, ExecutableSha256=D, ResponseSha256=D, Argv=[marker])
                for marker in ('-fwpa', '-fltrans')], Assembler=dict(ExecutableSha256=D, Argv=['as'])))


def machine(names=None):
    names = S.PUBLIC_FUNCTIONS + S.LOCAL_FUNCTIONS if names is None else names
    return dict(Status='CM3-LTO-PORT-POLICY-MACHINE-PASS', Scope='CM3_O2_LTO_SUPPORTED_PORT_POLICY_COMPONENT_ONLY',
        ObjectSha256=D, DisassemblySha256=D, FunctionsAudited=len(names),
        FinalELF=False,
        FunctionEvidence=[dict(Name=name, BodySha256=D, Instructions=1, References=[]) for name in names],
        CompleteExecutableCensus=True, ForbiddenDependenciesAbsent=True, RecognizedForbiddenFormsAbsent=True,
        RecognizedForbiddenForms=['synthetic recognized form'], FullInstructionSemantics=False,
        OriginalTranslationUnitOwnership=False, SourceIRSemantics=False, AttributeOnlyProtection=False,
        GeneralRegistersOnlyEffectProved=False, CPUExecution=False, BoardExecution=False,
        GlobalQualification=False, RequiredCellsSatisfied=0)


def stress(raw):
    imports = ['__cyg_profile_func_enter', '__cyg_profile_func_exit', '__stack_chk_guard', '__stack_chk_fail',
        '__gcov_init', '__gcov_exit', '__gcov_merge_add', '__ubsan_handle_add_overflow',
        '__ubsan_handle_out_of_bounds', '__sanitizer_cov_trace_pc'] if raw else []
    refs = [dict(CompilerHook=True, CompilerCounter=False, OriginalHookTransferValidated=True,
        Target=dict(name=name)) for name in imports]
    effects = dict(Status='CONTEXT-LTO-ANNOTATION-MUTANT-DETECTED' if raw else 'CONTEXT-LTO-DIRECT-ATTRIBUTE-CHECKS-PASS',
        Scope='CM3_O2_LTO_CONTEXT_ATTRIBUTE_EFFECT_COMPONENT_ONLY', ObjectSha256=D, UnresolvedAttribution=[],
        ProtectedFunctions=1, RequiredCellCount=0, AllProtectedBodiesClean=not raw,
        CompiledAnnotationMutantDetected=raw, StressFamiliesActivated=raw, ThreadSectionValidated=False,
        OrdinaryColdActivityValidated=False, ColdInlineAttributionValidated=True, CompilerImports=imports,
        StressCounterEvidence=dict(Definition=dict(name='__gcov0.ctxrt_attribute_stress'), References=[dict(Synthetic=True)])
            if raw else None,
        RootEvidence=[dict(Name='ctxrt_attribute_stress', BodySha256=D, InstructionCount=1, References=refs,
            MappedData=[], Symbol=dict(name='ctxrt_attribute_stress'), DirectCompilerEffects=len(refs), AnnotationMutant=raw)],
        **{name: False for name in ('TransitiveProtection', 'FullABI', 'FullIRSemantics', 'FullInstructionSemantics',
            'FullAttributeEquivalence', 'CPUExecution', 'BoardExecution', 'GlobalQualification')})
    proof = dict(Status='CM3-LTO-PORT-POLICY-STRESS-EFFECTS-DETECTED' if raw
        else 'CM3-LTO-PORT-POLICY-STRESS-CLEAN', SupportedPolicy=not raw, RequiredCellsSatisfied=0, Effects=effects)
    if raw:
        proof['CleanPredicateRejected'] = True
    else:
        proof['CleanMachine'] = machine(('ctxrt_attribute_stress',))
    return proof


def report():
    result = dict(Status=S.PASS, Scope=S.SCOPE, Profile='CM3', Mode='O2-lto', Linkage='direct', LTO=True,
        Error=None, PrimaryError=None, ClosingErrors=[], RequiredCellsSatisfied=0, RequiredCellCount=2774,
        RawFlags=list(S.RAW_FLAGS), SupportedCounterFlags=list(S.COUNTER_FLAGS),
        **{name: True for name in S.PHASES}, **{name: False for name in S.FALSE_CLAIMS})
    result['Commands'] = [dict(Label=name, State='TERMINAL', Status='PASS', Exit=0,
        ExpectedExit=0, TimedOut=False) for name in S.command_plan()]
    result['IRDefinitionSurface'] = P.inspect_ir_definitions({role: [dict(Name=name,
        Kind='W' if name == 'fiber_fallback_initial_msp' else 'T', Value=0, Size=None)
        for name in names] + ([dict(Name=name, Kind='D', Value=0, Size=None)
            for name in (P.PRIVATE, P.STORAGE)] if role == 'runtime' else [])
        for role, names in zip(('runtime', 'boot', 'exception'),
            (S.PUBLIC_FUNCTIONS[:13], S.PUBLIC_FUNCTIONS[13:27], S.PUBLIC_FUNCTIONS[27:]))})
    result['Compilations'] = [dict(Group=group, TemplateIndex=index, CompileDependenciesVerified=True,
        SlimIR=dict(SlimIR=True), CpuFreeIncludes=False, SupportedPolicy=group != 'stress-raw',
        SourceSha256=D, ObjectSha256=D) for group, index in zip(
            ('selected', 'selected', 'selected', 'stress-supported', 'stress-raw'), (3, 4, 5, 3, 3))]
    result['Lowerings'] = []
    for group in ('selected', 'stress-supported', 'stress-raw'):
        proof = machine() if group == 'selected' else stress(group == 'stress-raw')
        result['Lowerings'].append(dict(Group=group, ObjectSha256=D, ActualWorker=worker(group != 'stress-raw'),
            Disassembly=dict(Sha256=D), WorkerDisassembly=dict(Sha256=D), Effects=proof,
            WorkerEffects=copy.deepcopy(proof), OriginalCleanPredicateRejected=group == 'stress-raw'))
    proof = machine()
    proof['FinalELF'] = True
    proof['FinalRootVectorBindings'] = dict(Words=256, CanonicalRootProtocolsValidated=False)
    result['FinalLink'] = dict(ActualWorker=worker(), Sha256=D, Effects=proof, WorkerEffects=machine(),
        Disassembly=dict(Sha256=D), WorkerDisassembly=dict(Sha256=D), GlobalSupportedCounterPolicy=True,
        UnchangedOtherSixGeneratedBodies=False,
        UnchangedOtherSixObjects=[dict(Index=index, Sha256=D) for index in (0, 1, 2, 6, 7, 8)],
        TransferRoots=[dict(Name=name, GeneratedMachineBoundRootPreservation=True,
            OriginalTranslationUnitOwnership=False, BodySha256=D, References=[dict(Synthetic=True)])
            for name in ('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')])
    return result


class RunnerTests(unittest.TestCase):
    def test_exact_command_plan_and_typed_exits(self):
        expected = ['dump compiler specs']
        for group, names in (('selected', ('fiber_port', 'fiber_port_boot', 'fiber_port_exception')),
                ('stress-supported', ('stress',)), ('stress-raw', ('stress',))):
            for name in names:
                expected.extend(('discover ' + group + ' ' + name, 'compile ' + group + ' ' + name,
                    'inspect slim ' + name, 'imports ' + group + ' ' + name))
                if group == 'selected':
                    expected.append('definitions ' + group + ' ' + name)
            expected.extend(('lower ' + group, 'disassemble ' + group, 'disassemble worker ' + group))
        expected.extend(('link final-supported', 'disassemble final-supported', 'disassemble worker final-supported'))
        self.assertEqual(tuple(expected), S.command_plan())
        self.assertEqual(len(expected), 36)
        rows = report()['Commands']
        self.assertTrue(S.commands_pass(rows))
        for value in (False, 0.0, 1, None):
            bad = copy.deepcopy(rows)
            bad[0]['Exit'] = value
            self.assertFalse(S.commands_pass(bad))
        self.assertFalse(S.commands_pass(rows[:-1]))
        self.assertFalse(S.commands_pass(rows + rows[:1]))

    def test_selected_flags_preserve_real_headers_and_seven_counters(self):
        seed = flags()
        suite = NS(source=lambda index: dict(CompileFlags=copy.deepcopy(seed)))
        for index in (3, 4, 5):
            actual = S.flags_for(suite, index)
            self.assertEqual(actual[:len(seed)], seed)
            self.assertEqual(actual[len(seed):], list(S.RAW_FLAGS + S.COUNTER_FLAGS))
            self.assertIn('-fno-sanitize-coverage=trace-pc', actual)
            self.assertEqual(actual[-1], '-mgeneral-regs-only')
        self.assertEqual(S.flags_for(suite, 3, supported=False), seed + list(S.RAW_FLAGS))
        for extra in ('-march=armv8-m.main', '-mfpu=fpv5-sp-d16', '-fno-sanitize=all', '-finstrument-functions'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                S.flags_for(NS(source=lambda index: dict(CompileFlags=seed + [extra])), 3)
        for index in (True, 2, 6):
            with self.assertRaises(ValueError):
                S.flags_for(suite, index)
        self.assertEqual(seed, flags())

    def test_disassembly_retains_zero_filled_literal_pools(self):
        root = Path('C:/synthetic-port-policy')
        target = root / 'lowered' / 'image.o'
        saved = target.with_suffix('.o.dis')
        suite = NS(output=root, tools=dict(objdump=Path('C:/synthetic-tools/objdump.exe')),
            command=Mock(return_value=NS(stdout=b'complete disassembly', stderr=b'')),
            write_input=Mock(return_value=saved))
        result = S.disassemble(suite, target, 'synthetic disassembly')
        suite.command.assert_called_once_with(
            [str(suite.tools['objdump']), '-drwC', '-z', str(target)], 'synthetic disassembly')
        suite.write_input.assert_called_once_with('lowered/image.o.dis', b'complete disassembly')
        self.assertEqual(result, dict(Path=str(saved), Sha256=sha(b'complete disassembly')))

    def test_final_recipe_replaces_only_three_and_global_policy_explicit(self):
        base = Path(tempfile.gettempdir()) / 'synthetic-port-policy'
        objects = tuple(base / ('%02d.o' % index) for index in range(9))
        original = ['gcc', '-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-O2', '-flto', '-v',
            '-flto-partition=one', '-save-temps=obj', '-nostdlib', '-Wl,-plugin-opt=-save-temps',
            '-T', 'original.ld', *(str(path) for path in objects), '-Wl,-Map=original.map', '-o', 'original.elf']
        suite = NS(objects=objects, result=dict(Commands=[dict(Label='link ordinary', Argv=original)],
            Links=[dict(Path='original.elf')]))
        selected = [base / ('fresh-%d.o' % index) for index in (3, 4, 5)]
        actual, inputs = S.final_arguments(suite, selected, base / 'new.elf', base / 'new.map')
        self.assertEqual(inputs[3:6], selected)
        self.assertEqual([inputs[index] for index in (0, 1, 2, 6, 7, 8)],
            [objects[index] for index in (0, 1, 2, 6, 7, 8)])
        self.assertEqual([value for value in actual if value.endswith('.o')], [str(path) for path in inputs])
        self.assertEqual(actual[actual.index('-finstrument-functions'):actual.index('-mgeneral-regs-only') + 1],
            list(S.RAW_FLAGS + S.COUNTER_FLAGS))
        self.assertIn('-Wl,--emit-relocs', actual)
        self.assertNotIn('-specs=', ' '.join(actual))
        self.assertEqual(suite.result['Commands'][0]['Argv'], original)
        with self.assertRaises(ValueError):
            S.final_arguments(suite, [selected[0]] * 3, base / 'x', base / 'm')

    def test_effective_worker_leaf_is_typed_and_not_process_trace(self):
        for supported in (False, True):
            self.assertTrue(S.worker_pass(worker(supported), supported))
        for change in ('missing-execution', 'OS-trace', 'wrong-policy', 'no-options', 'wrong-stage', 'bad-hash'):
            proof = worker()
            if change == 'missing-execution':
                del proof['Execution']
            elif change == 'OS-trace':
                proof['Execution']['OsProcessTraceVerified'] = True
            elif change == 'wrong-policy':
                proof['SupportedPolicy'] = False
            elif change == 'no-options':
                proof['Execution']['EffectiveOptions'] = []
            elif change == 'wrong-stage':
                proof['Execution']['WorkerInvocations'][1]['Stage'] = '-fwpa'
            else:
                proof['MachineSha256'] = 'x'
            with self.subTest(change=change):
                self.assertFalse(S.worker_pass(proof))

    def test_machine_leaf_full_census_and_nonclaims(self):
        self.assertTrue(S.machine_pass(machine(), D, D))
        mutations = (('FunctionsAudited', True), ('FunctionEvidence', []), ('CompleteExecutableCensus', False),
            ('RecognizedForbiddenFormsAbsent', False), ('FullInstructionSemantics', True),
            ('OriginalTranslationUnitOwnership', True), ('RequiredCellsSatisfied', False),
            ('ObjectSha256', 'B' * 64), ('DisassemblySha256', 'B' * 64))
        for key, value in mutations:
            proof = machine()
            proof[key] = value
            with self.subTest(key=key):
                self.assertFalse(S.machine_pass(proof, D, D))
        for name in ('SVC_Handler', 'fiber_port_runtime_schedule', 'fiber_validate_feature_policy'):
            proof = machine()
            proof['FunctionEvidence'] = [row for row in proof['FunctionEvidence'] if row['Name'] != name]
            proof['FunctionsAudited'] -= 1
            self.assertFalse(S.machine_pass(proof, D, D))

    def test_complete_report_and_missing_final_evidence(self):
        self.assertTrue(S.succeeded(report(), attribute_runner=A))
        for change in ('no-final', 'no-vector', 'no-roots', 'no-worker', 'other-bodies', 'bool-cell', 'source-difference'):
            proof = report()
            if change == 'no-final':
                proof['FinalLink'] = None
            elif change == 'no-vector':
                del proof['FinalLink']['Effects']['FinalRootVectorBindings']
            elif change == 'no-roots':
                proof['FinalLink']['TransferRoots'] = []
            elif change == 'no-worker':
                proof['FinalLink']['WorkerEffects']['FunctionEvidence'] = []
            elif change == 'other-bodies':
                proof['FinalLink']['UnchangedOtherSixGeneratedBodies'] = True
            elif change == 'bool-cell':
                proof['RequiredCellsSatisfied'] = False
            else:
                proof['Compilations'][-1]['SourceSha256'] = 'B' * 64
            with self.subTest(change=change):
                self.assertFalse(S.succeeded(proof, attribute_runner=A))
        for group in (1, 2):
            for key in ('Effects', 'WorkerEffects'):
                bad = report()
                leaf = bad['Lowerings'][group][key]
                if group == 1:
                    leaf['CleanMachine']['CompleteExecutableCensus'] = False
                else:
                    leaf['Effects']['StressCounterEvidence'] = None
                self.assertFalse(S.succeeded(bad, attribute_runner=A))
        for key, value in (('StressFamiliesActivated', False), ('StressFamiliesActivated', 1),
                ('StressCounterEvidence', None), ('CompilerImports', [])):
            proof = stress(True)
            proof['Effects'][key] = value
            self.assertFalse(S.stress_pass(A, proof, D, D, raw=True))
        bad = report()
        bad['IRDefinitionSurface']['Definitions'].pop()
        self.assertFalse(S.succeeded(bad, attribute_runner=A))

    def test_failure_before_throwing_hook_and_independent_retry(self):
        suite = NS(report=report(), _started=True)
        observed = []
        def hook(error):
            observed.append(suite.report['Status'])
            self.assertTrue(all(suite.report[name] is False for name in S.PHASES))
            raise OSError('hook')
        def persist(value):
            observed.append(value.report['Status'])
            if len(observed) == 2:
                raise OSError('first write')
        suite._failure = hook
        suite.modules = dict(controls=NS(persist_failure=Mock(side_effect=persist)))
        S.revoke_failure(suite, ValueError('primary'))
        self.assertEqual(observed, ['FAIL', 'FAIL', 'FAIL'])
        self.assertEqual(suite.report['PrimaryError'], 'ValueError: primary')
        self.assertEqual(len(suite.report['ClosingErrors']), 2)
        self.assertTrue(all(suite.report[name] is False for name in S.PHASES))
        self.assertEqual(suite.modules['controls'].persist_failure.call_count, 2)

    def test_finish_missing_phase_never_promotes(self):
        class Base:
            def __init__(self, *args):
                self.report = dict(PrimaryError=None, Error=None, ClosingErrors=[])
                self._started = True
                self._finished = False
                self.commands = report()['Commands']
                self.modules = dict(controls=NS(persist_failure=Mock()), attribute_runner=A)
            def _failure(self, error):
                self.report['Error'] = str(error)
        suite = S.suite_type(Base)(None, None, None, None)
        result = suite.finish()
        self.assertEqual(result['Status'], 'FAIL')
        self.assertFalse(result['FinalExecutableValidated'])
        suite.modules['controls'].persist_failure.assert_called_once_with(suite)
        with self.assertRaises(ValueError):
            suite.finish()

    def test_finish_late_closure_revokes_written_pass(self):
        class Base:
            def __init__(self, *args):
                self.report = report()
                self._started, self._finished = True, False
                self.commands = self.report['Commands']
                self.expected = {'commands.json': D}
                self.saved = []
                self.modules = dict(controls=NS(persist_failure=Mock()), attribute_runner=A)
                self.watch = NS(hashes={}, close=Mock(side_effect=[None, OSError('late close')]))
                self.admitted = NS(identity=Mock())
            def _failure(self, error):
                pass
            def verify_objects(self):
                pass
            def _verify_outputs(self):
                pass
            def _save(self, name, value):
                self.saved.append((name, copy.deepcopy(value)))
        suite = S.suite_type(Base)(None, None, None, None)
        suite.report = report()
        suite._policy_done = True
        value = suite.finish()
        self.assertEqual(suite.saved[0][1]['Status'], S.PASS)
        self.assertEqual(value['Status'], 'FAIL')
        suite.modules['controls'].persist_failure.assert_called_once_with(suite)
        self.assertTrue(all(value[name] is False for name in S.PHASES))

    def test_stdout_flush_failure_is_failure_after_success(self):
        suite = NS(report=report(), _started=True, _failure=Mock(),
            modules=dict(controls=NS(persist_failure=Mock())))
        argv = []
        for name in ('capture-build', 'capture-receipt-sha256', 'capture-artifacts-sha256',
                'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir'):
            argv.extend(('--' + name, 'synthetic'))
        class Output:
            def write(self, text):
                return len(text)
            def flush(self):
                raise OSError('stdout flush')
        with patch.object(S, 'prepare', return_value=(suite, dict(attribute_runner=A))), \
                patch.object(S, 'run', return_value=suite.report), patch('sys.stdout', Output()):
            self.assertEqual(S.main(argv), 1)
        self.assertEqual(suite.report['Status'], 'FAIL')
        suite.modules['controls'].persist_failure.assert_called_once_with(suite)

    def test_run_failure_does_not_retry_tools_or_promote(self):
        suite = NS(start=Mock(side_effect=OSError('start failed')), finish=Mock(return_value=dict(Status='FAIL')))
        value = S.run(suite, {})
        self.assertEqual(value['Status'], 'FAIL')
        suite.start.assert_called_once()
        suite.finish.assert_called_once()
        self.assertIsInstance(suite.finish.call_args.args[0], OSError)
        class PolicyRejected(ValueError):
            pass
        class AttributesRejected(ValueError):
            pass
        policy = NS(Rejected=PolicyRejected, inspect_stress=Mock())
        attributes = NS(Rejected=AttributesRejected)
        raw_suite = NS(modules=dict(policy=policy, attributes=attributes))
        for rejection in (PolicyRejected('policy'), AttributesRejected('attributes')):
            with self.subTest(rejection=type(rejection).__name__):
                policy.inspect_stress.reset_mock()
                policy.inspect_stress.side_effect = rejection
                S.require_raw_stress_rejected(raw_suite, 'image', 'core', b'disassembly')
                policy.inspect_stress.assert_called_once_with('image', 'core', b'disassembly',
                    attributes, supported=True)
        unrelated = ValueError('unrelated parser failure')
        policy.inspect_stress.side_effect = unrelated
        with self.assertRaises(ValueError) as caught:
            S.require_raw_stress_rejected(raw_suite, 'image', 'core', b'disassembly')
        self.assertIs(caught.exception, unrelated)
        policy.inspect_stress.side_effect = None
        policy.inspect_stress.return_value = dict(Status='unexpected clean acceptance')
        with self.assertRaisesRegex(ValueError, 'same clean predicate rejects actual raw stress effects'):
            S.require_raw_stress_rejected(raw_suite, 'image', 'core', b'disassembly')

    def test_source_definition_authority_and_api_names(self):
        policy_path = HERE / 'policy.py'
        policy = load(policy_path, BUFFERS[policy_path], '_port_policy_pure_api')
        self.assertEqual(tuple(policy.RAW_FLAGS), S.RAW_FLAGS)
        self.assertEqual(tuple(policy.COUNTER_FLAGS), S.COUNTER_FLAGS)
        self.assertTrue(policy.require_effective_options(flags() + S.policy_flags(True), supported=True)['EffectiveOptionsVerified'])
        for name in ('inspect_ir_definitions', 'stress_source', 'inspect_lowered', 'inspect_stress', 'inspect_final'):
            self.assertTrue(callable(getattr(policy, name)))
        with self.assertRaises(policy.Rejected):
            policy.inspect_ir_definitions({})
        self.assertEqual(len(S.PUBLIC_FUNCTIONS), 29)
        self.assertEqual(len(S.LOCAL_FUNCTIONS), 20)
        self.assertEqual(set(S.PUBLIC_FUNCTIONS), set(policy.RUNTIME + policy.BOOT + policy.EXCEPTION))
        self.assertEqual(set(S.LOCAL_FUNCTIONS), set(policy.LOCAL))
        self.assertFalse(S.succeeded(dict(Status=S.PASS), attribute_runner=A))
        actual_style = (b'fiber_port_runtime_memory_barrier T 0 \r\n'
            b'fiber_port_storage_cohort_arm_cm3_v1_r0 D 0 \r\n')
        expected = [dict(Name='fiber_port_runtime_memory_barrier', Kind='T', Value=0, Size=None),
            dict(Name='fiber_port_storage_cohort_arm_cm3_v1_r0', Kind='D', Value=0, Size=None)]
        self.assertEqual(S.parse_ir_definitions(actual_style), expected)
        self.assertEqual(S.parse_ir_definitions(actual_style.replace(b' \r\n', b'\t \n')), expected)
        self.assertEqual(S.parse_ir_definitions(b'raw_symbol t a 10 \t\r\n'),
            [dict(Name='raw_symbol', Kind='t', Value=10, Size=16)])
        for malformed in (b'name T 0 garbage \n', b'name T -1 \n', b'name T G \n',
                b' name T 0 \n', b'name  T 0 \n', b'name T 0 \n\n', b'name T 0 \x00\n'):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                S.parse_ir_definitions(malformed)


BUFFERS = {}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if (output.exists() or output.is_relative_to(ROOT) or ROOT.is_relative_to(output)
            or not output.is_relative_to(Path(tempfile.gettempdir()).resolve())):
        parser.error('fresh external TEMP output required')
    result_report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_CM3_PORT_POLICY_RUNNER_CONTROLS_ONLY',
        ExpectedTestMethods=EXPECTED_METHODS, Tests=0, Errors=0, Failures=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ActualCompilerExecuted=False,
        ActualELFTested=False, TargetExecuted=False, FullABIProof=False, CellContractSatisfied=False,
        GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
    paths = {Path(__file__).resolve(), SUBJECT}
    subject_raw = SUBJECT.read_bytes()
    global S, A, P
    S = load(SUBJECT, subject_raw, '_port_policy_runner_under_test')
    paths.update(ROOT / relative for relative, expected in S.PINS.values())
    try:
        if sys.flags.optimize:
            raise ValueError('unoptimized host Python required')
        BUFFERS.update({path: path.read_bytes() for path in sorted(paths)})
        if BUFFERS[SUBJECT] != subject_raw:
            raise ValueError('runner changed during initial capture')
        result_report['SourceHashes'] = {str(path): sha(raw) for path, raw in BUFFERS.items()}
        for relative, expected in S.PINS.values():
            if sha(BUFFERS[ROOT / relative]) != expected:
                raise ValueError('helper pin: ' + relative)
        helper = ROOT / S.PINS['attribute_runner'][0]
        A = load(helper, BUFFERS[helper], '_port_policy_frozen_attribute_results')
        P = load(HERE / 'policy.py', BUFFERS[HERE / 'policy.py'], '_port_policy_real_pure_api')
        with patch('subprocess.Popen', side_effect=AssertionError('pure controls cannot launch processes')), \
                patch('os.system', side_effect=AssertionError('pure controls cannot execute tools')):
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError('exact implemented test count')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        result_report.update(Tests=result.testsRun, Errors=len(result.errors), Failures=len(result.failures),
            Skipped=len(result.skipped), Details=[dict(Test=str(test), Error=error)
                for test, error in result.errors + result.failures])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            result_report['Status'] = 'PASS'
    except Exception as error:
        result_report.update(Status='FAIL', Error=type(error).__name__ + ': ' + str(error))
    finally:
        for path, raw in BUFFERS.items():
            try:
                if path.read_bytes() != raw:
                    result_report['SourceDrift'].append(str(path))
            except OSError:
                result_report['SourceDrift'].append(str(path))
        result_report['SourceClosureVerified'] = len(BUFFERS) == len(paths) and not result_report['SourceDrift']
        result_report['ClosingFilesVerified'] = len(BUFFERS) - len(result_report['SourceDrift'])
        if not result_report['SourceClosureVerified']:
            result_report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    target = output / 'results.json'
    target.write_bytes((json.dumps(result_report, sort_keys=True, indent=2) + '\n').encode('ascii'))
    print('Receipt:', target, sha(target.read_bytes()), flush=True)
    return 0 if result_report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
