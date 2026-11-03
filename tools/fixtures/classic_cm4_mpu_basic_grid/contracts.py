"""Request-bound receipt grammar, independent of emitted subject fingerprints."""
from __future__ import annotations
from copy import deepcopy
import re
from cm4_mpu_basic_engine import GRID, MODES, basic_terminal, pilot, need
from cm4_mpu_basic_builds import EXPECTED, REF_REASONS

KEYS = tuple((c, case, opt, lto, archive) for c, opt, lto, archive in GRID for case in (0, 1, 2))
REFERENCE_KEYS = tuple((opt, lto, archive) for opt, lto in MODES for archive in (False, True))
SUBJECT_KEYS = tuple((c, opt, lto, archive, name, reason) for c, opt, lto, archive in
    (('context', 'O2', False, False), ('fiber', 'Os', True, True)) for name, reason in EXPECTED.items())
REFERENCE_CONTROL_KEYS = tuple((opt, lto, archive, name, reason) for opt, lto, archive in
    (('O2', False, False), ('Os', True, True)) for name, reason in REF_REASONS.items())


def typed(value, kind, reason):
    need(type(value) is kind, reason)
    return value


def sha(value):
    return type(value) is str and re.fullmatch(r'[0-9A-F]{64}', value) is not None


def key(row):
    need(type(row) is dict, 'row-object')
    return (typed(row.get('Consumer'), str, 'consumer-type'), typed(row.get('Case'), int, 'case-type'),
            typed(row.get('Optimization'), str, 'opt-type'), typed(row.get('LTO'), bool, 'lto-type'),
            typed(row.get('Archive'), bool, 'archive-type'))


def refkey(row):
    return (typed(row.get('Optimization'), str, 'ref-opt-type'), typed(row.get('LTO'), bool, 'ref-lto-type'),
            typed(row.get('Archive'), bool, 'ref-archive-type'))


def validate(report, execute):
    typed(execute, bool, 'request-type')
    need(type(report) is dict, 'receipt-object')
    need('Error' in report and report['Error'] is None, 'non-null-error')
    need(type(report.get('Verdict')) is str and report['Verdict'] == ('BASIC-GRID-PASS' if execute else 'COMPILE-PREFLIGHT-PASS'), 'verdict')
    for field, expected in (('CompleteSuite', execute), ('CompileOnly', not execute),
                            ('ArtifactsVerifiedBeforePass', True), ('ReferenceExecuted', False), ('NewFinalReferenceParity', False)):
        need(type(report.get(field)) is bool and report[field] is expected, field)
    need(report.get('Execution') == ('BOUNDED_BASIC_GRID' if execute else 'NOT_RUN') and type(report.get('Execution')) is str, 'execution-mode')
    need(type(report.get('InputDrift')) is list and not report['InputDrift'], 'input-drift')
    for field, count in (('Rows', 48), ('References', 8), ('Associations', 48), ('CompiledControls', 32), ('ReferenceControls', 8)):
        need(type(report.get(field)) is list and len(report[field]) == count, field + '-count')
    need(tuple(key(r) for r in report['Rows']) == KEYS, 'ordered-48-grid')
    need(tuple(refkey(r) for r in report['References']) == REFERENCE_KEYS, 'ordered-8-references')
    for row in report['References']:
        need(row.get('Status') == 'LINKED' and row.get('Executed') is False and type(row.get('Elf')) is str and sha(row.get('ElfSha256')), 'reference-state')
    refs = {refkey(r): r for r in report['References']}
    for row, assoc in zip(report['Rows'], report['Associations']):
        need(sha(row.get('ElfSha256')) and type(row.get('Elf')) is str, 'subject-identity')
        reference = refs[(row['Optimization'], row['LTO'], row['Archive'])]
        need(key(assoc) == key(row) and assoc.get('Status') == 'PASS' and assoc.get('Executed') is False and
             type(assoc.get('Checks')) is int and assoc['Checks'] == 3 and sha(assoc.get('BlockSha256')) and
             sha(assoc.get('MechanismEvidenceSha256')) and
             (assoc.get('SubjectElf'), assoc.get('SubjectSha256')) == (row['Elf'], row['ElfSha256']) and
             (assoc.get('ReferenceElf'), assoc.get('ReferenceSha256')) == (reference['Elf'], reference['ElfSha256']), 'hash-bound-association')
    for row, expected in zip(report['CompiledControls'], SUBJECT_KEYS):
        c, opt, lto, archive, mutation, reason = expected
        need(key(row) == (c, 1 if mutation == 'no-slot-store' else 2 if mutation == 'no-peer-load' else 0, opt, lto, archive) and
             row.get('Mutation') == mutation and row.get('Status') == 'CODEGEN_CONTROL_REJECTED' and
             row.get('Executed') is False and sha(row.get('ElfSha256')) and
             row.get('ExpectedCodegenRejection') == row.get('ActualCodegenRejection') == reason, 'subject-control')
    for row, expected in zip(report['ReferenceControls'], REFERENCE_CONTROL_KEYS):
        opt, lto, archive, mutation, reason = expected
        need(refkey(row) == (opt, lto, archive) and row.get('Mutation') == mutation and row.get('Status') == 'REJECTED' and
             row.get('Executed') is False and sha(row.get('ElfSha256')) and
             row.get('ExpectedCodegenRejection') == row.get('ActualCodegenRejection') == reason, 'reference-control')
    model = report.get('ModelProbe')
    need(type(model) is dict and model.get('Name') == 'model' and key(model) == ('context', 0, 'O2', False, False), 'model-identity')
    need(type(model.get('Elf')) is str and bool(model['Elf'].strip()) and sha(model.get('ElfSha256')), 'model-elf-identity')
    binding = report.get('ModelArtifactBinding')
    need(type(binding) is dict and binding.get('Verified') is True and
         binding.get('ArtifactRelative') == 'model/runtime.elf' and
         (binding.get('Elf'), binding.get('ElfSha256'), binding.get('ManifestEntrySha256')) ==
         (model['Elf'], model['ElfSha256'], model['ElfSha256']), 'model-artifact-binding')
    for row in [model, *report['Rows']]:
        need(type(row.get('Executed')) is bool and row['Executed'] is execute and
             type(row.get('Status')) is str and row['Status'] == ('PASS' if execute else 'COMPILED'), 'row-execution-state')
        if execute:
            need(type(row.get('Actual')) is dict, 'missing-execution')
            if row is model:
                facts = pilot.model_terminal(row['Actual'])
                need(report.get('ObservedModel') == facts and all(type(v) is int for v in report['ObservedModel'].values()), 'observed-model')
            else:
                need(basic_terminal(row['Actual'], row['Consumer'], row['Case'], row['Audit']['Addresses']), 'exact-terminal')
        else:
            need('Actual' not in row, 'compile-has-observation')
    if not execute:
        need('ObservedModel' not in report, 'compile-observed-model')


def synthetic(execute):
    """Orchestration controls only: these records are never target observations."""
    h = 'A' * 64
    report = dict(Error=None, Verdict='BASIC-GRID-PASS' if execute else 'COMPILE-PREFLIGHT-PASS', CompleteSuite=execute,
        CompileOnly=not execute, ArtifactsVerifiedBeforePass=True, ReferenceExecuted=False, NewFinalReferenceParity=False,
        Execution='BOUNDED_BASIC_GRID' if execute else 'NOT_RUN', InputDrift=[], Rows=[], References=[], Associations=[],
        CompiledControls=[], ReferenceControls=[])
    def row(c, case, opt, lto, archive):
        return dict(Consumer=c, Case=case, Optimization=opt, LTO=lto, Archive=archive, Elf='synthetic/' + c + str(case) + opt + str(lto) + str(archive), ElfSha256=h, Executed=False)
    for c, case, opt, lto, archive in KEYS:
        r = row(c, case, opt, lto, archive)
        r.update(Status='COMPILED', Audit=dict(Addresses={'return': 0x1010, 'slot': 0x1020, 'peer': 0x1030}))
        report['Rows'].append(r)
    for opt, lto, archive in REFERENCE_KEYS:
        report['References'].append(dict(Optimization=opt, LTO=lto, Archive=archive, Elf='ref/' + opt + str(lto) + str(archive), ElfSha256=h, Status='LINKED', Executed=False))
    refs = {refkey(r): r for r in report['References']}
    for r in report['Rows']:
        reference = refs[refkey(r)]
        a = {k: r[k] for k in ('Consumer', 'Case', 'Optimization', 'LTO', 'Archive')}
        a.update(Status='PASS', Executed=False, Checks=3, BlockSha256=h, MechanismEvidenceSha256=h,
                 SubjectElf=r['Elf'], SubjectSha256=h, ReferenceElf=reference['Elf'], ReferenceSha256=h)
        report['Associations'].append(a)
    for c, opt, lto, archive, mutation, reason in SUBJECT_KEYS:
        r = row(c, 1 if mutation == 'no-slot-store' else 2 if mutation == 'no-peer-load' else 0, opt, lto, archive)
        r.update(Mutation=mutation, Status='CODEGEN_CONTROL_REJECTED', ExpectedCodegenRejection=reason, ActualCodegenRejection=reason)
        report['CompiledControls'].append(r)
    for opt, lto, archive, mutation, reason in REFERENCE_CONTROL_KEYS:
        report['ReferenceControls'].append(dict(Optimization=opt, LTO=lto, Archive=archive, Mutation=mutation,
            Status='REJECTED', Executed=False, ElfSha256=h, ExpectedCodegenRejection=reason, ActualCodegenRejection=reason))
    model = row('context', 0, 'O2', False, False)
    model.update(Name='model', Status='COMPILED')
    report['ModelProbe'] = model
    report['ModelArtifactBinding'] = dict(Verified=True, ArtifactRelative='model/runtime.elf',
        Elf=model['Elf'], ElfSha256=h, ManifestEntrySha256=h)
    if execute:
        for r in report['Rows']:
            label = 'CONTEXT' if r['Consumer'] == 'context' else 'FIBERV1'
            if r['Case'] == 0:
                line = ('RETURN:CM4-MPU:CODE=00000052:IPSR=0000000B:PC=00001010:PSP=20002FC0:XPSR=01000000:CALLS=00000020:SELF=00000001:CROSS=0000001E\n'
                    'STRESS:CM4-MPU:R4-R11=0000000F:SP=0000000F:COOKIES=0000001E:PUBLIC=00000010:DIRECT=0000000F')
            else:
                line = ('FAULT:CM4-MPU:IPSR=00000004:EXC=FFFFFFFD:CFSR=00000082:HFSR=00000000:MMFAR=' +
                    ('20000000:PC=00001020' if r['Case'] == 1 else '20004080:PC=00001030') + ':PSP=20002FC0:XPSR=01000000')
            r.update(Executed=True, Status='PASS', Actual=dict(Exit=0, TimedOut=False, Stdout='', Stderr=line + '\nPASS:CM4-MPU:' + label + '\n'))
        model.update(Executed=True, Status='PASS', Actual=dict(Exit=0, TimedOut=False, Stdout='',
            Stderr='MODEL:CM4-MPU:CPUID=410FC241:MPU_TYPE=00000800:NVIC_MASK=000000FF:MVFR0=10110021:MPU_CTRL=00000000\nPASS:CM4-MPU:MODEL\n'))
        report['ObservedModel'] = pilot.model_terminal(model['Actual'])
    return report


def closing_controls():
    controls = []
    def test(name, receipt, execute, expected):
        try:
            validate(receipt, execute)
            accepted = True
        except (RuntimeError, KeyError, TypeError):
            accepted = False
        need(accepted is expected, 'Closing control: ' + name)
        controls.append(dict(Name=name, Execute=execute, Expected=expected, Receipt=receipt))
    for execute in (False, True):
        prefix = 'execute-' if execute else 'compile-'
        good = synthetic(execute)
        test(prefix + 'positive', good, execute, True)
        for field, value in (('Verdict', True), ('Execution', 'PASS'), ('CompleteSuite', not execute),
                ('CompleteSuite', int(execute)), ('ArtifactsVerifiedBeforePass', False), ('InputDrift', ['changed'])):
            mutant = deepcopy(good); mutant[field] = value
            test(prefix + field + '-' + repr(value), mutant, execute, False)
        for name, action in (
            ('missing-row', lambda x: x['Rows'].pop()),
            ('duplicate-row', lambda x: x['Rows'].__setitem__(1, deepcopy(x['Rows'][0]))),
            ('wrong-order', lambda x: x['Rows'].reverse()),
            ('case-bool', lambda x: x['Rows'][0].__setitem__('Case', False)),
            ('lto-int', lambda x: x['Rows'][0].__setitem__('LTO', 0)),
            ('row-status', lambda x: x['Rows'][0].__setitem__('Status', 'COMPILED' if execute else 'PASS')),
            ('row-executed-type', lambda x: x['Rows'][0].__setitem__('Executed', int(execute))),
            ('missing-model', lambda x: x.pop('ModelProbe')),
            ('missing-ref', lambda x: x['References'].pop()),
            ('ref-key', lambda x: x['References'][0].__setitem__('LTO', True)),
            ('ref-executed', lambda x: x['References'][0].__setitem__('Executed', True)),
            ('assoc-hash', lambda x: x['Associations'][0].__setitem__('ReferenceSha256', 'B' * 64)),
            ('assoc-case', lambda x: x['Associations'][0].__setitem__('Case', 1)),
            ('assoc-check-bool', lambda x: x['Associations'][0].__setitem__('Checks', True)),
            ('subject-control-reason', lambda x: x['CompiledControls'][0].__setitem__('ActualCodegenRejection', 'incidental')),
            ('reference-control-reason', lambda x: x['ReferenceControls'][0].__setitem__('ActualCodegenRejection', 'incidental'))):
            mutant = deepcopy(good); action(mutant)
            test(prefix + name, mutant, execute, False)
        if execute:
            for index in range(48):
                mutant = deepcopy(good); mutant['Rows'][index].update(Executed=False, Status='COMPILED'); mutant['Rows'][index].pop('Actual')
                test(prefix + 'skipped-' + str(index), mutant, execute, False)
            for name, action in (
                ('model-skipped', lambda x: x['ModelProbe'].update(Executed=False, Status='COMPILED')),
                ('bool-exit', lambda x: x['Rows'][0]['Actual'].__setitem__('Exit', False)),
                ('split-channel', lambda x: x['Rows'][0]['Actual'].update(Stdout=x['Rows'][0]['Actual']['Stderr'], Stderr='')),
                ('timeout', lambda x: x['Rows'][0]['Actual'].__setitem__('TimedOut', True)),
                ('wrong-model', lambda x: x['ObservedModel'].__setitem__('MPU_TYPE', 0x1000))):
                mutant = deepcopy(good); action(mutant); test(prefix + name, mutant, execute, False)
        else:
            mutant = deepcopy(good); mutant['Rows'][0]['Actual'] = {}
            test(prefix + 'invented-observation', mutant, execute, False)
    need(len(controls) == 100, 'Original 100 closing controls changed')
    # Keep all original IDs/order, then append the three reviewed contract gaps.
    for execute in (False, True):
        prefix = 'execute-' if execute else 'compile-'
        good = synthetic(execute)
        for name, value in (('error-empty', ''), ('error-zero', 0), ('error-false', False), ('error-text', 'SYNTHETIC_FAILURE')):
            mutant = deepcopy(good); mutant['Error'] = value
            test(prefix + name, mutant, execute, False)
        mutant = deepcopy(good); mutant.pop('Error')
        test(prefix + 'error-missing', mutant, execute, False)
        for name, action in (
            ('model-missing-elf', lambda x: x['ModelProbe'].pop('Elf')),
            ('model-missing-hash', lambda x: x['ModelProbe'].pop('ElfSha256')),
            ('model-missing-identity', lambda x: (x['ModelProbe'].pop('Elf'), x['ModelProbe'].pop('ElfSha256'))),
            ('model-elf-bool', lambda x: x['ModelProbe'].__setitem__('Elf', False)),
            ('model-elf-empty', lambda x: x['ModelProbe'].__setitem__('Elf', '')),
            ('model-hash-bool', lambda x: x['ModelProbe'].__setitem__('ElfSha256', True)),
            ('model-hash-empty', lambda x: x['ModelProbe'].__setitem__('ElfSha256', '')),
            ('model-hash-malformed', lambda x: x['ModelProbe'].__setitem__('ElfSha256', 'G' * 64)),
            ('model-binding-missing', lambda x: x.pop('ModelArtifactBinding')),
            ('model-binding-hash', lambda x: x['ModelArtifactBinding'].__setitem__('ManifestEntrySha256', 'B' * 64)),
            ('model-binding-verified-type', lambda x: x['ModelArtifactBinding'].__setitem__('Verified', 1))):
            mutant = deepcopy(good); action(mutant); test(prefix + name, mutant, execute, False)
    need(len(controls) == 132 and sum(c['Expected'] for c in controls) == 2, 'Literal 132 closing controls')
    return dict(Controls=controls, Scope='Synthetic orchestration controls, never target executions')
