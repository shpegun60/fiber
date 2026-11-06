"""One admitted Os build session, 134 commands, no final-reader qualification.

All phase/helper buffers are pinned before current-capture admission. The ABI
entrypoint contributes authenticated metadata only; its prepare/run/replay and
the frozen O2 drivers are not invoked. Generated machine evidence is collected
for a future single immutable reader, never promoted into semantic proof here.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import stat
import sys
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METADATA = ('tools/fixtures/cm3_os_lto_final_cell/abi_attempt.py',
            '18237999981DAF689C4D297CC93A9CE574804F1C65578FD4A9E91CD715440279')
ARGUMENTS = ('native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
    'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
    'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir')
STATUS = 'BUILT-PENDING-READER'
SCOPE = 'CURRENT_CM3_OS_LTO_134_COMMAND_BUILD_ONLY_PENDING_READER'
SOURCE = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
PHASES = (('ABIControls', 'abi_controls', 0, 41), ('Isolation', 'isolation', 41, 53),
          ('CommonAttributes', 'attributes_phase', 53, 98), ('PortPolicy', 'port_policy', 98, 134))
PINS = {
    'guard': ('tools/fixtures/cm3_os_lto_final_cell/batch_guard.py',
        '1281084AF70A6AADEA9590E4839311D3F3FA813B17ED06EEE5CD402F4E69BAFD'),
    'isolation': ('tools/fixtures/cm3_os_lto_final_cell/isolation.py',
        '3838848CF4421656ECF0DAFBDA03AE72FC4A2EFD5083C31202A592CBA16D9F65'),
    'attributes_phase': ('tools/fixtures/cm3_os_lto_final_cell/attributes_phase.py',
        'CAD8817F486DE3E3B945C54CC8AAF2EACCC185A85134BEE8D343835E3F07DF3C'),
    'port_policy': ('tools/fixtures/cm3_os_lto_final_cell/port_policy_phase.py',
        '371821947E1F14E0C0DEBC5561EFD3EF8B539B20C9B00F288A8534143D29EB80'),
    'ownership': ('tools/fixtures/cm0_final_cell/ownership.py',
        'F9971A707BC30FFA7AF0B816570ED476B2965F24369BC7A747C18784E5B0A552'),
    'attributes': ('tools/fixtures/cm3_lto_attributes/attributes.py',
        '93275A5903A67CB2DAEABB76BEF1431B052878BB478455E54343DB20881E83C0'),
    'attribute_runner': ('tools/fixtures/cm3_lto_attributes/runner.py',
        '9C99D38EACC8F3E3B2B63F343CA79555A66264AC76A3CA11957D2BEB0745987A'),
    'policy': ('tools/fixtures/cm3_lto_port_policy/policy.py',
        '8FC3AD729BF8903D716E34579700FC22D417040156EFCF0B434D2C43D75F0CA0'),
    'workers': ('tools/fixtures/cm3_lto_port_policy/runner.py',
        'E06E55AC26B3828EDA54333DC7D5E0982DCC791694A2E9FE64E2A31C3BBE9AAB'),
}
BUILT = ('ABIControlsBuilt', 'IsolationBuilt', 'CommonAttributesBuilt', 'PortPolicyBuilt')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'CurrentSlotIsolationProven', 'WholeSlotAccessIsolation', 'CanonicalProtocolValidated',
    'FinalRootRelocationProof', 'CommonAttributePolicyProven', 'SelectedPortAttributePolicyProven',
    'FinalReferenceParity', 'CompleteObjectProof', 'PolicyEquivalence', 'SourceIRProof',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'KernelRuntimeProof',
    'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'ArchiveQualification', 'GlobalFreezeQualified',
    'RequiredCellSatisfied', 'CellContractSatisfied', 'ProducerCompilersReexecuted',
    'ImmutableInputsConsumed', 'FinalReaderExecuted', 'PositiveLinkRevalidated',
    'RuntimeProviderBindingsValidated', 'FinalLinkContractValidated', 'CpuFreeCommonValidated',
    'ProtectedEffectsValidated', 'AnnotationControlsValidated', 'DispatcherStressValidated',
    'ActualLtransOptionsValidated', 'GeneralRegistersOnlyEffectProved')


def need(value, message):
    if not value:
        raise ValueError('cm3-os-lto-batch-attempt: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def _pins(rows):
    need(type(rows) is dict and rows, 'nonempty source-pin registry')
    for name, row in rows.items():
        need(type(name) is str and type(row) in (tuple, list) and len(row) == 2
             and type(row[0]) is str and row[0].startswith('tools/')
             and all(part not in ('', '.', '..') for part in row[0].split('/'))
             and '\\' not in row[0] and ':' not in row[0]
             and type(row[1]) is str and re.fullmatch('[0-9A-F]{64}', row[1]) is not None,
             'missing/unfrozen source pin: ' + str(name))


def prepare(args):
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize,
         'fresh isolated unoptimized -I -S -B interpreter')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules), 'fresh parser state')
    _pins(PINS)
    buffers = {}
    def enroll(relative, digest):
        path = ROOT / relative
        raw = buffers.get(path)
        if raw is None:
            raw = path.read_bytes()
        need(sha(raw) == digest, 'fixed source buffer: ' + relative)
        buffers[path] = raw
        return path, raw
    path, raw = enroll(*METADATA)
    metadata = load('_os_batch_metadata', path, raw)
    path, raw = enroll('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata.RUNNER_SHA256)
    runner = load('_os_batch_runner', path, raw)
    need(metadata.ARGUMENTS == ARGUMENTS and set(metadata.LEAF_PINS) == {'declarations', 'abi_controls'},
         'fixed ABI metadata interface')
    helpers_plan = {}
    for registry in (metadata.PINS, metadata.LEAF_PINS, PINS):
        _pins(registry)
        for name, row in registry.items():
            need(name not in helpers_plan or helpers_plan[name] == row, 'conflicting helper role/' + name)
            helpers_plan[name] = row
    for registry in (runner.PINS, helpers_plan):
        _pins(registry)
        for row in registry.values():
            enroll(*row)
    for documents in (runner.DOCUMENTS, metadata.DOCUMENTS):
        for row in documents.items():
            enroll(*row)
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    # There must be no newly discovered helper enrollment after this call.
    modules = {name: load('_os_batch_admission_' + name, ROOT / row[0], buffers[ROOT / row[0]])
               for name, row in runner.PINS.items()}
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'], extra_sources=buffers)(args)
    environment = dict(Witness=witness, Modules=modules)
    def read_bytes(path):
        need(path in buffers, 'helper read outside opening authenticated buffers: ' + str(path))
        return buffers[path]
    with patch.object(Path, 'read_bytes', read_bytes):
        helpers = {name: load('_os_batch_helper_' + name, ROOT / row[0], buffers[ROOT / row[0]])
                   for name, row in helpers_plan.items()}
    suite = helpers['session'].suite_type(helpers['utility'], helpers['lto'])(environment, helpers, buffers)
    suite.report = dict(runner.base_report(witness), **suite.report)
    suite.report.update(Scope=SCOPE, FinalReaderRequired=True, **dict.fromkeys(NONCLAIMS, False))
    suite.report['OpeningSourceBuffers'] = {str(path): sha(raw) for path, raw in sorted(buffers.items())}
    return runner, environment, helpers, suite


def _commands(report, helpers):
    rows, plan = report.get('Commands'), helpers['recipes'].batch_plan()
    need(type(rows) is list and len(rows) == len(plan['Commands']) == 134, 'complete 134-command journal')
    for index, (row, wanted) in enumerate(zip(rows, plan['Commands'])):
        need(type(row) is dict and row.get('Label') == wanted['Label'] and row.get('State') == 'TERMINAL'
             and row.get('TimedOut') is False and type(row.get('Exit')) is int
             and type(row.get('ExpectedExit')) is int and row['Exit'] == row['ExpectedExit'] == wanted['ExpectedExit']
             and row.get('Status') == ('EXPECTED-NONZERO' if wanted['ExpectedExit'] else 'PASS')
             and type(row.get('JournalErrors', [])) is list and row.get('JournalErrors', []) == []
             and row.get('Error') is None and type(row.get('Argv')) is list and row['Argv']
             and all(type(value) is str for value in row['Argv'])
             and type(row.get('Seconds')) in (int, float) and math.isfinite(row['Seconds']) and row['Seconds'] >= 0,
             'exact typed terminal recipe/' + str(index))
    need(sum(row['ExpectedExit'] for row in rows) == 8, 'five link and three compile intended rejections')
    expected = [dict(Name=name, First=first, Stop=stop, Commands=stop-first) for name, _, first, stop in PHASES]
    phases = report.get('Phases')
    need(type(phases) is list and len(phases) == 4 and phases == expected
         and all(type(row) is dict and set(row) == {'Name', 'First', 'Stop', 'Commands'}
             and all(type(row[key]) is int for key in ('First', 'Stop', 'Commands')) for row in phases),
         'four exact literal phase ranges')


def pending_reader(suite):
    """Capture explicit role bytes and complete leaf records, not a reader result."""
    report, roles = suite.report, []
    def add(component, role, path, expected=None):
        path = suite.api.checked_path(path)
        raw = suite.watch.read(path, expected)
        roles.append(dict(Component=component, Role=role, Path=str(path), Sha256=sha(raw)))
    abi = report['ABIControlsDeferredReader']
    need(abi.get('Status') == 'PENDING' and abi.get('ValidationDeferred') is True, 'ABI reader remains pending')
    for index, row in enumerate(abi['Inputs']):
        add('ABIControls', row.get('Role', 'Positive' + str(index)), row['Path'], row['Sha256'])
    add('ABIControls', 'ReproducedMap', abi['Map']['Path'], abi['Map']['Sha256'])
    probes = report['ABIProbes']
    need(type(probes) is dict and tuple(probes) == ('types.c', 'attributes.c', 'slot_read.c', 'slot_write.c', 'slot_address.c'),
         'exact five accepted/absent-slot probe records')
    for name, row in probes.items():
        for field in ('Source', 'Object', 'Preprocessed', 'DiscoveryDependencyFile', 'CompileDependencyFile'):
            if row.get(field) is not None:
                add('ABIControls', name + '/' + field, row[field])
    for component, key in (('Isolation', 'IsolationDeferredReader'), ('PortPolicy', 'PortPolicyDeferredReader')):
        record = report[key]
        need(record.get('Status') == 'PENDING' and record.get('ValidationDeferred') is True
             and type(record.get('Inputs')) is list and record['Inputs'], 'nonempty pending roles/' + component)
        for row in record['Inputs']:
            add(component, row['Role'], row['Path'], row['Sha256'])
    attributes = report['CommonAttributesDeferredReader']
    need(attributes.get('Status') == 'BUILT-PENDING-READER' and attributes.get('DeferredReaderRequired') is True
         and type(attributes.get('Lowerings')) is list and len(attributes['Lowerings']) == 6, 'six deferred hostile lowers')
    for lower in attributes['Lowerings']:
        need(type(lower.get('Roles')) is dict and lower['Roles'], 'nonempty generated hostile role set')
        for name, row in lower['Roles'].items():
            add('CommonAttributes', lower['Group'] + '/' + name, row['Path'], row['Sha256'])
    need(len({(row['Component'], row['Role']) for row in roles}) == len(roles), 'unique deferred role names')
    return dict(Status='PENDING', FinalReaderExecuted=False, OneImmutableReaderScopeRequired=True,
        InputRoleCount=len(roles), Inputs=roles,
        Obligations=['ABI provider/declaration and positive-image reproduction',
            'Original/isolated twins, slot protocols and generated common providers',
            'Six hostile aggregate/worker effects and Os saved-worker options',
            'Selected-port aggregate/final census, paired stress and transfer roots'],
        Components=dict(ABIControls=copy.deepcopy({key: report[key] for key in
            ('ABIControlsBuild', 'ABIControlsDeferredReader', 'PositiveAuthority', 'DeclaredProviders', 'ABIProbes', 'PreprocessedAttributes')}),
            Isolation=copy.deepcopy({key: report[key] for key in ('IsolationBuild', 'IsolationDeferredReader', 'IsolatedCommon', 'IsolatedLinkedObjects')}),
            CommonAttributes=copy.deepcopy(attributes),
            PortPolicy=copy.deepcopy({key: report[key] for key in ('PortPolicyBuild', 'PortPolicyDeferredReader',
                'PortPolicyCompilations', 'PortPolicyLowerings', 'PortPolicyFinalLink')})),
        Qualification=False, RequiredCellsSatisfied=0, ImmutableInputsConsumed=False)


def require_built(report, helpers):
    need(type(report) is dict and report.get('Status') == STATUS and report.get('Scope') == SCOPE
         and report.get('Profile') == 'CM3' and report.get('Mode') == 'Os-lto'
         and report.get('Linkage') == 'direct' and report.get('LTO') is True
         and report.get('Cohort') == COHORT and report.get('SourceInventorySha256') == SOURCE, 'bounded Os build disposition')
    _commands(report, helpers)
    for name in (*BUILT, 'FiveLinkControlsValidated', 'TypedDeclarationProbesValidated', 'NegativeLinkControlsExecuted',
                 'FinalReaderRequired', 'InputClosureVerified', 'OutputSealVerified'):
        need(report.get(name) is True, 'completed build fact/' + name)
    for name in NONCLAIMS:
        need(report.get(name) is False, 'unproved reader/semantic fact/' + name)
    for name, value in (('RequiredCellCount', 2774), ('RequiredCellsSatisfied', 0), ('ToolInvocations', 134)):
        need(type(report.get(name)) is int and report[name] == value, 'literal counter/' + name)
    need('Error' in report and report['Error'] is None and 'PrimaryError' in report and report['PrimaryError'] is None
         and type(report.get('ClosingErrors')) is list and report['ClosingErrors'] == [], 'exact clean error state')
    pending = report.get('PendingFinalReader')
    need(type(pending) is dict and pending.get('Status') == 'PENDING' and pending.get('FinalReaderExecuted') is False
         and pending.get('OneImmutableReaderScopeRequired') is True and type(pending.get('Inputs')) is list and pending['Inputs']
         and type(pending.get('Components')) is dict and set(pending['Components']) == {row[0] for row in PHASES}
         and all(type(row) is dict and row for row in pending['Components'].values())
         and pending.get('Qualification') is False and pending.get('ImmutableInputsConsumed') is False
         and type(pending.get('RequiredCellsSatisfied')) is int and pending['RequiredCellsSatisfied'] == 0,
         'complete explicit pending final reader')
    need(type(pending.get('InputRoleCount')) is int and pending['InputRoleCount'] == len(pending['Inputs'])
         and type(pending.get('Obligations')) is list and len(pending['Obligations']) == 4
         and all(type(value) is str and value for value in pending['Obligations']), 'literal pending role/obligation counts')
    names = set()
    for row in pending['Inputs']:
        need(type(row) is dict and set(row) == {'Component', 'Role', 'Path', 'Sha256'}
             and type(row['Component']) is str and row['Component'] in pending['Components']
             and type(row['Role']) is str and row['Role'] and type(row['Path']) is str
             and '\x00' not in row['Path'] and Path(row['Path']).is_absolute()
             and all(part not in ('.', '..') for part in Path(row['Path']).parts)
             and type(row['Sha256']) is str and re.fullmatch('[0-9A-F]{64}', row['Sha256']) is not None,
             'typed declared final-reader input role')
        key = row['Component'], row['Role']
        need(key not in names, 'duplicate pending reader role')
        names.add(key)
    need({row['Component'] for row in pending['Inputs']} == set(pending['Components']), 'roles for every phase')
    helpers['guard'].require_pending_catalog(report)


def recover_owned(runner, environment, suite, guard):
    """Keep frozen recovery, but guard every bounded destination write."""
    output = guard.require_owned_output(suite)
    original_write = Path.write_bytes
    def write(path, raw):
        need(guard.require_owned_output(suite) == output, 'same owned recovery root')
        need(path in (output / 'results.json', output / 'artifacts.json'), 'bounded recovery filename')
        try:
            info = path.lstat()
        except FileNotFoundError:
            info = None
        if info is not None:
            need(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_nlink == 1
                 and not getattr(info, 'st_file_attributes', 0) & 0x400, 'regular unaliased recovery destination')
        return original_write(path, raw)
    with patch.object(Path, 'write_bytes', write):
        runner.recover(environment, suite.report)


def revoke(runner, report, error):
    primary = report.get('PrimaryError') or report.get('Error') or type(error).__name__ + ': ' + str(error)
    report.update(Status='FAIL', PrimaryError=primary, Error=report.get('Error') or primary,
                  InputClosureVerified=False, OutputSealVerified=False, RequiredCellsSatisfied=0)
    report.update(**dict.fromkeys((*BUILT, *NONCLAIMS), False))
    try:
        runner.revoke(report, error)
    finally:
        report.update(Status='FAIL', PrimaryError=primary, RequiredCellsSatisfied=0,
                      InputClosureVerified=False, OutputSealVerified=False, **dict.fromkeys((*BUILT, *NONCLAIMS), False))


def run(runner, environment, helpers, suite):
    witness = environment['Witness']
    try:
        suite.start()
        for name, key, first, stop in PHASES:
            need(len(suite.commands) == first and suite.report.get('Status') == 'FAIL', 'one ordered build/' + name)
            helpers[key].build(suite, helpers)
            need(len(suite.commands) == stop and suite.report.get('Status') == 'FAIL', 'unpromoted complete build/' + name)
            need(all(suite.report.get(flag) is False for flag in NONCLAIMS), 'no reader/semantic promotion/' + name)
        suite.report['NegativeLinkControlsExecuted'] = True
        suite.report['PendingFinalReader'] = pending_reader(suite)
        suite.verify_objects()
        witness.close()
        suite._verify_outputs()
        suite.report.update(Status=STATUS, Commands=suite.commands, CommandsSha256=suite.expected['commands.json'],
            ToolInvocations=len(suite.commands), CompilerInvocations=sum(row['Argv'][0] == str(suite.tools['gcc']) for row in suite.commands),
            InputHashes={str(path): digest for path, digest in sorted(witness.watch.hashes.items())},
            InputPhysicalIdentities={str(path): list(witness._physical(path)) for path in sorted(witness.watch.hashes)},
            ClosingFilesVerified=len(witness.watch.hashes), InputClosureVerified=True, OutputSealVerified=True)
        require_built(suite.report, helpers)
        suite._save('results.json', suite.report)
        suite._save('artifacts.json', dict(Artifacts={name: digest for name, digest in suite.expected.items() if name != 'artifacts.json'}))
        witness.close()
        suite._verify_outputs()
        print(json.dumps(dict(Status=STATUS, ToolInvocations=134, RequiredCellsSatisfied=0, FinalReaderExecuted=False,
            Output=str(suite.output), ReceiptSha256=sha((suite.output / 'results.json').read_bytes()),
            ArtifactsSha256=sha((suite.output / 'artifacts.json').read_bytes())), sort_keys=True), flush=True)
        return suite.report
    except BaseException as error:
        suite.report.update(Commands=copy.deepcopy(suite.commands), ToolInvocations=len(suite.commands),
            CompilerInvocations=sum(row['Argv'][0] == str(suite.tools['gcc']) for row in suite.commands),
            CommandsSha256=suite.expected.get('commands.json'))
        try:
            revoke(runner, suite.report, error)
        except BaseException as secondary:
            suite.report.setdefault('ClosingErrors', []).append('failure hook: ' + type(secondary).__name__ + ': ' + str(secondary))
        try:
            recover_owned(runner, environment, suite, helpers['guard'])
        except BaseException as secondary:
            suite.report.setdefault('ClosingErrors', []).append('failure persistence: ' + type(secondary).__name__ + ': ' + str(secondary))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ARGUMENTS:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        run(*prepare(args))
        return 0
    except BaseException as error:
        try:
            print(type(error).__name__ + ': ' + str(error), file=sys.stderr, flush=True)
        except BaseException:
            pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
