"""Inspect the original Os-LTO images twice, then replay their complete census.

This extends a sealed batch without rebuilding it. It grants no whole-cell,
reference-parity, archive, CI, target-execution or global-freeze credit.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import sys
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BATCH = ('tools/fixtures/cm3_os_lto_final_cell/batch_attempt.py',
         'EC52A23182A5B0B4A09E18429E5BFB94902FBC42592785295D7283ACB572F38A')
PINS = {
    'machine': ('tools/fixtures/cm3_os_lto_final_cell/machine_attempt.py',
        '3CB43C29FF23281AC9EC36C32BC7C700E35038C78DE7BD95389213417D8684F0'),
    'census': ('tools/fixtures/cm3_os_lto_final_cell/port_census.py',
        'B3967886026A4082656380222ADB6451473F055E201E8383C6B9E555F9BC0D65'),
    'normal': ('tools/fixtures/cm3_os_lto_final_cell/normal_census.py',
        '65CE1B6E796390CFA8EDDA36C81D4986ED07BD41351CB8CBF72117FABBBD09D1'),
}
DOCUMENTS = {
    'tools/fixtures/cm3_os_lto_final_cell/NORMAL_ATTEMPT_CONTRACT.md':
        'E262137A5393EC7D245A1CEDFEFB7E5B8DB9A52CB97CDF2EB226A662BD3472BB',
}
PASS = 'ORIGINAL-CENSUS-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CURRENT_CM3_OS_LTO_ORIGINAL_MACHINE_AND_FINAL_CENSUS_ONLY'
ORDER = ('Final', 'Machine')
ARGUMENTS = ('batch-build', 'batch-receipt-sha256', 'batch-artifacts-sha256',
    'native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
    'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
    'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'ABIControlsReplayed', 'IsolationReplayed', 'FinalReferenceParity',
    'FinalRootTransferProtocolsValidated', 'CompleteCellProof', 'RequiredCellSatisfied',
    'CellContractSatisfied', 'GlobalFreezeQualified', 'HostedCIQualified', 'ArchiveQualification',
    'CpuExecution', 'BoardExecution', 'ProducerCompilersReexecuted', 'OsProcessTraceVerified',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'PolicyEquivalence')


def need(value, detail):
    if not value:
        raise ValueError('cm3-os-lto-normal-attempt: ' + detail)


def sha(raw):
    need(type(raw) is bytes, 'literal byte buffer')
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def structured(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate inspection JSON key')
            result[key] = value
        return result

    def constant(value):
        raise ValueError('nonfinite inspection JSON/' + value)

    def finite(value):
        result = float(value)
        need(math.isfinite(result), 'nonfinite inspection JSON number')
        return result

    need(type(raw) is bytes, 'literal journal byte buffer')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite)


def prepare(args):
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize,
         'fresh isolated unoptimized -I -S -B interpreter')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
         'initially unimported parser')
    buffers = {}

    def enroll(relative, digest):
        need(type(relative) is str and relative.startswith('tools/')
             and all(part not in ('', '.', '..') for part in relative.split('/'))
             and '\\' not in relative and ':' not in relative
             and type(digest) is str and re.fullmatch('[0-9A-F]{64}', digest) is not None,
             'fixed authenticated source pin')
        path = ROOT / relative
        raw = buffers[path] if path in buffers else path.read_bytes()
        need(sha(raw) == digest, 'source pin/' + relative)
        buffers[path] = raw
        return path, raw

    path, raw = enroll(*BATCH)
    builder = load('_os_normal_builder_metadata', path, raw)
    path, raw = enroll(*builder.METADATA)
    metadata = load('_os_normal_abi_metadata', path, raw)
    path, raw = enroll('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata.RUNNER_SHA256)
    runner = load('_os_normal_reader_entry', path, raw)
    plans = {}
    for registry in (metadata.PINS, metadata.LEAF_PINS, builder.PINS):
        builder._pins(registry)
        for name, row in registry.items():
            need(name not in plans or plans[name] == row, 'no conflicting helper/' + name)
            plans[name] = row
    for registry in (runner.PINS, plans):
        builder._pins(registry)
        for row in registry.values():
            enroll(*row)
    for documents in (runner.DOCUMENTS, metadata.DOCUMENTS):
        for row in documents.items():
            enroll(*row)
    opening = {str(path): sha(raw) for path, raw in sorted(buffers.items())}
    builder._pins(PINS)
    for name, row in PINS.items():
        need(name not in plans, 'distinct new helper role/' + name)
        enroll(*row)
        plans[name] = row
    for row in DOCUMENTS.items():
        enroll(*row)
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    modules = {name: load('_os_normal_admission_' + name, ROOT / row[0], buffers[ROOT / row[0]])
               for name, row in runner.PINS.items()}
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'], extra_sources=buffers)(args)
    environment = dict(Witness=witness, Modules=modules)

    def read(path):
        need(path in buffers, 'bootstrap helper outside authenticated opening buffers')
        return buffers[path]

    with patch.object(Path, 'read_bytes', read):
        helpers = {name: load('_os_normal_bootstrap_' + name, ROOT / row[0], buffers[ROOT / row[0]])
                   for name, row in plans.items()}
    return runner, environment, builder, helpers, opening, buffers


def original_targets(witness, batch, roles, machine):
    native = witness.groups['Native']
    links = native['Result']['Links']
    need(type(links) is list and len(links) == 2
         and [row.get('Kind') for row in links] == ['ordinary', 'emit-relocs'], 'original native twins')
    deferred = batch['IsolationDeferredReader']['Inputs']
    result = []
    for role, field, pending_role in (('Final', 'Path', 'OriginalEmitELF'),
                                      ('Machine', 'Machine', 'OriginalMachine')):
        path = witness.api.regular(links[1][field])
        digest = native['Artifacts'][path.relative_to(native['Root']).as_posix()]
        matches = [row for row in deferred if row.get('Role') == pending_role]
        need(len(matches) == 1 and matches[0] == dict(Role=pending_role, Path=str(path), Sha256=digest)
             and roles.get(path) == digest, 'original target agrees with batch and native/' + role)
        witness.watch.read(path, digest)
        machine.retain_identity(witness, path)
        result.append(dict(Role=role, Path=str(path), Sha256=digest,
                           PhysicalIdentity=list(witness.identities[path])))
    need(result[0]['Path'] != result[1]['Path'], 'distinct final and worker targets')
    return result


def validate_inspections(output, tool, targets, records, commands, read, same):
    """Bind exactly two original-target disassemblies to managed raw journals."""
    need(isinstance(output, Path) and output.is_absolute() and type(tool) is dict
         and set(tool) == {'Path', 'Sha256'} and type(targets) is list and len(targets) == 2
         and type(records) is list and len(records) == 2
         and type(commands) is list and len(commands) == 2, 'two explicit inspection roles')
    need(type(tool['Path']) is str and Path(tool['Path']).is_absolute()
         and '..' not in Path(tool['Path']).parts and type(tool['Sha256']) is str
         and re.fullmatch('[0-9A-F]{64}', tool['Sha256']) is not None, 'typed admitted inspection tool')
    same(structured(read(output / 'commands.json')), commands, 'inspection aggregate journal')
    dumps = {}
    for index, role in enumerate(ORDER):
        target, record, command = targets[index], records[index], commands[index]
        need(type(target) is dict and set(target) == {'Role', 'Path', 'Sha256', 'PhysicalIdentity'}
             and target['Role'] == role and type(target['Path']) is str and Path(target['Path']).is_absolute()
             and type(target['Sha256']) is str and re.fullmatch('[0-9A-F]{64}', target['Sha256']) is not None
             and type(target['PhysicalIdentity']) is list and len(target['PhysicalIdentity']) == 3
             and all(type(value) is int and value >= 0 for value in target['PhysicalIdentity']), 'typed original target')
        prefix = 'commands/%03d' % index
        same(structured(read(output / (prefix + '.json'))), command, 'inspection per-command journal')
        need(type(command) is dict and command.get('Label') == 'disassemble original ' + role
             and command.get('Argv') == [tool['Path'], '-drwC', '-z', target['Path']]
             and command.get('Cwd') == str(output) and command.get('State') == 'TERMINAL'
             and command.get('Status') == 'PASS' and command.get('TimedOut') is False
             and type(command.get('Exit')) is int and command['Exit'] == 0
             and type(command.get('ExpectedExit')) is int and command['ExpectedExit'] == 0
             and command.get('Error') is None and command.get('JournalErrors', []) == []
             and type(command.get('Seconds')) in (int, float) and math.isfinite(command['Seconds'])
             and command['Seconds'] >= 0, 'exact terminal inspection command/' + role)
        need(command.get('Stdout') == prefix + '.stdout' and command.get('Stderr') == prefix + '.stderr',
             'fixed inspection raw-stream names')
        stdout, stderr = read(output / command['Stdout']), read(output / command['Stderr'])
        need(type(stdout) is bytes and stdout and stderr == b''
             and command.get('StdoutSha256') == sha(stdout) and command.get('StderrSha256') == sha(stderr),
             'clean exact inspection streams/' + role)
        name = 'normal/original-' + role.lower() + '.dis'
        expected = dict(Role=role, CommandIndex=index, Target=target,
                        Path=str(output / name), Sha256=sha(stdout), Tool=tool)
        same(record, expected, 'exact original disassembly binding/' + role)
        need(read(Path(record['Path'])) == stdout, 'disassembly is exact tool stdout/' + role)
        need(sha(read(Path(target['Path']))) == target['Sha256'], 'same original target bytes/' + role)
        dumps[role] = Path(record['Path']), stdout
    need(sha(read(Path(tool['Path']))) == tool['Sha256'], 'same admitted objdump bytes')
    return dumps


def collect(suite, witness, helpers, targets):
    guard, machine = helpers['guard'], helpers['machine']
    tool = dict(Path=str(suite.tools['objdump']), Sha256=witness.watch.hashes[suite.tools['objdump']])
    records = []
    need(not suite.commands and type(targets) is list and len(targets) == 2
         and all(type(row) is dict for row in targets)
         and [row.get('Role') for row in targets] == list(ORDER), 'fresh exact two-inspection plan')
    for index, target in enumerate(targets):
        role, path = ORDER[index], Path(target['Path'])
        need(target['Role'] == role, 'fixed inspection order')
        guard.require_owned_output(suite)
        witness.watch.read(path, target['Sha256'])
        machine.retain_identity(witness, path, target['PhysicalIdentity'])
        result = suite.command([tool['Path'], '-drwC', '-z', str(path)], 'disassemble original ' + role)
        need(type(result.stdout) is bytes and result.stdout and result.stderr == b'', 'nonempty clean disassembly')
        guard.require_owned_output(suite)
        output = suite.write_input('normal/original-' + role.lower() + '.dis', result.stdout)
        machine.retain_identity(witness, path, target['PhysicalIdentity'])
        records.append(dict(Role=role, CommandIndex=index, Target=copy.deepcopy(target), Path=str(output),
                            Sha256=sha(result.stdout), Tool=dict(tool)))
    validate_inspections(suite.output, tool, targets, records, suite.commands, witness.watch.read, guard._same)
    return tool, records


def replay(runner, environment, batch, root, roles, suite, tool, targets, records):
    with patch('subprocess.Popen', side_effect=AssertionError('immutable replay cannot start processes')):
        return replay_without_processes(runner, environment, batch, root, roles, suite, tool, targets, records)


def replay_without_processes(runner, environment, batch, root, roles, suite, tool, targets, records):
    witness = environment['Witness']
    plan = dict(PINS, policy=environment['HelperPlans']['policy'],
                port_runner=environment['HelperPlans']['workers'], guard=environment['HelperPlans']['guard'],
                transport=environment['Modules']['capture'].PINS['api'])
    with runner.reader(environment, {'OriginalCensus': {str(i): path for i, path in enumerate(roles)}}) as (core, _, frozen):
        def frozen_load(name, relative):
            spec = importlib.util.spec_from_file_location(name, ROOT / relative)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            return module
        helpers = {name: frozen_load('_os_normal_frozen_' + name, row[0]) for name, row in plan.items()}
        native = witness.groups['Native']
        view = helpers['machine'].immutable_view(native['Result'], roles, helpers['transport'])
        bound_batch = json.loads(view.watch.read(root / 'results.json'), object_pairs_hook=helpers['transport'].unique_object)
        bound_native = json.loads(view.watch.read(native['Root'] / 'results.json', native['ReceiptSha256']),
                                  object_pairs_hook=helpers['transport'].unique_object)
        helpers['guard']._same(bound_batch, batch, 'same immutable batch receipt')
        helpers['guard']._same(bound_native, native['Result'], 'same immutable native receipt')
        dumps = validate_inspections(suite.output, tool, targets, records, suite.commands,
                                     view.watch.read, helpers['guard']._same)
        proof = helpers['normal'].inspect(bound_batch, bound_native, root, core,
            {name: helpers[name] for name in ('census', 'policy', 'port_runner', 'guard')}, view.watch.read, dumps)
        helpers['normal'].require_result(proof)
    witness.close()
    return proof, frozen


def require_result(report, normal):
    need(type(report) is dict and report.get('Status') == PASS and report.get('Scope') == SCOPE
         and report.get('Profile') == 'CM3' and report.get('Mode') == 'Os-lto'
         and report.get('Linkage') == 'direct' and report.get('LTO') is True, 'bounded original census disposition')
    for key in ('OriginalDisassembliesCollected', 'OriginalCensusReplayed', 'ImmutableInputsConsumed',
                'InputClosureVerified', 'OutputSealVerified'):
        need(report.get(key) is True, 'completed original census fact/' + key)
    for key in NONCLAIMS:
        need(report.get(key) is False, 'nonclaim/' + key)
    for key, value in (('ToolInvocations', 2), ('CompilerInvocations', 0),
                       ('RequiredCellsSatisfied', 0), ('RequiredCellCount', 2774)):
        need(type(report.get(key)) is int and report[key] == value, 'literal counter/' + key)
    need(type(report.get('Commands')) is list and len(report['Commands']) == 2
         and type(report.get('OriginalDisassemblies')) is list and len(report['OriginalDisassemblies']) == 2,
         'complete original inspection records')
    normal.require_result(report.get('OriginalCensus'))
    need('Error' in report and report['Error'] is None and 'PrimaryError' in report and report['PrimaryError'] is None
         and type(report.get('ClosingErrors')) is list and report['ClosingErrors'] == [], 'clean explicit error state')


def run(args, runner, environment, builder, helpers, opening, buffers):
    witness = environment['Witness']
    report = dict(runner.base_report(witness), Scope=SCOPE, LTO=True, OriginalDisassembliesCollected=False,
                  OriginalCensusReplayed=False, OriginalCensus=None, **dict.fromkeys(NONCLAIMS, False))
    suite = None
    try:
        with patch('subprocess.Popen', side_effect=AssertionError('admission cannot start processes')):
            root, batch, roles = helpers['machine'].admit_batch(args, runner, environment, builder, helpers, opening)
            targets = original_targets(witness, batch, roles, helpers['machine'])
            suite = helpers['session'].suite_type(helpers['utility'], helpers['lto'])(environment, helpers, buffers)
        suite.report = report
        report.update(Batch=dict(Build=str(root), ReceiptSha256=args.batch_receipt_sha256,
            ArtifactsSha256=args.batch_artifacts_sha256), OriginalTargets=targets)
        suite.start()
        tool, records = collect(suite, witness, helpers, targets)
        tool_path = Path(tool['Path'])
        need(tool_path not in roles or roles[tool_path] == tool['Sha256'], 'consistent admitted objdump role')
        roles[tool_path] = tool['Sha256']
        helpers['machine'].retain_identity(witness, tool_path)
        report.update(InspectionTool=tool, OriginalDisassemblies=records, Commands=copy.deepcopy(suite.commands),
            CommandsSha256=suite.expected['commands.json'], ToolInvocations=2, CompilerInvocations=0,
            OriginalDisassembliesCollected=True)
        for name, digest in suite.expected.items():
            if name != 'results.json':
                path = suite.output / name
                need(path not in roles or roles[path] == digest, 'consistent inspection output role')
                roles[path] = digest
                helpers['machine'].retain_identity(witness, path)
        environment['HelperPlans'] = {**builder.PINS}
        proof, frozen = replay(runner, environment, batch, root, roles, suite, tool, targets, records)
        report.update(Status=PASS, OriginalCensusReplayed=True, OriginalCensus=proof,
                      ImmutableInputsConsumed=True, ImmutableReader=frozen)
        suite.verify_objects()
        witness.close()
        suite._verify_outputs()
        helpers['guard'].require_owned_output(suite)
        runner.seal(environment, report, suite.expected)
        require_result(report, helpers['normal'])
        print(json.dumps(dict(Status=PASS, ToolInvocations=2, CompilerInvocations=0,
            RequiredCellsSatisfied=0, Output=str(suite.output),
            ReceiptSha256=sha((suite.output / 'results.json').read_bytes()),
            ArtifactsSha256=sha((suite.output / 'artifacts.json').read_bytes())), sort_keys=True), flush=True)
        return report
    except BaseException as error:
        runner.revoke(report, error)
        report.update(OriginalDisassembliesCollected=False, OriginalCensusReplayed=False,
                      **dict.fromkeys(NONCLAIMS, False))
        if suite is not None:
            report.update(Commands=copy.deepcopy(suite.commands), ToolInvocations=len(suite.commands),
                CompilerInvocations=0, CommandsSha256=suite.expected.get('commands.json'))
            if suite._started:
                try:
                    builder.recover_owned(runner, environment, suite, helpers['guard'])
                except BaseException as secondary:
                    report.setdefault('ClosingErrors', []).append('failure persistence: ' + type(secondary).__name__ + ': ' + str(secondary))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ARGUMENTS:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        with patch('os.system', side_effect=AssertionError('normal census cannot execute shell commands')):
            with patch('subprocess.Popen', side_effect=AssertionError('bootstrap cannot start processes')):
                prepared = prepare(args)
            run(args, *prepared)
        return 0
    except BaseException as error:
        try:
            print(type(error).__name__ + ': ' + str(error), file=sys.stderr, flush=True)
        except BaseException:
            pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
