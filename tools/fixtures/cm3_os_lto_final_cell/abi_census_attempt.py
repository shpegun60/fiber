"""Replay original Os census and deferred ABI facts in one fresh reader.

The sealed original-census handoff supplies journals and dumps, not a verdict.
No tools, target execution, full ABI controls or whole-cell credit are granted.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BATCH = ('tools/fixtures/cm3_os_lto_final_cell/batch_attempt.py',
         'EC52A23182A5B0B4A09E18429E5BFB94902FBC42592785295D7283ACB572F38A')
NORMAL = ('tools/fixtures/cm3_os_lto_final_cell/normal_attempt.py',
          'ADC2D945F336C4325D3A14151DF5B0E8566DE348871211B9EFB0280A3AC8E084')
PINS = {
    'abi_replay': ('tools/fixtures/cm3_os_lto_final_cell/abi_replay.py',
        '6854D207E12345E856CB9CDCF9B7BA6281EF66FE3C003A474573524D1B1FE3FB'),
}
DOCUMENTS = {
    'tools/fixtures/cm3_os_lto_final_cell/ABI_CENSUS_ATTEMPT_CONTRACT.md':
        'A2CF578726FF811AA028D811B65CAE19321A1697D3C32E29467062F15556A900',
}
PASS = 'ORIGINAL-CENSUS-AND-DEFERRED-ABI-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CURRENT_CM3_OS_LTO_ORIGINAL_CENSUS_AND_DEFERRED_ABI_ONLY'
ARGUMENTS = ('batch-build', 'batch-receipt-sha256', 'batch-artifacts-sha256',
    'native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
    'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
    'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir',
    'normal-build', 'normal-receipt-sha256', 'normal-artifacts-sha256')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'ABIControlsReplayed', 'IsolationReplayed', 'FinalReferenceParity',
    'FinalRootTransferProtocolsValidated', 'CompleteCellProof', 'RequiredCellSatisfied',
    'CellContractSatisfied', 'GlobalFreezeQualified', 'HostedCIQualified', 'ArchiveQualification',
    'CpuExecution', 'BoardExecution', 'ProducerCompilersReexecuted', 'OsProcessTraceVerified',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'PolicyEquivalence',
    'PriorReaderVerdictInherited')
FACTS = ('OriginalInspectionBindingsReplayed', 'OriginalCensusReplayed', 'DeferredABIReplayed',
         'ImmutableInputsConsumed', 'InputClosureVerified', 'OutputSealVerified')


def need(value, detail):
    if not value:
        raise ValueError('cm3-os-lto-abi-census: ' + detail)


def sha(raw):
    need(type(raw) is bytes, 'literal byte buffer')
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def prepare(args):
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize,
         'fresh isolated unoptimized -I -S -B interpreter')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
         'initially unimported parser')
    buffers = {}

    def enroll(relative, digest):
        need(type(relative) is str and relative.startswith('tools/')
             and all(part not in ('', '.', '..') for part in relative.split('/'))
             and '\\' not in relative and ':' not in relative and type(digest) is str
             and re.fullmatch('[0-9A-F]{64}', digest) is not None, 'fixed authenticated source pin')
        path = ROOT / relative
        raw = buffers[path] if path in buffers else path.read_bytes()
        need(sha(raw) == digest, 'source pin/' + relative)
        buffers[path] = raw
        return path, raw

    path, raw = enroll(*BATCH)
    builder = load('_os_abi_census_builder', path, raw)
    path, raw = enroll(*builder.METADATA)
    metadata = load('_os_abi_census_metadata', path, raw)
    path, raw = enroll('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata.RUNNER_SHA256)
    runner = load('_os_abi_census_reader_entry', path, raw)
    plans = {}

    def merge(registry):
        builder._pins(registry)
        for name, row in registry.items():
            need(name not in plans or plans[name] == row, 'consistent helper/' + name)
            plans[name] = row
            enroll(*row)

    for registry in (metadata.PINS, metadata.LEAF_PINS, builder.PINS):
        merge(registry)
    for row in runner.PINS.values():
        enroll(*row)
    for documents in (runner.DOCUMENTS, metadata.DOCUMENTS):
        for row in documents.items():
            enroll(*row)
    opening = {str(path): sha(raw) for path, raw in sorted(buffers.items())}
    path, raw = enroll(*NORMAL)
    normal = load('_os_abi_census_normal_metadata', path, raw)
    for registry in (normal.PINS, {'normal_entry': NORMAL}, PINS):
        merge(registry)
    for documents in (normal.DOCUMENTS, DOCUMENTS):
        for row in documents.items():
            enroll(*row)
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    modules = {name: load('_os_abi_census_admission_' + name, ROOT / row[0], buffers[ROOT / row[0]])
               for name, row in runner.PINS.items()}
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'], extra_sources=buffers)(args)
    environment = dict(Witness=witness, Modules=modules, HelperPlans=plans)

    def read(path):
        need(path in buffers, 'bootstrap helper outside authenticated opening buffers')
        return buffers[path]

    with patch.object(Path, 'read_bytes', read):
        helpers = {name: load('_os_abi_census_bootstrap_' + name, ROOT / row[0], buffers[ROOT / row[0]])
                   for name, row in plans.items()}
    return runner, environment, builder, helpers, opening, buffers


def admit_normal(args, runner, environment, batch_root, batch, roles, helpers):
    witness, normal, guard, machine = (environment['Witness'], helpers['normal_entry'],
                                     helpers['guard'], helpers['machine'])
    root = witness.replay_api.checked_path(args.normal_build, directory=True)
    for other in (batch_root, witness.output, Path(args.inventory),
                  *(group['Root'] for group in witness.groups.values())):
        need(not root.is_relative_to(other) and not other.is_relative_to(root), 'disjoint original-census handoff')
    receipt_hash = witness.replay_api.digest(args.normal_receipt_sha256)
    manifest_hash = witness.replay_api.digest(args.normal_artifacts_sha256)
    report = normal.structured(witness.watch.read(root / 'results.json', receipt_hash))
    manifest = normal.structured(witness.watch.read(root / 'artifacts.json', manifest_hash))
    need(type(manifest) is dict and set(manifest) == {'Artifacts'} and type(manifest['Artifacts']) is dict,
         'exact original-census manifest')
    artifacts = manifest['Artifacts']
    need('artifacts.json' not in artifacts and artifacts.get('results.json') == receipt_hash, 'handoff receipt binding')
    for name, digest in artifacts.items():
        witness.replay_api.relative_name(name)
        need(type(digest) is str and re.fullmatch('[0-9A-F]{64}', digest) is not None, 'typed handoff artifact')
    witness.watch.tree(root, dict(artifacts, **{'artifacts.json': manifest_hash}))
    normal.require_result(report, helpers['normal'])
    expected = runner.base_report(witness)
    for key in ('Profile', 'Mode', 'Linkage', 'Cohort', 'ReferenceCommit', 'SourceInventorySha256',
                'CurrentInventory', 'CurrentCaptureProducer', 'ProducerBindings'):
        guard._same(report.get(key), expected[key], 'same original-census authority/' + key)
    guard._same(report.get('Batch'), dict(Build=str(batch_root), ReceiptSha256=args.batch_receipt_sha256,
        ArtifactsSha256=args.batch_artifacts_sha256), 'same original sealed batch')
    hashes, identities = report.get('InputHashes'), report.get('InputPhysicalIdentities')
    need(type(hashes) is dict and hashes and type(identities) is dict and set(hashes) == set(identities),
         'complete original-census input identities')
    need(type(report.get('ClosingFilesVerified')) is int and report['ClosingFilesVerified'] == len(hashes),
         'literal handoff input count')
    for name, digest in hashes.items():
        path = witness.api.regular(name)
        need(str(path) == name and type(digest) is str and re.fullmatch('[0-9A-F]{64}', digest) is not None,
             'canonical handoff input')
        identity = identities[name]
        need(type(identity) is list and len(identity) == 3
             and all(type(value) is int and value >= 0 for value in identity), 'typed handoff physical identity')
        machine.retain_identity(witness, path, identity)
        witness.watch.read(path, digest)
    sources, seen = report.get('CapturedSources'), set()
    need(type(sources) is list and sources, 'handoff captured sources')
    for row in sources:
        need(type(row) is dict and set(row) == {'Original', 'Captured', 'Sha256'}, 'exact handoff source record')
        original, captured = witness.api.regular(row['Original']), witness.api.regular(row['Captured'])
        need(original not in seen and hashes.get(str(original)) == row['Sha256'] and captured.is_relative_to(root)
             and artifacts.get(captured.relative_to(root).as_posix()) == row['Sha256'], 'handoff source binding')
        need(witness.watch.read(original, row['Sha256']) == witness.watch.read(captured, row['Sha256']),
             'unchanged handoff source bytes')
        seen.add(original)
    targets = normal.original_targets(witness, batch, roles, machine)
    guard._same(report.get('OriginalTargets'), targets, 'same original image identities')
    compiler = Path(witness.groups['Native']['Result']['CapturedCompiler'])
    objdump = compiler.with_name('arm-none-eabi-objdump.exe')
    tool = dict(Path=str(objdump), Sha256=witness.watch.hashes[objdump])
    guard._same(report.get('InspectionTool'), tool, 'same admitted inspection executable')
    normal.validate_inspections(root, tool, targets, report['OriginalDisassemblies'], report['Commands'],
                                witness.watch.read, guard._same)
    for path, digest in {**{root / name: digest for name, digest in artifacts.items()},
                         root / 'artifacts.json': manifest_hash, objdump: tool['Sha256']}.items():
        need(path not in roles or roles[path] == digest, 'consistent handoff reader role')
        roles[path] = digest
        witness.watch.read(path, digest)
        machine.retain_identity(witness, path)
    source_root = Path(batch['SourceSeed']) / 'source'
    need(str(source_root.parent) == witness.groups['Native']['Result']['SeedBuild'], 'same canonical source seed')
    project = {Path(name): digest for name, digest in batch['InputHashes'].items()
               if Path(name).is_relative_to(source_root)}
    need(project, 'explicit project-source reader roles')
    for path, digest in project.items():
        need(path not in roles or roles[path] == digest, 'consistent project-source role')
        roles[path] = digest
        witness.watch.read(path, digest)
        machine.retain_identity(witness, path)
    witness.close()
    return root, report, targets, tool, len(project)


def replay(runner, environment, batch_root, batch, normal_root, handoff, roles, targets, tool):
    witness, plans = environment['Witness'], environment['HelperPlans']
    wanted = ('machine', 'normal_entry', 'normal', 'census', 'policy', 'workers',
              'guard', 'declarations', 'ordinary', 'abi_replay')
    plan = {name: plans[name] for name in wanted}
    plan['transport'] = environment['Modules']['capture'].PINS['api']
    with patch('subprocess.Popen', side_effect=AssertionError('immutable ABI/census replay cannot start processes')):
        with runner.reader(environment, {'CensusAndABI': {str(i): path for i, path in enumerate(roles)}}) as (core, _, frozen):
            def fresh(name, relative):
                spec = importlib.util.spec_from_file_location(name, ROOT / relative)
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
                return module
            helpers = {name: fresh('_os_abi_census_frozen_' + name, row[0]) for name, row in plan.items()}
            view = helpers['machine'].immutable_view(witness.groups['Native']['Result'], roles, helpers['transport'])
            normal = helpers['normal_entry']
            bound_batch = normal.structured(view.watch.read(batch_root / 'results.json'))
            bound_native = normal.structured(view.watch.read(witness.groups['Native']['Root'] / 'results.json'))
            bound_handoff = normal.structured(view.watch.read(normal_root / 'results.json'))
            guard = helpers['guard']
            guard._same(bound_batch, batch, 'same immutable batch receipt')
            guard._same(bound_native, witness.groups['Native']['Result'], 'same immutable native receipt')
            guard._same(bound_handoff, handoff, 'same immutable handoff receipt')
            dumps = normal.validate_inspections(normal_root, tool, targets, bound_handoff['OriginalDisassemblies'],
                                                bound_handoff['Commands'], view.watch.read, guard._same)
            census = helpers['normal'].inspect(bound_batch, bound_native, batch_root, core,
                dict(census=helpers['census'], policy=helpers['policy'], port_runner=helpers['workers'], guard=guard),
                view.watch.read, dumps)
            helpers['normal'].require_result(census)
            guard._same(census, bound_handoff['OriginalCensus'], 'recomputed original census comparison')
            abi = helpers['abi_replay'].inspect(bound_batch, bound_native, batch_root, core,
                {name: helpers[name] for name in ('declarations', 'ordinary', 'guard')}, view.watch.read)
            helpers['abi_replay'].require_result(abi)
            guard._same(abi['Inputs']['OriginalELF'], census['OriginalInputs']['OrdinaryFinal'],
                        'shared original ordinary image')
            guard._same(abi['PositiveAuthority']['LoadImageComparison'], census['Twins'],
                        'shared original load-image composition')
        witness.close()
    return census, abi, frozen


def require_result(report, helpers):
    need(type(report) is dict and report.get('Status') == PASS and report.get('Scope') == SCOPE
         and report.get('Profile') == 'CM3' and report.get('Mode') == 'Os-lto'
         and report.get('Linkage') == 'direct' and report.get('LTO') is True, 'bounded composed disposition')
    for key in FACTS:
        need(report.get(key) is True, 'completed composition fact/' + key)
    for key in NONCLAIMS:
        need(report.get(key) is False, 'nonclaim/' + key)
    for key, value in (('ToolInvocations', 0), ('CompilerInvocations', 0), ('RecordedInspectionInvocations', 2),
                       ('RequiredCellsSatisfied', 0), ('RequiredCellCount', 2774)):
        need(type(report.get(key)) is int and report[key] == value, 'literal separate counter/' + key)
    need(type(report.get('Commands')) is list and report['Commands'] == []
         and type(report.get('ProjectSourceReaderRoles')) is int and report['ProjectSourceReaderRoles'] > 0,
         'no new commands and explicit project roles')
    helpers['normal'].require_result(report.get('OriginalCensus'))
    helpers['abi_replay'].require_result(report.get('DeferredABI'))
    need('Error' in report and report['Error'] is None and 'PrimaryError' in report and report['PrimaryError'] is None
         and type(report.get('ClosingErrors')) is list and report['ClosingErrors'] == [], 'clean explicit errors')


def run(args, runner, environment, builder, helpers, opening, buffers):
    witness = environment['Witness']
    report = dict(runner.base_report(witness), Scope=SCOPE, LTO=True, OriginalCensus=None, DeferredABI=None,
        **dict.fromkeys(FACTS, False), **dict.fromkeys(NONCLAIMS, False))
    suite = None
    try:
        root, batch, roles = helpers['machine'].admit_batch(args, runner, environment, builder, helpers, opening)
        normal_root, handoff, targets, tool, project_count = admit_normal(
            args, runner, environment, root, batch, roles, helpers)
        suite = helpers['session'].suite_type(helpers['utility'], helpers['lto'])(environment, helpers, buffers)
        suite.report = report
        report.update(Batch=dict(Build=str(root), ReceiptSha256=args.batch_receipt_sha256,
            ArtifactsSha256=args.batch_artifacts_sha256), OriginalCensusHandoff=dict(Build=str(normal_root),
            ReceiptSha256=args.normal_receipt_sha256, ArtifactsSha256=args.normal_artifacts_sha256),
            OriginalTargets=targets, InspectionTool=tool, ProjectSourceReaderRoles=project_count,
            RecordedInspectionInvocations=2, Commands=[], ToolInvocations=0, CompilerInvocations=0)
        suite.start()
        suite._save('commands.json', [])
        report['CommandsSha256'] = suite.expected['commands.json']
        census, abi, frozen = replay(runner, environment, root, batch, normal_root, handoff, roles, targets, tool)
        report.update(Status=PASS, OriginalInspectionBindingsReplayed=True, OriginalCensusReplayed=True,
            DeferredABIReplayed=True, OriginalCensus=census, DeferredABI=abi,
            ImmutableInputsConsumed=True, ImmutableReader=frozen)
        suite.verify_objects()
        witness.close()
        suite._verify_outputs()
        helpers['guard'].require_owned_output(suite)
        runner.seal(environment, report, suite.expected)
        require_result(report, helpers)
        print(json.dumps(dict(Status=PASS, ToolInvocations=0, CompilerInvocations=0,
            RecordedInspectionInvocations=2, RequiredCellsSatisfied=0, Output=str(suite.output),
            ReceiptSha256=sha((suite.output / 'results.json').read_bytes()),
            ArtifactsSha256=sha((suite.output / 'artifacts.json').read_bytes())), sort_keys=True), flush=True)
        return report
    except BaseException as error:
        runner.revoke(report, error)
        report.update(**dict.fromkeys(FACTS, False), **dict.fromkeys(NONCLAIMS, False))
        if suite is not None and suite._started:
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
    with patch('os.system', side_effect=AssertionError('ABI/census replay cannot execute shell commands')), \
            patch('subprocess.Popen', side_effect=AssertionError('ABI/census replay cannot start processes')):
        try:
            run(args, *prepare(args))
            return 0
        except BaseException as error:
            try:
                print(type(error).__name__ + ': ' + str(error), file=sys.stderr, flush=True)
            except BaseException:
                pass
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
