"""Replay one sealed current Os batch without executing tools or granting a cell.

Admission, physical closing and output writes stay outside the immutable reader.
The reader recomputes actual machine effects and ten saved-worker chains; it
does not borrow a prior O2 verdict or promote unresolved attribution to PASS.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BATCH = ('tools/fixtures/cm3_os_lto_final_cell/batch_attempt.py',
         'EC52A23182A5B0B4A09E18429E5BFB94902FBC42592785295D7283ACB572F38A')
PINS = {
    'effects': ('tools/fixtures/cm3_os_lto_final_cell/common_effects.py',
        '800942F1CA34DCE0198258C13D85F5BA422DF6BF88726694360C16B39270C81D'),
    'census': ('tools/fixtures/cm3_os_lto_final_cell/port_census.py',
        'B3967886026A4082656380222ADB6451473F055E201E8383C6B9E555F9BC0D65'),
    'common_workers': ('tools/fixtures/cm3_os_lto_final_cell/common_workers.py',
        'F12A77717924A11DF5F6FA29800271D335A09C475819171C31EFC0B757474EDB'),
    'machine': ('tools/fixtures/cm3_os_lto_final_cell/machine_replay.py',
        '4BC653964316A501400BBA160608969C9F711D0F4BE9DDFF707589CCC7D74401'),
    'worker_bindings': ('tools/fixtures/cm3_os_lto_final_cell/worker_bindings.py',
        '7A899F3B0EAD365900086F252455ACA25E10684ACC24F7605754D29308896834'),
}
DOCUMENTS = {
    'tools/fixtures/cm3_os_lto_final_cell/MACHINE_ATTEMPT_CONTRACT.md':
        'F8FC812307D6D8DB3074B5CE78720FC24C9353D34FD01ABC2A3787428AEE053B',
    'tools/fixtures/cm3_os_lto_final_cell/MACHINE_REPLAY_CONTRACT.md':
        '89EB98B0DBE5053503DE545D77D35147A8879D6268B8E5221C743B4FAD6D8DCF',
}
SCOPE = 'CURRENT_CM3_OS_LTO_BATCH_MACHINE_AND_WORKER_COMPONENTS_ONLY'
REPLAYED = 'MACHINE-WORKER-COMPONENTS-REPLAYED-NOT-QUALIFIED'
PENDING = 'MACHINE-WORKER-REPLAY-PENDING-ATTRIBUTION'
ARGUMENTS = ('batch-build', 'batch-receipt-sha256', 'batch-artifacts-sha256')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'ABIControlsReplayed', 'IsolationReplayed', 'FinalReferenceParity',
    'FinalRootTransferProtocolsValidated', 'IRDefinitionProvenanceValidated',
    'CompleteCellProof', 'RequiredCellSatisfied', 'CellContractSatisfied',
    'GlobalFreezeQualified', 'HostedCIQualified', 'ArchiveQualification',
    'CpuExecution', 'BoardExecution', 'ProducerCompilersReexecuted',
    'OsProcessTraceVerified', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'PolicyEquivalence')


def need(value, detail):
    if not value:
        raise ValueError('cm3-os-lto-machine-attempt: ' + detail)


def sha(raw):
    need(type(raw) is bytes, 'literal byte buffer')
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def retain_identity(witness, path, expected=None):
    actual = witness._physical(path)
    need(type(actual) is tuple and len(actual) == 3
         and all(type(value) is int and value >= 0 for value in actual), 'literal physical input identity')
    if expected is not None:
        need(list(actual) == expected, 'original builder physical identity/' + str(path))
    if path in witness.identities:
        need(witness.identities[path] == actual, 'previously admitted physical identity changed/' + str(path))
    else:
        witness.identities[path] = actual


def prepare(args):
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize,
         'fresh isolated unoptimized -I -S -B interpreter')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
         'no inherited parser state')
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
    batch = load('_os_machine_batch_metadata', path, raw)
    path, raw = enroll(*batch.METADATA)
    metadata = load('_os_machine_abi_metadata', path, raw)
    path, raw = enroll('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata.RUNNER_SHA256)
    runner = load('_os_machine_reader_entry', path, raw)
    helper_plan = {}
    for registry in (metadata.PINS, metadata.LEAF_PINS, batch.PINS):
        batch._pins(registry)
        for name, row in registry.items():
            need(name not in helper_plan or helper_plan[name] == row, 'no conflicting helper role/' + name)
            helper_plan[name] = row
    for registry in (runner.PINS, helper_plan):
        batch._pins(registry)
        for row in registry.values():
            enroll(*row)
    for documents in (runner.DOCUMENTS, metadata.DOCUMENTS):
        for row in documents.items():
            enroll(*row)
    # This is exactly the opening source cohort of the authenticated builder.
    opening = {str(path): sha(raw) for path, raw in sorted(buffers.items())}
    for row in PINS.values():
        enroll(*row)
    for row in DOCUMENTS.items():
        enroll(*row)
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    modules = {name: load('_os_machine_admission_' + name, ROOT / row[0], buffers[ROOT / row[0]])
               for name, row in runner.PINS.items()}
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'], extra_sources=buffers)(args)
    environment = dict(Witness=witness, Modules=modules)

    def read(path):
        need(path in buffers, 'bootstrap source outside opening authenticated buffers')
        return buffers[path]

    with patch.object(Path, 'read_bytes', read):
        helpers = {name: load('_os_machine_bootstrap_' + name, ROOT / row[0], buffers[ROOT / row[0]])
                   for name, row in helper_plan.items()}
    return runner, environment, batch, helpers, opening


def admit_batch(args, runner, environment, batch, helpers, opening):
    witness = environment['Witness']
    root = witness.replay_api.checked_path(args.batch_build, directory=True)
    need(not witness.output.is_relative_to(root) and not root.is_relative_to(witness.output),
         'batch and output disjoint in both directions')
    report = witness.watch.structured(root / 'results.json', witness.replay_api.digest(args.batch_receipt_sha256))
    manifest_hash = witness.replay_api.digest(args.batch_artifacts_sha256)
    manifest = witness.watch.structured(root / 'artifacts.json', manifest_hash)
    need(type(manifest) is dict and set(manifest) == {'Artifacts'} and type(manifest['Artifacts']) is dict,
         'exact sealed batch manifest')
    artifacts = manifest['Artifacts']
    need('artifacts.json' not in artifacts and artifacts.get('results.json') == sha(witness.watch.read(root / 'results.json')),
         'manifest receipt binding without self-entry')
    for name, digest in artifacts.items():
        witness.replay_api.relative_name(name)
        need(type(digest) is str and re.fullmatch('[0-9A-F]{64}', digest) is not None, 'typed artifact digest')
    witness.watch.tree(root, dict(artifacts, **{'artifacts.json': manifest_hash}))
    batch.require_built(report, helpers)
    expected = runner.base_report(witness)
    for key in ('Profile', 'Mode', 'Linkage', 'Cohort', 'ReferenceCommit', 'SourceInventorySha256',
                'CurrentInventory', 'CurrentCaptureProducer', 'ProducerBindings'):
        helpers['guard']._same(report.get(key), expected[key], 'same admitted batch authority/' + key)
    helpers['guard']._same(report.get('OpeningSourceBuffers'), opening, 'exact original builder source cohort')
    hashes, identities = report.get('InputHashes'), report.get('InputPhysicalIdentities')
    need(type(hashes) is dict and hashes and type(identities) is dict and set(hashes) == set(identities),
         'complete input hashes and physical identities')
    need(type(report.get('ClosingFilesVerified')) is int and report['ClosingFilesVerified'] == len(hashes),
         'literal complete original input count')
    for name, digest in hashes.items():
        path = witness.api.regular(name)
        need(str(path) == name and type(digest) is str and re.fullmatch('[0-9A-F]{64}', digest) is not None,
             'canonical input identity')
        identity = identities[name]
        need(type(identity) is list and len(identity) == 3
             and all(type(value) is int and value >= 0 for value in identity), 'literal original physical input/' + name)
        retain_identity(witness, path, identity)
        witness.watch.read(path, digest)
    sources, seen = report.get('CapturedSources'), {}
    need(type(sources) is list and sources, 'builder captured source buffers')
    for row in sources:
        need(type(row) is dict and set(row) == {'Original', 'Captured', 'Sha256'}, 'exact captured source row')
        original, captured = witness.api.regular(row['Original']), witness.api.regular(row['Captured'])
        need(original not in seen and hashes.get(str(original)) == row['Sha256']
             and captured.is_relative_to(root) and artifacts.get(captured.relative_to(root).as_posix()) == row['Sha256'],
             'unique original/captured/manifest source binding')
        need(witness.watch.read(original, row['Sha256']) == witness.watch.read(captured, row['Sha256']),
             'unchanged actual builder source buffer')
        seen[original] = row['Sha256']
    need(all(seen.get(Path(name)) == digest for name, digest in opening.items()), 'every opening source captured')
    commands = witness.watch.structured(root / 'commands.json', report['CommandsSha256'])
    helpers['guard']._same(commands, report['Commands'], 'sealed original command journal')
    roles = {root / name: digest for name, digest in artifacts.items()}
    roles[root / 'artifacts.json'] = manifest_hash
    for row in report['PendingFinalReader']['Inputs']:
        path = witness.api.regular(row['Path'])
        need(path not in roles or roles[path] == row['Sha256'], 'consistent machine input role')
        roles[path] = row['Sha256']
    native = witness.groups['Native']['Result']
    native_group = witness.groups['Native']
    roles[native_group['Root'] / 'results.json'] = native_group['ReceiptSha256']
    for row in native['Sources']:
        roles[witness.api.regular(row['Object'])] = row['ObjectSha256']
    for name in ('lto1', 'as'):
        row = native['ResolvedWorkers'][name]
        roles[witness.api.regular(row['Path'])] = row['Sha256']
    for row in [*report['CommonAttributesDeferredReader']['Compilations'], *report['PortPolicyCompilations']]:
        path = witness.api.regular(row['Source'])
        digest = row['SourceSha256']
        need(hashes.get(str(path)) == digest and (path not in roles or roles[path] == digest),
             'source role agrees with closed builder inputs')
        roles[path] = digest
    for path, digest in roles.items():
        witness.watch.read(path, digest)
        retain_identity(witness, path)
    witness.close()
    return root, report, roles


def immutable_view(native, roles, transport):
    """No physical path API is reachable by neutral workers inside the reader."""
    def path(value):
        need(isinstance(value, (str, Path)) and Path(value).is_absolute()
             and '\0' not in os.fspath(value) and '..' not in Path(value).parts,
             'absolute lexical worker path without traversal')
        value = Path(os.path.abspath(os.fspath(value)))
        need(value in roles, 'worker escaped caller-admitted reader roles/' + str(value))
        return value

    def read(value, digest=None):
        value = path(value)
        raw = value.read_bytes()
        need(sha(raw) == roles[value] and (digest is None or digest == roles[value]), 'immutable worker byte binding')
        return raw

    def stable(value):
        need(isinstance(value, (str, Path)) and Path(value).is_absolute()
             and '\0' not in os.fspath(value), 'absolute reported worker executable path')
        return path(Path(os.path.abspath(os.fspath(value))))

    return SimpleNamespace(watch=SimpleNamespace(read=read), api=SimpleNamespace(checked_path=path),
        result=native, objects=tuple(Path(row['Object']) for row in native['Sources']), transport=transport,
        admitted=SimpleNamespace(base=SimpleNamespace(stable_path=stable)))


def replay_workers(batch, root, view, helpers):
    plans = helpers['worker_bindings'].bind(batch, root, view.result, view.watch.read,
        {name: helpers[name] for name in ('attributes', 'port_policy', 'attribute_runner', 'guard')})
    records = []
    port_view = helpers['port_policy']._worker_view(view)
    for row in plans:
        output, objects, specs = row['Output'], row['Objects'], row['Specs']
        if row['Component'] == 'CommonAttributes':
            machine, proof = helpers['common_workers'].worker_chain(view, output, objects, specs,
                row['Diagnostics'], helpers['attribute_runner'])
            need(machine == Path(str(output) + '.ltrans0.ltrans.o')
                 and proof.get('MachineSha256') == sha(view.watch.read(machine)),
                 'common worker exact derived machine/' + row['Group'])
        else:
            need(row['Component'] == 'PortPolicy', 'fixed worker component')
            proof = helpers['workers'].worker_chain(port_view, output, objects, row['Diagnostics'],
                                                   supported=row['Supported'], specs=specs)
            helpers['guard']._same(proof, row['StoredWorker'], 'recomputed exact port worker/' + row['Group'])
        records.append(dict(Component=row['Component'], Group=row['Group'], Proof=proof))
    need(len(records) == 10, 'six common and four port worker chains')
    return records


def replay(runner, environment, batch, root, roles, helper_plan):
    witness = environment['Witness']
    plan = {**PINS, **{key: value for key, value in helper_plan.items()
                     if key in ('attributes', 'policy', 'attribute_runner', 'workers', 'port_policy', 'guard')},
            'transport': environment['Modules']['capture'].PINS['api']}
    with runner.reader(environment, {'MachineAndWorkerInputs': {str(index): path for index, path in enumerate(roles)}}) as (core, _, frozen):
        def frozen_load(name, relative):
            spec = importlib.util.spec_from_file_location(name, ROOT / relative)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            return module
        helpers = {name: frozen_load('_os_machine_frozen_' + name, row[0]) for name, row in plan.items()}
        native = witness.groups['Native']
        probe = immutable_view(native['Result'], roles, helpers['transport'])
        bound_batch = json.loads(probe.watch.read(root / 'results.json'),
                                 object_pairs_hook=helpers['transport'].unique_object)
        bound_native = json.loads(probe.watch.read(native['Root'] / 'results.json', native['ReceiptSha256']),
                                  object_pairs_hook=helpers['transport'].unique_object)
        helpers['guard']._same(bound_batch, batch, 'same immutable batch receipt')
        helpers['guard']._same(bound_native, native['Result'], 'same immutable native capture receipt')
        view = immutable_view(bound_native, roles, helpers['transport'])
        workers = replay_workers(bound_batch, root, view, helpers)
        catalog = {(row['Component'], row['Role']): row for row in bound_batch['PendingFinalReader']['Inputs']}

        def read_role(component, role):
            row = catalog[component, role]
            path = Path(row['Path'])
            return path, view.watch.read(path, row['Sha256'])
        machine = helpers['machine'].inspect(bound_batch, core,
            {name: helpers[name] for name in ('effects', 'census', 'attributes', 'policy')}, read_role)
    witness.close()
    return machine, workers, frozen


def require_result(report):
    need(type(report) is dict and report.get('Scope') == SCOPE and report.get('Status') in (REPLAYED, PENDING),
         'bounded machine/worker replay disposition')
    need(report.get('Profile') == 'CM3' and report.get('Mode') == 'Os-lto' and report.get('Linkage') == 'direct',
         'actual current Os component identity')
    for key in ('MachineComponentsReplayed', 'WorkerChainsReplayed', 'ImmutableInputsConsumed',
                'InputClosureVerified', 'OutputSealVerified'):
        need(report.get(key) is True, 'completed component fact/' + key)
    for key in NONCLAIMS:
        need(report.get(key) is False, 'nonclaim/' + key)
    for key, value in (('RequiredCellCount', 2774), ('RequiredCellsSatisfied', 0),
                       ('CompilerInvocations', 0), ('ToolInvocations', 0)):
        need(type(report.get(key)) is int and report[key] == value, 'literal bounded counter/' + key)
    machine, workers = report.get('Machine'), report.get('Workers')
    need(type(machine) is dict and type(machine.get('UnresolvedAttribution')) is list
         and machine.get('MachineRoles') == 20 and type(machine['MachineRoles']) is int
         and type(workers) is list and len(workers) == 10, 'twenty actual machine and ten worker roles')
    need(machine.get('Scope') == 'CM3_OS_LTO_COMMON_AND_PORT_MACHINE_COMPONENTS_ONLY'
         and machine.get('Profile') == 'CM3' and machine.get('Mode') == 'Os-lto'
         and type(machine.get('CommonMachineRoles')) is int and machine['CommonMachineRoles'] == 12
         and type(machine.get('PortMachineRoles')) is int and machine['PortMachineRoles'] == 8,
         'exact machine component identity/counts')
    for key in ('Qualification', 'CompleteCellProof', 'FinalReferenceParity', 'GlobalFreezeQualified',
                'HostedCIQualified', 'CPUExecution', 'BoardExecution', 'ABIControlsReplayed',
                'IsolationReplayed', 'FinalRootTransferProtocolsValidated', 'IRDefinitionProvenanceValidated',
                'WorkerOptionsValidated', 'WorkerExecutionProvenanceValidated'):
        need(machine.get(key) is False, 'machine nonclaim/' + key)
    need(type(machine.get('RequiredCellsSatisfied')) is int and machine['RequiredCellsSatisfied'] == 0,
         'machine zero credit')
    common_groups = ('positive', 'mutant-engine', 'mutant-state', 'mutant-panic',
                     'stress-protected', 'stress-unprotected')
    common = machine.get('CommonMachines')
    need(type(common) is list and len(common) == 6
         and [row.get('Group') for row in common if type(row) is dict] == list(common_groups),
         'exact common machine groups')
    unresolved = []
    for row in common:
        pair = row.get('Machines')
        need(type(pair) is list and len(pair) == 2
             and [value.get('Role') for value in pair if type(value) is dict] == ['Object', 'Machine'],
             'exact common machine pair')
        for value in pair:
            proof = value.get('Proof')
            need(type(proof) is dict and type(proof.get('UnresolvedAttribution')) is list,
                 'explicit common leaf attribution')
            need(value.get('OriginalProtectedPredicateRejected') is
                 (row['Group'] in ('mutant-engine', 'mutant-state', 'mutant-panic', 'stress-unprotected')),
                 'actual mutant rejection disposition')
            if proof['UnresolvedAttribution']:
                unresolved.append(dict(Group=row['Group'], Role=value['Role'], Evidence=proof['UnresolvedAttribution']))
    need(json.dumps(unresolved, sort_keys=True, allow_nan=False) ==
         json.dumps(machine['UnresolvedAttribution'], sort_keys=True, allow_nan=False),
         'unresolved attribution is the full actual common-leaf projection')
    port = machine.get('PortMachines')
    port_plan = [(group, role) for group in ('selected', 'stress-supported', 'stress-raw')
                 for role in ('Aggregate', 'Machine')] + [('Final', 'ELF'), ('Final', 'Machine')]
    need(type(port) is list and len(port) == 8
         and [(row.get('Group'), row.get('Role')) for row in port if type(row) is dict] == port_plan
         and all(type(row.get('Proof')) is dict for row in port), 'exact port machine roles')
    worker_plan = [('CommonAttributes', group) for group in common_groups] + [
        ('PortPolicy', group) for group in ('selected', 'stress-supported', 'stress-raw', 'Final')]
    need([(row.get('Component'), row.get('Group')) for row in workers if type(row) is dict] == worker_plan,
         'ten unique ordered worker chains')
    for row in workers:
        proof = row.get('Proof')
        need(type(proof) is dict, 'explicit recomputed worker proof')
        for key in ('MachineSha256', 'IntermediateSha256'):
            need(type(proof.get(key)) is str and re.fullmatch('[0-9A-F]{64}', proof[key]) is not None,
                 'worker bytes/' + key)
        execution = proof.get('Execution')
        need(type(execution) is dict and execution.get('CompilerReportedWorkerExecutionVerified') is True
             and execution.get('OsProcessTraceVerified') is False
             and type(execution.get('TranscriptSha256')) is str
             and re.fullmatch('[0-9A-F]{64}', execution['TranscriptSha256']) is not None,
             'compiler-reported, not OS-traced worker execution')
        invocations = execution.get('WorkerInvocations')
        need(type(invocations) is list and len(invocations) == 2
             and [value.get('Stage') for value in invocations if type(value) is dict] == ['-fwpa', '-fltrans'],
             'exact actual worker stages')
        if row['Component'] == 'CommonAttributes':
            need(proof.get('SavedArgumentOsOptionsValidated') is True
                 and proof.get('ActualInvocationOsOptionsValidated') is True
                 and proof.get('Qualification') is False, 'recomputed common Os worker options')
        else:
            need(proof.get('SupportedPolicy') is (row['Group'] != 'stress-raw')
                 and proof.get('EffectiveOptionsVerified') is True, 'exact supported/raw port worker disposition')
    need(report['Status'] == (PENDING if machine['UnresolvedAttribution'] else REPLAYED),
         'unresolved attribution cannot be promoted')
    need(machine.get('Status') == ('MACHINE-REPLAY-PENDING-ATTRIBUTION' if unresolved else 'MACHINE-COMPONENTS-REPLAYED')
         and machine.get('CommonAttributionClosed') is (not unresolved), 'consistent nested attribution disposition')
    need('Error' in report and report['Error'] is None and 'PrimaryError' in report and report['PrimaryError'] is None
         and type(report.get('ClosingErrors')) is list and report['ClosingErrors'] == [], 'clean explicit error state')


def run(args, runner, environment, builder, helpers, opening):
    witness = environment['Witness']
    owner = SimpleNamespace(_started=False, output=witness.output, report=runner.base_report(witness))
    report = owner.report
    report.update(Scope=SCOPE, **dict.fromkeys(NONCLAIMS, False), MachineComponentsReplayed=False,
                  WorkerChainsReplayed=False, Machine=None, Workers=[])
    expected = {}
    try:
        root, batch, roles = admit_batch(args, runner, environment, builder, helpers, opening)
        report['Batch'] = dict(Build=str(root), ReceiptSha256=args.batch_receipt_sha256,
                               ArtifactsSha256=args.batch_artifacts_sha256)
        witness.output.mkdir(parents=True, exist_ok=False)
        owner._started = True
        info = witness.output.lstat()
        owner.output_identity = info.st_dev, info.st_ino

        def write(name, raw):
            helpers['guard'].require_owned_output(owner)
            witness.replay_api.relative_name(name)
            need(name not in expected and type(raw) is bytes, 'fresh predetermined output')
            path = witness.output / name
            need(not path.exists(), 'fresh captured output member')
            path.parent.mkdir(parents=True, exist_ok=True)
            need(path.write_bytes(raw) == len(raw) and path.read_bytes() == raw, 'complete intended output')
            expected[name] = sha(raw)
            return path

        report['CapturedSources'] = [dict(Original=str(path), Sha256=sha(raw),
            Captured=str(write('source-buffers/%04d-%s' % (index, path.name), raw)))
            for index, (path, raw) in enumerate(sorted(witness.buffers.items()))]
        report['CapturedReaderInputs'] = [dict(Original=str(path), Sha256=digest,
            Captured=str(write('reader-inputs/%04d-%s' % (index, path.name), witness.watch.read(path, digest))))
            for index, (path, digest) in enumerate(sorted(roles.items()))]
        machine, workers, frozen = replay(runner, environment, batch, root, roles, builder.PINS)
        report.update(Status=PENDING if machine['UnresolvedAttribution'] else REPLAYED,
            Machine=machine, Workers=workers, ImmutableReader=frozen, ImmutableInputsConsumed=True,
            MachineComponentsReplayed=True, WorkerChainsReplayed=True)
        runner.seal(environment, report, expected)
        require_result(report)
        print(json.dumps(dict(Status=report['Status'], MachineRoles=20, WorkerChains=10,
            RequiredCellsSatisfied=0, Output=str(witness.output),
            ReceiptSha256=sha((witness.output / 'results.json').read_bytes()),
            ArtifactsSha256=sha((witness.output / 'artifacts.json').read_bytes())), sort_keys=True), flush=True)
        return report
    except BaseException as error:
        runner.revoke(report, error)
        report.update(MachineComponentsReplayed=False, WorkerChainsReplayed=False,
                      **dict.fromkeys(NONCLAIMS, False))
        if owner._started:
            try:
                builder.recover_owned(runner, environment, owner, helpers['guard'])
            except BaseException as secondary:
                report.setdefault('ClosingErrors', []).append('failure persistence: ' + type(secondary).__name__ + ': ' + str(secondary))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in (*ARGUMENTS, 'native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
                 'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
                 'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        with patch('subprocess.Popen', side_effect=AssertionError('machine replay cannot execute processes')), \
                patch('os.system', side_effect=AssertionError('machine replay cannot execute shell commands')):
            run(args, *prepare(args))
        return 0
    except BaseException as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
