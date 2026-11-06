"""Replay current Os-LTO roots or provider bindings, without whole-cell credit."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.abc
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PASS = 'CURRENT-CM3-OS-LTO-BINDINGS-PASS-NOT-QUALIFIED'
SCOPE = 'CURRENT_CM3_OS_LTO_NATIVE_LINK_AND_RUNTIME_BINDINGS_ONLY'
SOURCE = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
ARGUMENTS = ('native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
    'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
    'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir')
PINS = {
    'capture': ('tools/fixtures/cm3_current_lto_capture/capture.py',
        '1191CDCDA9FC9312B09858D6439674DBCA19ABFCE5B0108F3575AEF3C65C0852'),
    'legacy': ('tools/fixtures/cm3_os_lto_join/witness.py',
        'BEC9C699F8C62A69CB2BF35B24CF51D8815329517F83A11517BF9657D294D7AB'),
    'admission': ('tools/fixtures/cm3_current_lto_replay/os_admission.py',
        'DA5EB7F209A1787A8C909267B258D7E5B835E64B77785ACCF052306D9D91E857'),
    'frontend': ('tools/fixtures/cm3_current_lto_replay/witness.py',
        '7AFE40E8344E0E9329004BB4D9682606251C9FB05E7B17A3233BF16F1798AC4A'),
    'link_helpers': ('tools/fixtures/cm3_lto_link_contract/audit.py',
        '9D6B4E1694A8C0A2D7F2E1C7B6D108B58B103131DD7C19D45CD08238E4CED759'),
    'binding_helpers': ('tools/fixtures/cm3_lto_runtime_bindings/bindings.py',
        'A8C994427DDE61619AB789D62E198B24DEC0B05EF8D1EE8E1C28BE86536E4C3B'),
    'abi': ('tools/fixtures/cm3_os_lto_final_cell/abi.py',
        'D0471869CA413901AB51016BDA662683FAED60231FB87CD9F9BA14BFD121A73E'),
}
DOCUMENTS = {
    'tools/fixtures/cm3_current_lto_replay/CONTRACT.md':
        'CDB260181CF3A1E4999E392A7478921198A1B868DC108261390ADBC3E490A0EF',
    'tools/fixtures/cm3_os_lto_final_cell/CONTRACT.md':
        '7F6FA323F1DC117541B7DFCB7CAE4844252E7C3FD19FCF46C8CF8174E4020057',
}
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'CurrentSlotIsolationProven', 'CanonicalProtocolValidated', 'FinalRootRelocationProof',
    'CommonAttributePolicyProven', 'SelectedPortAttributePolicyProven', 'NegativeLinkControlsExecuted',
    'FinalReferenceParity', 'CompleteObjectProof', 'PolicyEquivalence', 'SourceIRProof',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'KernelRuntimeProof',
    'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'ArchiveQualification', 'GlobalFreezeQualified',
    'RequiredCellSatisfied', 'CellContractSatisfied', 'ProducerCompilersReexecuted')


def need(value, message):
    if not value:
        raise ValueError('cm3-os-lto-bindings: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def prepare(args):
    need(not sys.flags.optimize and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
        'fresh unoptimized isolated -I -S -B Python required')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
        'no inherited parser state')
    buffers = {}
    for relative, digest in (*PINS.values(), *DOCUMENTS.items()):
        path = ROOT / relative
        raw = path.read_bytes()
        need(sha(raw) == digest, 'fixed authenticated helper/contract: ' + relative)
        buffers[path] = raw
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    modules = {name: load('_cm3_os_cell_' + name, ROOT / row[0], buffers[ROOT / row[0]])
        for name, row in PINS.items()}
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'],
        extra_sources=buffers)(args)
    return dict(Witness=witness, Modules=modules)


def roles(environment):
    witness = environment['Witness']
    group = witness.groups['Native']
    record, root, artifacts = group['Result'], group['Root'], group['Artifacts']
    need(record['Profile'] == 'CM3' and record['Mode'] == 'Os-lto' and record['Linkage'] == 'direct',
        'actual Os native authority, never an O2 projection')
    startup = Path(record['Sources'][-1]['Object'])
    result = {}
    for link in record['Links']:
        kind, machine, final = link['Kind'], Path(link['Machine']), Path(link['Path'])
        need(kind in ('ordinary', 'emit-relocs') and kind not in result, 'exact unique actual twin kind')
        row = dict(Machine=machine, Final=final, Disassembly=Path(str(final) + '.dis'),
            LinkMap=Path(link['Map']), Startup=startup, Attributes=Path(str(final) + '.readelf'),
            MachineAttributes=Path(str(machine) + '.readelf'))
        paths = list(row.values())
        need(len(set(paths)) == 7 and all(not path.samefile(other)
            for index, path in enumerate(paths) for other in paths[:index]), 'seven distinct actual roles per twin')
        for path in paths:
            need(path.is_relative_to(root), 'native role inside admitted capture')
            digest = artifacts[path.relative_to(root).as_posix()]
            witness.watch.read(path, digest)
            witness.identities[path] = witness._physical(path)
        result[kind] = row
    need(list(result) == ['ordinary', 'emit-relocs'], 'ordered actual machine twins')
    return result


@contextmanager
def reader(environment, by_kind):
    witness, legacy = environment['Witness'], environment['Modules']['legacy']
    loader_path = ROOT / legacy.LOADER
    loader = load('_cm3_os_cell_loader', loader_path, witness.buffers[loader_path])
    graph = None
    snapshots = {legacy.stable(path): raw for path, raw in witness.buffers.items()}
    for row in by_kind.values():
        for path in row.values():
            raw = witness.watch.read(path)
            need(path not in snapshots or snapshots[path] == raw, 'immutable source/role collision')
            snapshots[legacy.stable(path)] = raw
    package = witness.groups['Native']['Package']
    names = {}
    for path in witness.buffers:
        if path.is_relative_to(package):
            parts = list(path.relative_to(package.parent).with_suffix('').parts)
            is_package = parts[-1] == '__init__'
            if is_package:
                parts.pop()
            name = '.'.join(parts)
            need(name not in names, 'unique captured parser module')
            names[name] = path, is_package
    need('elftools' in names and not any(name == 'elftools' or name.startswith('elftools.')
        for name in sys.modules), 'closed initially unimported parser')

    class Finder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname != 'elftools' and not fullname.startswith('elftools.'):
                return None
            need(fullname in names and target is None, 'closed captured parser imports')
            source, is_package = names[fullname]
            spec = graph.spec(fullname, source)
            if is_package:
                spec.submodule_search_locations = [str(source.parent)]
            return spec

    reads = {}
    def read_bytes(path):
        key = legacy.stable(path)
        need(key in snapshots, 'immutable reader escaped authenticated buffers: ' + str(key))
        reads[str(key)] = sha(snapshots[key])
        return snapshots[key]

    def read_text(path, encoding=None, errors=None, newline=None):
        need(encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict') and newline is None,
            'bounded strict text decode')
        return read_bytes(path).decode(encoding or 'utf-8', errors or 'strict')

    def resolve(path, strict=False):
        need(type(strict) is bool and strict is False, 'lexical reader resolution only')
        return legacy.stable(path)

    witness.close()
    previous = list(sys.meta_path)
    try:
        with patch.object(Path, 'resolve', resolve):
            graph = loader.FrozenSources(witness.buffers)
            sys.meta_path.insert(0, Finder())
            with graph.active(), patch.object(Path, 'read_bytes', read_bytes), \
                    patch.object(Path, 'read_text', read_text):
                core = graph.load('_cm3_os_cell_core', ROOT / 'tools/fixtures/classic_final_image/elf.py')
                rules = {name: graph.load('_cm3_os_cell_rule_' + name, ROOT / PINS[name][0])
                    for name in ('abi', 'link_helpers', 'binding_helpers')}
                yield core, rules, dict(OneImmutableReaderScope=True, PhysicalClosingOutsideScope=True,
                    SourceBuffers=len(witness.buffers), InputPaths=len(snapshots), Reads=reads,
                    ExecutedSourceBuffers=graph.executed)
    finally:
        sys.meta_path[:] = previous
        for name in tuple(sys.modules):
            if name == 'elftools' or name.startswith('elftools.'):
                del sys.modules[name]
    witness.close()


def base_report(witness):
    return dict(Status='FAIL', Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct',
        Cohort=witness.report['Cohort'], ReferenceCommit=witness.report['ReferenceCommit'],
        SourceInventorySha256=SOURCE, CurrentInventory=witness.report['CurrentInventory'],
        CurrentCaptureProducer=witness.report['CurrentCaptureProducer'],
        ProducerBindings=[dict(Side=side, Build=str(group['Root']), ReceiptSha256=group['ReceiptSha256'],
            ArtifactsSha256=group['ManifestSha256'], CommandsReconstructed=group['CommandsReconstructed'])
            for side, group in witness.groups.items()],
        BootstrapSources=witness.report['CurrentReplaySources'], Error=None, PrimaryError=None, ClosingErrors=[],
        Links=[], InputClosureVerified=False, OutputSealVerified=False, ImmutableInputsConsumed=False,
        FinalLinkContractValidated=False, RuntimeProviderBindingsValidated=False,
        CompilerInvocations=0, ToolInvocations=0, RequiredCellCount=2774, RequiredCellsSatisfied=0,
        **dict.fromkeys(NONCLAIMS, False))


def revoke(report, error):
    message = type(error).__name__ + ': ' + str(error)
    report['PrimaryError'] = report.get('PrimaryError') or report.get('Error') or message
    report.setdefault('ClosingErrors', [])
    report.update(Status='FAIL', Error=report.get('Error') or message, InputClosureVerified=False,
        OutputSealVerified=False, ImmutableInputsConsumed=False, FinalLinkContractValidated=False,
        RuntimeProviderBindingsValidated=False, CanonicalProtocolValidated=False,
        FinalRootRelocationProof=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)


def recover(environment, report):
    witness = environment['Witness']
    report.setdefault('ClosingErrors', [])
    def attempt(label, action):
        try:
            action()
        except BaseException as error:
            report['ClosingErrors'].append(label + ': ' + type(error).__name__ + ': ' + str(error))

    write = lambda: (witness.output / 'results.json').write_bytes(encoded(report))
    def manifest():
        artifacts = {name: sha(path.read_bytes()) for name, path in witness.replay_api.files_under(witness.output).items()
            if name != 'artifacts.json'}
        (witness.output / 'artifacts.json').write_bytes(encoded(dict(Artifacts=artifacts)))
    attempt('initial FAIL receipt', write)
    attempt('FAIL manifest', manifest)
    attempt('final FAIL receipt', write)
    attempt('final FAIL manifest', manifest)


def seal(environment, report, expected):
    witness, api = environment['Witness'], environment['Witness'].replay_api
    witness.close()
    report.update(InputHashes={str(path): digest for path, digest in sorted(witness.watch.hashes.items())},
        InputPhysicalIdentities={str(path): list(witness._physical(path)) for path in sorted(witness.watch.hashes)},
        ClosingFilesVerified=len(witness.watch.hashes), InputClosureVerified=True, OutputSealVerified=True)
    for name, value in (('results.json', report),):
        raw = encoded(value)
        (witness.output / name).write_bytes(raw)
        expected[name] = sha(raw)
    raw = encoded(dict(Artifacts=dict(expected)))
    (witness.output / 'artifacts.json').write_bytes(raw)
    output_watch = api.Closure()
    output_watch.tree(witness.output, dict(expected, **{'artifacts.json': sha(raw)}))
    witness.close()
    output_watch.close()


def run(environment):
    witness, modules = environment['Witness'], environment['Modules']
    report, expected = base_report(witness), {}
    witness.output.mkdir(parents=True, exist_ok=False)
    def write(name, raw):
        witness.replay_api.relative_name(name)
        need(type(raw) is bytes and name not in expected, 'one predetermined intended-byte output')
        path = witness.output / name
        need(not path.exists(), 'fresh output member')
        path.parent.mkdir(parents=True, exist_ok=True)
        need(path.write_bytes(raw) == len(raw) and path.read_bytes() == raw, 'complete intended output bytes')
        expected[name] = sha(raw)
        return path
    try:
        by_kind = roles(environment)
        binaries = []
        for kind, row in by_kind.items():
            for role, path in row.items():
                raw = witness.watch.read(path)
                copied = write('binary-inputs/%s/%s%s' % (kind, role, path.suffix), raw)
                binaries.append(dict(Kind=kind, Role=role, Original=str(path), Captured=str(copied), Sha256=sha(raw)))
        sources = []
        for index, (path, raw) in enumerate(sorted(witness.buffers.items())):
            copied = write('source-buffers/%04d-%s' % (index, path.name), raw)
            sources.append(dict(Original=str(path), Captured=str(copied), Sha256=sha(raw)))
        proofs = []
        with reader(environment, by_kind) as (core, rules, frozen):
            for kind, row in by_kind.items():
                image = core.FinalImage(row['Machine'], row['Final'], row['Disassembly'],
                    provider_objects={str(row['Machine']): row['Machine'], str(row['Startup']): row['Startup']},
                    link_map=row['LinkMap'], float_abi='soft')
                proof = rules['abi'].inspect(image, core, rules['link_helpers'], rules['binding_helpers'],
                    row['Attributes'].read_text('ascii'), emit_relocs=kind == 'emit-relocs',
                    machine_attributes_text=row['MachineAttributes'].read_text('ascii'))
                rules['abi'].require_result(proof, emit_relocs=kind == 'emit-relocs')
                proofs.append(dict(Kind=kind, Proof=proof))
            twins = core.compare_load_images(by_kind['ordinary']['Final'], by_kind['emit-relocs']['Final'])
            witness.api.same(twins, witness.groups['Native']['Result']['TwinLoadImages'], 'actual Os twin load image')
        report.update(Links=proofs, Twins=twins, BinaryInputs=binaries, CapturedSourceBuffers=sources,
            ImmutableReader=frozen, ImmutableInputsConsumed=True, FinalLinkContractValidated=True,
            RuntimeProviderBindingsValidated=True, Status=PASS)
        seal(environment, report, expected)
        need(succeeded(report, abi_rules=modules['abi']), 'sealed bounded Os disposition')
    except BaseException as error:
        revoke(report, error)
        recover(environment, report)
    return report


def succeeded(report, *, abi_rules):
    if not (type(report) is dict and report.get('Status') == PASS and report.get('Scope') == SCOPE
        and report.get('Profile') == 'CM3' and report.get('Mode') == 'Os-lto' and report.get('Linkage') == 'direct'
        and report.get('SourceInventorySha256') == SOURCE and report.get('Error') is None
        and report.get('PrimaryError') is None and report.get('ClosingErrors') == []
        and type(report.get('RequiredCellsSatisfied')) is int and report['RequiredCellsSatisfied'] == 0
        and type(report.get('RequiredCellCount')) is int and report['RequiredCellCount'] == 2774
        and all(report.get(key) is True for key in ('InputClosureVerified', 'OutputSealVerified',
            'ImmutableInputsConsumed', 'FinalLinkContractValidated', 'RuntimeProviderBindingsValidated'))
        and all(report.get(key) is False for key in NONCLAIMS)
        and type(report.get('Links')) is list and len(report['Links']) == 2
        and all(type(row) is dict and set(row) == {'Kind', 'Proof'} for row in report['Links'])
        and [row['Kind'] for row in report['Links']] == ['ordinary', 'emit-relocs']):
        return False
    try:
        for row in report['Links']:
            abi_rules.require_result(row['Proof'], emit_relocs=row['Kind'] == 'emit-relocs')
    except (ValueError, TypeError, KeyError):
        return False
    return True


def roots(environment):
    """Keep frozen Os predicates, but protect post-PASS summary failures too."""
    witness = environment['Witness']
    need(witness.run() is True, 'root/protocol replay failed: ' + str(witness.report.get('Error')))
    modules = environment['Modules']
    modules['frontend'].require_result(witness, dict(legacy=modules['legacy']))
    return witness.report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ARGUMENTS:
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--stage', choices=('bindings', 'roots'), default='bindings')
    args = parser.parse_args(argv)
    environment, report = None, None
    try:
        with patch('subprocess.Popen', side_effect=AssertionError('Os bindings cannot execute processes')), \
                patch('os.system', side_effect=AssertionError('Os bindings cannot execute shell commands')):
            environment = prepare(args)
            if args.stage == 'bindings':
                report = run(environment)
            else:
                report = environment['Witness'].report
                report = roots(environment)
            print(json.dumps({key: report.get(key) for key in ('Status', 'Error', 'FinalLinkContractValidated',
                'RuntimeProviderBindingsValidated', 'InputClosureVerified', 'OutputSealVerified',
                'RequiredCellsSatisfied')}, sort_keys=True), flush=True)
            return 0 if (succeeded(report, abi_rules=environment['Modules']['abi']) if args.stage == 'bindings' else report['Status'] ==
                environment['Modules']['legacy'].PASS) else 1
    except BaseException as error:
        if environment is not None and report is not None:
            revoke(report, error)
            recover(environment, report)
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
