"""Compose one CM0/O2/direct static cell; never execute target code."""
import argparse
import copy
from contextlib import contextmanager
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
REPLAY = 'tools/freeze_replay.py'
REPLAY_SHA = '142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275'
JOIN = 'tools/fixtures/cm0_final_join/join.py'
PINS = dict(components='16490A20B1A75C5DBD2D21A5FED988C5BD82F4DE919350985B33491CE473A5F7',
            bindings='2237D0615B6D39FF2B7028F18FAC55685644F4B4A4ADD7ACEFDD736E2966E168')
COHORT = 'cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default'
KEY = (COHORT, 'runtime', 'final', 'O2', 'direct')
COMMON = ('cpu-neutral-engine', 'reverse-v1-ownership', 'source-provider-identity')
RUNTIME = ('forward-eight', 'reverse-v1', 'current-slot-isolation', 'strong-handlers',
           'exact-profile-context-cohort', 'generated-assembly-reference-parity',
           'final-elf-vectors', 'negative-link-controls')
DIFFERENCES = ('FAP-COMMON-START', 'FAP-COMMON-PROVENANCE', 'FAP-CM0-STAGED-FRAME',
               'FAP-COMMON-SCHEDULER', 'FAP-COMMON-MASK-RESTORE')
NONCLAIMS = ('FullABIProof', 'FullSemanticABIProof', 'WholeProviderEquivalence',
    'InstructionEquivalence', 'PolicyEquivalence', 'SourceIRProof', 'SourceToMachineSemanticProof',
    'KernelRuntimeProof', 'HandlerRoutingProven', 'CpuExecution', 'BoardExecution',
    'HostedCIQualified', 'ArchiveQualification', 'GlobalFreezeQualified')


def need(condition, message):
    if not condition:
        raise ValueError('cm0-cell-compose: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def module(name, path, raw):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


def cell_key(row):
    return tuple(row[name] for name in ('Cohort', 'ArtifactRole', 'Representation', 'Mode', 'Linkage'))


def coverage(required, backlog, verified):
    """Preserve every canonical key; credit at most the single exact static cell."""
    need(type(verified) is bool, 'literal qualification state')
    need(type(required) is dict and type(required.get('RequiredCellCount')) is int
         and required['RequiredCellCount'] == 2774, 'complete unchanged inventory')
    cells = required['RequiredCells']
    need(len(cells) == 2774 and len({cell_key(row) for row in cells}) == 2774, 'complete unique canonical keys')
    need(sum(cell_key(row) == KEY and row['SourceGroup'] == 'CM0' for row in cells) == 1, 'one exact CM0 cell')
    need(required['PlannedProofRequirements']['common'] == list(COMMON)
         and required['PlannedProofRequirements']['runtime'] == list(RUNTIME), 'canonical obligations')
    need(type(backlog) is list and len(backlog) == 26, 'all backlog records retained')
    rows, missing = [], []
    for cell in cells:
        item = copy.deepcopy(cell)
        passed = verified and cell_key(cell) == KEY
        obligations = required['PlannedProofRequirements'][cell['ArtifactRole']]
        item.update(Status='BOUNDED_STATIC_CELL_VERIFIED' if passed else 'PENDING',
                    RequiredCellSatisfied=passed, MissingWholeCellRequirements=[] if passed else list(obligations))
        rows.append(item)
        if not passed:
            missing.append(dict(Key=list(cell_key(cell)), MissingWholeCellRequirements=list(obligations)))
    credit = 1 if verified else 0
    return (dict(Cells=rows, RequiredCellCount=2774, RequiredCellsSatisfied=credit, GlobalFreezeQualified=False),
            dict(Cells=missing, Backlog=copy.deepcopy(backlog), RequiredCellsSatisfied=credit, GlobalFreezeQualified=False))


def rationale_facts(raw, identifiers):
    need(type(raw) is bytes and list(identifiers) == list(DIFFERENCES), 'five exact declared differences')
    text = raw.decode('ascii')
    headings = list(re.finditer(r'^#{1,3} ([^\r\n]+)\s*$', text, re.MULTILINE))
    facts = []
    for identifier in DIFFERENCES:
        matches = [index for index, row in enumerate(headings) if row[1] == identifier]
        need(len(matches) == 1, 'unique captured rationale: ' + identifier)
        index = matches[0]
        body = text[headings[index].end():headings[index + 1].start() if index + 1 < len(headings) else len(text)].strip()
        need(body and re.search(r'[A-Za-z]{3}', body), 'nonempty captured rationale: ' + identifier)
        facts.append(dict(Id=identifier, RationaleSha256=sha(body.encode('ascii'))))
    return facts


def prepare(args):
    need(not sys.flags.optimize, 'unoptimized Python required')
    replay_path = ROOT / REPLAY
    raw = replay_path.read_bytes()
    need(sha(raw) == REPLAY_SHA, 'fixed admission implementation')
    api = module('_cm0_cell_replay', replay_path, raw)
    watch = api.Closure()
    watch.read(replay_path, REPLAY_SHA)
    watch.read(Path(__file__).resolve())
    catalog = api.validate_catalog(api.structured(watch.read(args.catalog, api.digest(args.catalog_sha256))))
    need(len(catalog) == 1 and catalog[0]['Route'] == 'CM0/O2/direct', 'only the exact CM0/O2/direct route')
    selection = catalog[0]
    admission = api.Admission(watch)
    current = admission.snapshot(dict(Build=args.inventory, ReceiptSha256=api.digest(args.inventory_receipt_sha256),
                                     ArtifactsSha256=api.digest(args.inventory_artifacts_sha256)), current=True)
    api.same(selection['Inventory'], current['Bundle']['Descriptor'], 'one current inventory authority')
    groups = {side: admission.bundle(selection[side]) for side in ('Native', 'Reference', 'PriorJoin')}
    need(len({item['Root'] for item in groups.values()}) == 3, 'distinct producer/join roles')
    for side, group in groups.items():
        admission.require_inventory_binding(group, current, required=side != 'PriorJoin')
    api.report_evidence(selection['Route'], groups['PriorJoin']['Result'])
    api.require_bindings(groups['PriorJoin']['Result'], selection)
    for name, digest in api.SOURCE_PINS.items():
        watch.read(ROOT / name, digest)
    modules = {name: module('_cm0_cell_' + name, HERE / (name + '.py'),
                           watch.read(HERE / (name + '.py'), digest)) for name, digest in PINS.items()}
    watch.read(ROOT / 'tools/fixtures/freeze_cohorts/CM0_CELL_CONTRACT.md')
    output = api.checked_path(args.output_dir, fresh=True)
    denied = watch.denied | {path.parent for path in watch.hashes}
    need(all(not output.is_relative_to(path) and not path.is_relative_to(output) for path in denied),
         'output overlaps admitted sources/evidence')
    watch.close()
    return api, watch, admission, current, selection, groups, modules, output


def recheck_pilot(native, native_api, final_api, attributes, manifest):
    """Reuse the producer's full prelink and final predicates without rebuilding."""
    result, root = native['Result'], native['Root']
    pilot = native_api.Pilot.__new__(native_api.Pilot)
    pilot.root, pilot.profile, pilot.mode = ROOT, 'CM0', 'O2'
    pilot.sources = [Path(row['Source']) for row in result['Sources']]
    pilot.objects = [Path(row['Object']) for row in result['Sources']]
    pilot.object_hashes = tuple((row['Object'], row['ObjectSha256']) for row in result['Sources'])
    pilot.fixture_copy = root / 'source/tools/fixtures/classic_final_image'
    pilot.admission, pilot.final_reader = attributes, final_api
    pilot.storage = native_api.selection('CM0', 'O2')[2]
    pilot.artifact = native_api.require_manifest_selection(manifest, 'CM0', 'O2', attributes)
    pilot.report = dict(Sources=copy.deepcopy(result['Sources']))
    pilot.prelink()
    for name, value in pilot.report.items():
        need(encoded(value) == encoded(result[name]), 'recomputed native prelink: ' + name)
    for link in result['Links']:
        pilot.audit_final(Path(link['Path']))
    return pilot.report


@contextmanager
def immutable_reads(api, watch, copy_root, closed_roots):
    """Reuse the frozen source loader and bind data readers to admitted buffers."""
    loader_path = ROOT / api.LOADER
    loader = module('_cm0_cell_frozen_loader', loader_path,
                    watch.read(loader_path, api.SOURCE_PINS[api.LOADER]))
    pool, buffers = {}, {}
    for path, digest in tuple(watch.hashes.items()):
        raw = watch.read(path, digest)
        if digest not in pool:
            pool[digest] = raw
        buffers[path.resolve()] = pool[digest]
    graph = loader.FrozenSources(buffers)
    original_write = Path.write_bytes
    original_code = importlib.machinery.SourceFileLoader.get_code
    original_bytecode = sys.dont_write_bytecode
    reads, aliases, executed = {}, {}, []
    closed_roots = tuple(Path(root).resolve() for root in closed_roots)
    copy_root = copy_root.resolve()
    cwd = Path.cwd()

    def lexical(path, strict=False):
        # Physical identities are checked outside this buffered predicate scope.
        path = Path(path)
        need(not path.drive or path.is_absolute(), 'drive-relative buffered path')
        return Path(os.path.normpath(str(path if path.is_absolute() else cwd / path)))

    def read_bytes(path):
        key = lexical(path)
        need(key in buffers, 'reader escaped admitted immutable inputs: ' + str(key))
        raw = buffers[key]
        reads[str(key)] = sha(raw)
        return raw

    def read_text(path, encoding=None, errors=None, newline=None):
        with io.TextIOWrapper(io.BytesIO(read_bytes(path)), encoding=encoding, errors=errors, newline=newline) as text:
            return text.read()

    def write_copy(path, raw):
        key = lexical(path)
        need(key.is_relative_to(copy_root) and type(raw) is bytes, 'only declared immutable capture writes')
        digest = sha(raw)
        need(digest in pool and pool[digest] == raw, 'capture must contain admitted bytes')
        need(key not in buffers or buffers[key] == raw, 'capture alias changed')
        written = original_write(path, raw)
        need(written == len(raw), 'complete capture write')
        buffers[key] = pool[digest]
        graph.buffers[key] = pool[digest]
        aliases[str(key)] = digest
        return written

    def source_code(owner, name):
        path = lexical(owner.path)
        if path in buffers:
            raw = read_bytes(path)
            executed.append(dict(Name=name, Path=str(path), Sha256=sha(raw)))
            return compile(raw, str(path), 'exec')
        need(not any(path.is_relative_to(root) for root in closed_roots),
             'import escaped admitted source closure: ' + str(path))
        return original_code(owner, name)

    evidence = dict(Scope='ADMITTED_BUFFER_READS_AND_EXACT_CAPTURE_ALIASES_ONLY',
                    PathResolution='LEXICAL_ONLY_WITH_REAL_PHYSICAL_CLOSING_OUTSIDE_SCOPE',
                    UniqueInputBuffers=len(pool), InputPaths=len(buffers), Reads=reads,
                    CaptureAliases=aliases, PackageCode=executed, HelperCode=graph.executed)
    sys.dont_write_bytecode = True
    try:
        with graph.active(), patch.object(Path, 'read_bytes', read_bytes), patch.object(Path, 'read_text', read_text), \
             patch.object(Path, 'write_bytes', write_copy), \
             patch.object(Path, 'resolve', lexical), \
             patch.object(importlib.machinery.SourceFileLoader, 'get_code', source_code):
            yield evidence
    finally:
        sys.dont_write_bytecode = original_bytecode


def recompute(api, watch, output, selection, groups, current, bindings):
    join = module('_cm0_cell_join', ROOT / JOIN, watch.read(ROOT / JOIN, api.SOURCE_PINS[JOIN]))
    joined_watch = join.Watch(output / 'recomputed')
    helpers = join.load_api(joined_watch, groups['Native']['Root'])
    prepared = {side: join.prepare_group(joined_watch, groups[side]['Root'], selection[side]['ReceiptSha256'],
        side, 'CM0', 'O2', helpers) for side in ('Native', 'Reference')}
    proof = helpers['checker'].check_pair(prepared['Native']['MechanismObject'], prepared['Reference']['MechanismObject'], 'O2')
    helpers['attributes'].require_proof(proof, 'O2')
    join.require_pairings(proof, 'CM0')
    previous = groups['PriorJoin']['Result']
    for name, actual in (('ProtocolProof', proof), ('NativeFinalRoots', prepared['Native']['Roots']),
                        ('ReferenceFinalRoots', prepared['Reference']['Roots']),
                        ('NativeTwins', prepared['Native']['Twins']), ('ReferenceTwins', prepared['Reference']['Twins'])):
        api.same(actual, previous[name], 'recomputed complete join: ' + name)
    ledger = watch.read(current['Bundle']['Root'] / 'inputs/FREERTOS_ASM_PARITY.md')
    facts = dict(MechanismParityWithDeclaredDifferences=True, Protocol=proof,
                 Rationales=rationale_facts(ledger, proof['DifferenceIds']))
    facts['NativePredicates'] = recheck_pilot(groups['Native'], helpers['native'], helpers['final'],
                                             helpers['attributes'], current['Manifest'])
    facts['Bindings'] = bindings.inspect(groups['Native']['Result'], groups['Native']['Root'], helpers['final'])
    need(facts['Bindings'].get('Status') == 'PASS', 'all original/final thin bindings')
    joined_watch.close()
    for path, digest in tuple(joined_watch.hashes.items()):
        watch.read(path, digest)
    copies = {}
    for original, path in joined_watch.copies.items():
        digest = joined_watch.hashes[original]
        watch.read(path, digest)
        copies[path.relative_to(output).as_posix()] = digest
    return facts, joined_watch, copies


def seal(api, watch, output, report, expected):
    """A late seal failure must revoke credit, not just append a warning."""
    watch.close()
    report.update(InputHashes={str(path): digest for path, digest in sorted(watch.hashes.items())},
        InputPhysicalIdentities={str(path): list(value) for path, value in sorted(watch.identities.items())},
        ClosingFilesVerified=len(watch.hashes), InputClosureVerified=True, OutputSealVerified=True)
    raw = encoded(report)
    (output / 'results.json').write_bytes(raw)
    expected['results.json'] = sha(raw)
    raw = encoded(dict(Artifacts=dict(expected)))
    (output / 'artifacts.json').write_bytes(raw)
    expected['artifacts.json'] = sha(raw)
    watch.tree(output, expected)
    watch.close()


def revoke(report, error):
    message = type(error).__name__ + ': ' + str(error)
    report.update(Status='FAIL', Error=message, PrimaryError=message, CellContractSatisfied=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, InputClosureVerified=False, OutputSealVerified=False)
    for section in ('CommonPrerequisites', 'RuntimeObligations'):
        for value in report.get(section, {}).values():
            value['Satisfied'] = False


def recover(api, output, report, required, backlog):
    """Revoke a persisted PASS before attempting independent debug artifacts."""
    def attempt(label, action):
        try:
            action()
        except BaseException as error:
            report['ClosingErrors'].append(label + ': ' + type(error).__name__ + ': ' + str(error))

    write_report = lambda: (output / 'results.json').write_bytes(encoded(report))
    attempt('initial FAIL receipt', write_report)
    try:
        covered, missing = coverage(required, backlog, False)
    except BaseException as error:
        report['ClosingErrors'].append('recovery coverage model: ' + type(error).__name__ + ': ' + str(error))
    else:
        attempt('FAIL coverage', lambda: (output / 'coverage.json').write_bytes(encoded(covered)))
        attempt('FAIL missing-work', lambda: (output / 'missing-work.json').write_bytes(encoded(missing)))
    attempt('final FAIL receipt', write_report)

    def manifest():
        files = {name: sha(path.read_bytes()) for name, path in api.files_under(output).items() if name != 'artifacts.json'}
        (output / 'artifacts.json').write_bytes(encoded(dict(Artifacts=files)))

    before = len(report['ClosingErrors'])
    attempt('FAIL manifest', manifest)
    if len(report['ClosingErrors']) != before:
        attempt('FAIL receipt after manifest error', write_report)


def run(args):
    api, watch, admission, current, selection, groups, modules, output = prepare(args)
    report = dict(Status='FAIL', Scope='CM0_O2_DIRECT_BOUNDED_STATIC_CELL', Error=None, PrimaryError=None,
        ClosingErrors=[], RequiredCellSatisfied=False, RequiredCellsSatisfied=0, CellContractSatisfied=False,
        RequiredCellCount=2774, Key=list(KEY), CommonPrerequisites={}, RuntimeObligations={},
        SourceInventorySha256=current['SourceInventorySha256'], ReferenceCommit=api.PIN,
        InputClosureVerified=False, OutputSealVerified=False, **dict.fromkeys(NONCLAIMS, False))
    expected, joined_watch = {}, None
    output.mkdir(parents=True)
    try:
        with immutable_reads(api, watch, output / 'recomputed/inputs',
                (ROOT, current['Bundle']['Root'], *(group['Root'] for group in groups.values()))) as frozen:
            facts, joined_watch, copies = recompute(api, watch, output, selection, groups, current, modules['bindings'])
        facts['ImmutableReads'] = frozen
        expected.update(copies)
        component_output = output / 'components'
        native = selection['Native']
        components = modules['components'].run_components(native['Build'],
            native_receipt_sha256=native['ReceiptSha256'], native_artifacts_sha256=native['ArtifactsSha256'],
            output_dir=str(component_output))
        need(components['Status'] == 'CM0-O2-DIRECT-LINK-CONTROLS-PASS'
             and components.get('ComponentPhasesComplete') is True and components['Error'] is None
             and components['InputClosureVerified'] is True and components['OutputSealVerified'] is True,
             'fresh component suite and closing')
        descriptor = dict(Build=str(component_output), ReceiptSha256=sha((component_output / 'results.json').read_bytes()),
                          ArtifactsSha256=sha((component_output / 'artifacts.json').read_bytes()))
        closed = admission.bundle(descriptor)
        api.same(closed['Result'], components, 'fresh returned/written component identity')
        need(api.checked_path(components['Base']['Build'], directory=True) == groups['Native']['Root'],
             'fresh component positive root')
        for name in ('ReceiptSha256', 'ArtifactsSha256'):
            api.same(components['Base'][name], native[name], 'fresh component positive authority: ' + name)
        for name, digest in dict(closed['Artifacts'], **{'artifacts.json': descriptor['ArtifactsSha256']}).items():
            expected['components/' + name] = digest
        need(components['IntendedLinkRejects'] == 5 and len(components['ABIProbes']) == 5
             and len(components['IsolatedCommon']) == 3, 'complete actual component phases')
        report.update(Recomputed=facts, Components=descriptor,
            CommonPrerequisites={name: dict(Satisfied=True) for name in COMMON},
            RuntimeObligations={name: dict(Satisfied=True) for name in RUNTIME},
            CellContractSatisfied=True, RequiredCellSatisfied=True, RequiredCellsSatisfied=1, Status='PASS')
        covered, missing = coverage(current['Required'], current['Manifest']['scope_backlog'], True)
        for name, value in (('coverage.json', covered), ('missing-work.json', missing)):
            raw = encoded(value)
            (output / name).write_bytes(raw)
            expected[name] = sha(raw)
        joined_watch.close()
        seal(api, watch, output, report, expected)
    except BaseException as error:
        revoke(report, error)
        recover(api, output, report, current['Required'], current['Manifest']['scope_backlog'])
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256',
                 'catalog', 'catalog-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        report = run(args)
    except BaseException as error:
        print('CM0 cell admission failed: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps({name: report[name] for name in ('Status', 'Error', 'RequiredCellsSatisfied',
          'CellContractSatisfied', 'InputClosureVerified', 'OutputSealVerified')}, sort_keys=True))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
