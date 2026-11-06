"""Replay one fixed CM3 O2-LTO direct static cell without rebuilding targets."""
import argparse
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PINS = {
    'api': ('tools/freeze_replay.py',
        '142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275'),
    'controls': ('tools/fixtures/cm3_lto_abi_controls/controls.py',
        '7984A228966FC17641BD83D23486DB7E50BC2B7E5BC12D70A712F6E83800F14F'),
    'isolation': ('tools/fixtures/cm3_lto_isolation/isolation.py',
        '6EC1242D0ABBB120E2D684B30389B81043A67D267DE6F01F63F400FEC3E76524'),
    'attribute_runner': ('tools/fixtures/cm3_lto_attributes/runner.py',
        '9C99D38EACC8F3E3B2B63F343CA79555A66264AC76A3CA11957D2BEB0745987A'),
    'port_runner': ('tools/fixtures/cm3_lto_port_policy/runner.py',
        'E06E55AC26B3828EDA54333DC7D5E0982DCC791694A2E9FE64E2A31C3BBE9AAB'),
    'join_witness': ('tools/fixtures/cm3_lto_join/witness.py',
        '413089068C1C42ED1B9BE3E0E67E8E56BB6ABDF55CA3E3D866AC657C74B7EA97'),
    'coverage': ('tools/fixtures/ordinary_final_cell/coverage.py',
        'D513BEA4622DB4C0CD4FC7DED6D341BF940233E4FA3B219F9723EA84E6B31DC9'),
    'qualified': ('tools/fixtures/cm0_final_cell/compose.py',
        'E115BEC0D38CC2E753CD8331EA369414FF62C52A5BC4F6434F2A1458A00FB8DF'),
    'model': ('tools/fixtures/cm3_lto_final_cell/model.py',
        'B9E75BFD97510F7571F9D80161D92AF6FE2E251FEC629FE7608D7ED37CC75815'),
    'replay': ('tools/fixtures/cm3_lto_final_cell/replay.py',
        '2A4C48B121F991B6E509D9F57661867C5D638FE4FA3F4BD3F71FB1E90ACF2638'),
    'contract': ('tools/fixtures/cm3_lto_final_cell/CONTRACT.md',
        '7D5D8814CCBBC0E6DE242D0FFAF32D522E87DC6BB1844E3FE1E2C43756B1B6C2'),
}
SCOPE = 'ONE_CURRENT_CM3_O2_LTO_DIRECT_BOUNDED_STATIC_CELL'
COMPONENTS = ('ABIControls', 'Isolation', 'CommonAttributes', 'PortPolicy')
NONCLAIMS = ('FullABIProof', 'FullSemanticABIProof', 'WholeProviderEquivalence',
    'InstructionEquivalence', 'PolicyEquivalence', 'SourceIRProof', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'KernelRuntimeProof', 'HandlerRoutingProven',
    'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'ArchiveQualification', 'GlobalFreezeQualified')


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-final-cell: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def load(name, path, raw):
    result = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = result
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


class SharedClosure:
    """Use the existing combined physical/hash guard through the admission API."""
    def __init__(self, api, combined):
        self.api, self.combined = api, combined
        self.hashes = combined.hashes
        self.identities = combined.guard.identities
        self.denied = combined.guard.denied

    def read(self, path, expected=None):
        return self.combined.read(path, expected)

    def json(self, path, expected=None):
        return self.api.structured(self.read(path, expected))

    def tree(self, root, expected):
        return self.combined.tree(root, expected)

    def close(self):
        return self.combined.close()


def fixed_modules():
    need(not sys.flags.optimize and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
        'fresh unoptimized isolated -I -S -B interpreter')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
        'no inherited ELF parser package state')
    buffers, modules = {}, {}
    for name, (relative, expected) in PINS.items():
        path = ROOT / relative
        raw = path.read_bytes()
        need(sha(raw) == expected, 'fixed helper source: ' + relative)
        buffers[path] = raw
        if name != 'contract':
            modules[name] = load('cm3_final_cell_' + name, path, raw)
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    return modules, buffers


def merge_guard(watch, other):
    for path, digest in tuple(other.hashes.items()):
        watch.read(path, digest)
    for root, expected in tuple(getattr(other, 'trees', {}).items()):
        watch.tree(root, expected)
    for root, names in tuple(getattr(other, 'memberships', {}).items()):
        watch.tree(root, {name: other.hashes[root / name] for name in names})


def merge_sources(admitted, sources):
    for path, raw in sources.items():
        need(admitted.watch.read(path, sha(raw)) == raw, 'same authenticated helper buffer')
        need(path not in admitted.buffers or admitted.buffers[path] == raw, 'conflicting helper source bytes')
        admitted.buffers[path] = raw


def component_modules(modules, watch, buffers):
    result = {}
    for role, name in (('Isolation', 'isolation'), ('CommonAttributes', 'attribute_runner'),
                       ('PortPolicy', 'port_runner')):
        row = {}
        for key, (relative, digest) in modules[name].PINS.items():
            path = ROOT / relative
            raw = watch.read(path, digest)
            need(path not in buffers or buffers[path] == raw, 'component helper collision')
            buffers[path] = raw
            if key != 'contract':
                row[key] = load('cm3_final_cell_' + role + '_' + key, path, raw)
        result[role] = row
    return result


def same_capture(api, groups, native, admitted, inventory):
    for role in ('Bindings', *COMPONENTS):
        result = groups[role]['Result']
        need(api.checked_path(result['CaptureBuild'], directory=True) == native['Root'],
            'same native capture: ' + role)
        api.same([result['CaptureReceiptSha256'], result['CaptureArtifactsSha256']],
            [native['Descriptor']['ReceiptSha256'], native['Descriptor']['ArtifactsSha256']],
            'same capture digests: ' + role)
        api.same(result['CurrentInventory'], inventory['Bundle']['Descriptor'], 'same current inventory: ' + role)
        api.same(result['CurrentCaptureProducer'], admitted.report['CurrentCaptureProducer'],
            'same current producer: ' + role)
        api.same(result['SeedAuthority'], admitted.report['SeedAuthority'], 'same ordinary Seed: ' + role)
        api.same(result['SourceInventorySha256'], inventory['SourceInventorySha256'], 'same source cut: ' + role)


def prepare(args):
    modules, buffers = fixed_modules()
    api, model = modules['api'], modules['model']
    initial = api.Closure()
    catalog_path = api.checked_path(args.catalog)
    raw = initial.read(catalog_path, api.digest(args.catalog_sha256))
    catalog = model.validate_catalog(api.structured(raw))
    descriptors = catalog['Bundles']
    for row in descriptors.values():
        api.descriptor(row)
        need(str(api.checked_path(row['Build'], directory=True)) == row['Build'],
            'catalog Build must be a canonical path')
    need(len({api.checked_path(row['Build'], directory=True) for row in descriptors.values()}) == 9,
        'nine distinct input bundle roots')
    output = api.checked_path(args.output_dir, fresh=True)
    native, inventory = descriptors['Native'], descriptors['Inventory']
    arguments = SimpleNamespace(capture_build=native['Build'],
        capture_receipt_sha256=native['ReceiptSha256'], capture_artifacts_sha256=native['ArtifactsSha256'],
        inventory=inventory['Build'], inventory_receipt_sha256=inventory['ReceiptSha256'],
        inventory_artifacts_sha256=inventory['ArtifactsSha256'], output_dir=str(output))
    base, inherited = modules['controls'].prepare(arguments)
    admitted = base.admitted
    watch = SharedClosure(api, admitted.watch)
    merge_guard(watch, initial)
    merge_sources(admitted, buffers)
    admission = api.Admission(watch)
    current = admission.snapshot(inventory, current=True)
    api.same(current['SourceInventorySha256'], model.SOURCE_INVENTORY_SHA256, 'fixed E9 source cut')
    groups = {role: admission.bundle(row) for role, row in descriptors.items() if role != 'Inventory'}
    groups['Inventory'] = current['Bundle']
    for role in ('Native', 'Reference', 'Bindings', *COMPONENTS):
        admission.require_inventory_binding(groups[role], current)
    api.same(groups['Native']['Result'], admitted.authority.result, 'identical independently admitted native capture')
    for role in ('Native', 'Reference'):
        result = groups[role]['Result']
        api.same([result['Profile'], result['Mode'], result['Cohort'], result['Linkage']],
            ['CM3', 'O2-lto', model.COHORT, 'direct'], 'fixed current capture route: ' + role)
    same_capture(api, groups, groups['Native'], admitted, current)
    api.report_evidence(model.ROUTE, groups['Join']['Result'])
    rows = groups['Join']['Result']['ProducerBindings']
    need(type(rows) is list and len(rows) == 2 and [row['Side'] for row in rows] == ['Native', 'Reference'],
        'two exact protocol-child authorities')
    child_arguments = {'output_dir': str(output / 'unused-join-admission')}
    for row in rows:
        role, prefix = row['Side'], row['Side'].lower()
        need(api.checked_path(row['CaptureBuild'], directory=True) == groups[role]['Root'],
            'join child belongs to selected current capture: ' + role)
        child_arguments.update({prefix + '_build': row['Build'], prefix + '_receipt_sha256': row['ReceiptSha256'],
            prefix + '_artifacts_sha256': row['ArtifactsSha256']})
    joined = modules['join_witness'].Witness(SimpleNamespace(**child_arguments))
    merge_guard(watch, joined.watch)
    merge_sources(admitted, joined.buffers)
    for role in ('Native', 'Reference'):
        api.same(joined.groups[role]['Capture'], groups[role]['Result'], 'join same actual source capture: ' + role)
    dependencies = component_modules(modules, watch, buffers)
    merge_sources(admitted, buffers)
    suites, runners = {'ABIControls': base}, {'ABIControls': modules['controls']}
    base_class = type(base)
    for role, name in (('Isolation', 'isolation'), ('CommonAttributes', 'attribute_runner'), ('PortPolicy', 'port_runner')):
        local = dict(inherited, **dependencies[role])
        if role == 'PortPolicy':
            local.update(ownership=dependencies['CommonAttributes']['ownership'])
        suites[role] = modules[name].suite_type(base_class)(arguments, admitted, local, buffers)
        runners[role] = modules[name]
    for role, suite in suites.items():
        suite.output, suite.report = groups[role]['Root'], copy.deepcopy(groups[role]['Result'])
        if role == 'PortPolicy':
            need(runners[role].succeeded(suite.report, attribute_runner=suite.modules['attribute_runner']),
                'bounded selected-policy leaf interface')
        else:
            need(runners[role].succeeded(suite.report), 'bounded component leaf interface: ' + role)
    contract = model.contract()
    model.coverage(current['Required'], current['Manifest']['scope_backlog'], [], coverage_module=modules['coverage'])
    denied = {ROOT, *watch.denied, *(path.parent for path in watch.hashes)}
    need(all(not output.is_relative_to(path) and not path.is_relative_to(output) for path in denied),
        'fresh output disjoint from every admitted source/tool/evidence root')
    watch.close()
    return dict(Api=api, Modules=modules, Admission=admission, Admitted=admitted, Watch=watch,
        Current=current, Catalog=catalog, CatalogAuthority=dict(Path=str(catalog_path), Sha256=sha(raw)),
        Groups=groups, Join=joined, Suites=suites, Runners=runners, Contract=contract, Output=output)


def normal_roles(environment):
    result = environment['Groups']['Native']['Result']
    startup = Path(result['Sources'][-1]['Object'])
    rows = {}
    for link in result['Links']:
        machine, final = Path(link['Machine']), Path(link['Path'])
        rows[link['Kind']] = dict(Machine=machine, Final=final, Disassembly=Path(str(final) + '.dis'),
            LinkMap=Path(link['Map']), Startup=startup, Attributes=Path(str(final) + '.readelf'),
            MachineAttributes=Path(str(machine) + '.readelf'))
    need(list(rows) == ['ordinary', 'emit-relocs'], 'two ordered original normal link roles')
    return rows


def inspect_commands(environment, roles, write, records):
    suite = environment['Suites']['ABIControls']
    api, watch = environment['Api'], environment['Watch']
    tool = suite.tools['objdump']
    need(tool in watch.hashes, 'captured admitted read-only inspector')
    env = api.process_environment(dict(suite.environment))
    paths = {}
    for index, role in enumerate(('Machine', 'Final')):
        target = roles['emit-relocs'][role]
        argv = [str(tool), '-drwC', '-z', str(target)]
        prefix = 'inspection/%02d' % index
        record = dict(Role=role, Argv=argv, Cwd=str(environment['Output']), ToolSha256=watch.hashes[tool],
            Input=str(target), InputSha256=sha(watch.read(target)), State='ATTEMPT', Exit=None,
            TimedOut=None, ExpectedExit=0, JournalErrors=[])
        write(prefix + '.attempt.json', encoded(record))
        records.append(record)
        try:
            result = suite.process.run(argv, cwd=str(environment['Output']), env=env, timeout=60)
        except BaseException as error:
            record.update(State='LAUNCH-FAILED', PrimaryError=type(error).__name__ + ': ' + str(error))
            try:
                write(prefix + '.json', encoded(record))
            except BaseException as secondary:
                record['JournalErrors'].append(type(secondary).__name__ + ': ' + str(secondary))
            raise
        good = (type(result.returncode) is int and result.returncode == 0 and result.timed_out is False
            and result.stdout and result.stderr == b'')
        primary = None if good else 'unsuccessful bounded objdump inspection: %s; exit=%r timeout=%r' % (
            role, result.returncode, result.timed_out)
        record.update(State='TERMINAL', Exit=result.returncode, TimedOut=result.timed_out, PrimaryError=primary)
        for label, raw in (('Stdout', result.stdout), ('Stderr', result.stderr)):
            name = prefix + ('.stdout' if label == 'Stdout' else '.stderr')
            record.update({label: name, label + 'Sha256': sha(raw)})
            try:
                write(name, raw)
            except BaseException as error:
                record['JournalErrors'].append(label + ': ' + type(error).__name__ + ': ' + str(error))
        try:
            write(prefix + '.json', encoded(record))
        except BaseException as error:
            record['JournalErrors'].append('terminal journal: ' + type(error).__name__ + ': ' + str(error))
        need(primary is None, str(primary) + '; journal errors=' + repr(record['JournalErrors']))
        need(not record['JournalErrors'], 'objdump journal persistence: ' + repr(record['JournalErrors']))
        paths[role] = environment['Output'] / record['Stdout']
    return records, paths


@contextmanager
def immutable_scope(environment, paths):
    admitted, watch, api = (environment[name] for name in ('Admitted', 'Watch', 'Api'))
    snapshots = {admitted.base.stable_path(path): raw for path, raw in admitted.buffers.items()}
    for path in sorted(set(paths)):
        path = api.checked_path(path)
        raw = watch.read(path)
        need(path not in snapshots or snapshots[path] == raw, 'immutable data/source buffer collision')
        snapshots[path] = raw
    watch.close()
    reads = {}

    def read_bytes(path):
        key = admitted.base.stable_path(path)
        need(key in snapshots, 'immutable reader escaped declared input snapshots: ' + str(key))
        reads[str(key)] = sha(snapshots[key])
        return snapshots[key]

    def read_text(path, encoding=None, errors=None, newline=None):
        need(newline is None and encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict'),
            'bounded strict immutable text decoding')
        return read_bytes(path).decode(encoding or 'utf-8', errors or 'strict')

    def snapshot_read(path, expected=None):
        raw = read_bytes(path)
        need(expected is None or sha(raw) == api.digest(expected), 'immutable read expected digest')
        return raw

    def lexical_resolve(path, strict=False):
        need(type(strict) is bool and strict is False, 'lexical reader resolution; physical closing outside')
        return admitted.base.stable_path(path)

    with patch.object(Path, 'resolve', lexical_resolve):
        with environment['Modules']['controls'].reader_scope(admitted, snapshots) as (core, graph):
            with patch.object(Path, 'read_bytes', read_bytes), patch.object(Path, 'read_text', read_text), \
                    patch.object(admitted.watch, 'read', snapshot_read), \
                    patch.object(subprocess, 'Popen', side_effect=AssertionError('immutable replay cannot spawn processes')):
                yield core, graph, dict(Reads=reads, SourceBuffers=len(admitted.buffers),
                    InputPaths=len(snapshots), OneImmutableReaderScope=True,
                    PhysicalClosingOutsideScope=True, TargetExecution=False)


def replay_bindings(environment, core, graph, roles):
    admitted, modules = environment['Admitted'], environment['Modules']
    runner = environment['Suites']['ABIControls'].modules['admission']
    fixed_audit = graph.load('cm3_final_normal_fixed_audit', ROOT / runner.BUFFER_PINS['audit'][0])
    bindings = graph.load('cm3_final_normal_binding_rules', ROOT / runner.BUFFER_PINS['bindings'][0])
    proofs = []
    for kind, row in roles.items():
        image = core.FinalImage(row['Machine'], row['Final'], row['Disassembly'],
            provider_objects={str(row['Machine']): row['Machine'], str(row['Startup']): row['Startup']},
            link_map=row['LinkMap'], float_abi='soft')
        proof = bindings.inspect(image, core, fixed_audit, row['Attributes'].read_text('ascii'),
            emit_relocs=kind == 'emit-relocs', machine_attributes_text=row['MachineAttributes'].read_text('ascii'))
        runner.require_bindings_result(proof, emit_relocs=kind == 'emit-relocs')
        proofs.append(dict(Kind=kind, Proof=proof))
    twins = core.compare_load_images(roles['ordinary']['Final'], roles['emit-relocs']['Final'])
    environment['Api'].same(twins, admitted.authority.result['TwinLoadImages'], 'normal native actual load twins')
    previous = environment['Groups']['Bindings']['Result']
    environment['Api'].same(proofs, previous['Links'], 'fresh normal own-machine runtime binding evidence')
    environment['Api'].same(twins, previous['Twins'], 'fresh normal runtime binding twins')
    return dict(Links=proofs, Twins=twins)


def replay_join(environment, core, graph):
    joined, api = environment['Join'], environment['Api']
    decoder = graph.load('cm3_final_join_decoder', ROOT / 'tools/fixtures/cm55_tfm_parity/elf.py')
    checker = graph.load('cm3_final_join_checker', ROOT / 'tools/fixtures/cm3_freeze_parity/check.py')
    view, sides = {}, {}
    for side, folder in (('Native', 'cm3_lto'), ('Reference', 'cm3_reference_lto')):
        adapter = graph.load('cm3_final_' + side + '_adapter', ROOT / ('tools/fixtures/' + folder + '_roots/'
            + ('native.py' if side == 'Native' else 'reference.py')))
        protocol = graph.load('cm3_final_' + side + '_protocol', ROOT / ('tools/fixtures/' + folder + '_protocol/protocol.py'))
        group = joined.groups[side]
        roles = {role: row['Path'] for role, row in group['Roles'].items()}
        factory = adapter.NativeCM3LTOImage if side == 'Native' else adapter.ReferenceCM3LTOImage
        image = factory(core, roles['Machine'], roles['Final'], roles['Disassembly'],
            provider_objects={str(roles['Machine']): roles['Machine'], str(roles['Startup']): roles['Startup']},
            link_map=roles['LinkMap'])
        decoded = decoder.Object(roles['Machine'], roles['MachineDisassembly'])
        check = protocol.check_native if side == 'Native' else protocol.check_reference
        proof = check(decoded, image, checker)
        api.same(proof, group['Result']['ProtocolProof'], 'fresh complete canonical protocol: ' + side)
        api.same({row['Name']: image.function(row['Name']) for row in group['Result']['Roots']},
            {row['Name']: row for row in group['Result']['Roots']}, 'fresh complete transport records: ' + side)
        twins = core.compare_load_images(roles['Plain'], roles['Final'])
        api.same(twins, group['Result']['Twins'], 'fresh native/reference own-machine twins: ' + side)
        view_class = protocol.NativeProtocolView if side == 'Native' else protocol.ReferenceProtocolView
        view[side] = view_class(decoded, image)
        sides[side] = dict(Canonical=proof, Twins=twins)
    rules = graph.load('cm3_final_join_rules', ROOT / 'tools/fixtures/cm3_lto_join/join.py')
    proof = rules.check_join(view['Native'], view['Reference'], checker, joined.policy.decode('ascii'))
    rationales = rules.require_ledger(joined.groups['Native']['MasterLedgerBytes'].decode('ascii'), proof['ProtocolProof'])
    previous = environment['Groups']['Join']['Result']
    api.same(proof, previous['JoinProof'], 'fresh six-body native/reference composition')
    api.same(sides, previous['RecomputedSides'], 'fresh independent producer protocols and twins')
    api.same(rationales, previous['MasterDifferenceRationales'], 'fresh declared difference rationales')
    return dict(JoinProof=proof, RecomputedSides=sides, MasterDifferenceRationales=rationales)


def normal_census(environment, core, roles, dumps):
    suite = environment['Suites']['PortPolicy']
    policy = suite.modules['policy']
    definitions = environment['Groups']['PortPolicy']['Result']['IRDefinitionSurface']
    machine, final = roles['emit-relocs']['Machine'], roles['emit-relocs']['Final']
    return dict(OriginalLtrans=policy.inspect_lowered(core._ELF(machine, 'ET_REL'), core,
            dumps['Machine'].read_bytes(), definitions, whole_image=True),
        OriginalFinal=policy.inspect_final(core._ELF(final, 'ET_EXEC'), core,
            dumps['Final'].read_bytes(), definitions),
        ReplacementGeneratedBodyIdentity=False, SourceToMachineSemanticProof=False)


def recover(environment, report):
    output, modules, current = (environment[key] for key in ('Output', 'Modules', 'Current'))
    report.update(Status='FAIL', CellContractSatisfied=False, RequiredCellSatisfied=False,
        RequiredCellsSatisfied=0, InputClosureVerified=False, OutputSealVerified=False)
    for field in ('CommonPrerequisites', 'RuntimeObligations'):
        for row in report.get(field, {}).values():
            row['Satisfied'] = False

    def attempt(label, action):
        try:
            action()
        except BaseException as error:
            report['ClosingErrors'].append(label + ': ' + type(error).__name__ + ': ' + str(error))

    attempt('initial FAIL receipt', lambda: (output / 'results.json').write_bytes(encoded(report)))
    try:
        covered, missing = modules['model'].coverage(current['Required'], current['Manifest']['scope_backlog'], [],
            coverage_module=modules['coverage'])
    except BaseException as error:
        report['ClosingErrors'].append('FAIL coverage model: ' + type(error).__name__ + ': ' + str(error))
    else:
        attempt('FAIL coverage', lambda: (output / 'coverage.json').write_bytes(encoded(covered)))
        attempt('FAIL missing work', lambda: (output / 'missing-work.json').write_bytes(encoded(missing)))
    attempt('final FAIL receipt', lambda: (output / 'results.json').write_bytes(encoded(report)))
    def manifest():
        raw = encoded(dict(Artifacts={name: sha(path.read_bytes()) for name, path in
            environment['Api'].files_under(output).items() if name != 'artifacts.json'}))
        (output / 'artifacts.json').write_bytes(raw)
    previous = len(report['ClosingErrors'])
    attempt('FAIL manifest', manifest)
    if len(report['ClosingErrors']) != previous:
        attempt('FAIL receipt after manifest fault', lambda: (output / 'results.json').write_bytes(encoded(report)))
        attempt('FAIL manifest recovery', manifest)
        attempt('final FAIL diagnostics', lambda: (output / 'results.json').write_bytes(encoded(report)))


def compose(environment):
    modules, watch, current, output = (environment[name] for name in ('Modules', 'Watch', 'Current', 'Output'))
    model, api = modules['model'], environment['Api']
    report = dict(Status='FAIL', Scope=SCOPE, Route=model.ROUTE, Key=list(model.KEY), Profile='CM3',
        Mode='O2-lto', Linkage='direct', Cohort=model.COHORT, CohortSha256=model.COHORT_SHA256,
        SourceInventorySha256=model.SOURCE_INVENTORY_SHA256, ReferenceCommit=api.PIN,
        Catalog=copy.deepcopy(environment['CatalogAuthority']), Bundles=copy.deepcopy(environment['Catalog']['Bundles']),
        Error=None, PrimaryError=None, ClosingErrors=[], RequiredCellCount=2774,
        CellContractSatisfied=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
        CommonPrerequisites={}, RuntimeObligations={}, CompilerInvocations=0,
        InspectionCommands=[], InputClosureVerified=False, OutputSealVerified=False,
        **dict.fromkeys(NONCLAIMS, False))
    expected = {}
    output.mkdir(parents=True, exist_ok=False)

    def write(name, raw):
        api.relative_name(name)
        need(name not in expected and type(raw) is bytes, 'one planned byte output')
        path = output / name
        need(not path.exists(), 'fresh output member')
        path.parent.mkdir(parents=True, exist_ok=True)
        need(path.write_bytes(raw) == len(raw) and path.read_bytes() == raw, 'complete intended output bytes')
        expected[name] = sha(raw)
        return path

    try:
        suites, groups, runners = (environment[name] for name in ('Suites', 'Groups', 'Runners'))
        bundles = {role: groups[role] for role in COMPONENTS}
        records = modules['replay'].verify_records(suites, bundles, runners, environment['Admitted'].watch)
        roles = normal_roles(environment)
        _, dumps = inspect_commands(environment, roles, write, report['InspectionCommands'])
        paths = set(modules['replay'].binary_paths(suites, bundles))
        for bundle in bundles.values():
            paths.update(bundle['Root'] / name for name in bundle['Artifacts'])
        for row in roles.values():
            paths.update(row.values())
        for group in environment['Join'].groups.values():
            paths.update(row['Path'] for row in group['Roles'].values())
        source_root = suites['ABIControls'].base
        paths.update(source_root / name for name in suites['ABIControls'].bundle['Artifacts'] if name.startswith('source/'))
        paths.update(dumps.values())
        with immutable_scope(environment, paths) as (core, graph, frozen):
            bindings = replay_bindings(environment, core, graph, roles)
            joined = replay_join(environment, core, graph)
            machines = modules['replay'].inspect_machines(suites, bundles, runners, core, graph)
            census = normal_census(environment, core, roles, dumps)
        report.update(ComponentRecords=records, ComponentMachines=machines, RuntimeBindings=bindings,
            MechanismJoin=joined, NormalExecutableCensus=census,
            ImmutableReader=frozen, ExecutedReaderBuffers=copy.deepcopy(graph.executed))
        watch.close()
        report.update(CommonPrerequisites={name: dict(Satisfied=True) for name in model.COMMON},
            RuntimeObligations={name: dict(Satisfied=True) for name in model.RUNTIME},
            CellContractSatisfied=True, RequiredCellSatisfied=True, RequiredCellsSatisfied=1, Status='PASS')
        covered, missing = model.coverage(current['Required'], current['Manifest']['scope_backlog'], [model.KEY],
            coverage_module=modules['coverage'])
        write('coverage.json', encoded(covered))
        write('missing-work.json', encoded(missing))
        modules['qualified'].seal(api, watch, output, report, expected)
        need(succeeded(report), 'sealed whole-cell disposition')
    except BaseException as error:
        modules['qualified'].revoke(report, error)
        recover(environment, report)
    return report


def succeeded(report):
    if not (type(report) is dict and report.get('Status') == 'PASS' and report.get('Scope') == SCOPE
            and report.get('Route') == 'CM3/O2-lto/direct' and report.get('Error') is None
            and report.get('PrimaryError') is None and report.get('ClosingErrors') == []
            and type(report.get('RequiredCellsSatisfied')) is int and report['RequiredCellsSatisfied'] == 1
            and type(report.get('RequiredCellCount')) is int and report['RequiredCellCount'] == 2774
            and all(report.get(name) is True for name in ('CellContractSatisfied', 'RequiredCellSatisfied',
                'InputClosureVerified', 'OutputSealVerified'))
            and all(report.get(name) is False for name in NONCLAIMS)):
        return False
    for field, names in (('CommonPrerequisites', ('cpu-neutral-engine', 'reverse-v1-ownership', 'source-provider-identity')),
                         ('RuntimeObligations', ('forward-eight', 'reverse-v1', 'current-slot-isolation',
                          'strong-handlers', 'exact-profile-context-cohort', 'generated-assembly-reference-parity',
                          'final-elf-vectors', 'negative-link-controls'))):
        rows = report.get(field)
        if not (type(rows) is dict and set(rows) == set(names)
                and all(type(row) is dict and row.get('Satisfied') is True for row in rows.values())):
            return False
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('catalog', 'catalog-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    environment, report = None, None
    try:
        environment = prepare(args)
        report = compose(environment)
        print(json.dumps({key: report.get(key) for key in ('Status', 'Error', 'RequiredCellsSatisfied',
            'CellContractSatisfied', 'InputClosureVerified', 'OutputSealVerified')}, sort_keys=True), flush=True)
        return 0 if succeeded(report) else 1
    except BaseException as error:
        if environment is not None and report is not None:
            first, previous = report.get('PrimaryError'), report.get('Error')
            environment['Modules']['qualified'].revoke(report, error)
            report['PrimaryError'] = first or report['PrimaryError']
            report['Error'] = previous or report['Error']
            recover(environment, report)
        print('CM3 LTO cell admission failed: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
