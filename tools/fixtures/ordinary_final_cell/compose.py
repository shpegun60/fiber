"""Compose one explicit ordinary direct static cell; never execute target code.

Invoke each route in a fresh isolated Python process. A catalog is input
authority, not a request to reuse parser/module state or award bulk credit.
"""
import argparse
import copy
from contextlib import contextmanager, nullcontext
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENT_SHA = '0421B9D9D53F9844C601AC14BC5B91074A6A4D10753C030BE2A7038FDE3D2B68'
PINS = {
    'bindings': ('ordinary_final_cell/bindings.py', '5AD660BFBF88F0F25B41434844FD2A5BA28C91D15D494AE92AAC5482C70DC6BB'),
    'coverage': ('ordinary_final_cell/coverage.py', 'D513BEA4622DB4C0CD4FC7DED6D341BF940233E4FA3B219F9723EA84E6B31DC9'),
    'recompute': ('ordinary_final_cell/recompute.py', '23BCFCD22B2C49F4066A7D32EA6126674D03D09CEEB6AB12AED9A352796B6956'),
    'qualified': ('cm0_final_cell/compose.py', 'E115BEC0D38CC2E753CD8331EA369414FF62C52A5BC4F6434F2A1458A00FB8DF'),
}
NONCLAIMS = ('FullABIProof', 'FullSemanticABIProof', 'WholeProviderEquivalence',
    'InstructionEquivalence', 'PolicyEquivalence', 'SourceIRProof', 'SourceToMachineSemanticProof',
    'KernelRuntimeProof', 'HandlerRoutingProven', 'CpuExecution', 'BoardExecution',
    'HostedCIQualified', 'ArchiveQualification', 'GlobalFreezeQualified')
SCOPE = 'ONE_EXPLICIT_ORDINARY_DIRECT_BOUNDED_STATIC_CELL'
SIDES = ('Native', 'Reference', 'PriorJoin')
COMMON = ('cpu-neutral-engine', 'reverse-v1-ownership', 'source-provider-identity')
RUNTIME = ('forward-eight', 'reverse-v1', 'current-slot-isolation', 'strong-handlers',
           'exact-profile-context-cohort', 'generated-assembly-reference-parity',
           'final-elf-vectors', 'negative-link-controls')


def need(condition, message):
    if not condition:
        raise ValueError('ordinary-cell-compose: ' + message)


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


def load_environment():
    need(not sys.flags.optimize and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         'fresh isolated unoptimized -I -S -B Python required')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
         'no inherited ELF parser package state')
    path = HERE / 'components.py'
    raw = path.read_bytes()
    need(sha(raw) == COMPONENT_SHA, 'fixed component implementation')
    components = module('_ordinary_cell_components', path, raw)
    helpers, watch = components.load_helpers()
    api = helpers['api']
    need(watch.read(path, COMPONENT_SHA) == raw, 'executed component buffer')
    buffers = {name: watch.read(HERE.parent / relative, digest) for name, (relative, digest) in PINS.items()}
    modules = {name: module('_ordinary_cell_' + name, HERE.parent / relative, buffers[name])
               for name, (relative, _) in PINS.items()}
    modules.update(components=components, profiles=helpers['profiles'])
    watch.read(Path(__file__).resolve())
    watch.read(HERE / 'ORDINARY_CELL_CONTRACT.md')
    for name, digest in api.SOURCE_PINS.items():
        watch.read(ROOT / name, digest)
    return api, watch, helpers, modules


def select(api, profiles, catalog, route):
    """Closed metadata selection only; no receipt or compiler proof is implied."""
    rows = api.validate_catalog(catalog)
    models = {row['Route']: profiles.route_contract(row['Route']) for row in rows}
    need(type(route) is str and route in models, 'one exact explicit ordinary route from the catalog')
    matches = [row for row in rows if row['Route'] == route]
    need(len(matches) == 1, 'unique selected catalog row')
    return copy.deepcopy(matches[0]), models[route], rows


def prepare(args):
    api, watch, helpers, modules = load_environment()
    catalog_path = api.checked_path(args.catalog)
    catalog = api.structured(watch.read(catalog_path, api.digest(args.catalog_sha256)))
    selection, contract, catalog_rows = select(api, modules['profiles'], catalog, args.route)
    admission = api.Admission(watch)
    current = admission.snapshot(dict(Build=args.inventory, ReceiptSha256=api.digest(args.inventory_receipt_sha256),
        ArtifactsSha256=api.digest(args.inventory_artifacts_sha256)), current=True)
    api.same(selection['Inventory'], current['Bundle']['Descriptor'], 'one current inventory authority')
    api.same(current['SourceInventorySha256'], contract['SourceInventorySha256'], 'independent E9 source identity')
    groups = {side: admission.bundle(selection[side]) for side in SIDES}
    need(len({group['Root'] for group in groups.values()}) == 3, 'distinct selected producer and prior-join roles')
    for side, group in groups.items():
        admission.require_inventory_binding(group, current, required=side != 'PriorJoin')
    profile, mode = contract['Profile'], contract['Mode']
    modules['profiles'].require_native(groups['Native']['Result'], profile, mode)
    modules['profiles'].require_reference(groups['Reference']['Result'], profile, mode)
    api.report_evidence(selection['Route'], groups['PriorJoin']['Result'])
    api.require_bindings(groups['PriorJoin']['Result'], selection)
    # Validate the complete plan and selected key before creating any output.
    modules['coverage'].coverage(current['Required'], current['Manifest']['scope_backlog'], [contract], [])
    interpreter = api.interpreter_path()
    watch.read(interpreter)
    output = api.checked_path(args.output_dir, fresh=True)
    declared = {api.checked_path(row[side]['Build'], directory=True) for row in catalog_rows for side in SIDES}
    denied = watch.denied | declared | {path.parent for path in watch.hashes}
    need(all(not output.is_relative_to(path) and not path.is_relative_to(output) for path in denied),
         'output overlaps admitted or catalog-declared evidence/source/tool roots')
    watch.close()
    return dict(Api=api, Watch=watch, Helpers=helpers, Modules=modules, Admission=admission,
        Current=current, Selection=selection, Contract=contract, Groups=groups, Output=output,
        Catalog=dict(Path=str(catalog_path), Sha256=watch.hashes[catalog_path]),
        Interpreter=dict(ModulePath=str(interpreter), Sha256=watch.hashes[interpreter], Version=sys.version,
                         Isolated=True, NoSite=True, BytecodeWrites=False, Optimized=False))


def require_components(api, components, modules, selection, contract, native_root):
    need(modules['components'].succeeded(components), 'fresh complete component suite and closing')
    for key in ('ReceiptSha256', 'ArtifactsSha256'):
        api.same(components['Base'][key], selection['Native'][key], 'fresh native descriptor: ' + key)
    need(api.checked_path(components['Base']['Build'], directory=True) == native_root, 'fresh native root')
    for key in ('Profile', 'Mode', 'Cohort', 'SourceInventorySha256'):
        api.same(components[key], contract[key], 'same fresh component route: ' + key)
    need(type(components['IntendedLinkRejects']) is int and components['IntendedLinkRejects'] == 5
         and len(components['Controls']) == 5 and len(components['ABIProbes']) == 5
         and len(components['IsolatedCommon']) == 3, 'complete actual component phases')


@contextmanager
def immutable_scope(qualified, api, watch, copy_root, closed_roots, profile):
    """Keep one spec-loader authority while retaining every buffered data hook."""
    original_spec = importlib.util.spec_from_file_location
    with qualified.immutable_reads(api, watch, copy_root, closed_roots) as evidence:
        # The CM3 family supplies its own frozen spec loader; chaining two of
        # those loaders rejects the inner loader's explicitly supplied loader.
        authority = (patch.object(importlib.util, 'spec_from_file_location', original_spec)
                     if profile == 'CM3' else nullcontext())
        with authority:
            evidence['SpecLoaderAuthority'] = ('CM3_FAMILY_FROZEN_LOADER' if profile == 'CM3'
                                               else 'QUALIFIED_OUTER_FROZEN_LOADER')
            yield evidence


def recover(api, output, report, required, backlog, contract, coverage):
    """Persist revoked credit first, even if later debug artifacts cannot be saved."""
    def attempt(label, action):
        try:
            action()
        except BaseException as failure:
            report['ClosingErrors'].append(label + ': ' + type(failure).__name__ + ': ' + str(failure))

    write_report = lambda: (output / 'results.json').write_bytes(encoded(report))
    attempt('initial FAIL receipt', write_report)
    try:
        covered, missing = coverage.coverage(required, backlog, [contract], [])
    except BaseException as failure:
        report['ClosingErrors'].append('recovery coverage model: ' + type(failure).__name__ + ': ' + str(failure))
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


def compose(environment):
    api, watch, helpers, modules = (environment[key] for key in ('Api', 'Watch', 'Helpers', 'Modules'))
    admission, current, selection, contract, groups, output = (environment[key] for key in
        ('Admission', 'Current', 'Selection', 'Contract', 'Groups', 'Output'))
    key = [contract[name] for name in ('Cohort', 'ArtifactRole', 'Representation', 'Mode', 'Linkage')]
    common, runtime = contract['CommonRequirements'], contract['RuntimeRequirements']
    report = dict(Status='FAIL', Scope=SCOPE, Route=selection['Route'], Profile=contract['Profile'], Mode=contract['Mode'],
        Error=None, PrimaryError=None, ClosingErrors=[], RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
        CellContractSatisfied=False, RequiredCellCount=2774, Key=key, CommonPrerequisites={}, RuntimeObligations={},
        Catalog=copy.deepcopy(environment['Catalog']), Interpreter=copy.deepcopy(environment['Interpreter']),
        SourceInventorySha256=current['SourceInventorySha256'], ReferenceCommit=api.PIN,
        InputClosureVerified=False, OutputSealVerified=False, **dict.fromkeys(NONCLAIMS, False))
    expected, joined_watch = {}, None
    output.mkdir(parents=True)
    try:
        with immutable_scope(modules['qualified'], api, watch, output / 'recomputed/inputs',
                (ROOT, current['Bundle']['Root'], *(group['Root'] for group in groups.values())), contract['Profile']) as frozen:
            facts, joined_watch, copies = modules['recompute'].recompute(api, watch, output, selection, groups,
                current, contract, modules['bindings'])
        need(facts['MechanismParityWithDeclaredDifferences'] is True and facts['Bindings']['Status'] == 'PASS',
             'recomputed complete mechanisms and final thin bindings')
        facts['ImmutableReads'] = frozen
        expected.update(copies)
        component_output = output / 'components'
        components = modules['components'].run_components(groups['Native'], profile=contract['Profile'],
            mode=contract['Mode'], inventory=current, helpers=helpers, watch=watch, output_dir=str(component_output))
        require_components(api, components, modules, selection, contract, groups['Native']['Root'])
        descriptor = dict(Build=str(component_output), ReceiptSha256=sha((component_output / 'results.json').read_bytes()),
            ArtifactsSha256=sha((component_output / 'artifacts.json').read_bytes()))
        closed = admission.bundle(descriptor)
        api.same(closed['Result'], components, 'fresh returned/written component identity')
        for name, digest in dict(closed['Artifacts'], **{'artifacts.json': descriptor['ArtifactsSha256']}).items():
            expected['components/' + name] = digest
        report.update(Recomputed=facts, Components=descriptor,
            CommonPrerequisites={name: dict(Satisfied=True) for name in common},
            RuntimeObligations={name: dict(Satisfied=True) for name in runtime},
            CellContractSatisfied=True, RequiredCellSatisfied=True, RequiredCellsSatisfied=1, Status='PASS')
        covered, missing = modules['coverage'].coverage(current['Required'], current['Manifest']['scope_backlog'],
                                                       [contract], [tuple(key)])
        for name, value in (('coverage.json', covered), ('missing-work.json', missing)):
            raw = encoded(value)
            (output / name).write_bytes(raw)
            expected[name] = sha(raw)
        joined_watch.close()
        modules['qualified'].seal(api, watch, output, report, expected)
    except BaseException as failure:
        modules['qualified'].revoke(report, failure)
        recover(api, output, report, current['Required'], current['Manifest']['scope_backlog'],
                contract, modules['coverage'])
    return report


def succeeded(report):
    def complete(name, expected):
        rows = report.get(name)
        return (type(rows) is dict and set(rows) == set(expected)
            and all(type(row) is dict and row.get('Satisfied') is True for row in rows.values()))
    return (report.get('Scope') == SCOPE and report.get('Status') == 'PASS'
        and type(report.get('RequiredCellCount')) is int and report['RequiredCellCount'] == 2774
        and report.get('CellContractSatisfied') is True
        and report.get('RequiredCellSatisfied') is True and type(report.get('RequiredCellsSatisfied')) is int
        and report['RequiredCellsSatisfied'] == 1 and report.get('InputClosureVerified') is True
        and report.get('OutputSealVerified') is True and report.get('Error') is None
        and report.get('PrimaryError') is None and report.get('ClosingErrors') == []
        and complete('CommonPrerequisites', COMMON) and complete('RuntimeObligations', RUNTIME)
        and all(report.get(name) is False for name in NONCLAIMS))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256',
                 'catalog', 'catalog-sha256', 'route', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        report = compose(prepare(args))
    except BaseException as failure:
        print('Ordinary cell admission failed: ' + type(failure).__name__ + ': ' + str(failure), file=sys.stderr)
        return 1
    print(json.dumps({name: report.get(name) for name in ('Status', 'Route', 'Error', 'RequiredCellsSatisfied',
        'CellContractSatisfied', 'InputClosureVerified', 'OutputSealVerified')}, sort_keys=True))
    return 0 if succeeded(report) else 1


if __name__ == '__main__':
    raise SystemExit(main())
