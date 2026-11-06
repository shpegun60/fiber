"""Mock-only admission-flow controls; no filesystem fixtures or cell evidence.

Run with host Python -B. Only subject/helper/test source files are read.
prepare() sees in-memory receipts, metadata and a fake read-only closure.
No parser, compiler, subprocess, output directory or historical bundle is used.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = Path(HERE.anchor) / '_ordinary_prepare_synthetic_paths'
BUFFERS = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, expected=None):
    raw = path.read_bytes()
    if expected is not None and sha(raw) != expected:
        raise AssertionError('fixed pure helper source: ' + str(path))
    BUFFERS[path] = raw
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


BUFFERS[Path(__file__).resolve()] = Path(__file__).read_bytes()
c = load('_ordinary_prepare_compose', HERE / 'compose.py')
p = load('_ordinary_prepare_profiles', HERE / 'profiles.py',
         'BDD5C9A1F490FF3156CB4DC752F0C411F6FA07852BA5024124E91CC05601CFCD')
r = load('_ordinary_prepare_catalog', ROOT / 'tools/freeze_replay.py',
         '142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275')


def tearDownModule():
    changed = [str(path) for path, raw in BUFFERS.items() if path.read_bytes() != raw]
    if changed:
        raise AssertionError('prepare test source closure drift: ' + repr(changed))


def descriptor(root, tag):
    return dict(Build=str(root), ReceiptSha256=sha((tag + ' receipt').encode('ascii')),
                ArtifactsSha256=sha((tag + ' artifact manifest').encode('ascii')))


def fixture(route='CM3/Os/direct'):
    """The fake authorities assert call ordering, not real artifact validity."""
    trace, data, registry = [], {}, {}
    inventory_descriptor = descriptor(BASE / 'Inventory', 'synthetic current E9')
    rows = []
    for profile in p.PROFILES:
        for mode in p.MODES:
            model = p.profile(profile, mode)
            name = model['Route']
            selection = dict(Route=name, Inventory=copy.deepcopy(inventory_descriptor))
            for side in c.SIDES:
                path = BASE / 'evidence' / name.replace('/', '-') / side
                item = descriptor(path, name + ' ' + side)
                selection[side] = item
                result = dict(Profile=profile, Mode=mode, Cohort=model['Cohort'],
                    Linkage='direct', LTO=False, SourceInventorySha256=model['SourceInventorySha256'],
                    TestRole=side, SyntheticFixtureOnly=True)
                registry[path] = dict(Root=path, Descriptor=copy.deepcopy(item), Result=result, Artifacts={})
            rows.append(selection)
    catalog = dict(SchemaVersion=1, Selections=rows)
    catalog_path = BASE / 'catalogs' / 'ordinary30.json'
    interpreter = BASE / 'tools' / 'python3.13.exe'
    source = BASE / 'fixed-sources' / 'helper.py'
    output = BASE / 'fresh-cell'
    source_root = BASE / 'SourceRepo'
    current = dict(Bundle=dict(Root=BASE / 'Inventory', Descriptor=copy.deepcopy(inventory_descriptor)),
        SourceInventorySha256=p.SNAPSHOT['SourceInventorySha256'],
        Required=dict(RequiredCellCount=2774),
        Manifest=dict(scope_backlog=[dict(Id='synthetic-backlog-' + str(i)) for i in range(26)]))
    args = SimpleNamespace(catalog=str(catalog_path), catalog_sha256='', route=route,
        inventory=inventory_descriptor['Build'], inventory_receipt_sha256=inventory_descriptor['ReceiptSha256'],
        inventory_artifacts_sha256=inventory_descriptor['ArtifactsSha256'], output_dir=str(output))
    data[interpreter], data[source] = b'synthetic interpreter bytes', b'# synthetic fixed helper bytes\n'

    class Watch:
        def __init__(self):
            self.hashes = {source: sha(data[source])}
            self.denied = {source_root}
            self.fail_close = False

        def read(self, path, expected=None):
            path = Path(path)
            trace.append(('read', path))
            if path not in data:
                raise ValueError('synthetic admitted file missing: ' + str(path))
            raw = data[path]
            c.need(expected is None or sha(raw) == expected, 'synthetic caller-bound raw hash')
            c.need(path not in self.hashes or self.hashes[path] == sha(raw), 'synthetic input drift')
            self.hashes[path] = sha(raw)
            return raw

        def close(self):
            trace.append(('close',))
            if self.fail_close:
                raise RuntimeError('synthetic final admission drift')

    watch = Watch()

    def same(actual, expected, label):
        trace.append(('same', label))
        c.need(c.encoded(actual) == c.encoded(expected), label)

    class Admission:
        def __init__(self, selected_watch):
            c.need(selected_watch is watch, 'one synthetic admission closure')
            trace.append(('admission',))

        def snapshot(self, item, *, current=False):
            trace.append(('snapshot', copy.deepcopy(item), current))
            same(item, inventory_descriptor, 'synthetic current inventory descriptor')
            c.need(current is True, 'explicit current snapshot admission')
            watch.denied.add(BASE / 'Inventory')
            return snapshot

        def bundle(self, item):
            path = Path(item['Build'])
            trace.append(('bundle', path, copy.deepcopy(item)))
            c.need(path in registry, 'synthetic known selected evidence root')
            group = registry[path]
            same(item, group['Descriptor'], 'synthetic selected receipt/manifest authentication')
            watch.denied.add(path)
            return group

        def require_inventory_binding(self, group, selected, *, required=True):
            trace.append(('inventory binding', group['Root'], required))
            c.need(selected is snapshot, 'one synthetic inventory object')
            actual = group['Result'].get('SourceInventorySha256')
            c.need(not required or actual is not None, 'synthetic required reachable inventory')
            c.need(actual is None or actual == selected['SourceInventorySha256'], 'synthetic reachable inventory mismatch')
            return []

    snapshot = current

    def metadata(side, result, profile, mode):
        trace.append(('metadata', side, profile, mode))
        expected = p.profile(profile, mode)
        for field in ('Profile', 'Mode', 'Cohort'):
            same(result[field], expected[field], 'synthetic selected ' + side + ' ' + field)
        c.need(result['TestRole'] == side, 'synthetic selected producer role')

    def evidence(selected_route, result):
        trace.append(('evidence', selected_route))
        expected = p.route_contract(selected_route)
        for field in ('Profile', 'Mode', 'Cohort'):
            same(result[field], expected[field], 'synthetic prior evidence ' + field)
        c.need(result['TestRole'] == 'PriorJoin', 'synthetic prior evidence role')
        c.need(not result.get('BadEvidence'), 'synthetic invalid prior evidence')

    def bindings(result, selection):
        trace.append(('prior bindings', selection['Route']))
        c.need(not result.get('BadBindings'), 'synthetic prior producer binding mismatch')

    def coverage(required, backlog, contracts, verified):
        trace.append(('coverage', required, backlog, copy.deepcopy(contracts), copy.deepcopy(verified)))
        c.need(type(required.get('RequiredCellCount')) is int and required['RequiredCellCount'] == 2774,
               'synthetic complete canonical plan')
        c.need(len(backlog) == 26, 'synthetic complete backlog')
        c.need(len(contracts) == 1 and verified == [], 'admission cannot award cell credit')
        same(contracts[0], p.route_contract(args.route), 'synthetic selected key passed to coverage')
        return {}, {}

    invalid_paths = set()
    fresh_refusals = set()

    def checked_path(value, *, directory=False, fresh=False):
        path = Path(value)
        trace.append(('path', path, directory, fresh))
        c.need(path not in invalid_paths, 'synthetic unsafe or missing input path')
        c.need(not fresh or path not in fresh_refusals, 'synthetic output already exists')
        c.need(path.is_absolute(), 'synthetic explicit absolute path')
        return path

    def interpreter_path():
        trace.append(('interpreter',))
        return interpreter

    api = SimpleNamespace(checked_path=checked_path, digest=r.digest, structured=r.structured,
        validate_catalog=r.validate_catalog, Admission=Admission, same=same,
        report_evidence=evidence, require_bindings=bindings, interpreter_path=interpreter_path)
    profiles = SimpleNamespace(route_contract=p.route_contract,
        require_native=lambda result, profile, mode: metadata('Native', result, profile, mode),
        require_reference=lambda result, profile, mode: metadata('Reference', result, profile, mode))
    modules = dict(profiles=profiles, coverage=SimpleNamespace(coverage=coverage))
    helpers = dict(SyntheticAuthenticatedHelpers=True)
    item = SimpleNamespace(args=args, catalog=catalog, catalog_path=catalog_path, data=data,
        watch=watch, trace=trace, registry=registry, current=current, api=api, modules=modules,
        helpers=helpers, interpreter=interpreter, output=output, source_root=source_root,
        invalid_paths=invalid_paths, fresh_refusals=fresh_refusals)

    def refresh_catalog():
        data[catalog_path] = c.encoded(catalog)
        args.catalog_sha256 = sha(data[catalog_path])

    item.refresh_catalog = refresh_catalog
    item.selected = lambda: next(row for row in catalog['Selections'] if row['Route'] == args.route)
    refresh_catalog()
    return item


class PrepareTests(unittest.TestCase):
    def setUp(self):
        for target in ('Popen', 'run'):
            guard = patch.object(subprocess, target, side_effect=AssertionError('no process in admission controls'))
            guard.start()
            self.addCleanup(guard.stop)
        for method in ('mkdir', 'open', 'read_bytes', 'read_text', 'write_bytes', 'write_text'):
            guard = patch.object(Path, method, side_effect=AssertionError('no fixture filesystem access: ' + method))
            guard.start()
            self.addCleanup(guard.stop)

    def prepare(self, item):
        with patch.object(c, 'load_environment', return_value=(
                item.api, item.watch, item.helpers, item.modules)):
            return c.prepare(item.args)

    def assert_no_output_admission(self, item):
        self.assertFalse(any(row[0] == 'path' and row[1] == item.output for row in item.trace))
        self.assertFalse(any(row[0] == 'close' for row in item.trace))

    def test_each_route_authenticates_only_selected_roles_before_any_output(self):
        for profile in p.PROFILES:
            for mode in p.MODES:
                route = profile + '/' + mode + '/direct'
                with self.subTest(route=route):
                    item = fixture(route)
                    before = copy.deepcopy(item.catalog)
                    env = self.prepare(item)
                    selected = item.selected()
                    bundles = [row for row in item.trace if row[0] == 'bundle']
                    self.assertEqual([row[1] for row in bundles], [Path(selected[side]['Build']) for side in c.SIDES])
                    self.assertEqual(len(bundles), 3)
                    evidence_index = next(i for i, row in enumerate(item.trace) if row[0] == 'evidence')
                    self.assertTrue(all(i < evidence_index for i, row in enumerate(item.trace) if row[0] == 'bundle'))
                    self.assertEqual(item.trace[-1], ('close',))
                    self.assertEqual(env['Selection']['Route'], route)
                    self.assertEqual(env['Contract'], p.profile(profile, mode))
                    self.assertIs(env['Current'], item.current)
                    self.assertEqual(env['Output'], item.output)
                    self.assertEqual(env['Catalog']['Sha256'], item.args.catalog_sha256)
                    self.assertEqual(item.catalog, before)
                    self.assertEqual(env['Interpreter']['Sha256'], sha(item.data[item.interpreter]))

    def test_wrong_catalog_hash_and_invalid_selection_stop_before_admission(self):
        for change in ('hash', 'missing-route', 'unknown', 'lto', 'duplicate', 'malformed-json'):
            item = fixture()
            if change == 'hash':
                item.args.catalog_sha256 = '0' * 64
            elif change == 'missing-route':
                item.catalog['Selections'] = [row for row in item.catalog['Selections'] if row['Route'] != item.args.route]
                item.refresh_catalog()
            elif change in ('unknown', 'lto'):
                item.args.route = 'CM99/O2/direct' if change == 'unknown' else 'CM3/O2-lto/direct'
            elif change == 'duplicate':
                item.catalog['Selections'].append(copy.deepcopy(item.selected()))
                item.refresh_catalog()
            else:
                item.data[item.catalog_path] = b'{'
                item.args.catalog_sha256 = sha(b'{')
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.prepare(item)
            self.assertFalse(any(row[0] == 'admission' for row in item.trace))
            self.assert_no_output_admission(item)

    def test_wrong_current_descriptor_and_fingerprint_stop_before_producers(self):
        for change in ('receipt', 'manifest', 'selected-descriptor', 'fingerprint'):
            item = fixture()
            if change == 'receipt':
                item.args.inventory_receipt_sha256 = '0' * 64
            elif change == 'manifest':
                item.args.inventory_artifacts_sha256 = '0' * 64
            elif change == 'selected-descriptor':
                item.selected()['Inventory']['ReceiptSha256'] = '0' * 64
                item.refresh_catalog()
            else:
                item.current['SourceInventorySha256'] = '0' * 64
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.prepare(item)
            self.assertFalse(any(row[0] == 'bundle' for row in item.trace))
            self.assert_no_output_admission(item)

    def test_each_selected_receipt_and_manifest_failure_precedes_evidence(self):
        for side in c.SIDES:
            for field in ('ReceiptSha256', 'ArtifactsSha256'):
                item = fixture()
                item.selected()[side][field] = '0' * 64
                item.refresh_catalog()
                with self.subTest(side=side, field=field), self.assertRaisesRegex(ValueError, 'receipt/manifest authentication'):
                    self.prepare(item)
                self.assertFalse(any(row[0] in ('evidence', 'metadata', 'coverage') for row in item.trace))
                self.assert_no_output_admission(item)

    def test_selected_native_reference_and_prior_root_aliases_reject(self):
        for first, second in (('Native', 'Reference'), ('Native', 'PriorJoin'), ('Reference', 'PriorJoin')):
            item = fixture()
            item.selected()[second] = copy.deepcopy(item.selected()[first])
            item.refresh_catalog()
            with self.subTest(first=first, second=second), self.assertRaisesRegex(ValueError, 'distinct selected'):
                self.prepare(item)
            self.assertFalse(any(row[0] == 'inventory binding' for row in item.trace))
            self.assert_no_output_admission(item)

    def test_all_roles_bind_current_and_prior_optional_still_checks_present_facts(self):
        item = fixture()
        self.prepare(item)
        calls = [row for row in item.trace if row[0] == 'inventory binding']
        self.assertEqual([row[2] for row in calls], [True, True, False])
        for side in c.SIDES:
            for change in ('wrong', 'missing'):
                item = fixture()
                group = item.registry[Path(item.selected()[side]['Build'])]
                if change == 'wrong':
                    group['Result']['SourceInventorySha256'] = '0' * 64
                else:
                    del group['Result']['SourceInventorySha256']
                with self.subTest(side=side, change=change):
                    if side == 'PriorJoin' and change == 'missing':
                        self.prepare(item)
                    else:
                        with self.assertRaisesRegex(ValueError, 'synthetic (reachable|required reachable) inventory'):
                            self.prepare(item)
                        self.assert_no_output_admission(item)

    def test_producer_metadata_and_prior_evidence_bindings_fail_before_coverage(self):
        for side in ('Native', 'Reference'):
            for key, value in (('Profile', 'CM7'), ('Mode', 'O2'), ('Cohort', 'foreign')):
                item = fixture()
                item.registry[Path(item.selected()[side]['Build'])]['Result'][key] = value
                with self.subTest(side=side, field=key), self.assertRaises(ValueError):
                    self.prepare(item)
                self.assertFalse(any(row[0] in ('coverage', 'interpreter') for row in item.trace))
                self.assert_no_output_admission(item)
        for field in ('BadEvidence', 'BadBindings'):
            item = fixture()
            item.registry[Path(item.selected()['PriorJoin']['Build'])]['Result'][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.prepare(item)
            self.assertFalse(any(row[0] == 'coverage' for row in item.trace))
            self.assert_no_output_admission(item)

    def test_complete_plan_and_backlog_validation_are_nonpromoting_and_preoutput(self):
        item = fixture()
        self.prepare(item)
        calls = [row for row in item.trace if row[0] == 'coverage']
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0][1], item.current['Required'])
        self.assertIs(calls[0][2], item.current['Manifest']['scope_backlog'])
        self.assertEqual(calls[0][3], [p.route_contract(item.args.route)])
        self.assertEqual(calls[0][4], [])
        for change in ('plan', 'typed-count', 'backlog'):
            item = fixture()
            if change == 'plan':
                item.current['Required']['RequiredCellCount'] = 2773
            elif change == 'typed-count':
                item.current['Required']['RequiredCellCount'] = 2774.0
            else:
                item.current['Manifest']['scope_backlog'].pop()
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.prepare(item)
            self.assert_no_output_admission(item)

    def test_output_denies_selected_unselected_inventory_source_tool_and_catalog_roots(self):
        targets = ('selected', 'unselected', 'inventory', 'source', 'tool', 'catalog', 'ancestor', 'existing')
        for target in targets:
            item = fixture()
            if target == 'selected':
                output = Path(item.selected()['Native']['Build']) / 'new'
            elif target == 'unselected':
                other = next(row for row in item.catalog['Selections'] if row['Route'] != item.args.route)
                output = Path(other['Reference']['Build']) / 'new'
            elif target == 'inventory':
                output = item.current['Bundle']['Root'] / 'new'
            elif target == 'source':
                output = item.source_root / 'new'
            elif target == 'tool':
                output = item.interpreter.parent / 'new'
            elif target == 'catalog':
                output = item.catalog_path.parent / 'new'
            elif target == 'ancestor':
                output = BASE / 'evidence'
            else:
                output = item.output
                item.fresh_refusals.add(output)
            item.args.output_dir = str(output)
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'output overlaps|output already exists'):
                self.prepare(item)
            self.assertFalse(any(row[0] == 'close' for row in item.trace))

    def test_interpreter_read_and_final_close_are_required_before_returning_environment(self):
        item = fixture()
        env = self.prepare(item)
        self.assertEqual(env['Interpreter']['ModulePath'], str(item.interpreter))
        for key, value in (('Isolated', True), ('NoSite', True), ('BytecodeWrites', False), ('Optimized', False)):
            self.assertIs(env['Interpreter'][key], value)
        interpreter_index = item.trace.index(('read', item.interpreter))
        output_index = item.trace.index(('path', item.output, False, True))
        self.assertLess(interpreter_index, output_index)
        for change in ('missing-interpreter', 'closing-drift'):
            item = fixture()
            if change == 'missing-interpreter':
                del item.data[item.interpreter]
            else:
                item.watch.fail_close = True
            with self.subTest(change=change), self.assertRaises((ValueError, RuntimeError)):
                self.prepare(item)
            if change == 'missing-interpreter':
                self.assert_no_output_admission(item)

    def test_initial_helper_refusal_propagates_without_reading_or_starting_anything(self):
        item = fixture()
        with patch.object(c, 'load_environment', side_effect=ValueError('fixed source pin mismatch')), \
             patch.object(c, 'compose', side_effect=AssertionError('admission cannot compose')):
            with self.assertRaisesRegex(ValueError, 'fixed source pin mismatch'):
                c.prepare(item.args)
        self.assertEqual(item.trace, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
