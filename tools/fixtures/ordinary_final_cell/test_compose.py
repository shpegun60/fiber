"""Composition/admission fault controls, not compiler or complete-cell evidence."""
from contextlib import contextmanager
import copy
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name, path, digest=None):
    raw = path.read_bytes()
    if digest is not None:
        import hashlib
        if hashlib.sha256(raw).hexdigest().upper() != digest:
            raise AssertionError('fixed test helper buffer')
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


c = load('_ordinary_compose_subject', HERE / 'compose.py')
p = load('_ordinary_compose_profiles', HERE / 'profiles.py')
q = load('_ordinary_compose_qualified', HERE.parent / 'cm0_final_cell/compose.py',
         'E115BEC0D38CC2E753CD8331EA369414FF62C52A5BC4F6434F2A1458A00FB8DF')
replay = load('_ordinary_compose_catalog', ROOT / 'tools/freeze_replay.py',
              '142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275')


def descriptor(root, receipt='A', manifest='B'):
    return dict(Build=str(root), ReceiptSha256=receipt * 64, ArtifactsSha256=manifest * 64)


def catalog(root, routes):
    return dict(SchemaVersion=1, Selections=[dict(Route=route,
        **{side: descriptor(root / route.replace('/', '-') / side) for side in ('Inventory', *c.SIDES)})
        for route in routes])


def fixture(root, profile='CM3', mode='Os'):
    contract = p.profile(profile, mode)
    output, native, reference, prior = (root / name for name in ('Output', 'Native', 'Reference', 'Prior'))
    for path in (native, reference, prior):
        path.mkdir()
    selection = dict(Route=contract['Route'], Native=descriptor(native), Reference=descriptor(reference),
                     PriorJoin=descriptor(prior), Inventory=descriptor(root / 'Inventory'))
    trace = []

    class Watch:
        hashes, identities = {}, {}
        fail_close, fail_tree = False, False

        def close(self):
            trace.append('close inputs')
            if self.fail_close:
                raise RuntimeError('late input drift')

        def tree(self, base, expected):
            trace.append('seal outputs')
            if self.fail_tree:
                raise RuntimeError('late output membership drift')
            actual = {path.relative_to(base).as_posix(): c.sha(path.read_bytes())
                      for path in base.rglob('*') if path.is_file()}
            if actual != expected:
                raise RuntimeError('test output closure differs')

    watch = Watch()

    def same(left, right, label):
        if c.encoded(left) != c.encoded(right):
            raise ValueError(label)

    api = SimpleNamespace(PIN='a50edad08b29052631aa469d4df6e6ec7ff68878', same=same,
        checked_path=lambda value, **_: Path(value),
        files_under=lambda base: {path.relative_to(base).as_posix(): path for path in base.rglob('*') if path.is_file()})
    current = dict(Bundle=dict(Root=root / 'Inventory'), Required=dict(RequiredCellCount=2774),
        Manifest=dict(scope_backlog=[dict(Id='backlog-' + str(i)) for i in range(26)]),
        SourceInventorySha256=contract['SourceInventorySha256'])

    class Coverage:
        calls = []
        fail_verified, fail_recovery = False, False

        def coverage(self, required, backlog, contracts, keys):
            trace.append(('coverage', copy.deepcopy(keys)))
            self.calls.append((required, backlog, contracts, keys))
            if keys and self.fail_verified:
                raise RuntimeError('qualification accounting failed')
            if not keys and self.fail_recovery:
                raise RuntimeError('recovery accounting failed')
            return (dict(RequiredCellCount=2774, RequiredCellsSatisfied=len(keys), GlobalFreezeQualified=False),
                    dict(RequiredCellsSatisfied=len(keys), Backlog=copy.deepcopy(backlog), GlobalFreezeQualified=False))

    coverage = Coverage()
    coverage.calls = []

    @contextmanager
    def immutable(*args):
        trace.append('enter buffers')
        yield dict(Scope='SYNTHETIC_UNIT_BUFFER_SCOPE_NOT_INPUT_PROOF')
        trace.append('leave buffers')

    joined = SimpleNamespace(close=lambda: trace.append('real joined closing'))
    facts = dict(Profile=profile, Mode=mode, MechanismParityWithDeclaredDifferences=True,
                 Bindings=dict(Status='PASS'), NativePredicates=dict(Sources=[]))

    def recompute(*args):
        trace.append('recompute')
        return copy.deepcopy(facts), joined, {}

    def run_components(bundle, **kwargs):
        trace.append('fresh components')
        if kwargs['profile'] != profile or kwargs['mode'] != mode or kwargs['inventory'] is not current:
            raise AssertionError('exact selected component route')
        base = Path(kwargs['output_dir'])
        base.mkdir()
        result = dict(Status='ORDINARY-DIRECT-LINK-CONTROLS-PASS', ComponentPhasesComplete=True,
            Base=copy.deepcopy(selection['Native']), Error=None, PrimaryError=None, ClosingErrors=[],
            InputClosureVerified=True, OutputSealVerified=True, RequiredCellsSatisfied=0, IntendedLinkRejects=5,
            Profile=profile, Mode=mode, Cohort=contract['Cohort'], SourceInventorySha256=contract['SourceInventorySha256'],
            Controls=[dict(Name=str(i)) for i in range(5)], ABIProbes={str(i): {} for i in range(5)},
            IsolatedCommon=[{} for _ in range(3)])
        raw = c.encoded(result)
        (base / 'results.json').write_bytes(raw)
        (base / 'artifacts.json').write_bytes(c.encoded(dict(Artifacts={'results.json': c.sha(raw)})))
        return result

    components = SimpleNamespace(run_components=run_components,
        succeeded=lambda row: row.get('Status') == 'ORDINARY-DIRECT-LINK-CONTROLS-PASS'
            and row.get('InputClosureVerified') is True and row.get('OutputSealVerified') is True
            and row.get('ComponentPhasesComplete') is True and row.get('RequiredCellsSatisfied') == 0
            and row.get('Error') is None)

    def bundle(item):
        trace.append('admit fresh components')
        base = Path(item['Build'])
        result_raw, manifest_raw = (base / 'results.json').read_bytes(), (base / 'artifacts.json').read_bytes()
        if c.sha(result_raw) != item['ReceiptSha256'] or c.sha(manifest_raw) != item['ArtifactsSha256']:
            raise RuntimeError('fresh component descriptor drift')
        artifacts = json.loads(manifest_raw)['Artifacts']
        for name, digest in artifacts.items():
            if c.sha((base / name).read_bytes()) != digest:
                raise RuntimeError('fresh component artifact drift')
        return dict(Result=json.loads(result_raw), Artifacts=artifacts)

    env = dict(Api=api, Watch=watch, Helpers={}, Modules=dict(qualified=SimpleNamespace(
        immutable_reads=immutable, seal=q.seal, revoke=q.revoke), coverage=coverage,
        recompute=SimpleNamespace(recompute=recompute), bindings=object(), components=components),
        Admission=SimpleNamespace(bundle=bundle), Current=current, Selection=selection, Contract=contract,
        Groups={side: dict(Root=path, Result={}) for side, path in zip(c.SIDES, (native, reference, prior))}, Output=output,
        Catalog=dict(Path='synthetic-catalog.json', Sha256='C' * 64), Interpreter=dict(Synthetic=True))
    return SimpleNamespace(env=env, trace=trace, watch=watch, coverage=coverage, facts=facts, components=components,
                           output=output, contract=contract, selection=selection)


class ComposeTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(subprocess, 'Popen', side_effect=AssertionError('no tools in composition unit controls'))
        guard.start()
        self.addCleanup(guard.stop)

    def test_selects_each_explicit_route_from_complete_catalog_without_mutation(self):
        routes = [profile + '/' + mode + '/direct' for profile in p.PROFILES for mode in p.MODES]
        model = catalog(HERE, routes)
        before = copy.deepcopy(model)
        for route in routes:
            row, contract, all_rows = c.select(replay, p, model, route)
            self.assertEqual((row['Route'], contract['Route'], len(all_rows)), (route, route, 30))
        self.assertEqual(model, before)

    def test_selection_rejects_implicit_duplicate_unknown_and_lto_routes(self):
        for routes, selected in ((['CM3/O2/direct'], None), (['CM3/O2/direct'], 'CM7/O3/direct'),
                                 (['CM3/O2/direct'] * 2, 'CM3/O2/direct'),
                                 (['CM3/O2/direct', 'CM3/O2-lto/direct'], 'CM3/O2/direct'),
                                 (['CM3/O2/direct'], True)):
            with self.subTest(routes=routes, selected=selected), self.assertRaises(ValueError):
                c.select(replay, p, catalog(HERE, routes), selected)

    def test_generic_flow_credits_only_one_exact_key_for_each_of_thirty_routes(self):
        for profile in p.PROFILES:
            for mode in p.MODES:
                with self.subTest(profile=profile, mode=mode), tempfile.TemporaryDirectory() as temporary:
                    item = fixture(Path(temporary), profile, mode)
                    result = c.compose(item.env)
                    self.assertTrue(c.succeeded(result))
                    self.assertEqual(result['Route'], profile + '/' + mode + '/direct')
                    key = tuple(item.contract[name] for name in ('Cohort', 'ArtifactRole', 'Representation', 'Mode', 'Linkage'))
                    self.assertEqual(item.coverage.calls[-1][-1], [key])
                    self.assertEqual(result['RequiredCellsSatisfied'], 1)
                    self.assertLess(item.trace.index('leave buffers'), item.trace.index('fresh components'))
                    self.assertLess(item.trace.index('admit fresh components'), item.trace.index('real joined closing'))
                    self.assertIs(result['CpuExecution'], False)

    def test_recompute_failure_stops_before_components_and_revokes_credit(self):
        with tempfile.TemporaryDirectory() as temporary:
            item = fixture(Path(temporary))
            item.env['Modules']['recompute'].recompute = lambda *_: (_ for _ in ()).throw(RuntimeError('bad original relocation'))
            result = c.compose(item.env)
            self.assertEqual(result['PrimaryError'], 'RuntimeError: bad original relocation')
            self.assertNotIn('fresh components', item.trace)
            self.assertEqual(result['RequiredCellsSatisfied'], 0)
            self.assertEqual(json.loads((item.output / 'coverage.json').read_bytes())['RequiredCellsSatisfied'], 0)

    def test_failed_binding_or_protocol_facts_cannot_reach_components(self):
        for key in ('binding', 'protocol'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                item = fixture(Path(temporary))
                if key == 'binding':
                    item.facts['Bindings']['Status'] = 'FAIL'
                else:
                    item.facts['MechanismParityWithDeclaredDifferences'] = False
                result = c.compose(item.env)
                self.assertFalse(c.succeeded(result))
                self.assertNotIn('fresh components', item.trace)

    def test_component_route_descriptor_and_phase_mismatch_rejects(self):
        for name in ('Profile', 'Mode', 'Cohort', 'SourceInventorySha256', 'Base', 'InputClosureVerified', 'IntendedLinkRejects'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                item = fixture(Path(temporary))
                actual = item.components.run_components
                def mutated(*args, **kwargs):
                    result = actual(*args, **kwargs)
                    result[name] = (dict(result['Base'], ReceiptSha256='D' * 64) if name == 'Base'
                                    else False if name == 'InputClosureVerified'
                                    else True if name == 'IntendedLinkRejects' else 'foreign')
                    return result
                item.components.run_components = mutated
                result = c.compose(item.env)
                self.assertFalse(c.succeeded(result))
                self.assertEqual(result['RequiredCellsSatisfied'], 0)

    def test_returned_and_written_component_identity_must_agree(self):
        with tempfile.TemporaryDirectory() as temporary:
            item = fixture(Path(temporary))
            actual = item.components.run_components
            def mutated(*args, **kwargs):
                result = actual(*args, **kwargs)
                result['UnwrittenExtra'] = 'cannot be silently accepted'
                return result
            item.components.run_components = mutated
            self.assertFalse(c.succeeded(c.compose(item.env)))
            self.assertNotIn('real joined closing', item.trace)

    def test_late_input_and_output_failures_revoke_all_obligations(self):
        for attribute in ('fail_close', 'fail_tree'):
            with self.subTest(attribute=attribute), tempfile.TemporaryDirectory() as temporary:
                item = fixture(Path(temporary))
                setattr(item.watch, attribute, True)
                result = c.compose(item.env)
                self.assertFalse(c.succeeded(result))
                self.assertEqual(result['RequiredCellsSatisfied'], 0)
                self.assertTrue(all(row['Satisfied'] is False for name in ('CommonPrerequisites', 'RuntimeObligations')
                                    for row in result[name].values()))
                stored = json.loads((item.output / 'results.json').read_bytes())
                self.assertEqual(stored['Status'], 'FAIL')
                self.assertEqual(stored['RequiredCellsSatisfied'], 0)

    def test_recovery_persists_fail_before_secondary_accounting_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            item = fixture(Path(temporary))
            item.watch.fail_tree = True
            item.coverage.fail_recovery = True
            result = c.compose(item.env)
            self.assertIn('late output membership drift', result['PrimaryError'])
            self.assertTrue(any('recovery accounting failed' in value for value in result['ClosingErrors']))
            self.assertEqual(json.loads((item.output / 'results.json').read_bytes())['RequiredCellsSatisfied'], 0)

    def test_coverage_write_error_preserves_primary_and_no_persisted_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            item = fixture(Path(temporary))
            original = Path.write_bytes
            seen = []
            def write(path, raw):
                if path.name == 'coverage.json':
                    seen.append(json.loads((item.output / 'results.json').read_bytes())['Status']
                                if (item.output / 'results.json').exists() else 'not yet written')
                    raise OSError('coverage output unavailable')
                return original(path, raw)
            with patch.object(Path, 'write_bytes', write):
                result = c.compose(item.env)
            self.assertEqual(result['PrimaryError'], 'OSError: coverage output unavailable')
            self.assertIn('FAIL', seen)
            self.assertEqual(json.loads((item.output / 'results.json').read_bytes())['Status'], 'FAIL')

    def test_success_postcondition_rejects_partial_bool_or_broadened_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = c.compose(fixture(Path(temporary)).env)
        for key, value in (('RequiredCellsSatisfied', True), ('RequiredCellCount', True), ('Scope', 'foreign'),
                           ('CommonPrerequisites', {}), ('RuntimeObligations', {}), ('Error', 'late failure'),
                           ('ClosingErrors', ['late error']), ('FullSemanticABIProof', True), ('CpuExecution', True)):
            with self.subTest(key=key):
                self.assertFalse(c.succeeded(dict(result, **{key: value})))
        bad = copy.deepcopy(result)
        bad['RuntimeObligations']['forward-eight']['Satisfied'] = 1
        self.assertFalse(c.succeeded(bad))

    def test_main_requires_route_and_reports_only_complete_result(self):
        names = ('inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'catalog', 'catalog-sha256',
                 'route', 'output-dir')
        args = [value for name in names for value in ('--' + name, 'synthetic')]
        with tempfile.TemporaryDirectory() as temporary:
            item = fixture(Path(temporary))
            with patch.object(c, 'prepare', return_value=item.env), patch('builtins.print'):
                self.assertEqual(c.main(args), 0)
        with patch.object(c, 'prepare', side_effect=ValueError('bad authenticated input')), \
             patch.object(c, 'compose') as compose, patch('builtins.print'):
            self.assertEqual(c.main(args), 1)
            compose.assert_not_called()

    def test_source_and_qualified_function_authority_are_unchanged(self):
        self.assertEqual(c.sha((HERE.parent / 'cm0_final_cell/compose.py').read_bytes()), c.PINS['qualified'][1])
        self.assertEqual(set(c.COMMON), set(p.profile('CM7', 'O3')['CommonRequirements']))
        self.assertEqual(set(c.RUNTIME), set(p.profile('CM7', 'O3')['RuntimeRequirements']))

    def test_single_spec_authority_preserves_buffered_data_code_and_path_hooks(self):
        loader_path = ROOT / replay.LOADER
        loader_raw = loader_path.read_bytes()
        for profile in ('CM0', 'CM3', 'CM7'):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                helper = root / 'helper.py'
                raw = b'ANSWER = 7\n'
                helper.write_bytes(raw)
                watch = replay.Closure()
                watch.read(helper)
                watch.read(loader_path, replay.SOURCE_PINS[replay.LOADER])
                original_spec = importlib.util.spec_from_file_location
                original_read, original_resolve = Path.read_bytes, Path.resolve
                original_code = importlib.machinery.SourceFileLoader.get_code
                with c.immutable_scope(q, replay, watch, root / 'copies', (root, ROOT), profile) as facts:
                    self.assertIsNot(Path.read_bytes, original_read)
                    self.assertIsNot(Path.resolve, original_resolve)
                    self.assertIsNot(importlib.machinery.SourceFileLoader.get_code, original_code)
                    self.assertEqual(helper.read_bytes(), raw)
                    if profile == 'CM3':
                        self.assertIs(importlib.util.spec_from_file_location, original_spec)
                        namespace = dict(__file__=str(loader_path), __name__='_ordinary_nested_loader_unit')
                        exec(compile(loader_raw, str(loader_path), 'exec'), namespace)
                        inner = namespace['FrozenSources']({helper: raw})
                        with inner.active():
                            loaded = inner.load('_ordinary_cm3_helper_unit', helper)
                        self.assertEqual(inner.executed[0]['Sha256'], c.sha(raw))
                    else:
                        self.assertIsNot(importlib.util.spec_from_file_location, original_spec)
                        spec = importlib.util.spec_from_file_location('_ordinary_outer_helper_unit', helper)
                        loaded = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(loaded)
                    self.assertEqual(loaded.ANSWER, 7)
                    self.assertIn('SpecLoaderAuthority', facts)
                self.assertIs(importlib.util.spec_from_file_location, original_spec)
                self.assertIs(Path.read_bytes, original_read)
                self.assertIs(Path.resolve, original_resolve)
                self.assertIs(importlib.machinery.SourceFileLoader.get_code, original_code)
                watch.close()


if __name__ == '__main__':
    unittest.main()
