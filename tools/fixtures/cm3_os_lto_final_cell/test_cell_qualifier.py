"""Independent qualifier boundary controls, not an actual qualifying run.

Published byte fixtures, detailed validators and returned helpers remain real.
Witness construction, admitted replay and input closing are disclosed lifecycle
doubles; output filesystem guards and published seal/recovery functions are real.
"""
import argparse
from contextlib import contextmanager, ExitStack, redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ENTRY = HERE / 'cell_qualifier.py'
ENTRY_SHA = 'D950845973F801F13C154BFBB8FF11338C1716C4F893E4D958559C5F3FCFD9C8'
FINALIZED = True
NINE_FIXTURE = (HERE / 'test_final_controls_census_attempt.py',
    '476B85C93B5FC76C80E3E9A30FBDBF55CF6CD37E8AC5B5026B4BFFD2708A0002')
MODEL = (HERE / 'cell_model.py',
    'E9CA01CA5DF0E459E2F8FCDF0FA3C4C2CFF725E0330EA03571F336664D5EEA53')
COVERAGE = (HERE.parent / 'ordinary_final_cell/coverage.py',
    'D513BEA4622DB4C0CD4FC7DED6D341BF940233E4FA3B219F9723EA84E6B31DC9')
CONTRACT = (HERE / 'CELL_QUALIFIER_CONTRACT.md',
    '2DC6DA23F50A9E7ADB2D71CB1B94B8B492069A5EB8F9C8A0C820FBD76726B04A')
NINE_RECEIPT = (Path('C:/fzosfinalcontrols-census-20261109-e3/results.json'),
    'A81B23B024B5DD770B061BC6BD9BAF21B3922EADA6452CA49DA45FBF023E9621')
NINE_MANIFEST = (Path('C:/fzosfinalcontrols-census-20261109-e3/artifacts.json'),
    'E3EDA80F1976C653D47C3D5CF89F6FDAB563C49886F0753191605F4E1F16DA15')
REPLAY_API = (ROOT / 'tools/freeze_replay.py',
    '142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275')
INVENTORY = Path('C:/fzin-20261104-e9')
INVENTORY_PINS = {
    'results.json': '1910B53001FD37DF4B6DC57805EE49E4381B2529E1E3ECB47FDB312EB43A4DFC',
    'artifacts.json': '640C2CAC37DFC0A10F5A6E8538E7A9F81C7967DEEDEAA4B2924A15CAA1600CEA',
    'required-cells.json': '3AFBE9C8B5534AA64CC333F7D4519F2B88E74A72485BD97E2916DAB9ECCB6E4C',
    'inputs/tools/freeze_cohorts.json': 'BC6B8EADABCAA6637FDD121D03B5CA341EEE31848D7E007D1D027AEE63EC8CBE',
}
METHODS = 33
EXPECTED_METHOD_NAMES = (
    'test_real_prepare_returns_actual_model_and_nine_helpers',
    'test_qualifier_model_coverage_contract_and_entry_precede_witness',
    'test_corrupt_model_coverage_nine_or_contract_prevents_witness',
    'test_missing_and_zero_helper_pins_are_not_optional',
    'test_contract_document_membership_is_exact',
    'test_no_postwitness_physical_reads_or_unadmitted_helper_loading',
    'test_inherited_parser_state_rejects_before_witness',
    'test_real_prepare_keeps_frozen_helper_registries_unchanged',
    'test_real_prepare_helpers_validate_outer_and_real_nine_projection',
    'test_all_eleven_mappings_bind_subrecord_and_component_hashes',
    'test_each_obligation_missing_extra_typed_flag_or_foreign_evidence_rejects',
    'test_detailed_proof_corruption_rejects_with_completion_facts_unchanged',
    'test_nonclosed_common_attribution_is_not_qualifiable',
    'test_outer_fields_counts_fingerprints_and_nonclaims_are_literal',
    'test_model_own_source_and_each_pin_are_retained_before_witness',
    'test_four_inventory_raw_buffers_bind_path_hash_size_and_descriptor',
    'test_exact_full_zero_one_accounting_and_all_backlog_rows',
    'test_copied_accounting_or_artifact_binding_cannot_forge_credit',
    'test_detached_validation_needs_no_physical_io_or_binary_constructors',
    'test_real_postseal_validator_and_persisted_one_cell_accounting',
    'test_postseal_validation_fault_persists_fail_report_coverage_and_manifest',
    'test_stdout_fault_after_real_seal_persists_all_four_failed_metadata_files',
    'test_partial_seal_after_manifest_write_persists_zero_credit_accounting',
    'test_late_input_close_failure_is_revoked_and_persisted',
    'test_missing_work_write_failure_cannot_leave_positive_coverage',
    'test_unavailable_zero_plan_still_persists_guarded_fail_and_invalidates_positive_files',
    'test_prior_byte_read_root_replacement_never_writes_foreign_output',
    'test_prior_byte_read_destination_replacement_never_overwrites_foreign_file',
    'test_recovery_failure_keeps_primary_and_zero_in_memory_credit',
    'test_fresh_metadata_destination_appearing_before_write_is_untouched',
    'test_swallowed_recovery_write_errors_cannot_be_mistaken_for_a_fail_seal',
    'test_cli_process_guards_and_abbreviation_rejection_need_no_admission',
    'test_harness_requires_exact_catalog_counts_and_no_skips',
)
SOURCES, FIXTURES, FIRST_READS = {}, {}, {}
subject = nine_fixture = prepared = original_nine = outer_proof = replay_api = None
source_bytes = {}
inventory_bytes = {}
RETENTION_ROOT = None
COMMON = ('cpu-neutral-engine', 'reverse-v1-ownership', 'source-provider-identity')
RUNTIME = ('forward-eight', 'reverse-v1', 'current-slot-isolation', 'strong-handlers',
    'exact-profile-context-cohort', 'generated-assembly-reference-parity',
    'final-elf-vectors', 'negative-link-controls')
COMPONENTS = ('OriginalCensus', 'DeferredABI', 'ABIControls', 'IsolationComponent',
    'CommonAttributes', 'PortPolicyComponent', 'OriginalComponent', 'FinalReplacementComponent',
    'FinalControlComponent')


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def catalog_matches(names, count):
    return (type(count) is int and count == METHODS
            and len(EXPECTED_METHOD_NAMES) == len(set(EXPECTED_METHOD_NAMES)) == METHODS
            and names == sorted(EXPECTED_METHOD_NAMES))


def completed(result):
    return (result is not None and type(result.testsRun) is int and result.testsRun == METHODS
            and result.wasSuccessful() and not result.failures and not result.errors
            and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses)


def retain(destination, path, raw):
    if not isinstance(path, Path) or type(raw) is not bytes:
        raise ValueError('literal source/fixture snapshot')
    if path in destination and destination[path] != raw:
        raise ValueError('first-seen byte collision: ' + str(path))
    destination.setdefault(path, raw)
    return raw


def merge(destination, incoming):
    for path, raw in incoming.items():
        retain(destination, path, raw)


def load_buffer(name, path, raw):
    value = ModuleType(name)
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def physical(path):
    info = path.lstat()
    return info.st_dev, info.st_ino, info.st_nlink


def fixture_read(path, expected):
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError('pinned metadata/archive fixture mismatch: ' + str(path))
    return retain(FIXTURES, path, raw)


def make_outer(output, *, retain_copies=False):
    """Rebind source retention only; never synthesize a detailed component proof."""
    value = deepcopy(original_nine)
    helpers, model = prepared[3], prepared[3]['cell_model']
    bootstrap_rows = {row['Path']: dict(row) for row in value['BootstrapSources']}
    retained = dict(source_bytes)
    for path, raw in prepared[5].items():
        name, digest = str(path), sha(raw)
        if name in retained and retained[name] != raw:
            raise ValueError('actual/prepared source bytes conflict: ' + name)
        retained[name] = raw
        bootstrap_rows[name] = dict(Path=name, Sha256=digest)
        value['InputHashes'][name] = digest
        value['InputPhysicalIdentities'][name] = list(physical(path))
    copies = []
    for index, name in enumerate(sorted(retained, key=Path)):
        raw = retained[name]
        target = output / 'source-buffers' / ('%04d-%s' % (index, Path(name).name))
        copies.append(dict(Original=name, Captured=str(target), Sha256=sha(raw)))
        if retain_copies:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            retain(FIXTURES, target, raw)
    value['BootstrapSources'] = [bootstrap_rows[name] for name in sorted(bootstrap_rows, key=Path)]
    value['CapturedSources'] = copies
    reader = value['ImmutableReader']
    reader['InputPaths'] += len(retained) - reader['SourceBuffers']
    reader['SourceBuffers'] = len(retained)
    value['ClosingFilesVerified'] = len(value['InputHashes'])
    value.update(Status=subject.PASS, Scope=subject.SCOPE, Route=model.ROUTE, Key=list(model.KEY),
        CohortSha256=model.COHORT_SHA256, ModelContract=model.contract(), Output=str(output),
        QualifierSource=dict(Path=str(ENTRY), Sha256=ENTRY_SHA),
        RequiredCellSatisfied=True, CellContractSatisfied=True, RequiredCellsSatisfied=1)
    names = dict(Receipt='results.json', Manifest='artifacts.json', RequiredCells='required-cells.json',
                 CohortManifest='inputs/tools/freeze_cohorts.json')
    value['CurrentInventoryInputs'] = {role: dict(Path=str(INVENTORY / name),
        Sha256=sha(inventory_bytes[name]), Bytes=len(inventory_bytes[name])) for role, name in names.items()}
    value['CurrentInventoryBytes'] = {role: inventory_bytes[name].hex() for role, name in names.items()}
    value['CommonPrerequisites'], value['RuntimeObligations'] = subject.obligation_rows(value, helpers)
    subject._accounting(value, helpers, [model.KEY])
    return value, retained


@contextmanager
def detached():
    """Actual detached validators may use pure token/byte checks, not constructors."""
    helpers = prepared[3]
    with nine_fixture.detached(), ExitStack() as stack:
        for value in helpers.values():
            for name in ('inspect', 'replay', 'mutate', 'run_cases'):
                if callable(getattr(value, name, None)):
                    stack.enter_context(patch.object(value, name,
                        side_effect=AssertionError('detached validation executed a producer/binary inspector')))
        yield


def validate(value, helpers=None):
    with detached():
        return subject.require_result(value, prepared[3] if helpers is None else helpers)


class LifecycleSuite:
    def __init__(self, case, output, retained):
        self.case, self.output, self.retained = case, output, retained
        self._started, self.output_identity = False, None
        self.expected, self.identities, self.report = {}, {}, None
        self.watch = NS(hashes={})
        self.command = Mock(side_effect=AssertionError('no commands in qualifier tests'))
        self.verify_objects = Mock()
        self._verify_outputs = Mock()

    def start(self):
        self.output.mkdir(parents=True, exist_ok=False)
        info = self.output.lstat()
        self.output_identity = info.st_dev, info.st_ino
        self._started = True
        for row in self.report['CapturedSources']:
            self.write(Path(row['Captured']).relative_to(self.output).as_posix(), self.retained[row['Original']])

    def write(self, name, raw):
        if name in self.expected:
            raise AssertionError('duplicate lifecycle intended output')
        path = self.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise AssertionError('nonfresh lifecycle output')
        self.case.assertEqual(path.write_bytes(raw), len(raw))
        self.case.assertEqual(path.read_bytes(), raw)
        info = path.lstat()
        self.expected[name] = sha(raw)
        self.identities[name] = info.st_dev, info.st_ino, info.st_nlink, info.st_size
        return path

    def _save(self, name, value):
        return self.write(name, subject.encoded(value))


class Lifecycle:
    """Real TEMP outputs/guards/seal/recovery; admitted replay and input-close doubles."""
    def __init__(self, case):
        self.case = case
        self.root = Path(tempfile.mkdtemp(prefix='os-cell-qualifier-lifecycle-'))
        self.output = self.root / 'output'
        self.seed, retained = make_outer(self.output)
        self.helpers = prepared[3]
        self.nine = self.helpers['nine_composition']
        self.suite = LifecycleSuite(case, self.output, retained)
        hashes = {Path(name): value for name, value in self.seed['InputHashes'].items()}

        def read(path, expected=None):
            path = Path(path)
            if path not in hashes:
                raise AssertionError('lifecycle watch read outside explicit admitted-metadata fixture')
            raw = path.read_bytes()
            case.assertEqual(sha(raw), hashes[path])
            if expected is not None:
                case.assertEqual(sha(raw), expected)
            return raw

        self.watch = NS(hashes=hashes, read=read)
        self.witness = NS(output=self.output, replay_api=replay_api, watch=self.watch,
                          identities={}, _physical=physical, close=Mock())
        self.environment = dict(prepared[1], Witness=self.witness)
        self.suite.watch = self.watch
        self.real_runner = prepared[0]
        self.runner = NS(base_report=lambda witness: deepcopy(self.seed),
                         revoke=self.real_runner.revoke, recover=self.real_runner.recover,
                         seal=Mock(wraps=self.real_runner.seal))
        self.builder = prepared[2]
        batch, normal = self.seed['Batch'], self.seed['OriginalCensusHandoff']
        self.args = NS(batch_build=batch['Build'], batch_receipt_sha256=batch['ReceiptSha256'],
            batch_artifacts_sha256=batch['ArtifactsSha256'], normal_build=normal['Build'],
            normal_receipt_sha256=normal['ReceiptSha256'], normal_artifacts_sha256=normal['ArtifactsSha256'])
        self.replay = Mock(return_value=tuple(deepcopy(self.seed[key]) for key in (
            'OriginalCensus', 'DeferredABI', 'ABIControls', 'IsolationComponent', 'CommonAttributes',
            'PortPolicyComponent', 'OriginalComponent', 'FinalReplacementComponent',
            'FinalControlComponent', 'ImmutableReader')))

    @contextmanager
    def active(self):
        parent = self.nine._parent(self.helpers)
        with ExitStack() as stack:
            stack.enter_context(patch.object(self.helpers['machine'], 'admit_batch',
                return_value=(Path(self.seed['Batch']['Build']), {}, {})))
            stack.enter_context(patch.object(parent, 'admit_normal', return_value=(
                Path(self.seed['OriginalCensusHandoff']['Build']), {}, deepcopy(self.seed['OriginalTargets']),
                deepcopy(self.seed['InspectionTool']), self.seed['ProjectSourceReaderRoles'])))
            stack.enter_context(patch.object(self.helpers['session'], 'suite_type',
                return_value=lambda environment, helpers, buffers: self.suite))
            stack.enter_context(patch.object(self.nine, 'replay', self.replay))
            yield

    def run(self):
        with self.active(), redirect_stdout(io.StringIO()):
            return subject.run(self.args, self.runner, self.environment, self.builder,
                               self.helpers, prepared[4], prepared[5])

    def persisted_failure(self, *, require_accounting=True):
        report_raw = (self.output / 'results.json').read_bytes()
        report = json.loads(report_raw)
        self.case.assertEqual(report['Status'], 'FAIL')
        for key in (*self.nine.FACTS, *self.nine.NONCLAIMS, 'CommonAttributionClosed'):
            self.case.assertIs(report[key], False, key)
        for key, _ in (*self.nine.COUNTERS, *self.nine.CONTROL_COUNTERS,
                       ('RecordedInspectionInvocations', 2), ('RequiredCellsSatisfied', 1)):
            self.case.assertIs(type(report[key]), int, key)
            self.case.assertEqual(report[key], 0, key)
        for field in ('CommonPrerequisites', 'RuntimeObligations'):
            for row in report[field].values():
                self.case.assertIs(row['Satisfied'], False)
        for field, name in subject.ACCOUNTING_FILES.items():
            path = self.output / name
            if require_accounting:
                raw = path.read_bytes()
                value = json.loads(raw)
                self.case.assertEqual(raw, subject.encoded(report[field]))
                self.case.assertIs(type(value['RequiredCellsSatisfied']), int)
                self.case.assertEqual(value['RequiredCellsSatisfied'], 0)
                self.case.assertEqual(len(value['Cells']), 2774)
                if field == 'Coverage':
                    self.case.assertTrue(all(row['RequiredCellSatisfied'] is False for row in value['Cells']))
            elif path.exists():
                value = json.loads(path.read_bytes())
                self.case.assertFalse(isinstance(value, dict) and value.get('RequiredCellsSatisfied') == 1)
        manifest = json.loads((self.output / 'artifacts.json').read_bytes())
        files = replay_api.files_under(self.output)
        self.case.assertEqual(set(files), set(manifest['Artifacts']) | {'artifacts.json'})
        self.case.assertNotIn('artifacts.json', manifest['Artifacts'])
        for name, digest in manifest['Artifacts'].items():
            self.case.assertEqual(sha(files[name].read_bytes()), digest, name)
        self.case.assertEqual(manifest['Artifacts']['results.json'], sha(report_raw))
        return report


def clear_parser():
    for name in list(sys.modules):
        if name == 'elftools' or name.startswith('elftools.'):
            del sys.modules[name]


@contextmanager
def bootstrap(case, *, corrupt=None, pins=None, documents=None):
    state = NS(constructed=False, reads=[], events=[], enrolled={}, registries=[])
    physical_read, real_load = Path.read_bytes, subject.load

    def read(path):
        if state.constructed:
            raise AssertionError('physical source read after Witness construction')
        state.reads.append(path)
        raw = physical_read(path)
        retain(FIRST_READS, path, raw)
        return b'synthetic corrupt source' if path == corrupt else raw

    def construct(args):
        state.constructed = True
        state.events.append('Witness')
        return NS(SyntheticWitness=True)

    constructor = Mock(side_effect=construct)

    def factory(legacy, capture, *, extra_sources):
        state.enrolled = dict(extra_sources)
        case.assertEqual(state.events, ['Transport'])
        for path, raw in extra_sources.items():
            case.assertEqual(raw, SOURCES[path], str(path))
        return constructor

    state.factory = Mock(side_effect=factory)

    def load(name, path, raw):
        value = real_load(name, path, raw)
        for attribute in ('PINS', 'DOCUMENTS', 'RECIPE_PINS', 'ALIASES', 'ORIGINAL_ALIASES'):
            registry = getattr(value, attribute, None)
            if isinstance(registry, dict):
                state.registries.append((value, attribute, deepcopy(registry)))
        if name == '_os_cell_qualifier_admission_admission':
            value.witness_type = state.factory
        if name == '_os_cell_qualifier_bootstrap_transport':
            state.events.append('Transport')
        return value

    with ExitStack() as stack:
        stack.enter_context(patch.dict(sys.modules))
        if pins is not None:
            stack.enter_context(patch.object(subject, 'PINS', pins))
        if documents is not None:
            stack.enter_context(patch.object(subject, 'DOCUMENTS', documents))
        stack.enter_context(patch.object(Path, 'read_bytes', read))
        stack.enter_context(patch.object(subject, 'load', side_effect=load))
        clear_parser()
        yield state, constructor


class BootstrapTests(unittest.TestCase):
    def test_real_prepare_returns_actual_model_and_nine_helpers(self):
        with bootstrap(self) as (state, constructor):
            actual = subject.prepare(NS())
        constructor.assert_called_once()
        self.assertEqual(len(actual), 6)
        helpers = actual[3]
        for name in ('nine_composition', 'cell_model', 'cell_coverage'):
            self.assertIsInstance(helpers[name], ModuleType)
            self.assertEqual(Path(helpers[name].__file__), ROOT / subject.PINS[name][0])
        self.assertEqual(helpers['cell_model'].contract()['Mode'], 'Os-lto')
        self.assertTrue(callable(helpers['cell_coverage']._plan))
        helpers['nine_composition'].final_control_helpers(helpers)
        self.assertTrue(state.enrolled)

    def test_qualifier_model_coverage_contract_and_entry_precede_witness(self):
        with bootstrap(self) as (state, constructor):
            actual = subject.prepare(NS())
        constructor.assert_called_once()
        self.assertEqual(actual[4], nine_fixture.prepared[4])
        self.assertEqual(len(actual[4]), 35)
        for path in (ENTRY, MODEL[0], COVERAGE[0], CONTRACT[0]):
            self.assertIn(path, state.enrolled)
            self.assertEqual(state.enrolled[path], SOURCES[path])
        self.assertEqual(state.events, ['Transport', 'Witness'])
        self.assertEqual(actual[5], state.enrolled)

    def test_corrupt_model_coverage_nine_or_contract_prevents_witness(self):
        paths = [MODEL[0], COVERAGE[0], CONTRACT[0], ROOT / subject.PINS['nine_composition'][0]]
        for path in paths:
            with self.subTest(path=path), bootstrap(self, corrupt=path) as (state, constructor):
                with self.assertRaises(ValueError):
                    subject.prepare(NS())
            constructor.assert_not_called()
            self.assertIs(state.constructed, False)

    def test_missing_and_zero_helper_pins_are_not_optional(self):
        for name in ('nine_composition', 'cell_model', 'cell_coverage'):
            for change in ('missing', 'zero', 'wrong'):
                pins = dict(subject.PINS)
                if change == 'missing':
                    del pins[name]
                else:
                    pins[name] = (pins[name][0], ('0' if change == 'zero' else 'A') * 64)
                with self.subTest(name=name, change=change), bootstrap(self, pins=pins) as (state, constructor):
                    with self.assertRaises(ValueError):
                        subject.prepare(NS())
                constructor.assert_not_called()

    def test_contract_document_membership_is_exact(self):
        relative = 'tools/fixtures/cm3_os_lto_final_cell/CELL_QUALIFIER_CONTRACT.md'
        candidates = ({}, {relative: '0' * 64}, {relative: 'A' * 64},
            dict(subject.DOCUMENTS, **{'tools/fixtures/cm3_os_lto_final_cell/FOREIGN.md': 'A' * 64}))
        for documents in candidates:
            with self.subTest(documents=documents), bootstrap(self, documents=documents) as (state, constructor):
                with self.assertRaises(ValueError):
                    subject.prepare(NS())
            constructor.assert_not_called()

    def test_no_postwitness_physical_reads_or_unadmitted_helper_loading(self):
        with bootstrap(self) as (state, constructor):
            actual = subject.prepare(NS())
        constructor.assert_called_once()
        self.assertTrue(set(state.reads) <= set(state.enrolled))
        self.assertTrue(set(actual[2].PINS) <= set(actual[3]))
        self.assertTrue(set(actual[3]['nine_composition'].READER_HELPERS) <= set(actual[3]))

    def test_inherited_parser_state_rejects_before_witness(self):
        with bootstrap(self) as (state, constructor):
            sys.modules['elftools'] = ModuleType('elftools')
            with self.assertRaises(ValueError):
                subject.prepare(NS())
        constructor.assert_not_called()
        self.assertEqual(state.reads, [])

    def test_real_prepare_keeps_frozen_helper_registries_unchanged(self):
        with bootstrap(self) as (state, constructor):
            subject.prepare(NS())
        constructor.assert_called_once()
        self.assertTrue(state.registries)
        for module, name, before in state.registries:
            self.assertEqual(getattr(module, name), before, (module.__name__, name))


class ValidatorTests(unittest.TestCase):
    def rejected(self, value):
        with self.assertRaises(ValueError):
            validate(value)

    def test_real_prepare_helpers_validate_outer_and_real_nine_projection(self):
        before = deepcopy(outer_proof)
        self.assertIsNone(validate(outer_proof))
        projected = subject.project_nine(outer_proof, prepared[3])
        with detached():
            prepared[3]['nine_composition'].require_result(projected, prepared[3])
        self.assertEqual(outer_proof, before)
        self.assertEqual(projected['RequiredCellsSatisfied'], 0)
        self.assertIs(projected['RequiredCellSatisfied'], False)
        self.assertIs(projected['CellContractSatisfied'], False)
        for name in COMPONENTS:
            self.assertEqual(projected[name], original_nine[name])

    def test_all_eleven_mappings_bind_subrecord_and_component_hashes(self):
        self.assertEqual(set(outer_proof['CommonPrerequisites']), set(COMMON))
        self.assertEqual(set(outer_proof['RuntimeObligations']), set(RUNTIME))
        for field in ('CommonPrerequisites', 'RuntimeObligations'):
            for name, row in outer_proof[field].items():
                self.assertEqual(set(row), {'Satisfied', 'Evidence'})
                self.assertIs(row['Satisfied'], True)
                self.assertTrue(row['Evidence'], name)
                for ref in row['Evidence']:
                    self.assertEqual(set(ref), {'Component', 'Path', 'Sha256', 'ComponentSha256'})
                    component = outer_proof[ref['Component']]
                    value = component
                    self.assertIs(type(ref['Path']), list)
                    for part in ref['Path']:
                        self.assertIs(type(part), str)
                        value = value[part]
                    self.assertIs(type(value) in (dict, list), True)
                    self.assertTrue(value)
                    self.assertEqual(ref['Sha256'], sha(subject.canonical(value)))
                    self.assertEqual(ref['ComponentSha256'], sha(subject.canonical(component)))

    def test_each_obligation_missing_extra_typed_flag_or_foreign_evidence_rejects(self):
        for field, names in (('CommonPrerequisites', COMMON), ('RuntimeObligations', RUNTIME)):
            for name in names:
                for mutation in ('missing', 'false', 'int', 'extra', 'empty', 'foreign-path',
                                 'subrecord-hash', 'component-hash'):
                    value = deepcopy(outer_proof)
                    row = value[field][name]
                    if mutation == 'missing':
                        del value[field][name]
                    elif mutation == 'false':
                        row['Satisfied'] = False
                    elif mutation == 'int':
                        row['Satisfied'] = 1
                    elif mutation == 'extra':
                        row['ForeignClaim'] = False
                    elif mutation == 'empty':
                        row['Evidence'] = []
                    elif mutation == 'foreign-path':
                        row['Evidence'][0]['Path'] = ['ForeignEvidence']
                    else:
                        row['Evidence'][0]['Sha256' if mutation == 'subrecord-hash' else 'ComponentSha256'] = 'A' * 64
                    with self.subTest(field=field, name=name, mutation=mutation):
                        self.rejected(value)
            value = deepcopy(outer_proof)
            value[field]['foreign-obligation'] = dict(Satisfied=True, Evidence=[])
            self.rejected(value)

    def test_detailed_proof_corruption_rejects_with_completion_facts_unchanged(self):
        def forward(value):
            value['OriginalComponent']['NativeBindings']['Emitted']['ForwardProviders'].pop()
        def slot(value):
            value['IsolationComponent']['SlotProofs']['SlotProofs']['Original']['SlotReferences'] += 1
        def diagnostics(value):
            value['ABIControls']['Controls'][0]['Classification']['DiagnosticSha256'] = 'A' * 64
        def port(value):
            value['PortPolicyComponent']['LoweredProofs']['Machines'][-1]['Images'][0]['Proof']['ObjectSha256'] = 'A' * 64
        def controls(value):
            value['FinalControlComponent']['DerivedBuffers'][0]['Output']['Sha256'] = 'A' * 64
        for mutation in (forward, slot, diagnostics, port, controls):
            value = deepcopy(outer_proof)
            mutation(value)
            with self.subTest(mutation=mutation.__name__):
                self.rejected(value)

    def test_nonclosed_common_attribution_is_not_qualifiable(self):
        for field in ('CommonAttributionClosed', 'UnresolvedAttribution'):
            value = deepcopy(outer_proof)
            value[field] = False if field == 'CommonAttributionClosed' else [dict(Group='positive')]
            self.rejected(value)
        for field in ('CommonAttributionClosed', 'UnresolvedAttribution'):
            value = deepcopy(outer_proof)
            value['CommonAttributes']['LoweredProofs'][field] = False if field == 'CommonAttributionClosed' else ['unresolved']
            self.rejected(value)

    def test_outer_fields_counts_fingerprints_and_nonclaims_are_literal(self):
        nine = prepared[3]['nine_composition']
        changes = [('RequiredCellsSatisfied', True), ('RequiredCellsSatisfied', 1.0),
            ('RequiredCellsSatisfied', 0), ('RequiredCellCount', 2774.0), ('RequiredCellSatisfied', 1),
            ('CellContractSatisfied', 1), ('CohortSha256', prepared[3]['cell_model'].SOURCE_INVENTORY_SHA256),
            ('Route', 'CM3/O2-lto/direct'), ('Key', list(prepared[3]['cell_model'].KEY[:-2]) + ['O2-lto', 'direct'])]
        changes += [(name, True) for name in nine.NONCLAIMS if name not in ('RequiredCellSatisfied', 'CellContractSatisfied')]
        changes += [(name, 1) for name in nine.FACTS]
        for field, changed in changes:
            value = deepcopy(outer_proof)
            value[field] = changed
            with self.subTest(field=field, changed=changed):
                self.rejected(value)
        value = deepcopy(outer_proof)
        value['ForeignClaim'] = False
        self.rejected(value)

    def test_model_own_source_and_each_pin_are_retained_before_witness(self):
        required = (ENTRY, MODEL[0], COVERAGE[0], CONTRACT[0])
        for path in required:
            for field, key in (('BootstrapSources', 'Path'), ('CapturedSources', 'Original')):
                value = deepcopy(outer_proof)
                value[field] = [row for row in value[field] if row[key] != str(path)]
                with self.subTest(path=path, field=field):
                    self.rejected(value)
        value = deepcopy(outer_proof)
        value['QualifierSource']['Sha256'] = 'A' * 64
        self.rejected(value)

    def test_four_inventory_raw_buffers_bind_path_hash_size_and_descriptor(self):
        for role in ('Receipt', 'Manifest', 'RequiredCells', 'CohortManifest'):
            for mutation in ('missing', 'hash', 'path', 'size', 'bool-size', 'bytes'):
                value = deepcopy(outer_proof)
                row = value['CurrentInventoryInputs'][role]
                if mutation == 'missing':
                    del value['CurrentInventoryInputs'][role]
                elif mutation == 'hash':
                    row['Sha256'] = 'A' * 64
                elif mutation == 'path':
                    row['Path'] = str(INVENTORY / 'foreign.json')
                elif mutation == 'size':
                    row['Bytes'] += 1
                elif mutation == 'bool-size':
                    row['Bytes'] = True
                else:
                    value['CurrentInventoryBytes'][role] += '00'
                with self.subTest(role=role, mutation=mutation):
                    self.rejected(value)

    def test_exact_full_zero_one_accounting_and_all_backlog_rows(self):
        model = prepared[3]['cell_model']
        required = json.loads(inventory_bytes['required-cells.json'])
        backlog = json.loads(inventory_bytes['inputs/tools/freeze_cohorts.json'])['scope_backlog']
        for keys in ([], [model.KEY]):
            value = deepcopy(outer_proof)
            subject._accounting(value, prepared[3], keys)
            covered, missing = value['Coverage'], value['MissingWork']
            self.assertIs(type(covered['RequiredCellsSatisfied']), int)
            self.assertEqual(covered['RequiredCellsSatisfied'], len(keys))
            self.assertEqual(missing['RequiredCellsSatisfied'], len(keys))
            self.assertEqual(len(covered['Cells']), 2774)
            self.assertEqual(len(missing['Cells']), 2774 - len(keys))
            self.assertEqual(missing['Backlog'], backlog)
            self.assertEqual(sum(row['status'] == 'Pending' for row in missing['Backlog']), 23)
            self.assertEqual(sum(row['status'] == 'ReferenceOnly' for row in missing['Backlog']), 3)
            for original, row in zip(required['RequiredCells'], covered['Cells']):
                for field, expected in original.items():
                    self.assertEqual(row[field], expected)
                key = tuple(row[field] for field in model.KEY_FIELDS)
                passed = bool(keys) and key == model.KEY
                self.assertIs(row['RequiredCellSatisfied'], passed)
                self.assertEqual(row['Status'], 'BOUNDED_STATIC_CELL_VERIFIED' if passed else 'PENDING')

    def test_copied_accounting_or_artifact_binding_cannot_forge_credit(self):
        for field in ('Coverage', 'MissingWork'):
            for mutation in ('count-bool', 'count-zero', 'row-missing', 'foreign-key'):
                value = deepcopy(outer_proof)
                record = value[field]
                if mutation == 'count-bool':
                    record['RequiredCellsSatisfied'] = True
                elif mutation == 'count-zero':
                    record['RequiredCellsSatisfied'] = 0
                elif mutation == 'row-missing':
                    record['Cells'].pop()
                elif field == 'Coverage':
                    record['Cells'][0]['Cohort'] = 'foreign'
                else:
                    record['Cells'][0]['Key'][0] = 'foreign'
                raw = subject.encoded(record)
                value['AccountingArtifacts'][field].update(Sha256=sha(raw), Bytes=len(raw))
                with self.subTest(field=field, mutation=mutation):
                    self.rejected(value)
            for key, changed in (('Path', str(RETENTION_ROOT / 'foreign.json')), ('Sha256', 'A' * 64), ('Bytes', True)):
                value = deepcopy(outer_proof)
                value['AccountingArtifacts'][field][key] = changed
                self.rejected(value)

    def test_detached_validation_needs_no_physical_io_or_binary_constructors(self):
        def forbidden(*args, **kwargs):
            raise AssertionError('detached validator attempted physical I/O')
        with detached(), ExitStack() as stack:
            for name in ('read_bytes', 'read_text', 'open', 'stat', 'lstat', 'exists', 'resolve', 'write_bytes'):
                stack.enter_context(patch.object(Path, name, forbidden))
            self.assertIsNone(subject.require_result(outer_proof, prepared[3]))


class LifecycleTests(unittest.TestCase):
    def test_real_postseal_validator_and_persisted_one_cell_accounting(self):
        model = Lifecycle(self)
        result = model.run()
        self.assertEqual(result['RequiredCellsSatisfied'], 1)
        self.assertEqual(len(result['Coverage']['Cells']), 2774)
        self.assertEqual(len(result['MissingWork']['Cells']), 2773)
        model.replay.assert_called_once()
        model.suite.command.assert_not_called()
        with detached():
            subject.require_result(result, prepared[3])
        subject.verify_seal(model.environment, model.suite, result, model.helpers)

    def test_postseal_validation_fault_persists_fail_report_coverage_and_manifest(self):
        model = Lifecycle(self)
        real_validate = subject.require_result
        calls = []
        def fail_after_validation(value, helpers):
            real_validate(value, helpers)
            calls.append(True)
            raise ValueError('synthetic postseal validation failure')
        with patch.object(subject, 'require_result', side_effect=fail_after_validation), \
                self.assertRaisesRegex(ValueError, 'synthetic postseal validation failure'):
            model.run()
        self.assertEqual(calls, [True])
        report = model.persisted_failure()
        self.assertIn('synthetic postseal validation failure', report['PrimaryError'])

    def test_stdout_fault_after_real_seal_persists_all_four_failed_metadata_files(self):
        model = Lifecycle(self)
        with patch('builtins.print', side_effect=BrokenPipeError('synthetic flushed stdout failure')), \
                self.assertRaisesRegex(BrokenPipeError, 'synthetic flushed stdout failure'):
            model.run()
        report = model.persisted_failure()
        self.assertIn('synthetic flushed stdout failure', report['PrimaryError'])
        self.assertIn('artifacts.json', model.suite.identities)
        self.assertNotIn('artifacts.json', model.suite.expected)

    def test_partial_seal_after_manifest_write_persists_zero_credit_accounting(self):
        model = Lifecycle(self)
        original_closure = replay_api.Closure
        def closure():
            actual = original_closure()
            def after_manifest(*args, **kwargs):
                self.assertTrue((model.output / 'artifacts.json').is_file())
                raise ValueError('synthetic seal tree failure after manifest write')
            actual.tree = after_manifest
            return actual
        with patch.object(replay_api, 'Closure', side_effect=closure), \
                self.assertRaisesRegex(ValueError, 'after manifest write'):
            model.run()
        report = model.persisted_failure()
        self.assertIn('after manifest write', report['PrimaryError'])

    def test_late_input_close_failure_is_revoked_and_persisted(self):
        model = Lifecycle(self)
        calls = []
        def close():
            calls.append(True)
            if len(calls) == 4:
                raise ValueError('synthetic late current-input closing failure')
        model.witness.close.side_effect = close
        with self.assertRaisesRegex(ValueError, 'synthetic late current-input closing failure'):
            model.run()
        model.persisted_failure()

    def test_missing_work_write_failure_cannot_leave_positive_coverage(self):
        model = Lifecycle(self)
        save = model.suite._save
        def fail(name, value):
            if name == 'missing-work.json':
                raise ValueError('synthetic missing-work write failure')
            return save(name, value)
        model.suite._save = fail
        with self.assertRaisesRegex(ValueError, 'synthetic missing-work write failure'):
            model.run()
        model.persisted_failure()

    def test_unavailable_zero_plan_still_persists_guarded_fail_and_invalidates_positive_files(self):
        model = Lifecycle(self)
        model.run()
        with patch.object(subject, '_accounting', side_effect=ValueError('synthetic unavailable E9 plan')):
            subject.revoke(model.runner, model.suite.report, model.helpers, ValueError('original primary failure'))
            subject.recover_owned(model.runner, model.environment, model.builder, model.suite, model.helpers)
        report = model.persisted_failure(require_accounting=False)
        self.assertIn('original primary failure', report['PrimaryError'])
        self.assertTrue(any('unavailable E9 plan' in text for text in report['ClosingErrors']))
        self.assertIs(report['Coverage'], None)
        self.assertIs(report['MissingWork'], None)

    def test_prior_byte_read_root_replacement_never_writes_foreign_output(self):
        model = Lifecycle(self)
        model.run()
        subject.revoke(model.runner, model.suite.report, model.helpers, ValueError('primary before root replacement'))
        target = model.output / 'coverage.json'
        real_read, real_write = Path.read_bytes, Path.write_bytes
        triggered = []
        def read(path):
            raw = real_read(path)
            if path == target and not triggered:
                triggered.append(True)
                model.output.rename(model.root / 'retired-output')
                model.output.mkdir()
                real_write(target, b'foreign untouched root\n')
            return raw
        with patch.object(Path, 'read_bytes', read), self.assertRaises(ValueError):
            subject.recover_owned(model.runner, model.environment, model.builder, model.suite, model.helpers)
        self.assertEqual(triggered, [True])
        self.assertEqual(target.read_bytes(), b'foreign untouched root\n')
        self.assertEqual(set(replay_api.files_under(model.output)), {'coverage.json'})

    def test_prior_byte_read_destination_replacement_never_overwrites_foreign_file(self):
        model = Lifecycle(self)
        model.run()
        subject.revoke(model.runner, model.suite.report, model.helpers, ValueError('primary before destination replacement'))
        target = model.output / 'coverage.json'
        real_read, real_write = Path.read_bytes, Path.write_bytes
        triggered = []
        def read(path):
            raw = real_read(path)
            if path == target and not triggered:
                triggered.append(True)
                path.rename(model.output / 'retired-coverage.json')
                real_write(path, b'foreign untouched destination\n')
            return raw
        with patch.object(Path, 'read_bytes', read), self.assertRaises(ValueError):
            subject.recover_owned(model.runner, model.environment, model.builder, model.suite, model.helpers)
        self.assertEqual(triggered, [True])
        self.assertEqual(target.read_bytes(), b'foreign untouched destination\n')

    def test_recovery_failure_keeps_primary_and_zero_in_memory_credit(self):
        model = Lifecycle(self)
        real_validate = subject.require_result
        def fail(value, helpers):
            real_validate(value, helpers)
            raise ValueError('synthetic primary after seal')
        with patch.object(subject, 'require_result', side_effect=fail), \
                patch.object(model.runner, 'recover', side_effect=OSError('synthetic secondary recovery failure')), \
                self.assertRaisesRegex(ValueError, 'synthetic primary after seal'):
            model.run()
        report = model.suite.report
        self.assertEqual(report['Status'], 'FAIL')
        self.assertEqual(report['RequiredCellsSatisfied'], 0)
        self.assertIn('synthetic primary after seal', report['PrimaryError'])
        self.assertTrue(any('secondary recovery failure' in item for item in report['ClosingErrors']))
        for field, filename in subject.ACCOUNTING_FILES.items():
            raw = (model.output / filename).read_bytes()
            disk = json.loads(raw)
            self.assertEqual(raw, subject.encoded(report[field]))
            if disk is not None:
                self.assertIs(type(disk['RequiredCellsSatisfied']), int)
                self.assertEqual(disk['RequiredCellsSatisfied'], 0)
                self.assertEqual(len(disk['Cells']), 2774)
                if field == 'Coverage':
                    self.assertTrue(all(row['RequiredCellSatisfied'] is False for row in disk['Cells']))
        self.assertEqual(json.loads((model.output / 'results.json').read_bytes())['Status'], subject.PASS)
        with self.assertRaises(ValueError):
            subject.verify_seal(model.environment, model.suite, report, model.helpers)

    def test_fresh_metadata_destination_appearing_before_write_is_untouched(self):
        model = Lifecycle(self)
        model.suite.report = deepcopy(model.seed)
        model.suite.start()
        target = model.output / 'results.json'
        original_regular, physical_write = subject._regular_output, Path.write_bytes
        appeared = []
        def appear(suite, guard, name):
            path, before = original_regular(suite, guard, name)
            self.assertEqual(path, target)
            self.assertIsNone(before)
            appeared.append(True)
            physical_write(path, b'foreign fresh destination\n')
            return path, before
        with patch.object(subject, '_regular_output', side_effect=appear), \
                subject.metadata_writes(model.suite, model.helpers['guard']), \
                self.assertRaisesRegex(ValueError, 'appeared before write'):
            target.write_bytes(subject.encoded(dict(Status='FAIL')))
        self.assertEqual(appeared, [True])
        self.assertEqual(target.read_bytes(), b'foreign fresh destination\n')
        self.assertNotIn('results.json', model.suite.identities)

    def test_swallowed_recovery_write_errors_cannot_be_mistaken_for_a_fail_seal(self):
        model = Lifecycle(self)
        physical_write, real_validate = Path.write_bytes, subject.require_result
        state = NS(armed=False, writes=[], recovery_returned=False)
        def postseal(value, helpers):
            real_validate(value, helpers)
            state.armed = True
            raise ValueError('synthetic original controlled postseal failure')
        def write(path, raw):
            if state.armed and path.parent == model.output and path.name in ('results.json', 'artifacts.json'):
                state.writes.append(path.name)
                raise OSError('synthetic swallowed metadata write failure')
            return physical_write(path, raw)
        def recover(environment, report):
            model.real_runner.recover(environment, report)
            state.recovery_returned = True
        model.runner.recover = Mock(side_effect=recover)
        with patch.object(subject, 'require_result', side_effect=postseal), \
                patch.object(Path, 'write_bytes', write), \
                self.assertRaisesRegex(ValueError, 'synthetic original controlled postseal failure'):
            model.run()
        self.assertIs(state.recovery_returned, True)
        self.assertEqual(state.writes, ['results.json', 'artifacts.json', 'results.json', 'artifacts.json'])
        report = model.suite.report
        self.assertEqual(report['Status'], 'FAIL')
        self.assertEqual(report['RequiredCellsSatisfied'], 0)
        self.assertIn('synthetic original controlled postseal failure', report['PrimaryError'])
        self.assertTrue(any('synthetic swallowed metadata write failure' in text for text in report['ClosingErrors']))
        self.assertTrue(any('failure persistence:' in text for text in report['ClosingErrors']))
        for field, filename in subject.ACCOUNTING_FILES.items():
            raw = (model.output / filename).read_bytes()
            disk = json.loads(raw)
            self.assertEqual(raw, subject.encoded(report[field]))
            if disk is not None:
                self.assertIs(type(disk['RequiredCellsSatisfied']), int)
                self.assertEqual(disk['RequiredCellsSatisfied'], 0)
                self.assertEqual(len(disk['Cells']), 2774)
                if field == 'Coverage':
                    self.assertTrue(all(row['RequiredCellSatisfied'] is False for row in disk['Cells']))
        with self.assertRaises(ValueError):
            subject.verify_seal(model.environment, model.suite, report, model.helpers)
        # Failed recovery can leave positive diagnostics, but cannot return a current successful seal.
        self.assertEqual(json.loads((model.output / 'results.json').read_bytes())['Status'], subject.PASS)


class HarnessTests(unittest.TestCase):
    def test_cli_process_guards_and_abbreviation_rejection_need_no_admission(self):
        with patch.object(subject, 'prepare') as prepare, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            subject.main(['--batch-b', 'never'])
        prepare.assert_not_called()
        argv = [value for name in subject.ARGUMENTS for value in ('--' + name, 'synthetic')]
        def process(*args, **kwargs):
            import subprocess
            return subprocess.Popen(['NEVER'])
        with patch.object(subject, 'prepare', side_effect=process), patch('subprocess.Popen') as external, \
                redirect_stderr(io.StringIO()):
            self.assertEqual(subject.main(argv), 1)
        external.assert_not_called()
        with patch.object(subject, 'prepare', side_effect=ValueError('synthetic bootstrap failure')), \
                patch('builtins.print', side_effect=process), patch('subprocess.Popen') as external:
            self.assertEqual(subject.main(argv), 1)
        external.assert_not_called()

    def test_harness_requires_exact_catalog_counts_and_no_skips(self):
        names = sorted(EXPECTED_METHOD_NAMES)
        self.assertIs(catalog_matches(names, METHODS), True)
        for values in (names[:-1], names + [names[0]], ['foreign'] + names[1:]):
            self.assertIs(catalog_matches(values, METHODS), False)
        for count in (0, METHODS - 1, METHODS + 1, True, float(METHODS)):
            self.assertIs(catalog_matches(names, count), False)
            result = unittest.TestResult()
            result.testsRun = count
            self.assertIs(completed(result), False)
        for field in ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
            result = unittest.TestResult()
            result.testsRun = METHODS
            self.assertIs(completed(result), True)
            getattr(result, field).append(('synthetic test', 'synthetic detail'))
            self.assertIs(completed(result), False)


def initialize():
    global subject, nine_fixture, prepared, original_nine, outer_proof, replay_api
    global source_bytes, inventory_bytes, RETENTION_ROOT
    if not FINALIZED or type(ENTRY_SHA) is not str or len(ENTRY_SHA) != 64:
        raise ValueError('test scaffold awaits finalized qualifier API and frozen source SHA')
    physical_read = Path.read_bytes

    def read(path):
        return retain(FIRST_READS, path, physical_read(path))

    with patch.object(Path, 'read_bytes', read):
        own = Path(__file__).resolve()
        retain(SOURCES, own, own.read_bytes())
        for path, digest in ((ENTRY, ENTRY_SHA), NINE_FIXTURE, MODEL, COVERAGE, CONTRACT):
            raw = retain(SOURCES, path, path.read_bytes())
            if sha(raw) != digest:
                raise ValueError('pinned source/fixture mismatch: ' + str(path))
        nine_fixture = load_buffer('_cell_qualifier_published_nine_fixture', NINE_FIXTURE[0], SOURCES[NINE_FIXTURE[0]])
        nine_fixture.initialize()
        merge(SOURCES, nine_fixture.BUFFERS)
        merge(FIXTURES, nine_fixture.FIXTURES)
        subject = load_buffer('_cell_qualifier_subject', ENTRY, SOURCES[ENTRY])
        real_load = subject.load

        def collecting(name, path, raw):
            retain(SOURCES, path, raw)
            value = real_load(name, path, raw)
            if name == '_os_cell_qualifier_admission_admission':
                value.witness_type = lambda legacy, capture, *, extra_sources: (lambda args: NS(SyntheticWitness=True))
            return value

        with patch.dict(sys.modules), patch.object(subject, 'load', side_effect=collecting):
            clear_parser()
            prepared = subject.prepare(NS())
        merge(SOURCES, prepared[5])
        receipt_raw = fixture_read(*NINE_RECEIPT)
        manifest = json.loads(fixture_read(*NINE_MANIFEST))
        if manifest['Artifacts'].get('results.json') != NINE_RECEIPT[1]:
            raise ValueError('actual nine receipt/manifest fixture join')
        original_nine = json.loads(receipt_raw)
        for row in original_nine['CapturedSources']:
            source_bytes[row['Original']] = fixture_read(Path(row['Captured']), row['Sha256'])
        inventory_bytes = {name: fixture_read(INVENTORY / name, digest)
                           for name, digest in INVENTORY_PINS.items()}
        raw = retain(SOURCES, REPLAY_API[0], REPLAY_API[0].read_bytes())
        if sha(raw) != REPLAY_API[1]:
            raise ValueError('authenticated published output seal API source')
        replay_api = load_buffer('_qualifier_test_real_output_api', REPLAY_API[0], raw)
        RETENTION_ROOT = Path(tempfile.mkdtemp(prefix='os-cell-qualifier-retention-')) / 'qualified'
        outer_proof, _ = make_outer(RETENTION_ROOT, retain_copies=True)
    for path, raw in FIRST_READS.items():
        retain(SOURCES if path in SOURCES else FIXTURES, path, raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output, temp = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temp) or output.is_relative_to(ROOT):
        parser.error('fresh external TEMP output required')
    report = dict(Status='FAIL', ExpectedTests=METHODS, LoadedTests=0, Tests=0,
        Failures=0, Errors=0, Skipped=0, ExpectedFailures=0, UnexpectedSuccesses=0,
        ExactMethodCatalogVerified=False, MethodCatalog=[], FailureDetails=[], ErrorDetails=[],
        SourceHashes={}, FixtureHashes={}, SourceClosureVerified=False, FixtureClosureVerified=False,
        ScaffoldOnly=not FINALIZED, FullQualifierBoundaryCovered=False,
        RealPrepareWitnessDouble=True, LifecycleDoubles=True, ActualCaptureAdmitted=False,
        DetailedProofsFromPinnedActualNineReceipt=True, RealReturnedHelpersUsed=True,
        SyntheticRetentionAndReaderCounts=True, ActualPublishedSealAndRecoveryUsed=True,
        OwnedOutputFilesystemGuardsReal=True, FullInputClosureRevalidated=False,
        ActualQualifierCLIExecuted=False, Qualification=False, RequiredCellsSatisfied=0,
        CompilerInvocations=0, ToolInvocations=0, CpuExecution=False, BoardExecution=False)
    saved_meta = list(sys.meta_path)
    with (patch('subprocess.Popen', side_effect=AssertionError('no producer process')),
          patch('os.system', side_effect=AssertionError('no shell'))):
        try:
            if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
                raise ValueError('fresh unoptimized isolated -I -S -B interpreter required')
            initialize()
            cases = (BootstrapTests, ValidatorTests, LifecycleTests, HarnessTests)
            names = sorted(name for case in cases for name in unittest.defaultTestLoader.getTestCaseNames(case))
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case) for case in cases)
            report.update(LoadedTests=suite.countTestCases(), MethodCatalog=names)
            if not catalog_matches(names, suite.countTestCases()):
                raise ValueError('exact fixed method count and catalog required')
            report['ExactMethodCatalogVerified'] = True
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
                Skipped=len(result.skipped), ExpectedFailures=len(result.expectedFailures),
                UnexpectedSuccesses=len(result.unexpectedSuccesses),
                FailureDetails=[dict(Test=str(test), Traceback=detail) for test, detail in result.failures],
                ErrorDetails=[dict(Test=str(test), Traceback=detail) for test, detail in result.errors])
            if completed(result):
                report['Status'] = 'PASS'
        except BaseException:
            report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=traceback.format_exc())
        finally:
            sys.meta_path[:] = saved_meta
        for label, buffers in (('Source', SOURCES), ('Fixture', FIXTURES)):
            report[label + 'Hashes'] = {str(path): sha(raw) for path, raw in buffers.items()}
            errors = []
            for path, raw in buffers.items():
                try:
                    if path.read_bytes() != raw:
                        errors.append(str(path) + ': byte drift')
                except OSError as error:
                    errors.append(str(path) + ': ' + type(error).__name__)
            closed = bool(buffers) and not errors
            report[label + 'ClosureVerified'] = closed
            report[label + 'ClosingFiles'] = len(buffers) - len(errors)
            report[label + 'ClosingErrors'] = errors
            if not closed:
                report['Status'] = 'FAIL'
        report['FullQualifierBoundaryCovered'] = report['Status'] == 'PASS'
        output.mkdir(parents=True, exist_ok=False)
        raw = encoded(report)
        target = output / 'results.json'
        if target.write_bytes(raw) != len(raw) or target.read_bytes() != raw:
            raise RuntimeError('incomplete test receipt')
        print(json.dumps(dict(Status=report['Status'], Tests=report['Tests'], ExpectedTests=METHODS,
            Failures=report['Failures'], Errors=report['Errors'], Receipt=str(target), ReceiptSha256=sha(raw)),
            sort_keys=True), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
