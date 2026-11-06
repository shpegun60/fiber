"""Synthetic composition controls, not machine/reader/toolchain qualification."""

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 10
m = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


class LeafRejected(ValueError):
    pass


class Model:
    def __init__(self):
        self.raw, self.info, self.calls = {}, {}, []
        self.pending = self.disagree = self.bad_parse = self.accept_control = False
        inputs = []
        common = []
        def add(component, role, mutation=None, stress=False, final=False):
            path = Path('C:/synthetic-os-machine-replay') / component / role
            raw = (component + '/' + role).encode('ascii')
            self.raw[path] = raw
            self.info[path] = mutation, stress, final, role
            inputs.append(dict(Component=component, Role=role, Path=str(path), Sha256=sha(raw)))
        for index, group in enumerate(m.COMMON):
            mutation, stress = m.MUTATIONS[index], index >= 4
            common.append(dict(Group=group, Mutation=mutation, Stress=stress))
            for role in ('Object', 'Machine'):
                add('CommonAttributes', group + '/' + role, mutation, stress)
        for group in m.PORT:
            for role in ('Aggregate', 'AggregateDisassembly', 'Machine', 'MachineDisassembly'):
                add('PortPolicy', group + '/' + role)
        for role in ('ELF', 'Disassembly', 'Machine', 'MachineDisassembly'):
            add('PortPolicy', 'Final/' + role, final=role == 'ELF')
        self.batch = dict(Status='BUILT-PENDING-READER', Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
            PendingFinalReader=dict(Status='PENDING', OneImmutableReaderScopeRequired=True, Inputs=inputs),
            CommonAttributesDeferredReader=dict(Lowerings=common),
            PortPolicyLowerings=[dict(Group=group) for group in m.PORT],
            PortPolicyIRDefinitionSurface=dict(IRDefinitionsValidated=True))
        def parse(path, kind):
            mutation, stress, final, role = self.info[path]
            if kind != ('ET_EXEC' if final else 'ET_REL'):
                raise ValueError('synthetic expected machine role')
            return SimpleNamespace(data=b'wrong parsed bytes' if self.bad_parse else self.raw[path],
                final=final, mutation=mutation, stress=stress, role=role)
        self.core = SimpleNamespace(_ELF=parse)
        def effect(image, core, helpers, *, mutation=None, stress=False):
            self.calls.append(('effect', image.role, mutation, stress))
            if image.mutation is not None and mutation is None and not self.accept_control:
                raise LeafRejected('synthetic actual control effect')
            if mutation != image.mutation and not self.accept_control or stress is not image.stress:
                raise LeafRejected('synthetic wrong effect selector')
            unresolved = [{'Function': 'ctxrt_v1_set_dispatcher'}] if self.pending else []
            return dict(Status='PENDING' if unresolved else 'CONTROL' if mutation else 'CLEAN',
                Undefined=['synthetic-import'] if self.disagree and image.role.endswith('/Machine') else [],
                UnresolvedAttribution=unresolved, SyntheticLeaf=True)
        def require(proof, **kwargs):
            if proof.get('SyntheticLeaf') is not True:
                raise LeafRejected('synthetic malformed effect')
        def lower(image, core, dis, surface, policy, *, whole_image=False):
            self.calls.append(('lower', image.role, whole_image))
            return dict(SyntheticLeaf=True, Whole=whole_image)
        def final(image, core, dis, surface, policy):
            self.calls.append(('final', image.role))
            return dict(SyntheticLeaf=True)
        def stress(image, core, dis, policy, effects, attrs, *, supported):
            self.calls.append(('stress', image.role, supported))
            return dict(SyntheticLeaf=True, Supported=supported)
        self.helpers = dict(effects=SimpleNamespace(inspect_lowered=effect, require_result=require, Rejected=LeafRejected),
            census=SimpleNamespace(inspect_lowered=lower, inspect_final=final, inspect_stress=stress),
            attributes=SimpleNamespace(STRESS='ctxrt_attribute_stress'), policy=SimpleNamespace())

    def read(self, component, role):
        path = Path('C:/synthetic-os-machine-replay') / component / role
        return path, self.raw[path]

    def run(self, read=None):
        return m.inspect(self.batch, self.core, self.helpers, self.read if read is None else read)


class ReplayTests(unittest.TestCase):
    def test_complete_twenty_roles_and_all_stronger_nonclaims(self):
        model = Model()
        before = copy.deepcopy(model.batch)
        result = model.run()
        self.assertEqual(result['Status'], 'MACHINE-COMPONENTS-REPLAYED')
        self.assertEqual((result['MachineRoles'], result['CommonMachineRoles'], result['PortMachineRoles']), (20, 12, 8))
        self.assertEqual(len(result['ReadRoles']), 28)
        self.assertEqual(before, model.batch)
        self.assertEqual(sum(row[0] == 'effect' for row in model.calls), 20)
        self.assertEqual(sum(row[0] == 'lower' for row in model.calls), 3)
        self.assertEqual(sum(row[0] == 'stress' for row in model.calls), 4)
        self.assertEqual(sum(row[0] == 'final' for row in model.calls), 1)
        for key in ('WorkerOptionsValidated', 'WorkerExecutionProvenanceValidated', 'IRDefinitionProvenanceValidated',
                    'FinalRootTransferProtocolsValidated', 'ABIControlsReplayed', 'IsolationReplayed', 'FinalReferenceParity',
                    'CompleteCellProof', 'Qualification', 'GlobalFreezeQualified', 'HostedCIQualified', 'CPUExecution', 'BoardExecution'):
            self.assertIs(result[key], False)
        self.assertEqual(result['RequiredCellsSatisfied'], 0)

    def test_pending_attribution_is_not_clean_or_cell_pass(self):
        model = Model()
        model.pending = True
        result = model.run()
        self.assertEqual(result['Status'], 'MACHINE-REPLAY-PENDING-ATTRIBUTION')
        self.assertFalse(result['CommonAttributionClosed'])
        self.assertEqual(len(result['UnresolvedAttribution']), 12)
        self.assertFalse(result['Qualification'])

    def test_actual_controls_must_be_rejected_by_unchanged_clean_predicate(self):
        model = Model()
        model.accept_control = True
        with self.assertRaises(m.Rejected):
            model.run()

    def test_aggregate_and_worker_dispositions_must_agree(self):
        model = Model()
        model.disagree = True
        with self.assertRaises(m.Rejected):
            model.run()

    def test_wrong_hash_or_path_or_reader_type_is_rejected(self):
        for change in ('hash', 'path', 'type'):
            model = Model()
            def read(component, role):
                path, raw = model.read(component, role)
                if change == 'hash':
                    raw += b'x'
                elif change == 'path':
                    path = path.with_name(path.name + '-alias')
                else:
                    path = str(path)
                return path, raw
            with self.subTest(change=change), self.assertRaises(m.Rejected):
                model.run(read)

    def test_parser_must_consume_same_bound_raw_bytes(self):
        model = Model()
        model.bad_parse = True
        with self.assertRaises(m.Rejected):
            model.run()

    def test_duplicate_missing_and_malformed_role_catalog(self):
        for change in ('duplicate', 'missing', 'extra-field', 'bool-hash'):
            model = Model()
            rows = model.batch['PendingFinalReader']['Inputs']
            if change == 'duplicate':
                rows.append(dict(rows[0]))
            elif change == 'missing':
                rows.pop(0)
            elif change == 'extra-field':
                rows[0]['Unexpected'] = 'value'
            else:
                rows[0]['Sha256'] = True
            with self.subTest(change=change), self.assertRaises(m.Rejected):
                model.run()

    def test_exact_group_order_and_literal_stress_selectors(self):
        for change in ('order', 'stress', 'mutation', 'port-order'):
            model = Model()
            rows = model.batch['CommonAttributesDeferredReader']['Lowerings']
            if change == 'order':
                rows.reverse()
            elif change == 'stress':
                rows[0]['Stress'] = 0
            elif change == 'mutation':
                rows[0]['Mutation'] = 'ctxrt_v1_current'
            else:
                model.batch['PortPolicyLowerings'].reverse()
            with self.subTest(change=change), self.assertRaises(m.Rejected):
                model.run()

    def test_current_os_mode_and_surface_are_mandatory(self):
        for change in ('mode', 'lto', 'status', 'surface'):
            model = Model()
            if change == 'surface':
                model.batch['PortPolicyIRDefinitionSurface'] = None
            else:
                key, value = {'mode': ('Mode', 'O2-lto'), 'lto': ('LTO', 1), 'status': ('Status', 'PASS')}[change]
                model.batch[key] = value
            with self.subTest(change=change), self.assertRaises(m.Rejected):
                model.run()

    def test_no_implicit_extra_helper_or_missing_immutable_reader(self):
        model = Model()
        model.helpers['old_o2_driver'] = object()
        with self.assertRaises(m.Rejected):
            model.run()
        model = Model()
        with self.assertRaises(m.Rejected):
            m.inspect(model.batch, model.core, model.helpers, None)


def main():
    global m
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.absolute()
    if output.exists() or output == ROOT or ROOT in output.parents:
        raise SystemExit('fresh external output directory required')
    sources = (Path(__file__), HERE / 'machine_replay.py')
    opening = {str(path): sha(path.read_bytes()) for path in sources}
    spec = importlib.util.spec_from_file_location('os_machine_replay_under_test', sources[1])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReplayTests))
    closing = {str(path): sha(path.read_bytes()) for path in sources}
    report = dict(Status='PASS' if result.wasSuccessful() and result.testsRun == METHODS and opening == closing else 'FAIL',
        Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
        SourceHashes=opening, SourceDrift=opening != closing, SyntheticControlsOnly=True,
        ActualMachineBytesValidated=False, CompilerExecuted=False, RequiredCellsSatisfied=0)
    output.mkdir(parents=True)
    (output / 'results.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n', encoding='ascii')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
