"""Synthetic ordinary-control contracts; no compiler, linker, or ELF execution."""
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


HERE = Path(__file__).resolve().parent
SUBJECT = HERE / 'controls.py'
RAW = SUBJECT.read_bytes()


def load(name, path, raw):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


with patch.object(subprocess, 'Popen', side_effect=AssertionError('no processes in pure controls')):
    c = load('_ordinary_controls_subject', SUBJECT, RAW)
    utility_path = HERE.with_name('cm0_final_cell') / 'controls.py'
    utility_raw = utility_path.read_bytes()
    if hashlib.sha256(utility_raw).hexdigest().upper() != '9FA3297C5C1D3861F8B422977E876D40B0F6D7275AA4431B0AC579AECB777C9A':
        raise AssertionError('qualified utility drift')
    utility = load('_ordinary_controls_qualified_mechanics', utility_path, utility_raw)

BASE = Path(HERE.anchor) / '_ordinary_controls_synthetic_paths'
TABLE = {
    'CM0': ('cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default', 'ARM_CM0', 'arm_cm0', 'cortex-m0'),
    'CM0PLUS': ('cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default', 'ARM_CM0', 'arm_cm0', 'cortex-m0plus'),
    'CM0PLUSVTOR': ('cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default', 'ARM_CM0', 'arm_cm0', 'cortex-m0plus'),
    'CM3': ('cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default', 'ARM_CM3', 'arm_cm3', 'cortex-m3'),
    'CM4': ('cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default', 'ARM_CM4', 'arm_cm4', 'cortex-m4'),
    'CM7': ('cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default', 'ARM_CM7/r0p1', 'arm_cm7_r0p1', 'cortex-m7'),
}
COMMON = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c')


class Watch:
    def __init__(self):
        self.data, self.hashes, self.identities = {}, {}, {}
        self.denied = {BASE / 'workspace'}
        self.closes = 0

    def add(self, path, raw):
        path = Path(path)
        self.data[path], self.hashes[path] = raw, c.sha(raw)
        self.identities[path] = (1, len(self.data), 1, len(raw))

    def read(self, path, expected=None):
        path = Path(path)
        if path not in self.data or expected is not None and c.sha(self.data[path]) != expected:
            raise c.Rejected('synthetic admitted hash mismatch')
        return self.data[path]

    def close(self):
        self.closes += 1


def fixture(profile='CM0', mode='O2'):
    root = BASE / (profile + '-' + mode) / 'Native'
    cohort, directory, storage, cpu = TABLE[profile]
    group = 'CM0' if profile.startswith('CM0') else profile
    arch = ['-mcpu=' + cpu, '-mthumb', '-mfloat-abi=' + ('hard' if profile in ('CM4', 'CM7') else 'soft')]
    if profile in ('CM4', 'CM7'):
        arch.append('-mfpu=' + ('fpv4-sp-d16' if profile == 'CM4' else 'fpv5-d16'))
    artifact = dict(compile_flags=arch, target=dict(nvic_priority_bits=2 if group == 'CM0' else 4))
    ports = tuple('fiber/port/' + directory + '/' + name for name in ('fiber_port.c', 'fiber_port_boot.c', 'fiber_port_exception.c'))
    names = (*COMMON, *ports, 'fiber/port/fiber_port_context_cohort_expectation.c', c.FIXTURE + '/application.c', c.FIXTURE + '/startup.S')
    model = dict(Cohort=cohort, SourceGroup=group, StorageSymbol='fiber_port_storage_cohort_' + storage + '_v1_r0',
                 CohortArtifact=artifact, SourceOrder=list(names), SourceInventorySha256='A' * 64)
    watch = Watch()
    tool = {key: BASE / 'toolchain' / (key + '.exe') for key in ('gcc', 'nm', 'objdump', 'readelf', 'ld')}
    for key, path in tool.items():
        watch.add(path, ('admitted synthetic tool ' + key).encode('ascii'))
    def flags(artifact, mode, fixture, port, source, cmsis):
        return [*artifact['compile_flags'], '-' + mode, '-std=gnu11', '-I' + str(port),
                '-I' + str(cmsis), '-include', str(fixture / 'main.h')]
    def startup(artifact, mode):
        return [*artifact['compile_flags'], '-' + mode, '-g0']
    def dependencies(before, after):
        if not before or before != after:
            raise c.Rejected('synthetic dependency mismatch')
    native = SimpleNamespace(COMMON_SOURCES=COMMON,
        selection=lambda p, m: (TABLE[p][0], TABLE[p][1], TABLE[p][2], tuple('fiber/port/' + TABLE[p][1] + '/' + n
            for n in ('fiber_port.c', 'fiber_port_boot.c', 'fiber_port_exception.c'))),
        startup_flags=startup, require_compile_dependencies=dependencies, process_environment=lambda _: {})
    helpers = dict(api=SimpleNamespace(checked_path=lambda value, **_: Path(value), structured=json.loads),
        native=native, recipe=SimpleNamespace(native_flags=flags), cm0_controls=utility,
        profiles=SimpleNamespace(require_native=lambda *_: None, profile=lambda *_: copy.deepcopy(model)),
        facade=SimpleNamespace(), process=SimpleNamespace())
    for key, helper in helpers.items():
        if key == 'cm0_controls':
            watch.add(Path(helper.__file__), utility_raw)
        else:
            helper.__file__ = str(BASE / 'helpers' / (key + '.py'))
            watch.add(helper.__file__, ('synthetic authenticated helper ' + key).encode('ascii'))
    watch.add(SUBJECT, RAW)
    sources, commands = [], []
    def command(label, argv):
        commands.append(dict(Label=label, Argv=argv, Exit=0, Status='PASS', TimedOut=False))
    command('compiler version', [str(tool['gcc']), '--version'])
    for key, suffix in (('nm', '.nm'), ('objdump', '.dis'), ('readelf', '.attributes')):
        command('inspect 03-fiber_port.o' + suffix, [str(tool[key]), 'synthetic inspect'])
    for index, name in enumerate(names):
        source, obj = root / 'source' / name, root / 'objects' / ('%02d-' % index + Path(name).stem + '.o')
        watch.add(source, ('synthetic source ' + name).encode('ascii'))
        watch.add(obj, ('synthetic object ' + str(index)).encode('ascii'))
        actual_flags = startup(artifact, mode) if index == 8 else [*flags(artifact, mode, root / 'source' / c.FIXTURE,
            root / 'source/fiber/port' / directory, root / 'source', root / 'cmsis'), '-I' + str(source.parent)]
        deps = [dict(Path=str(source), Sha256=watch.hashes[source])]
        row = dict(Source=str(source), SourceSha256=watch.hashes[source], Object=str(obj), ObjectSha256=watch.hashes[obj],
            CompileFlags=actual_flags, CompileDependencyFile=str(obj.with_suffix('.compile.d')),
            Dependencies=deps, ActualCompileDependencies=copy.deepcopy(deps), CompileDependenciesVerified=True)
        sources.append(row)
        command('compile ' + source.name, [str(tool['gcc']), *actual_flags, '-MD', '-MF', row['CompileDependencyFile'],
            '-MT', 'pilot-source-' + str(index), '-c', str(source), '-o', str(obj)])
    index = len(commands)
    command('resolve ld', [str(tool['gcc']), '-print-prog-name=ld'])
    watch.add(root / ('command-%04d.stdout' % index), str(tool['ld']).encode('utf-8'))
    ordinary = [str(tool['gcc']), *arch, '-' + mode, '-nostdlib',
        '-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack',
        '-T', str(root / 'source' / c.FIXTURE / 'link.ld'), *(row['Object'] for row in sources),
        '-Wl,-Map=' + str(root / 'ordinary.map'), '-o', str(root / 'ordinary.elf')]
    command('link ordinary', ordinary)
    while len(commands) < 73:
        command('synthetic other record ' + str(len(commands)), [str(tool['gcc']), '--version'])
    inventory_root = BASE / 'inventory'
    fingerprint = 'A' * 64
    result = dict(Verdict='NATIVE-FINAL-TWIN-BUILD-PASS', Profile=profile, Mode=mode, Cohort=cohort,
        CohortArtifact=artifact, Linkage='direct', LTO=False, Error=None, InputDrift=[],
        SourceInventorySha256=fingerprint, SourceInventoryReceipt=str(inventory_root), Sources=sources, Commands=commands,
        Links=[dict(Kind='ordinary', Path=str(root / 'ordinary.elf'), Sha256='B' * 64), dict(Kind='emit-relocs')])
    bundle = dict(Root=root, Result=result, Descriptor=dict(Build=str(root), ReceiptSha256='C' * 64, ArtifactsSha256='D' * 64), Artifacts={})
    inventory = dict(SourceInventorySha256=fingerprint, Bundle=dict(Root=inventory_root))
    kwargs = dict(profile=profile, mode=mode, inventory=inventory, helpers=helpers, watch=watch, output_dir=BASE / (profile + '-' + mode) / 'fresh')
    return bundle, kwargs


class OrdinaryControlsTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(subprocess, 'Popen', side_effect=AssertionError('pure tests cannot start tools'))
        guard.start()
        self.addCleanup(guard.stop)

    def test_all_thirty_routes_construct_without_commands_or_outputs(self):
        for profile in TABLE:
            for mode in c.MODES:
                with self.subTest(profile=profile, mode=mode):
                    bundle, kwargs = fixture(profile, mode)
                    suite = c.create_suite(bundle, **kwargs)
                    self.assertEqual(suite.commands, [])
                    self.assertFalse(suite._started)
                    self.assertEqual(suite.report['Mode'], mode)
                    self.assertEqual(suite.report['Cohort'], TABLE[profile][0])
                    self.assertEqual(suite.report['RequiredCellsSatisfied'], 0)
                    self.assertIs(suite.report['CellContractSatisfied'], False)
                    self.assertNotIn('CM0-O2', suite.report['Status'])

    def test_control_plan_uses_two_to_three_or_four_to_five_not_invalid_lowering(self):
        for profile in TABLE:
            bundle, kwargs = fixture(profile)
            suite = c.create_suite(bundle, **kwargs)
            before, after = suite.plan[0]['Mutations'][0][1:]
            bits = 2 if profile.startswith('CM0') else 4
            self.assertEqual(before, ('#define __NVIC_PRIO_BITS %dU' % bits).encode('ascii'))
            self.assertEqual(after, ('#define __NVIC_PRIO_BITS %dU' % (bits + 1)).encode('ascii'))
            self.assertEqual([row['Index'] for row in suite.plan], [6, 7, 1, 3, 3])

    def test_storage_mutation_exact_nested_cm7_path_and_unchanged_state_recipe(self):
        for profile in TABLE:
            bundle, kwargs = fixture(profile)
            suite = c.create_suite(bundle, **kwargs)
            self.assertEqual(suite.plan[1]['Mutations'][0][0], 'fiber/port/' + TABLE[profile][1] + '/fiber_port_types.h')
            self.assertIn(b'REVISION 999', suite.plan[1]['Mutations'][0][2])
            self.assertEqual(suite.plan[2]['Mutations'][0][0], 'context/context_runtime_state.c')
            self.assertIn(b'abi_v2_anchor', suite.plan[2]['Mutations'][0][2])
            self.assertEqual(suite.plan[3]['Added'], b'void SVC_Handler(void) { for (;;) { } }\n')
            self.assertEqual(suite.plan[4]['Added'], b'void PendSV_Handler(void) { for (;;) { } }\n')

    def test_private_identity_changes_only_one_admitted_priority_token(self):
        for bits in (2, 4):
            original = 'fiber_port_context_cohort_arch_g%d_u00010000_r0' % bits
            nm = original + ' R 0 1\nother T 0 4\n'
            self.assertEqual(c.alternate_private(nm, bits), (original, original.replace('_g%d_' % bits, '_g%d_' % (bits + 1))))
        for nm, bits in (('', 2), ('fiber_port_context_cohort_a_g4_x R 0 1\n', 2),
                         ('fiber_port_context_cohort_a_g2_g2_x R 0 1\n', 2),
                         ('fiber_port_context_cohort_a_g2_x R 0 1\nfiber_port_context_cohort_b_g2_x R 0 1\n', 2)):
            with self.subTest(nm=nm), self.assertRaises(c.Rejected):
                c.alternate_private(nm, bits)

    def test_wrong_route_inventory_artifact_and_source_role_fail_before_start(self):
        for change in ('profile', 'mode', 'fingerprint', 'artifact', 'source', 'object', 'lto'):
            bundle, kwargs = fixture('CM7', 'Og')
            if change == 'profile':
                kwargs['profile'] = 'CM4'
            elif change == 'mode':
                kwargs['mode'] = 'O2-lto'
            elif change == 'fingerprint':
                bundle['Result']['SourceInventorySha256'] = 'F' * 64
            elif change == 'artifact':
                bundle['Result']['CohortArtifact'] = copy.deepcopy(bundle['Result']['CohortArtifact'])
                bundle['Result']['CohortArtifact']['compile_flags'].append('-flto')
            elif change in ('source', 'object'):
                bundle['Result']['Sources'][3][change.title()] = str(BASE / 'foreign')
            else:
                bundle['Result']['LTO'] = True
            with self.subTest(change=change), self.assertRaises(c.Rejected):
                c.create_suite(bundle, **kwargs)

    def test_compile_flag_override_and_command_binding_controls(self):
        for mutation in ('foreign-mode', 'fpu', 'basepri', 'compile-tail', 'deps', 'bool-exit'):
            bundle, kwargs = fixture('CM0PLUSVTOR', 'Os')
            row = bundle['Result']['Sources'][3]
            if mutation in ('foreign-mode', 'fpu', 'basepri'):
                row['CompileFlags'].append({'foreign-mode': '-O3', 'fpu': '-mfpu=fpv4-sp-d16', 'basepri': '-DFIBER_SCHEDULER_BASEPRI=16'}[mutation])
            elif mutation == 'compile-tail':
                next(r for r in bundle['Result']['Commands'] if r['Label'] == 'compile fiber_port.c')['Argv'][-1] = 'other.o'
            elif mutation == 'deps':
                row['ActualCompileDependencies'] = []
            else:
                bundle['Result']['Commands'][0]['Exit'] = False
            with self.subTest(mutation=mutation), self.assertRaises(c.Rejected):
                c.create_suite(bundle, **kwargs)

    def test_link_order_and_unadmitted_tool_reject(self):
        for change in ('objects', 'forced-anchor', 'tool'):
            bundle, kwargs = fixture('CM4', 'O3')
            row = next(r for r in bundle['Result']['Commands'] if r['Label'] == 'link ordinary')
            if change == 'objects':
                row['Argv'][-4], row['Argv'][-5] = row['Argv'][-5], row['Argv'][-4]
            elif change == 'forced-anchor':
                row['Argv'].insert(1, '-Wl,--whole-archive')
            else:
                del kwargs['watch'].hashes[Path(bundle['Result']['Commands'][0]['Argv'][0])]
            with self.subTest(change=change), self.assertRaises(c.Rejected):
                c.create_suite(bundle, **kwargs)

    def test_inherited_command_and_compile_are_exact_qualified_methods(self):
        cls = c.suite_type(utility)
        for name in ('command', 'compile_tuple', 'start', '_write', '_verify_outputs', '_link', '_undefined', '_definitions'):
            self.assertIs(getattr(cls, name), getattr(utility.Suite, name))
        self.assertIsNot(cls.finish, utility.Suite.finish)
        self.assertEqual(utility.RECEIPT_SHA, 'D5FF0D8A8368EC38C816ABC627D506278EB47978676A69ACC11FD19603D96FBB')

    def test_gcc_linker_resolution_dot_segments_bind_to_admitted_tool(self):
        bundle, kwargs = fixture('CM3', 'Os')
        index = next(i for i, row in enumerate(bundle['Result']['Commands']) if row['Label'] == 'resolve ld')
        stdout = bundle['Root'] / ('command-%04d.stdout' % index)
        kwargs['watch'].add(stdout, str(BASE / 'toolchain/bin/../ld.exe').encode('utf-8'))
        suite = c.create_suite(bundle, **kwargs)
        self.assertEqual(suite.tools['ld'], BASE / 'toolchain/ld.exe')

    def test_descriptor_slash_spelling_still_binds_the_exact_native_root(self):
        bundle, kwargs = fixture('CM7', 'O3')
        bundle['Descriptor']['Build'] = bundle['Root'].as_posix()
        self.assertEqual(c.create_suite(bundle, **kwargs).base, bundle['Root'])
        bundle['Descriptor']['Build'] = str(BASE / 'different-native')
        with self.assertRaises(c.Rejected):
            c.create_suite(bundle, **kwargs)

    def test_terminal_schema_rejects_attempt_timeout_bool_exit_and_journal_error(self):
        row = dict(State='TERMINAL', Status='EXPECTED-NONZERO', Exit=1, ExpectedExit=1, TimedOut=False)
        self.assertTrue(c.terminal_success([row]))
        for field, value in (('State', 'ATTEMPT'), ('Exit', True), ('Exit', 1.0), ('ExpectedExit', True),
                             ('Status', 'PASS'), ('TimedOut', True), ('JournalErrors', ['write failed'])):
            bad = dict(row, **{field: value})
            with self.subTest(field=field):
                self.assertFalse(c.terminal_success([bad]))
        self.assertFalse(c.terminal_success([]))

    def test_incomplete_finish_cannot_inherit_old_cm0_pass_or_cell_credit(self):
        bundle, kwargs = fixture('CM3', 'O0')
        suite = c.create_suite(bundle, **kwargs)
        result = suite.finish()
        self.assertEqual(result['Status'], 'FAIL')
        self.assertEqual(result['RequiredCellsSatisfied'], 0)
        self.assertFalse(result['CellContractSatisfied'])
        self.assertIn('incomplete', result['PrimaryError'])
        with self.assertRaises(c.Rejected):
            suite.finish()

    def test_primary_failure_is_preserved_without_starting_or_writing(self):
        bundle, kwargs = fixture('CM7', 'O2')
        suite = c.create_suite(bundle, **kwargs)
        report = suite.finish(RuntimeError('first compiler failure'))
        self.assertEqual(report['PrimaryError'], 'RuntimeError: first compiler failure')
        self.assertEqual(report['Status'], 'FAIL')
        self.assertFalse(report['OutputSealVerified'])

    def test_literal_control_traits_and_no_shared_output_container(self):
        for bits in (True, 2.0, 3, 5, '4'):
            with self.subTest(bits=bits), self.assertRaises(c.Rejected):
                c.control_plan(dict(target=dict(nvic_priority_bits=bits)), 'ARM_CM0', 'arm_cm0')
        plan = c.control_plan(dict(target=dict(nvic_priority_bits=4)), 'ARM_CM7/r0p1', 'arm_cm7_r0p1')
        plan[0]['Name'] = 'mutant'
        self.assertEqual(c.control_plan(dict(target=dict(nvic_priority_bits=4)), 'ARM_CM7/r0p1', 'arm_cm7_r0p1')[0]['Name'], c.CONTROLS[0])
        self.assertEqual(SUBJECT.read_bytes(), RAW)


if __name__ == '__main__':
    unittest.main(verbosity=2)
