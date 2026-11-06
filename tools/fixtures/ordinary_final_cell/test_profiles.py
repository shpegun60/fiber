"""Pure profile controls with authenticated E9 JSON fixtures; no tool or ELF runs."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
INV = Path('C:/fzin-20261104-e9')
SNAPSHOT = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
MODES = ('O0', 'Og', 'O2', 'Os', 'O3')
EXPECTED = {
    'CM0': ('cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default', 'CM0', 'ARM_CM0', 'arm_cm0', 'armv6m', '0x434D3030u', False),
    'CM0PLUS': ('cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default', 'CM0', 'ARM_CM0', 'arm_cm0', 'armv6m', '0x434D3030u', False),
    'CM0PLUSVTOR': ('cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default', 'CM0', 'ARM_CM0', 'arm_cm0', 'armv6m', '0x434D3030u', True),
    'CM3': ('cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default', 'CM3', 'ARM_CM3', 'arm_cm3', 'armv7m', '0x434D3033u', True),
    'CM4': ('cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default', 'CM4', 'ARM_CM4', 'arm_cm4', 'armv7em', '0x434D3034u', True),
    'CM7': ('cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default', 'CM7', 'ARM_CM7/r0p1', 'arm_cm7_r0p1', 'armv7em', '0x434D3701u', True),
}
COMMON = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c')


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


class ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        files = (HERE / 'profiles.py', Path(__file__).resolve(), INV / 'artifacts.json',
                 INV / 'results.json', INV / 'inputs/tools/freeze_cohorts.json')
        raw = {p: p.read_bytes() for p in files}
        hashes = {p: sha(b) for p, b in raw.items()}

        def close():
            if {p: sha(p.read_bytes()) for p in files} != hashes:
                raise AssertionError('profile test/subject/E9 fixture drift')

        cls.addClassCleanup(close)
        if hashes[INV / 'artifacts.json'] != '640C2CAC37DFC0A10F5A6E8538E7A9F81C7967DEEDEAA4B2924A15CAA1600CEA':
            raise AssertionError('E9 caller-bound artifact manifest')
        if hashes[INV / 'results.json'] != '1910B53001FD37DF4B6DC57805EE49E4381B2529E1E3ECB47FDB312EB43A4DFC':
            raise AssertionError('E9 caller-bound receipt')
        artifact_map = json.loads(raw[INV / 'artifacts.json'])['Artifacts']
        if hashes[INV / 'inputs/tools/freeze_cohorts.json'] != artifact_map['inputs/tools/freeze_cohorts.json']:
            raise AssertionError('E9 raw captured manifest binding')
        cls.manifest = json.loads(raw[INV / 'inputs/tools/freeze_cohorts.json'])
        spec = importlib.util.spec_from_file_location('ordinary_cell_profiles_controls', files[0])
        cls.subject = importlib.util.module_from_spec(spec)
        exec(compile(raw[files[0]], str(files[0]), 'exec'), cls.subject.__dict__)

    def fixture(self, name='CM0', mode='O2', reference=False):
        cohort, group, directory, storage, arch, port_id, vtor = EXPECTED[name]
        artifact = copy.deepcopy(next(x for x in self.manifest['cohorts'] if x['id'] == cohort)['artifacts'][0])
        port = 'portable/GCC/' + ('ARM_CM0' if group == 'CM0' else 'ARM_CM3' if name == 'CM3' else
                                 'ARM_CM4F' if name == 'CM4' else 'ARM_CM7/r0p1')
        fixture = 'tools/fixtures/' + ('cm0_final_image' if group == 'CM0' else
            'cm3_final_image' if name == 'CM3' else 'classic_final_image') + '/reference'
        sources = ([port + '/port.c'] + ([port + '/portasm.c'] if group == 'CM0' else []) +
            [fixture + '/' + f for f in ('providers.c', 'consumer.c', 'startup.S')] if reference else
            [*COMMON, *('fiber/port/' + directory + '/' + f for f in
             ('fiber_port.c', 'fiber_port_boot.c', 'fiber_port_exception.c')),
             'fiber/port/fiber_port_context_cohort_expectation.c',
             'tools/fixtures/classic_final_image/application.c', 'tools/fixtures/classic_final_image/startup.S'])
        defs = artifact['upstream_defines' if reference else 'defines']
        flags = [*artifact['compile_flags'], '-' + mode, '-std=gnu11', '-g0', '-ffreestanding',
                 *('-D' + k + '=' + defs[k] for k in sorted(defs)), '-I/pure fixture/include path']
        result = dict(Profile=name, Mode=mode, Cohort=cohort, SourceGroup=group,
            CohortArtifact=artifact, SourceInventorySha256=SNAPSHOT,
            Linkage='direct', LTO=False, CompileFlags=flags, Sources=[])
        for i, relative in enumerate(sources):
            source = '/pure fixture/' + ('freertos/' if reference and relative.startswith('portable/') else 'source/') + relative
            tu_flags = ([*artifact['compile_flags'], '-' + mode, '-g0'] +
                ([] if reference else ['-DPILOT_HAS_VTOR=' + str(int(vtor))]) if relative.endswith('.S') else
                flags + ([] if reference else ['-I' + str(PurePosixPath(source).parent)]))
            result['Sources'].append(dict(Source=source, Object='/pure fixture/objects/%02d-%s.o' % (i, PurePosixPath(relative).stem),
                SourceSha256='A' * 64, ObjectSha256='B' * 64, CompileFlags=tu_flags))
        if reference:
            result['ReferenceCommit'] = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
            if name in ('CM4', 'CM7'):
                result['FPCCRPolicy'] = dict(DeclaredNativePolicy='eager', ReferencePolicy='upstream-lazy',
                    ReferenceASPEN=1, ReferenceLSPEN=1, ReferenceBits=3221225472,
                    DifferenceId='FAP-FP-SETUP-POLICY', PolicyEquivalenceProven=False, HardwareEffectsProven=False)
            else:
                result.update(DeclaredVTOR=vtor, FixtureHandlerInstallationCheck=int(vtor),
                    FPPolicy='NOT-APPLICABLE-NO-FPU',
                    SchedulerThreshold='BASEPRI-NOT-APPLICABLE;PRIMASK-ENVELOPE' if group == 'CM0' else 16)
        return result

    def rejects(self, value, name='CM0', mode='O2', reference=False):
        with self.assertRaises(self.subject.Rejected):
            (self.subject.require_reference if reference else self.subject.require_native)(value, name, mode)

    def test_exact_thirty_routes_and_closed_selectors(self):
        expected = tuple(p + '/' + m + '/direct' for p in EXPECTED for m in MODES)
        self.assertEqual(self.subject.PROFILES, tuple(EXPECTED))
        self.assertEqual(self.subject.MODES, MODES)
        self.assertEqual(self.subject.ROUTES, expected)
        for route in expected:
            contract = self.subject.route_contract(route)
            self.assertEqual(contract['Route'], route)
        for bad in ('CM0/O2/archive', 'CM3/O2-lto/direct', 'CM3/Os-lto/direct', 'cm0/O2/direct',
                    'CM0/O1/direct', 'CM0/O2/direct/', '', None, True, ['CM0/O2/direct']):
            with self.subTest(bad=bad), self.assertRaises(self.subject.Rejected):
                self.subject.route_contract(bad)
        for bad in (None, True, 0, 'CM33', 'cm0'):
            with self.subTest(profile=bad), self.assertRaises(self.subject.Rejected):
                self.subject.profile(bad, 'O2')

    def test_independent_cohorts_groups_source_order_and_e9_artifacts(self):
        groups = {x['id']: x for x in self.manifest['source_groups']}
        for name, (cohort, group, directory, storage, arch, port_id, vtor) in EXPECTED.items():
            with self.subTest(profile=name):
                actual = self.subject.profile(name, 'O2')
                self.assertEqual(actual['Cohort'], cohort)
                self.assertEqual(actual['SourceInventorySha256'], SNAPSHOT)
                self.assertEqual(actual['SourceGroup'], group)
                self.assertEqual(actual['SourceOrder'][3:6], groups[group]['sources'])
                self.assertEqual(actual['SourceOrder'], [*COMMON,
                    *('fiber/port/' + directory + '/' + f for f in ('fiber_port.c', 'fiber_port_boot.c', 'fiber_port_exception.c')),
                    'fiber/port/fiber_port_context_cohort_expectation.c',
                    'tools/fixtures/classic_final_image/application.c', 'tools/fixtures/classic_final_image/startup.S'])
                canonical = next(x for x in self.manifest['cohorts'] if x['id'] == cohort)['artifacts'][0]
                self.assertTrue(self.subject._same(actual['CohortArtifact'], canonical))

    def test_private_storage_and_abi_literals(self):
        for name, (_, group, _, storage, arch, port_id, vtor) in EXPECTED.items():
            actual = self.subject.profile(name, 'O2')
            fp, cm0 = name in ('CM4', 'CM7'), group == 'CM0'
            expected = ('fiber_port_context_cohort_' + arch + '_p' + port_id + '_l0x00010001u'
                + ('_f1_e1_h1_j1' if fp else '_f0_e0_h0_j0' if cm0 else '_f0_e0_h1_j1')
                + '_v' + str(int(vtor)) + '_d0_r0_z8u_' + ('y1_w2_g4_u00010000' if fp else
                    'y0_w1_g2_u00000000' if cm0 else 'y0_w2_g4_u00010000')
                + ('_i1' if name == 'CM7' else '_i0') + '_o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0')
            self.assertEqual(actual['PrivateSymbol'], expected)
            self.assertEqual(actual['StorageSymbol'], 'fiber_port_storage_cohort_' + storage + '_v1_r0')
            self.assertEqual(actual['FloatABI'], 'hard' if fp else 'soft')
            self.assertEqual(actual['FinalFloatABIFlag'], 1024 if fp else 512)
        self.assertEqual(self.subject.profile('CM0', 'O2')['PrivateSymbol'], self.subject.profile('CM0PLUS', 'O2')['PrivateSymbol'])
        self.assertNotEqual(self.subject.profile('CM0PLUS', 'O2')['Cohort'], self.subject.profile('CM0PLUSVTOR', 'O2')['Cohort'])

    def test_fixed_reverse_cold_slot_and_vector_contracts_have_no_observed_offsets(self):
        for name in EXPECTED:
            actual = self.subject.profile(name, 'O3')
            rows = actual['ReverseReferences']
            self.assertEqual([(r['Function'], r['Symbol'], r['Kind'], r['Addend'], r['Count']) for r in rows], [
                ('fiber_port_runtime_schedule', 'fiber_internal_runtime_require_current_context', 10, -4, 1),
                ('fiber_port_scheduler_pick_first_from_start', 'fiber_internal_runtime_select_scheduler_candidate', 10, -4, 1),
                ('fiber_port_scheduler_pick_next_from_pendsv', 'fiber_internal_runtime_select_scheduler_candidate', 10, -4, 1),
                ('fiber_port_scheduler_pick_next_from_pendsv', 'fiber_internal_runtime_publish_current_context', 10, -4, 1),
                ('fiber_port_init_context_frame', 'fiber_internal_task_return', 2, 0, 1)])
            self.assertTrue(all(r['ObjectIndex'] == 3 and r['Section'] == '.text.' + r['Function'] and 'Offset' not in r for r in rows))
            self.assertEqual([(r['ObjectIndex'], r['Function'], r['Register'], r['Read']) for r in actual['ColdAnchors']],
                [(3, 'fiber_port_runtime_prepare_start', 'r3', 'ldrb'), (4, 'fiber_port_context_init', 'r3', 'ldrb')])
            self.assertEqual(actual['SlotOwners'], {'SVC_Handler': 'r0', 'PendSV_Handler': 'r1'})
            self.assertEqual([(r['Offset'], r['Symbol']) for r in actual['StartupVectors']], [(4, 'Reset_Handler'), (44, 'SVC_Handler'), (56, 'PendSV_Handler')])
            self.assertEqual([r['ObjectIndex'] for r in actual['CohortConsumers']], [4, 5, 6, 7])

    def test_profile_exceptions_and_reference_owners(self):
        for name in EXPECTED:
            c = self.subject.profile(name, 'O0')
            self.assertEqual(c['Target']['nvic_priority_bits'], 2 if name.startswith('CM0') else 4)
            self.assertEqual(c['Target']['scheduler_basepri'], 0 if name.startswith('CM0') else 16)
            self.assertEqual(len(c['ReferenceSourceOrder']), 5 if name.startswith('CM0') else 4)
            self.assertEqual(len(c['ReferenceRootOwners']), 5 if name.startswith('CM0') else 3)
            self.assertEqual(c['ReferenceHandlerInstallationCheck'], int(EXPECTED[name][-1]))
            if name.startswith('CM0'):
                self.assertEqual(c['ReferenceRootOwners']['vPortSVCHandler_C'], 0)
                self.assertIsNone(c['NativeTailNops'])
            else:
                self.assertEqual(c['NativeTailNops'], 1)
                self.assertEqual(self.subject.profile(name, 'Os')['NativeTailNops'], 0)
        cm7 = self.subject.profile('CM7', 'O2')
        self.assertEqual(cm7['CohortArtifact']['upstream_defines']['configENABLE_ERRATA_837070_WORKAROUND'], '1')
        self.assertEqual(cm7['ReferenceHeaderFacts'], [1, 4, 4, 4, 8, 14, 1, 16, 16, 4])
        self.assertEqual(cm7['ReferenceFPPolicy'], 'upstream-lazy-ASPEN1-LSPEN1')
        self.assertEqual(cm7['NativeFPPolicy'], 'eager')

    def test_api_is_no_io_and_returns_fresh_nonpromoting_values(self):
        with patch('builtins.open', side_effect=AssertionError('profile opened file')), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('profile read file')), \
                patch.object(Path, 'resolve', side_effect=AssertionError('profile resolved physical path')):
            a = self.subject.profile('CM4', 'O2')
            b = self.subject.profile('CM4', 'O2')
            a['Target']['vtor'] = False
            a['SourceOrder'].clear()
            a['Snapshot']['Build'] = '/foreign'
            self.assertIs(b['Target']['vtor'], True)
            self.assertEqual(len(b['SourceOrder']), 9)
            self.assertEqual(b['Snapshot']['Build'], 'C:/fzin-20261104-e9')
            self.assertNotIn('Mode', self.subject.profile_contract('CM3'))
        for field in ('RequiredCellSatisfied', 'FullABIProof', 'FullSemanticABIProof', 'InputAuthenticationProof',
                      'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'GlobalFreezeQualified'):
            self.assertIs(b[field], False, field)
        self.assertIs(type(b['RequiredCellsSatisfied']), int)
        self.assertEqual(b['RequiredCellsSatisfied'], 0)

    def test_sixty_synthetic_receipt_metadata_admissions(self):
        for name in EXPECTED:
            for mode in MODES:
                for reference in (False, True):
                    fn = self.subject.require_reference if reference else self.subject.require_native
                    result = fn(self.fixture(name, mode, reference), name, mode)
                    self.assertIs(result['MetadataOnly'], True)
                    self.assertIs(result['RequiredCellSatisfied'], False)
                    self.assertEqual(result['RequiredCellsSatisfied'], 0)

    def test_wrong_route_snapshot_and_typed_aliases_reject(self):
        for key, value in (('Profile', 'CM0PLUS'), ('Mode', 'O0'), ('Cohort', 'foreign'),
                           ('SourceInventorySha256', 'E8'), ('Linkage', 'archive'), ('LTO', 0)):
            r = self.fixture(); r[key] = value
            with self.subTest(key=key): self.rejects(r)
        for name in EXPECTED:
            for key in ('vtor', 'fpu_used', 'nvic_priority_bits', 'scheduler_basepri', 'mpu_regions'):
                r = self.fixture(name); old = r['CohortArtifact']['target'][key]
                r['CohortArtifact']['target'][key] = int(old) if type(old) is bool else float(old)
                with self.subTest(profile=name, field=key): self.rejects(r, name)

    def test_artifact_extra_fields_wrong_defines_and_reference_pin(self):
        for mutate in (lambda a: a.update(foreign=True), lambda a: a['target'].update(extra=False),
                       lambda a: a['defines'].update(FIBER_PORT_BUILD_SELECTED='0'),
                       lambda a: a.update(compile_flags=['-mcpu=cortex-m3'])):
            r = self.fixture(); mutate(r['CohortArtifact']); self.rejects(r)
        r = self.fixture('CM7', reference=True)
        del r['CohortArtifact']['upstream_defines']['configENABLE_ERRATA_837070_WORKAROUND']
        self.rejects(r, 'CM7', reference=True)
        r = self.fixture(reference=True); r['ReferenceCommit'] = '0' * 40
        self.rejects(r, reference=True)

    def test_source_order_object_alias_and_traversal_reject(self):
        for variant in ('swap', 'extra', 'wrong-dir', 'object-alias', 'traversal', 'bad-hash'):
            r = self.fixture()
            if variant == 'swap': r['Sources'][3], r['Sources'][4] = r['Sources'][4], r['Sources'][3]
            elif variant == 'extra': r['Sources'].append(copy.deepcopy(r['Sources'][0]))
            elif variant == 'wrong-dir': r['Sources'][3]['Source'] = r['Sources'][3]['Source'].replace('ARM_CM0', 'ARM_CM3')
            elif variant == 'object-alias': r['Sources'][1]['Object'] = r['Sources'][0]['Object']
            elif variant == 'traversal': r['Sources'][3]['Source'] = r['Sources'][3]['Source'].replace('/source/', '/source/../source/')
            else: r['Sources'][0]['SourceSha256'] = True
            with self.subTest(variant=variant): self.rejects(r)

    def test_compile_target_mode_define_and_lto_mutations_reject(self):
        for flag in ('-O3', '-flto', '-mfloat-abi=hard', '-ffixed-r9', '-DFOREIGN=1'):
            r = self.fixture(); r['CompileFlags'].append(flag)
            with self.subTest(flag=flag): self.rejects(r)
        r = self.fixture(); r['Sources'][0]['CompileFlags'].pop()
        self.rejects(r)

    def test_exact_startup_vtor_and_no_fp_policy_promotion(self):
        for name in EXPECTED:
            r = self.fixture(name); r['Sources'][-1]['CompileFlags'][-1] = '-DPILOT_HAS_VTOR=' + str(1 - int(EXPECTED[name][-1]))
            with self.subTest(profile=name): self.rejects(r, name)
        r = self.fixture('CM0PLUSVTOR', reference=True); r['DeclaredVTOR'] = False
        self.rejects(r, 'CM0PLUSVTOR', reference=True)
        r = self.fixture(reference=True); r['FixtureHandlerInstallationCheck'] = False
        self.rejects(r, reference=True)
        r = self.fixture('CM7', reference=True); r['FPCCRPolicy']['ReferencePolicy'] = 'eager'
        self.rejects(r, 'CM7', reference=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
