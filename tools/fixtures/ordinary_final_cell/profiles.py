"""Independent finite ordinary-cell metadata. Pure; no file reads or imports of gates.

Expected symbols come from the published source/header contracts, never ELF
observations. Receipt checks below are metadata checks, not authentication or
proof of an executed compiler command, provider, function body, or full cell.
"""
from copy import deepcopy
from pathlib import PurePosixPath, PureWindowsPath
import re


PROFILES = ('CM0', 'CM0PLUS', 'CM0PLUSVTOR', 'CM3', 'CM4', 'CM7')
MODES = ('O0', 'Og', 'O2', 'Os', 'O3')
ROUTES = tuple(p + '/' + m + '/direct' for p in PROFILES for m in MODES)
PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
SNAPSHOT = dict(Build='C:/fzin-20261104-e9',
    ReceiptSha256='1910B53001FD37DF4B6DC57805EE49E4381B2529E1E3ECB47FDB312EB43A4DFC',
    ArtifactsSha256='640C2CAC37DFC0A10F5A6E8538E7A9F81C7967DEEDEAA4B2924A15CAA1600CEA',
    SourceInventorySha256='69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313',
    ManifestPath='inputs/tools/freeze_cohorts.json',
    ManifestRawSha256='BC6B8EADABCAA6637FDD121D03B5CA341EEE31848D7E007D1D027AEE63EC8CBE')
COMMON = ('cpu-neutral-engine', 'reverse-v1-ownership', 'source-provider-identity')
RUNTIME = ('forward-eight', 'reverse-v1', 'current-slot-isolation', 'strong-handlers',
           'exact-profile-context-cohort', 'generated-assembly-reference-parity',
           'final-elf-vectors', 'negative-link-controls')
COMMON_SOURCES = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c')
NATIVE_FIXTURE = 'tools/fixtures/classic_final_image'
FORWARD_OWNERS = {'fiber_port_context_init': 4, 'fiber_port_runtime_memory_barrier': 3,
    'fiber_port_panic_wait': 3, 'fiber_port_require_scheduler_configuration_environment': 3,
    'fiber_port_runtime_prepare_start': 3, 'fiber_port_runtime_select_first': 3,
    'fiber_port_runtime_start_first': 3, 'fiber_port_runtime_schedule': 3}
REVERSE_OWNERS = {'fiber_internal_runtime_select_scheduler_candidate': 1,
    'fiber_internal_runtime_publish_current_context': 1,
    'fiber_internal_runtime_require_current_context': 1, 'fiber_internal_task_return': 0}
ANCHOR = 'fiber_internal_runtime_port_abi_v1_anchor'
SLOT = 'fiber_internal_runtime_current_context_slot'
_DIFF_COMMON = ['FAP-COMMON-START', 'FAP-COMMON-PROVENANCE',
                'FAP-COMMON-MASK-RESTORE', 'FAP-COMMON-SCHEDULER']
# Explicit selectors, not parsed from an inventory row or an observed symbol.
_ROWS = {
    'CM0': ('cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default',
            'CM0', 'ARM_CM0', 'arm_cm0', 'ARMV6M', 'cortex-m0', False, '', 'none', '0x434D3030u'),
    'CM0PLUS': ('cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default',
            'CM0', 'ARM_CM0', 'arm_cm0', 'ARMV6M', 'cortex-m0plus', False, '', 'none', '0x434D3030u'),
    'CM0PLUSVTOR': ('cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default',
            'CM0', 'ARM_CM0', 'arm_cm0', 'ARMV6M', 'cortex-m0plus', True, '', 'none', '0x434D3030u'),
    'CM3': ('cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default',
            'CM3', 'ARM_CM3', 'arm_cm3', 'ARMV7M', 'cortex-m3', True, '', 'none', '0x434D3033u'),
    'CM4': ('cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default',
            'CM4', 'ARM_CM4', 'arm_cm4', 'ARMV7EM', 'cortex-m4', True,
            'fpv4-sp-d16', 'none', '0x434D3034u'),
    'CM7': ('cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default',
            'CM7', 'ARM_CM7/r0p1', 'arm_cm7_r0p1', 'ARMV7EM', 'cortex-m7', True,
            'fpv5-d16', '837070-primask-preserving', '0x434D3701u'),
}


class Rejected(ValueError):
    pass


def _need(condition, message):
    if not condition:
        raise Rejected('ordinary-cell-profile: ' + message)


def _same(actual, expected):
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return set(actual) == set(expected) and all(_same(actual[k], v) for k, v in expected.items())
    if type(expected) is list:
        return len(actual) == len(expected) and all(_same(a, b) for a, b in zip(actual, expected))
    return actual == expected


def _reference(function, target, kind=10):
    return dict(ObjectIndex=3, Function=function, Section='.text.' + function,
                Symbol=target, Kind=kind, Addend=-4 if kind == 10 else 0, Count=1)


def profile(name, mode):
    """Return a fresh JSON-like contract for one of exactly thirty direct routes."""
    _need(type(name) is str and name in PROFILES, 'closed profile')
    _need(type(mode) is str and mode in MODES, 'closed ordinary mode')
    cohort, group, directory, storage, arch, cpu, vtor, fpu, errata, port_id = _ROWS[name]
    cm0, fp = group == 'CM0', name in ('CM4', 'CM7')
    abi = 'hard' if fp else 'soft'
    target = dict(cpu=cpu, architecture=arch, float_abi=abi, fpu_present=fp, fpu_used=fp,
        fpu_unit=fpu, fp_stacking='eager' if fp else 'none', vtor=vtor, mpu_regions=0,
        security_role='classic', psplim_slot=False, psplim_register=False, mve='none',
        pac=False, bti=False, errata_policy=errata, r9_abi='aapcs',
        nvic_priority_bits=2 if cm0 else 4, scheduler_basepri=0 if cm0 else 16)
    flags = ['-mcpu=' + cpu, '-mthumb', '-mfloat-abi=' + abi] + (['-mfpu=' + fpu] if fp else [])
    defines = ({'FIBER_PORT_ARMV6M': '1', 'FIBER_PORT_BUILD_SELECTED': '1'} if cm0 else
        {'FIBER_PORT_ARMV7M': '1', 'FIBER_PORT_BUILD_SELECTED': '1', 'FIBER_SCHEDULER_BASEPRI': '16'}
        if name == 'CM3' else {'FIBER_FPU_LAZY': '0', 'FIBER_PORT_ARMV7EM': '1',
            'FIBER_PORT_BUILD_SELECTED': '1', 'FIBER_SCHEDULER_BASEPRI': '16'})
    upstream = dict(FIBER_FREERTOS_PARITY_ENABLE_FPU='1' if fp else '0',
                    FIBER_FREERTOS_PARITY_ENABLE_MPU='0', FIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE='0')
    if name == 'CM7':
        upstream['configENABLE_ERRATA_837070_WORKAROUND'] = '1'
    port = 'portable/GCC/' + ('ARM_CM0' if cm0 else 'ARM_CM3' if name == 'CM3' else
                             'ARM_CM4F' if name == 'CM4' else 'ARM_CM7/r0p1')
    upstream_sources = [port + '/port.c'] + ([port + '/portasm.c'] if cm0 else [])
    fixture = 'tools/fixtures/' + ('cm0_final_image' if cm0 else 'cm3_final_image'
                                 if name == 'CM3' else 'classic_final_image') + '/reference'
    source_order = [*COMMON_SOURCES, *('fiber/port/' + directory + '/' + f for f in
        ('fiber_port.c', 'fiber_port_boot.c', 'fiber_port_exception.c')),
        'fiber/port/fiber_port_context_cohort_expectation.c',
        NATIVE_FIXTURE + '/application.c', NATIVE_FIXTURE + '/startup.S']
    private = ('fiber_port_context_cohort_' + arch.lower() + '_p' + port_id + '_l0x00010001u'
        + ('_f1_e1' if fp else '_f0_e0') + ('_h0_j0' if cm0 else '_h1_j1')
        + '_v' + str(int(vtor)) + '_d0_r0_z8u_y' + str(int(fp))
        + ('_w1_g2_u00000000' if cm0 else '_w2_g4_u00010000')
        + '_i' + str(int(name == 'CM7')) + '_o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0')
    reference_roots = ({'vStartFirstTask': 1, 'SVC_Handler': 1, 'vPortSVCHandler_C': 0,
                        'vRestoreContextOfFirstTask': 1, 'PendSV_Handler': 1} if cm0 else
                       {'prvPortStartFirstTask': 0, 'vPortSVCHandler': 0, 'xPortPendSVHandler': 0})
    family = 'cm0' if cm0 else 'cm3' if name == 'CM3' else 'classic'
    artifact = dict(role='runtime', source_group_id=group, abi_contract='forward8',
                    target=target, compile_flags=flags, defines=defines,
                    upstream_defines=upstream, upstream_sources=upstream_sources)
    return dict(Profile=name, Mode=mode, Route=name + '/' + mode + '/direct', Cohort=cohort,
        SourceGroup=group, ArtifactRole='runtime', Representation='final', Linkage='direct', LTO=False,
        SourceOrder=source_order, ReferenceSourceOrder=[*upstream_sources,
            *(fixture + '/' + f for f in ('providers.c', 'consumer.c', 'startup.S'))],
        PrivateSymbol=private, StorageSymbol='fiber_port_storage_cohort_' + storage + '_v1_r0',
        FloatABI=abi, FinalFloatABIFlag=0x400 if fp else 0x200,
        Target=target, CompileFlags=flags, Defines=defines, CohortArtifact=artifact,
        StartupFlags=[*flags, '-' + mode, '-g0', '-DPILOT_HAS_VTOR=' + str(int(vtor))],
        ReferenceStartupFlags=[*flags, '-' + mode, '-g0'],
        NativeCSourceIncludePolicy='APPEND_EXACT_TU_PARENT',
        SlotOwners={'SVC_Handler': 'r0', 'PendSV_Handler': 'r1'}, SlotSymbol=SLOT,
        SlotProvider=1, SlotInputSection='.bss.fiber_runtime_current_context_slot', SlotSize=4,
        AnchorSymbol=ANCHOR, AnchorProvider=1, ForwardOwners=deepcopy(FORWARD_OWNERS),
        ReverseOwners=deepcopy(REVERSE_OWNERS), PrivateProvider=3, StorageProvider=3, StartupProvider=8,
        ReverseReferences=[
            _reference('fiber_port_runtime_schedule', 'fiber_internal_runtime_require_current_context'),
            _reference('fiber_port_scheduler_pick_first_from_start', 'fiber_internal_runtime_select_scheduler_candidate'),
            _reference('fiber_port_scheduler_pick_next_from_pendsv', 'fiber_internal_runtime_select_scheduler_candidate'),
            _reference('fiber_port_scheduler_pick_next_from_pendsv', 'fiber_internal_runtime_publish_current_context'),
            _reference('fiber_port_init_context_frame', 'fiber_internal_task_return', 2)],
        ColdAnchors=[dict(ObjectIndex=i, Function=f, Section='.text.' + f, Symbol=ANCHOR,
            Kind=2, Addend=0, Count=1, Register='r3', Read='ldrb', ReadOffset=0)
            for i, f in ((3, 'fiber_port_runtime_prepare_start'), (4, 'fiber_port_context_init'))],
        CohortConsumers=[dict(ObjectIndex=i, Section=s, Symbol=symbol, Kind=2, Addend=0, Count=1)
            for i, s, symbol in ((4, '.text.fiber_port_context_init', private),
                (5, '.text.fiber_exception_runtime_check', private),
                (6, '.fiber_port_context_cohort_expectation', private),
                (7, '.fiber_port_context_cohort_expectation', 'fiber_port_storage_cohort_' + storage + '_v1_r0'))],
        StartupVectors=[dict(Offset=o, Symbol=s, Provider=i, Kind=2, Addend=0)
            for o, s, i in ((4, 'Reset_Handler', 8), (44, 'SVC_Handler', 3), (56, 'PendSV_Handler', 3))],
        VectorBytes=1024, InitialMSP=0x20010000, StartupVTORLiteralCount=int(vtor),
        ReferenceCommit=PIN, ReferenceRootOwners=reference_roots,
        ReferenceHeaderFacts=[1, 4, 4, 4, 8, 14 if name == 'CM7' else 4 if fp else 0,
                              int(fp), 0 if cm0 else 16, 0 if cm0 else 16, 2 if cm0 else 4],
        ReferenceHandlerInstallationCheck=int(vtor), NativeFPPolicy='eager' if fp else 'not-applicable',
        ReferenceFPPolicy='upstream-lazy-ASPEN1-LSPEN1' if fp else 'not-applicable',
        BaseConfig=('tools/fixtures/classic_cm7_fp_context_runtime/reference/FreeRTOSConfig.h' if name == 'CM7' else
                    'tools/fixtures/classic_fp_context_runtime/reference/FreeRTOSConfig.h' if fp else
                    'tools/fixtures/freertos_asm_parity/FreeRTOSConfig.h'),
        ProtocolPadding='CM0_MODE_SPECIFIC_FULL_BODY_AND_OWN_SECTION' if cm0 else 'O0_ONE_POST_ISLAND_NOP_OTHER_MODES_ZERO',
        NativeTailNops=None if cm0 else int(mode == 'O0'),
        DifferenceIds=_DIFF_COMMON + (['FAP-CM0-STAGED-FRAME'] if cm0 else
            ['FAP-CM3-EXC-RETURN', 'FAP-CM3-LOCAL-LITERAL-POOLS'] if name == 'CM3' else
            ['FAP-FP-VALIDATION', 'FAP-FP-SETUP-POLICY'] + (['FAP-CM7-ERRATA-PRIMASK'] if name == 'CM7' else [])),
        Gate='tools/fixtures/' + family + '_final_join/join.py',
        AttributeGate=('tools/freeze_cm0_mechanisms.py' if cm0 else
            'tools/fixtures/cm3_final_image/admission.py' if name == 'CM3' else 'tools/freeze_classic_fp_mechanisms.py'),
        SourceInventorySha256=SNAPSHOT['SourceInventorySha256'],
        Snapshot=deepcopy(SNAPSHOT), CommonRequirements=list(COMMON), RuntimeRequirements=list(RUNTIME),
        MetadataOnly=True, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
        FullABIProof=False, FullSemanticABIProof=False, InputAuthenticationProof=False,
        CpuExecution=False, BoardExecution=False, HostedCIQualified=False, GlobalFreezeQualified=False)


def route_contract(route):
    _need(type(route) is str and route in ROUTES, 'one of exactly thirty ordinary-direct routes')
    name, mode, _ = route.split('/')
    return profile(name, mode)


def profile_contract(name):
    """Mode-independent convenience view; no default mode is admitted implicitly."""
    result = profile(name, 'O2')
    for key in ('Mode', 'Route', 'StartupFlags', 'ReferenceStartupFlags', 'NativeTailNops'):
        del result[key]
    return result


def _path_parts(value):
    _need(type(value) is str and value.isascii() and not any(c in value for c in '\r\n\0'), 'source path string')
    path = PureWindowsPath(value) if PureWindowsPath(value).is_absolute() else PurePosixPath(value)
    _need(path.is_absolute() and '..' not in path.parts, 'absolute source identity without traversal')
    return tuple(p.casefold() for p in path.parts)


def _flags(flags, contract, reference, startup=False):
    _need(type(flags) is list and all(type(f) is str for f in flags), 'literal compile flags')
    if startup:
        _need(_same(flags, contract['ReferenceStartupFlags' if reference else 'StartupFlags']), 'exact startup flags')
        return
    prefix = [*contract['CompileFlags'], '-' + contract['Mode']]
    _need(flags[:len(prefix)] == prefix, 'target and optimization prefix')
    _need([f for f in flags if f.startswith('-m')] == contract['CompileFlags'], 'no alternate target/ABI flags')
    _need([f for f in flags if f.startswith('-O')] == ['-' + contract['Mode']]
          and not any(f.startswith(('-flto', '-fno-lto', '-ffixed-', '-fpic', '-fPIC')) for f in flags), 'ordinary mode/r9 only')
    defines = contract['CohortArtifact']['upstream_defines'] if reference else contract['Defines']
    _need([f for f in flags if f.startswith('-D')] == ['-D' + k + '=' + defines[k] for k in sorted(defines)], 'exact literal defines')


def _require(result, name, mode, reference):
    contract = profile(name, mode)
    _need(type(result) is dict, 'receipt metadata object')
    for key in ('Profile', 'Mode', 'Cohort', 'Linkage', 'LTO'):
        _need(_same(result.get(key), contract[key]), 'receipt ' + key)
    _need(_same(result.get('CohortArtifact'), contract['CohortArtifact']), 'full typed cohort artifact')
    _need(result.get('SourceInventorySha256') == SNAPSHOT['SourceInventorySha256'], 'E9 snapshot identity')
    if 'SourceGroup' in result:
        _need(result['SourceGroup'] == contract['SourceGroup'], 'source group')
    _flags(result.get('CompileFlags'), contract, reference)
    order = contract['ReferenceSourceOrder' if reference else 'SourceOrder']
    rows = result.get('Sources')
    _need(type(rows) is list and len(rows) == len(order) and all(type(row) is dict for row in rows), 'exact TU count')
    roots, objects = {}, set()
    for index, (row, relative) in enumerate(zip(rows, order)):
        parts, suffix = _path_parts(row.get('Source')), tuple(p.casefold() for p in PurePosixPath(relative).parts)
        _need(len(parts) > len(suffix) and parts[-len(suffix):] == suffix, 'ordered source identity')
        role = 'kernel' if reference and relative.startswith('portable/') else 'source'
        root = parts[:-len(suffix)]
        _need(role not in roots or roots[role] == root, 'consistent source root')
        roots[role] = root
        obj = _path_parts(row.get('Object'))
        _need(obj not in objects and obj[-1] == ('%02d-%s.o' % (index, PurePosixPath(relative).stem)).casefold(), 'ordered object identity')
        objects.add(obj)
        for field in ('SourceSha256', 'ObjectSha256'):
            _need(type(row.get(field)) is str and re.fullmatch(r'[0-9A-F]{64}', row[field]) is not None, 'declared byte hash')
        _flags(row.get('CompileFlags'), contract, reference, startup=relative.endswith('.S'))
        if not relative.endswith('.S'):
            source = row['Source']
            source_path = PureWindowsPath(source) if PureWindowsPath(source).is_absolute() else PurePosixPath(source)
            expected_flags = result['CompileFlags'] + ([] if reference else ['-I' + str(source_path.parent)])
            _need(_same(row['CompileFlags'], expected_flags), 'exact per-TU C recipe')
    if reference:
        _need(result.get('ReferenceCommit') == PIN, 'exact FreeRTOS pin')
        if name.startswith('CM0') or name == 'CM3':
            _need(_same(result.get('DeclaredVTOR'), contract['Target']['vtor'])
                  and _same(result.get('FixtureHandlerInstallationCheck'), contract['ReferenceHandlerInstallationCheck']), 'reference VTOR/check policy')
            _need(result.get('FPPolicy') == 'NOT-APPLICABLE-NO-FPU', 'no-FPU reference policy')
            _need(_same(result.get('SchedulerThreshold'), 'BASEPRI-NOT-APPLICABLE;PRIMASK-ENVELOPE' if name.startswith('CM0') else 16), 'reference threshold')
        else:
            _need(_same(result.get('FPCCRPolicy'), dict(DeclaredNativePolicy='eager', ReferencePolicy='upstream-lazy',
                ReferenceASPEN=1, ReferenceLSPEN=1, ReferenceBits=0xC0000000,
                DifferenceId='FAP-FP-SETUP-POLICY', PolicyEquivalenceProven=False, HardwareEffectsProven=False)), 'eager/lazy distinction')
    return dict(Profile=name, Mode=mode, Route=contract['Route'], ReceiptMetadataMatched=True,
                MetadataOnly=True, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
                FullABIProof=False, FullSemanticABIProof=False, InputAuthenticationProof=False,
                CpuExecution=False, BoardExecution=False, HostedCIQualified=False, GlobalFreezeQualified=False)


def require_native(result, name, mode):
    return _require(result, name, mode, False)


def require_reference(result, name, mode):
    return _require(result, name, mode, True)
