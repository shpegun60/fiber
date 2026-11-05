"""Pure fixed CM3 policy-cohort grammar; not an ELF or callable-ABI proof."""
import re


PRIVATE16 = (
    'fiber_port_context_cohort_armv7m_p0x434D3033u_l0x00010001u_'
    'f0_e0_h1_j1_v1_d0_r0_z8u_y0_w2_g4_u00010000_i0_'
    'o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0')
PRIVATE32 = PRIVATE16.replace('_u00010000_', '_u00100000_')
STORAGE = 'fiber_port_storage_cohort_arm_cm3_v1_r0'
FUNCTIONS = (
    'fiber_port_init_context_frame', 'fiber_port_panic_wait',
    'fiber_port_require_scheduler_configuration_environment',
    'fiber_port_runtime_memory_barrier', 'fiber_port_runtime_prepare_start',
    'fiber_port_runtime_schedule', 'fiber_port_runtime_select_first',
    'fiber_port_runtime_start_first', 'fiber_port_scheduler_pick_first_from_start',
    'fiber_port_scheduler_pick_next_from_pendsv', 'fiber_port_start_first_context',
    'PendSV_Handler', 'SVC_Handler')


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-cohort-identity: ' + message)


def _text(text):
    need(type(text) is str and text and text.isascii() and '\x00' not in text,
         'nonempty literal ASCII tool text')
    return text.splitlines()


def _runtime_rows(text, private):
    rows = []
    for line in _text(text):
        match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*) ([DT]) 0[ \t]*', line)
        need(match is not None, 'complete plugin-NM row grammar')
        rows.append(dict(Name=match[1], Kind=match[2], PluginValue=0))
    expected = [dict(Name=private, Kind='D', PluginValue=0)]
    expected.extend(dict(Name=name, Kind='T', PluginValue=0) for name in FUNCTIONS[:-2])
    expected.append(dict(Name=STORAGE, Kind='D', PluginValue=0))
    expected.extend(dict(Name=name, Kind='T', PluginValue=0) for name in FUNCTIONS[-2:])
    need(rows == expected, 'exact ordered CM3 runtime IR definitions')
    return rows


def cohort_pair(runtime16_nm_text, runtime32_nm_text):
    first = _runtime_rows(runtime16_nm_text, PRIVATE16)
    second = _runtime_rows(runtime32_nm_text, PRIVATE32)
    need(first[1:] == second[1:] and PRIVATE16 != PRIVATE32,
         'only exact private scheduler-policy identity may differ')
    return dict(Private16=PRIVATE16, Private32=PRIVATE32, Storage=STORAGE,
        Rows16=first, Rows32=second, PolicyDifferenceOnly=True,
        StorageIdentityChanged=False, ELFValidated=False, FullABIProof=False,
        SourceToMachineSemanticProof=False, CpuExecution=False,
        BoardExecution=False, RequiredCellsSatisfied=0, GlobalFreezeQualified=False)


def require_mismatch(stderr_text, expected_symbol):
    need(type(expected_symbol) is str and expected_symbol in (PRIVATE16, PRIVATE32),
         'one fixed expected private cohort')
    missing, headers, endings = [], 0, 0
    for line in _text(stderr_text):
        reference = re.fullmatch(r".+: undefined reference to `([A-Za-z_][A-Za-z0-9_]*)'[ \t]*", line)
        if reference:
            missing.append(reference[1])
        elif re.fullmatch(r".+: in function `[^'\r\n]+':", line):
            headers += 1
        elif re.fullmatch(r'(?:.*[/\\])?collect2(?:\.exe)?: error: ld returned 1 exit status', line):
            endings += 1
        else:
            need(False, 'unrecognized or unrelated linker diagnostic')
    need(missing and set(missing) == {expected_symbol} and endings == 1,
         'only intended missing exact private cohort with one linker exit')
    return dict(MissingSymbols=[expected_symbol], ReferenceCount=len(missing),
        FunctionHeaders=headers, LinkerExitRecords=endings,
        IntendedPrivateCohortMismatch=True, StorageMismatchProven=False,
        RuntimeABIVersionMismatchProven=False, FullABIProof=False,
        CpuExecution=False, BoardExecution=False, RequiredCellsSatisfied=0,
        GlobalFreezeQualified=False)
