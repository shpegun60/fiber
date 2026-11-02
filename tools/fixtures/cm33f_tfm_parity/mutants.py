"""Compile bounded mutations of copied actual Fiber and pinned source only."""
import importlib.util
from pathlib import Path
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

path = Path(__file__).resolve().parent.parent/'cm55_tfm_parity/mutants.py'
spec = importlib.util.spec_from_file_location('c3ft_common_mutants',path)
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)

INDEPENDENT = frozenset(('save-count','save-writeback','save-slot-order','restore-count',
    'restore-writeback','restore-psplim-source','restore-psp-source','first-restore-r9',
    'first-control-readback','svc-opcode','svc-raw-core-offset','constructor-r9',
    'constructor-argument','constructor-psplim','constructor-cursor','constructor-cpu-write',
    'init-sticky','init-cpu-preservation','init-ready-readback','mutex-owner','mutex-recursion',
    'mutex-finite-timeout','reference-save-count','reference-restore-writeback',
    'reference-first-skip','reference-constructor-xpsr','reference-wrapper-status',
    'fp-save-count','fp-save-writeback-cancel','fp-restore-count','fp-restore-writeback',
    'fp-save-condition','fp-restore-condition','fpu-eager-policy','fpu-lspact-readiness',
    'fpu-running-lspact','init-full-fpca'))


def cases():
    result = [c for c in common.cases() if c[0] not in common.R9_DATAFLOW_MUTANTS]
    result += [
        ('constructor-r9','Fiber',None,'frame[fiber_portFRAME_R9] = fiber_port_read_r9();',
         'frame[fiber_portFRAME_R9] = 0u;'),
        ('fp-save-count','Fiber','void PendSV_Handler(void)','vstmdb r0!, {s16-s31}','vstmdb r0!, {s16-s30}'),
        # VSTMDB without writeback is unencodable. Cancel the real update
        # with a separately compiled ADD instead of counting an assembler error.
        ('fp-save-writeback-cancel','Fiber','void PendSV_Handler(void)',
         'vstmdb r0!, {s16-s31}','vstmdb r0!, {s16-s31}\\nadd r0, r0, #64'),
        ('fp-restore-count','Fiber','void PendSV_Handler(void)','vldmia r0!, {s16-s31}','vldmia r0!, {s16-s30}'),
        ('fp-restore-writeback','Fiber','void PendSV_Handler(void)','vldmia r0!, {s16-s31}','vldmia r0, {s16-s31}'),
        ('fp-save-condition','Fiber','void PendSV_Handler(void)','bne   2f','beq   2f'),
        ('fp-restore-condition','Fiber','void PendSV_Handler(void)','bne   22f','beq   22f'),
        ('fpu-eager-policy','Fiber','void fiber_port_fpu_prepare(void)',
         'fpccr &= ~fiber_portFPCCR_LSPEN_BIT;','fpccr |= fiber_portFPCCR_LSPEN_BIT;'),
        ('fpu-lspact-readiness','Fiber','void fiber_port_fpu_require_ready(void)',
         "FIBER_REQUIRE((fpccr & fiber_portFPCCR_LSPACT_BIT) == 0u, 'E');",'(void)fpccr;'),
        ('fpu-running-lspact','Fiber','void fiber_port_fpu_require_configured(void)',
         'const uint32_t fpccr = fiber_portFPCCR_REG;',
         "const uint32_t fpccr = fiber_portFPCCR_REG; FIBER_REQUIRE((fpccr & 1u) == 0u, 'E');"),
        ('init-full-fpca','Init',None,"fiber_port_cpu_control() == before->control, 'l'",
         "(fiber_port_cpu_control() & 3u) == (before->control & 3u), 'l'"),
    ]
    return result
