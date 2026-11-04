# Captured CM0/M0+ Closed Roots

This independent gate consumes closed compile receipts. It does not replace
this directory's existing `run.py`/`check.py` final-ELF fixture or inherit that
fixture's qualification. The new protocol lives in `closed_roots.py` and its
driver is `tools/freeze_cm0_mechanisms.py`.

## Scope

Three explicit p2, no-MPU, no-FP, soft-ABI, ordinary-AAPCS cohorts are required:

```text
cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default
cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default
cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default
```

These distinguish M0 without VTOR, M0+ without VTOR and M0+ with VTOR. They
do not identify a physical board or assert that every STM32F0/G0 part has
identical capabilities. MPU, other priority widths, fixed-R9, other CPU
profiles, direct/archive final links and LTO are separate obligations.

Each cohort requires O0/Og/O2/Os/O3 and eight complete bodies:

| Side | Roots |
| --- | --- |
| Native | `fiber_port_start_first_context`, `SVC_Handler`, `PendSV_Handler` |
| Pinned FreeRTOS | `vStartFirstTask`, `SVC_Handler`, `vPortSVCHandler_C`, `vRestoreContextOfFirstTask`, `PendSV_Handler` |

The reference uses actual non-MPU `portable/GCC/ARM_CM0/port.c` and
`portasm.c` from `a50edad08b29052631aa469d4df6e6ec7ff68878`. Its SVC
handler dispatches through a C helper to a separate first-restore routine;
closing only the outer handler would not close that first-start path.
Other C callees, context construction and the whole runtime remain outside
this bounded root set.

Every instruction, local branch, literal island, relocation/addend and NOP
must match a reviewed protocol; ordered subsequences or generated hash
baselines are not substitutes. Native hardening, MSP/CONTROL/SVC policy,
PRIMASK preservation, external scheduler/publication and staged Thumb-1 frame
differences retain their rationale IDs rather than disappearing in token
normalization. Actual exception execution and routing are not proved.

The decoder explicitly opts into `literal_islands=True, thumb1_tail_nop=True`
to retain exact `46c0` (`mov r8,r8`) tails after a structural literal island.
It preserves the existing instruction token and bounded tail count, including
GNU's alias comment. The default reader API is unchanged. This opt-in does
not prove a data island or tail unreachable and does not make SVC a terminal
instruction. Ordinary alignment NOPs in the reference are retained too.

## Run

```text
python -B tools/freeze_cm0_mechanisms.py --inventory <inventory> \
  --native <native> --reference <reference> --output-dir <fresh-external>
```

The driver binds complete receipt membership, source/compiler inputs, exact
cohort facts and Thumb-1 attributes. It executes captured checker/decoder bytes
and closes all input/output hashes. It invokes no compiler, objdump, emulator
or board. The resulting 15 paired cells/120 bodies are bounded mechanism
records, not satisfied global coverage keys. Required counters remain integer
zero and whole-object/final-ELF/CPU/board/global flags remain false.

Pure driver admission/result controls:

```text
python -B tools/fixtures/cm0_freeze_parity/test_driver.py
```

Complete-protocol and private retained-byte mutations:

```text
python -B tools/fixtures/cm0_freeze_parity/test_closed_roots.py \
  --native-root <native> --reference-root <reference> --temp-root <fresh-temp>
```

The mutation output must be a fresh directory below system TEMP. The tests
reject changes to the staged frame, high registers, PRIMASK, SVC numbers,
reference C PC offset/assertion loop/epilogue, first-restore skip, branch
targets, literal/call relocations, tail bytes and disassembly-byte binding.
They rehash original receipts and leave the existing final-ELF checker and
runner unchanged. Passing mutations do not prove execution or general C
source semantics.

Decoder controls and retained replay use an unchanged captured pre-extension
reader, whose expected content hash is checked:

```text
python -B tools/fixtures/cm0_freeze_parity/test_decoder.py \
  --baseline-reader <captured-reader> --output-dir <fresh-external> \
  --native <native> --reference <reference>
```

These decoder controls are separate from mechanism proof. Existing default
and explicit literal-island APIs must keep their previous outcomes, including
rejections. Synthetic mutated files are parsed only, never executed. Retained
receipts remain immutable, and later documentation does not turn a captured
snapshot into exact-commit hosted CI.
