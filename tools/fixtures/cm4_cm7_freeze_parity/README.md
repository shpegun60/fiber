# Classic CM4/CM7 Closed Roots

This bounded, offline gate matches six complete generated root bodies per
profile/mode against independently transcribed native and pinned FreeRTOS
protocols. It is not general instruction equivalence or whole-port validation.

The two exact cohorts are privileged, no-MPU, hard-FP, eager, ordinary AAPCS,
VTOR1, four NVIC priority bits and raw BASEPRI16:

- `cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default`
- `cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default`

CM4 uses `fpv4-sp-d16`; CM7 uses `fpv5-d16` and the PRIMASK-preserving
837070 workaround. The driver validates all target fields and exact compiler
flags, not merely those names. Neither a p5 target nor a softfp witness is an
accepted substitute. This does not qualify other FPU, MPU or R9 combinations.

## Scope

| Native Root | Pinned FreeRTOS Root |
| --- | --- |
| `fiber_port_start_first_context` | `prvPortStartFirstTask` |
| `SVC_Handler` | `vPortSVCHandler` |
| `PendSV_Handler` | `xPortPendSVHandler` |

The reference pin is `a50edad08b29052631aa469d4df6e6ec7ff68878`, using the
actual `portable/GCC/ARM_CM4F` and `portable/GCC/ARM_CM7/r0p1` sources.
Every instruction, branch target, call relocation/addend, literal-island
descriptor and padding NOP is consumed. O0 requires one post-island NOP per
root; Og/O2/Os/O3 require zero. A subsequence is not accepted. The inherited
decoder's literal-island representation is explicit opt-in.

Differences retain the existing ledger IDs for start, provenance, saved mask
restoration, external scheduler/publication, FP validation and CM7 PRIMASK
preservation. Actual bit-4 predicates, S16-S31 transfers, software/hardware FP
extents, carry/borrow guards, saved-stack pointers, BASEPRI and PRIMASK operands
are preserved rather than removed by normalization.

Only these roots are closed. Their C callees, constructor, whole-object ABI,
handler routing, SVC nonreturn, final executable, direct/archive/LTO links and
CPU/board behavior are not proved. In particular the native eager FPCCR policy
differs from the reference's ASPEN=1/LSPEN=1 policy. The result must explicitly
report `UNRESOLVED-BY-THREE-ROOTS` and `PolicyEquivalenceProven=false`.
Matching the initial exception-return protocol does not establish vector
routing or make SVC an intrinsic decoder terminal.

## Run

Use compatible closed inventory/native/reference receipt directories from
`freeze_cohorts.py`, `freeze_compile.py` and `freeze_reference_compile.py`.
The supplied preflights must contain all five matching exact cohort rows.
The driver invokes no compiler, objdump, emulator or board:

```text
python -B tools/freeze_classic_fp_mechanisms.py --profile CM4 \
  --inventory <inventory> --native <native> --reference <reference> \
  --output-dir <fresh-external-directory>
```

Repeat with `--profile CM7`. The driver binds complete receipt membership,
source/compiler inputs, cohort keys, code-generation attributes, captured
checker/reader bytes and closing input/output hashes. Source bytes executed
by its dynamic imports are the captured bytes, not a later reread. Results
are captured-source evidence, not hosted CI for a later documentation commit.
`RequiredCellsSatisfied` remains integer zero; all per-cell required coverage,
whole-object, final-ELF, CPU and global-freeze flags remain false.

Pure admission/result/attribute controls:

```text
python -B tools/fixtures/cm4_cm7_freeze_parity/test_driver.py
```

Private retained-ELF and token mutations (fresh directory below system TEMP):

```text
python -B tools/fixtures/cm4_cm7_freeze_parity/test_check.py \
  --native-root <native> --reference-root <reference> --temp-root <fresh-temp>
```

Mutated objects/disassemblies are parsed, never executed; original receipts
are rehashed after the tests. Token controls mutate the specification-facing
input at every position, and retained-byte controls include FP bit-4,
high-register set, software/hardware extent, BASEPRI snapshot, CM7 PRIMASK,
branch, relocation/addend, literal bytes, tail and disassembly disagreement.
These are rejection controls, not additional successful runtime scenarios.
