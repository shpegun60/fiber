# CM4 MPU Basic Grid

This separate opt-in gate does not replace or modify the seven-image pilot.
The fixed scope is Cortex-M4/AN386, eight MPU regions, hard FPv4-SP-D16
compilation, eager policy, basic FP-inactive tasks, and hash/map policy 0/0.
There is no FP-active, MPU16, softfp, all-optimization, STM32, board, or global
FreeRTOS-parity claim.

## Invocation

`tools/test_classic_cm4_mpu_basic_grid.ps1` requires `-ArmGcc`, `-CmsisCore`,
and `-FreeRtosRoot`; `-BuildRoot`, `-Python`, and `-PythonModules` are optional.
The default is compile-only. It must not invoke WSL or QEMU. Execution requires
`-ExecuteGrid -QemuRoot /absolute/existing/prefix` and optionally `-WslDistro`.
No mode provisions tools. Direct Python uses the corresponding kebab-case
arguments, including `--execute-grid` or `--compile-only`.

The selected source/helper bytes, CMSIS headers, pinned reference inputs, and
pyelftools source/version metadata are captured before local helper import.
Compilation and local helper/package imports use
only these copies, with no missing-file/live-tree fallback. Both original and
captured hashes are checked on closing. Installed toolchain files remain
explicit captured inputs. `capture.json` records that relationship. The
reference inventory names an expected commit and exact selected file hashes;
it does not assert a clean Git working tree or require a historical receipt.

## Literal Inventory

The ordered modes are O2 normal, O2 final LTO, Os normal, Os final LTO. For each
consumer (Context, then FiberV1), mode and direct/archive link, cases 0/1/2 give
48 production ELFs. A separate model ELF probes CPU/MPU/NVIC/FPU facts.
The cases cover repeated public/direct real SVC71 yield, self/bidirectional
selection and task return through real SVC72 to R; current-slot write denial;
and peer-stack read denial. Worker progress lives in each worker's stack;
metadata and reports remain privileged. Register stress uses a real naked
schedule call, all r4-r11, a 56-byte aligned caller frame, exact SP and two
cookies, and exact CONTROL3/IPSR0 checks.

Eight real pinned `portable/GCC/ARM_CM4_MPU/port.c` final ELFs are link-only.
Readonly typed roots retain the actual constructor/start and inline-ASM-only
C helpers under LTO. Kernel boundaries fail-stop; no reference handlers,
scheduler or TCB state are emulated. Actual prelink upstream owners, final
strong vectors, archive extraction, and header facts are checked. Every
production ELF has a hash-bound reference association for the same opt/LTO/
archive key: 48 associations, each importing the three maintained decoded
SVC/first-restore/PendSV mechanisms from `freertos_asm_parity.ps1`. These are
bounded ordered mechanism checks, not byte or whole-kernel equivalence.
Upstream's always-lazy policy differs intentionally from this eager subject.

There are 32 compiled subject causal controls: the original six omissions and
ten individual SP/cookie/CONTROL/IPSR compare-or-reject omissions in each of
two representative configurations. Eight actual upstream omission controls
check exact first PSP, raw CONTROL-before-FP, scheduler BASEPRI envelope, and
first MPU-map diagnostics. All controls compile/link and are rejected by the
intended decoded check, never by an incidental build error. They are not CPU
executions.

## Receipt Contract

The receipt is `BuildRoot/evidence/results.json`. Compile-only requires
`Verdict=COMPILE-PREFLIGHT-PASS`, `Execution=NOT_RUN`, `CompleteSuite=false`,
`CompileOnly=true`, all 49 production/model rows `COMPILED`, `Executed=false`,
and no `Actual` or observed model fields. Only the exact requested bounded
48-plus-model execution closure can emit `BASIC-GRID-PASS`,
`Execution=BOUNDED_BASIC_GRID` and `CompleteSuite=true`. It does not mean full
MPU or hardware qualification. Reference execution and
`NewFinalReferenceParity` remain false in both modes.

`contracts.py` and `Assert-Cm4MpuBasicGridReceipt` independently validate ordered
keys, types, hash-bound associations and control reasons. The original 100
synthetic closing IDs remain first and unchanged; 32 additional cases reject
non-null/missing Error, missing/malformed model ELF identity, and incorrect
model artifact bindings. Only the None/null sentinel means no failure: empty,
zero and false errors cannot become success. The finalizer binds the model to
the actual `model/runtime.elf` path, bytes and manifest entry before PASS, and
checks that binding again after the final manifest.

The original four actual-finalizer IDs remain first. Six more cases exercise
empty/zero/false error values, the actual entry-point formatting of an empty
exception, and wrong model path/hash. Their model files are labelled non-ELF
orchestration data, not additional native ARM ELFs or target observations.
There are ten such files plus one shadow file for the wrong-path control.
The 97 native ARM ELF builds are counted separately.

The same self-contained PowerShell finalizer assertion is called by the normal
wrapper and controls route. Twenty-five mutations test that actual function,
including string-false artifact flags in all ten first-call records, numeric
Verify flags, final/recovery flag types, and zero/false Error coercion.
Success is persisted only after first artifact verification; late failure
rewrites FAIL before best-effort recovery. All synthetic controls remain
separate from target observations.

Artifacts, dependencies, generated mutants, full commands, actual native NM/AR
with explicit LTO plugin, and compiler-resolved cc1/as/collect2/ld/lto1/
lto-wrapper opening/closing identities are retained. Execute mode additionally
requires existing-prefix QEMU/tool/library manifests and rejects drift.
