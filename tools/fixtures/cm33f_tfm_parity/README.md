# C3FT Actual Pinned FP Parity

`tools/freertos_asm_parity.ps1 -Cm33fTfmOnly` runs O2 or Os with both hard and
softfp ABIs. It compiles unmodified production C and pinned M33_NTZ FP port C,
portasm C and ARM_TFM wrapper C. The profile stays RuntimeSelectable0; this gate
does not alter public ABI, provide missing runtime/TF-M implementations, or
claim actual CPU/FP/TrustZone execution.

The target is explicitly `-mcpu=cortex-m33 -mfpu=fpv5-sp-d16 -mthumb`. Real
CMSIS is used with a declared device boundary: FPU/DSP/VTOR present, MPU absent,
four NVIC priority bits. ELF attributes and compiled configuration assertions
are independent numeric checks. GCC 14.3.1 emits CPU name `8-M.MAIN`, Thumb use
`Yes`, v8-M.mainline and SP-only FPv5; the exact compiler command establishes
the chosen M33, not an assertion that generic predefines identify every CPU.

## Closed Streams

`expected-O2.json` and `expected-Os.json` contain fixed instruction counts and
SHA-256 fingerprints of all 77 complete decoded function streams: all functions
in Fiber/Boot/Init/Wrapper, all reference portasm functions, the actual pinned
constructor/SVC C/scheduler-start functions, the pinned mutex wrapper and the
separately labelled FPU probe. There is no baseline-learning mode. Actual full
streams are archived as `decoded-bodies.json`. Unknown instructions, changed
operands/counts/order/writeback/predicates/local targets or relocation addends
cannot be erased by these fingerprints. The shared strict ELF decoder checks
instruction bytes and mapping symbols against each real object.

Hard and softfp streams happen to match for these integer-signature functions;
their actual VFP ABI attributes must differ correctly. Boot's measured undefined
set contains no memcpy/memset allowance. Production FP instructions are exactly
the two conditional high-register transfers in PendSV. Frame init has no FP or
CPU register instruction. Broader compiler versions/optimization modes, lazy=1,
hostile instrumentation, archive/LTO closure and real exceptions need their own
proof and are not inferred here.

## Numeric Oracles

The bounded integer/bit-transfer interpreters consume actual decoded operations
with explicit CPU/MMIO/provider doubles. They are not instruction-accurate ARM
emulators. The local execution view implements two-register ANDS using the
shared engine's AND plus N/Z updates; the closed stream still records ANDS.

The 151 grouped scenarios are 33 constructor, four first-start, four first-restore,
16 crossed basic/extended transfer, 34 FPU policy, and 60 TF-M policy cases.
Constructors check all 18 words, exact stores/cursors, canaries and NULL. The
builder's current R9 seed is not a promise about an outer ordinary AAPCS call.
Boot admission and restored-context validation are explicit external boundaries,
not mocked replacements for compiling actual Boot code or claims of its runtime
validation behavior.

PendSV cases preserve distinct outgoing/incoming task images, poison restored
GPRs, check optional S16..S31 and raw PSP minus 40/104, and require PSPLIM before
PSP. Hardware core/low-FP memory is unchanged: this proves software does not
overwrite it, not hardware stacking or FPCA semantics. First-start stops at the
decoded SVC instruction; first-restore stops at the exception-return branch.

Fiber defaults to eager FPU preservation: CPACR CP10/11 and ASPEN enabled,
LSPEN cleared. The actual pin enables lazy preservation. Numeric policy tests
check both intentional policies and unrelated bits. Default actual port.c is
compiled/closed. `ReferenceFpuProbe` compiles that same real source separately
with `-fno-inline` only to expose static `prvSetupFPU`; it is not default-codegen
or hardware evidence. Configured LSPACT is accepted, first-start readiness
rejects it. TF-M cases preserve all eight observations including full CONTROL,
CPACR and FPCCR; running mutex CONTROL 2/6 and pre-start CONTROL 0/4 are valid.

## Mutations And Evidence

Each tuple compiles 46 bounded mutations of fixture COPIES of actual source,
including the actual pinned side. All fail the closed gate; 37 additionally fail
the independent `--oracles-only` mode without reading expected fingerprints.
That mode never writes a parity receipt. VSTMDB requires writeback, so the
save-writeback mutation compiles an ADD cancelling the update instead of
counting an assembler failure. All mutation compile/diagnostic evidence remains.

Thirty-one controls reject `-O`, `-OO`, PYTHONOPTIMIZE=1/2, optimized compiled
imports and traceback counterfeits. Exact rejection classifiers require one
expected diagnostic line and no traceback. The runner validates every tracked
regular file in the clean exact pinned FreeRTOS checkout, preserves commands,
preprocessing, assembly, ELF attributes/relocations and compile dependencies,
hashes consumed sources/tools, rejects input drift and snapshots documentation.
No install or optional package is needed. Shared ELF/runner primitives, integer
engine and protected bit-transfer engine are explicit hashed fixture dependencies;
production source is never extracted, rewritten or replaced for a positive case.
