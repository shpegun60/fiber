# C55S Initializer Qualification Fixture

Run the owning `tools/test_m55_secure_initialize.ps1` with an existing `-ArmGcc`
and explicit WSL `-QemuRoot`; `-WslDistro`, `-CmsisCore`, `-FreeRtosRoot`, and
`-BuildRoot` are selectable. No provisioning, hardware programming, runtime
activation, or additional NSC fixture export occurs.

The runner separately compiles the three production Secure translation units.
Real M55 `mps3-an547` Secure/NS images execute SG calls at O2/Os, with/without
LTO. Low-overhead-loop codegen remains enabled. The NS consumer uses the actual
import-only header; it does not select a Non-secure fiber runtime. Each mode
checks exact twelve-entry imports, frozen old-eight C/C++ negative links, and
matching C/C++ positive links.

## Execution And Injection

Each mode executes success, eight postcommit readback/return failures, two latch
UDF failures, and a BFHFNMINS guard-removal mutant. Five O2 classifier controls
exercise unrelated UDF, absent report, timeout, register-offset SCR store, and
unrecognized STRT. Total: 53 independent QEMU launches.

The private Unix-socket debugger observes production instructions. Readback
injection changes a destination register only after the actual load/MRS executes;
CONTROL is actually read as exactly 2 before forcing 0/6/10/14. This is not proof
that a pre-SG SFPA seed survives SG. Pool-return injection follows the actual
pool's scrub and READY publication. Repeat rejection must preserve partial state
or an intentionally poisoned live byte after success.

Observations use the Secure bank while stopped in Secure code. Two private,
non-exported fixture sequences execute actual CPU stores/MSRs for platform AIRCR
policy and nonzero Secure masks; direct debugger special-register/MMIO writes
are not assumed equivalent. Production must preserve PRIMASK=1, BASEPRI=0x80,
FAULTMASK=1. Masks stay unmasked in latch-UDF tests for fault delivery.

Every generated initializer store is decoded or rejected before execution.
Only exact AIRCR/gateway-word stores and bounded fixture-stack stores are
permitted. The SCR register-offset control is actual compiled `str r0,[r1,r2]`;
it and STRT are terminated while paused. The BFHFNMINS mutant is likewise killed
before its exact pending forbidden AIRCR STR, never after executing that write.

## Fault Origin

The vector reads EXC_RETURN.Mode first: Handler always uses MSP; only Thread
uses SPSEL to choose its frame. Fault reports include raw PC, CFSR, HFSR, current
IPSR, EXC_RETURN, frame address, and stacked xPSR. Independent paused before-UDF
and vector-entry observations corroborate actual Secure MSP, CONTROL, and frame.
The exact production UDF must report UNDEFINSTR only, current IPSR=6, stacked
IPSR=11, and stacked T=1. Nineteen mutations per genuine fault must be rejected.

Initial-latch failure requires EXC_RETURN=0xFFFFFFF1. Ready-latch failure requires
0xFFFFFFF5 because CONTROL.SPSEL has become 1; Mode remains Handler and the
32-byte basic frame is still on Secure MSP. This is not an exception-return
allowlist. [Arm DDI0553B.y](https://community.arm.com/cfs-file/__key/communityserver-discussions-components-files/471/DDI0553B_5F00_y_5F00_armv8m_5F00_arm.pdf),
B3.8 (page 78) and D1 EXC_RETURN (pages 1628-1629), specifies Handler stack use
and saved transitory SPSEL; [QEMU's exception implementation](https://github.com/qemu/qemu/blob/v8.2.2/target/arm/tcg/m_helper.c#L831-L834)
copies that bit. Actual execution receipts, not these references, qualify the
installed emulator and generated fixture.

## Hostile Whole-Companion Build

Each mode additionally builds/links the complete twelve-entry gateway plus all
private pool functions with instrumentation, SSP, coverage, UBSan, and sanitizer
coverage enabled *after* disabling defaults. GCC effective-option reports and
an unannotated contaminated control prove the settings are active. This build
is not executed. Expanded canonical attributes, all sensitive identities/call
edges, exact imports, no external compiler support, and exactly 488 mutable
bytes (pool plus two markers) are checked in the final ELF, including LTO.
The private cohort extraction helper must cover every byte of its sized ELF
symbol with exact `BX LR`/NOP encodings. Six compiled, never-executed controls
must reject UDF, undefined words (including the default-M55 STC counterexample),
literal data, an undecoded zero gap, and a store; one pure control must pass.

No ordinary FP/MVE datapath operation is allowed. The only named exception is
GCC's Secure-entry `vstr FPCXTNS,[sp,#-4]!` and corresponding return sequence
`vscclrm {s0-s15,VPR}; clrm ...; vldr FPCXTNS,[sp],#4; bxns lr`, with a
save-less early rejection permitted. These security-state save/clear operations
are confined to the twelve exact NSC bodies; their opcode/operand forms must
occur in actual pinned FreeRTOS `SecureContext_Init` output. This hostile
callgraph gate checks those forms, not complete path balance. The separate
`FAP-CMSE-M55` parity gate checks bounded initializer entry/return ordering and
instruction encodings, including its save-less early rejection. The
[GCC 14 soft-CMSE tests](https://gcc.gnu.org/pipermail/gcc-patches/2024-October/666067.html)
explicitly distinguish them from ordinary FP operations. Private pool functions
have no such exception. Normal execution retains mandatory build counterflags.

Fixture `__FPU_PRESENT=0` does not disable physical FP/MVE in the QEMU machine.
The execution receipts therefore do not establish absent-hardware behavior.
The Arm no-FP/MVE FPCXT_NS and VSCCLRM semantics and the QEMU 8.2.2 decoder
limitation are recorded under `FAP-CMSE-M55` in `FREERTOS_ASM_PARITY.md`.

Actual pinned FreeRTOS `secure_init.c`, `secure_context.c`, and port assembly
compile/link in every mode; unexecuted trapping heap stubs only satisfy other
retained reference NSC exports. Comparison notes explain Fiber's stronger origin,
policy, readback, and irreversible-latch guards rather than claiming equality.

Each unique evidence directory retains commands, effective options, preprocessed
sources, objects, maps, imports, ELFs, disassembly, execution traces/receipts,
classifier controls, source/tool input hashes before/after, and output SHA256s.
Failed directories are retained. A PASS is emulator/build evidence only, not
hardware qualification or a production Non-secure runtime/attach contract.
