# CM33 Secure Caller And Seal Guards

Run from the repository root with an existing isolated QEMU prefix:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/test_cm33_secure_guards.ps1 `
    -ArmGcc $env:ARM_NONE_EABI_GCC -CmsisCore $env:CMSIS_CORE_INCLUDE `
    -QemuRoot /home/ruslan/.cache/fiber-qemu-control-owner-20261101 `
    -BuildRoot "$env:TEMP/cm33-secure-guard-evidence"
```

The runner requires all target/QEMU arguments, throws on failure, and never
downloads or installs packages. It uses WSL `Ubuntu-24.04` by default. QEMU
provisioning is a separate explicit operation described in
`../arm_control/README.md`. No board programming or full matrix is performed.
The AIRCR execution probe also requires WSL `python3` (standard library only;
tested with `/usr/bin/python3`, Python 3.12.3). It needs no Python packages,
GDB installation, `PYTHONPATH`, or TCP listener. A missing dependency is a hard
failure, not a skipped regression. `-QemuRoot` remains explicit.

## Executed Implementation

The actual CM33 `fiber_secure_context_gateway.c` is compiled as its own Secure
translation unit. The Secure fixture includes the actual
`fiber_secure_context_pool.c`, without source substitutions, to inspect its
private storage and call the seal helpers. This inclusion is a test-only
inspection boundary, not a new public interface. CMSIS supplies real ARM
instructions. Secure and Non-secure images are linked separately using the
linker-generated CMSE import object and SG veneers, then loaded together on
QEMU `mps2-an505` / Cortex-M33.

The five production configurations are O0, O2, Os, O2+LTO, and Os+LTO, all with
`-fstrict-aliasing -Wstrict-aliasing=3 -Werror`, general-register-only code, and
the maintained sensitive-code counterflags. Optimization and LTO flags apply to
compilation and linking. The fixture does not simulate CONTROL, IPSR, LR, PSP,
PSPLIM, or the CMSE caller intrinsic.

## Origin Checks

Non-secure SVCall calls initialize/allocate/load through real generated SG
veneers. Non-secure PendSV calls save/load through those veneers. Successful
calls, duplicate owners, repeat initialization, a wrong owner, and save from the
wrong exception are checked. All four pure queries remain callable from both
security states.

Test-only NSC entries make ordinary direct Secure C calls to each production
stateful entry. IPSR is still 11 or 14, and the other gateway preconditions are
deliberately valid. Initialize is tested before READY with a poisoned pool;
allocate/load are tested while READY with no loaded stack; save is tested with
an owned loaded stack and also with the empty-handle fast path. Each direct
Secure call must return zero without changing the relevant state.

Four additional generated source copies disable just one immediate-caller
predicate. They must be rejected by actual execution with exact status/marker:
initialize 40, allocate 41, load 42, save 43. A fault, timeout, another nonzero
status, or a missing marker is not an accepted negative result. Production files
are never modified by these mutation tests.

For every production ELF the runner qualifies exact symbols, not substrings:
`__acle_se_fiber_secure_context_gateway_v1_{initialize,allocate,load,save}`.
The optimized GCC shape tests incoming `lr & 1` before any call. The O0 shape
captures untouched LR in r3, then masks/tests it before any call. Only the
observed bounded, flag-preserving prologues are accepted. Each generated `SG`
veneer must branch to its exact corresponding entry. The prefix instructions
and veneer binding are retained in `nsc-entry-lr-proof.txt`. Unknown codegen is
an unqualified test failure, not a claimed compiler/runtime defect.
The four real mutant ELFs must also fail this static proof for exactly their
disabled operation; the other three entries must still qualify.

`cmse_nonsecure_caller()` checks the immediate caller's security state. IPSR
checks a separate exception-number condition. Neither authenticates an owned
Non-secure instruction address or scheduler: the trusted Non-secure port owns
its call-site validation. The tests do not claim resistance to malicious
privileged Secure code that deliberately fabricates an ABI return address.

## A26 AIRCR Precondition

Every production mode first executes two real Non-secure SVCall / SG
initialization attempts with Secure AIRCR.BFHFNMINS=1 and PRIS=0. Secure setup
verifies that valid keyed seed before either attempt. Both must return zero,
preserving all poisoned record/stack bytes, the pool marker, AIRCR including
nonzero PRIGROUP, Secure PSP/PSPLIM/CONTROL and masks, and Non-secure
PSP/PSPLIM/CONTROL and masks. PSP/PSPLIM use nonzero sentinels. No forbidden
BFHFNMINS=1 / PRIS=1 combination is intentionally executed.

`aircr_rsp.py` launches the same two production ELFs using the QEMU GDB remote
protocol over a fresh private AF_UNIX socket in WSL. It reads the exact private
gateway BSS symbol from the ELF at both rejection checkpoints and requires
zero, independently rechecks every pool/marker byte, and observes actual
initializer entry LR bit zero and IPSR=11. The gateway remains a separate
production translation unit; no production hook or symbol visibility change
is introduced. Fixture checkpoints are test-only, noinline functions.

The probe obtains registers through QEMU's target XML and sets execution
breakpoints at every decoded initializer STR. Before executing a store it
computes the effective address and value from actual stopped registers. The
five additional guard-removal mutant ELFs must reach the exact AIRCR STR with
key 0x05FA, BFHFNMINS=1 and PRIS=1 pending, while AIRCR still has PRIS=0. The
inferior is terminated while paused, before that instruction executes. A
fault, timeout, arbitrary nonzero exit, missing breakpoint, or unknown store
shape is never a mutant kill. SIGKILL prevents guest execution during
termination; failure cleanup also kills QEMU before closing RSP.

After both normal rejections, the CM33 fixture restores BFHFNMINS=0 and zero
Secure PSP/PSPLIM. The same initializer must succeed, reaching its decoded
AIRCR store with the correct key and PRIS=1, preserving PRIGROUP, then completing
the existing allocation/load/save and pool cases. This also proves that the
precondition rejection did not consume the one-shot gate. All five production
modes, all four original origin mutants, and five AIRCR mutants remain
mandatory: 14 two-image cases total. The RSP manifests, register descriptions,
store/entry/checkpoint event traces and receipts are retained beside each ELF;
the probe verifies both ELF hashes against its manifest before launch.

## Seal And Pool Checks

Production seal helpers now use character access to the native representation
of the seal constant. This avoids treating a declared byte array as uint32_t
objects. A compiler may legally combine such accesses into wider instructions;
the source-level effective-type fix does not require byte-only machine code.

For every permitted fixture stack size (8..64, step 8), execution checks all
eight seal bytes through a volatile byte observer, every surrounding byte, and
rejection of independent corruption of each seal byte. It also checks full
stack/record clearing, handle bounds, wrong owner, minimum/maximum sizes,
overflow/unaligned requests, exhaustion, and duplicate ownership even after an
earlier synthetic free metadata slot. The synthetic slot is private test setup,
not a release API. The record array remains 72 bytes, stack array 216 bytes,
and initialized marker 4 bytes for count 3 / maximum stack 64; production record
offset/alignment assertions remain in force.
The runner independently verifies exact final-ELF storage symbol sizes and
alignments, not only C `sizeof` values.

The pool algorithm is reset repeatedly only inside the private pool test,
after the gateway save/load cycle is finished. This does not relax one-shot NSC
initialization. A source assertion rejects reintroduction of uint32_t-pointer
seal access. Runtime tests under strict aliasing alone cannot establish the
absence of C undefined behavior, nor do they imply the old undefined access
must miscompile on every compiler.

## Evidence And References

Each invocation retains commands, compiler identity, source/fixture/ELF SHA256,
preprocessed Secure sources, assembly, ELF/map/disassembly, CMSE import objects,
entry-LR proofs, per-case QEMU logs, and a result ledger. Existing emulator
identity, package hashes/versions, and dynamic-library resolution are inspected
read-only using `../arm_control/qemu.sh`; semihost reporting is shared with
`../arm_control/report.h`. Each image pair has a strict execution timeout.

Initial qualification used STM32 ARM GCC 14.3.rel1 and QEMU 8.2.2 (Ubuntu package
`1:8.2.2+ds-0ubuntu1.18`). All five production modes and four origin-predicate
mutants passed their required outcomes. This is executed QEMU evidence, not
hardware qualification, complete TrustZone policy proof, or C55S lifecycle
qualification. No runtime-only Non-secure headers enter the Secure public ABI.

- [Arm CMSE tool requirements](https://arm-software.github.io/acle/cmse/cmse.html),
  especially entry functions, security state of the caller, and the SG effect
  on LR bit zero. The intrinsic must be evaluated in the actual entry function,
  not an out-of-line helper.
- [GCC CMSE support](https://gcc.gnu.org/onlinedocs/gcc/ARM-ARMv8-M-Security-Extensions.html).
- Pinned local FreeRTOS `a50edad08b29052631aa469d4df6e6ec7ff68878`,
  `portable/GCC/ARM_CM33/secure/secure_context.c`: `SecureContext_Init` gates on
  nonzero IPSR; `SecureContext_AllocateContext` obtains heap storage and writes
  two `0xFEF5EDA5` words at the stack top. Fiber preserves that geometry but its
  declared static byte arrays need alias-safe access. The immediate-caller
  checks are additional Fiber hardening, not a claim that FreeRTOS provides the
  same origin policy.
