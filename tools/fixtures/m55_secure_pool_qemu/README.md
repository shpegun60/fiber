# C55S Private Pool: Actual M55 QEMU Execution

This independent runner complements `test_m55_secure_pool.ps1`. That runner's
Unicorn execution uses a scalar M33 instruction model and a documented
low-overhead-loop counterflag. This fixture instead runs default M55 production
code on QEMU `mps3-an547`, including emitted DLS/LE instructions. It never adds
`-fno-branch-count-reg` or changes production attributes or implementation.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_m55_secure_pool_qemu.ps1 `
  -ArmGcc $env:ARM_NONE_EABI_GCC -WslDistro Ubuntu-24.04 `
  -QemuRoot /home/ruslan/.cache/fiber-qemu-control-owner-20261101
```

`-BuildRoot` and `-TimeoutSeconds` are optional. `-QemuRoot` must explicitly name
an existing isolated installation. Only `inspect` and `run` actions from
`tools/fixtures/arm_control/qemu.sh` are used. There is no install/provision path,
Python package dependency, or silent skip. Parent integration may report NOT_RUN
when this optional QEMU root was not supplied; that is not an execution PASS.

Each of `-O2`, `-Os`, `-O2 -flto`, and `-Os -flto` compiles the real
`fiber/port/ARM_CM55/secure/fiber_secure_context_pool.c` as a separate object.
Startup/fixture objects are separate; production source is never included into
the fixture, renamed, or modeled. Links use section GC. Inputs, preprocessed
sources, compiler/isolated-QEMU identities, commands, maps, ELFs, disassembly,
raw execution logs, parsed receipts, and SHA-256 manifests remain in a unique
artifact directory. Source hashes must agree before and after execution.

The bare-metal image boots in Secure privileged Thread/MSP with vectors/text at
zero and RAM at `0x20000000`. Startup explicitly zeros normal BSS, then poisons
the distinct 480-byte NOLOAD image. Three slots budget 128 usable stack bytes
each. Success proves complete erasure, distinct owned allocations, valid stack
geometry/seals, zero-default unused bytes, invalid requests, wrong/invalid owner
lookups, duplicate-owner rejection, exhaustion, repeated-init non-destruction,
and preservation of CPU configuration across memory-only pool calls.

Unready allocation, corrupted seal, and corrupted metadata each run in a fresh
image. The fault handler reports stacked PC/xPSR, CFSR, HFSR, IPSR and EXC_RETURN,
then exits by semihosting. A negative PASS requires all of:

- exact case-specific start/fault-exit markers and process exit 42;
- exactly one fault report with CFSR equal to UNDEFINSTR, no other fault bits;
- UsageFault from a basic-frame Secure Thread/MSP context;
- stacked PC inside the linked production `fiber_secure_context_pool_fail_closed`
  symbol range and exactly at its disassembled UDF instruction.

An unrelated UDF, UNALIGNED fault, forged exit marker without a fault report,
and timeout are actual QEMU classifier controls. The runner must reject each
for its specific reason. A missing fault, assertion, emulator crash, unexpected
exit, or timeout can never qualify a pool failure as PASS.

These receipts prove execution of this private memory-only pool on the QEMU M55
model. They do not exercise NSC veneers, Non-secure switching, Secure stack
load/save, a production fiber runtime, real TrustZone isolation, or hardware.
The existing eight-query NSC surface is neither compiled here nor modified.
