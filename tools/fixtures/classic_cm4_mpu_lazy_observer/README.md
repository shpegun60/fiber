# CM4 MPU Lazy-Save Observer

This is a bounded observation of the four existing FP-pilot positive
ELFs: Context/FiberV1 x eager/lazy, O2 ordinary/direct only, on the existing
explicit QEMU AN386 prefix. It does not recompile, relink, instrument production,
replace handlers, rerun the pilot's ten mutation images, or create new FreeRTOS
parity evidence. Implementation of a static image plan is not qualification of
the observation or an execution PASS. Measured receipts and their exact scope
are recorded in the repository's
[architecture audit](../../../PORT_ARCHITECTURE_AUDIT.md#cm4-mpu-lazy-save-observer).
This file defines the maintained fixture contract, not a substitute PASS receipt.

## Explicit Inputs

The parent observer requires a deliberately supplied qualified FP-pilot receipt
and immutable copies of its four positive ELFs and corresponding disassemblies.
That existing receipt is an intentional dependency, not a hidden TEMP fallback
or a live-tree lookup. The original ELF hashes must agree before planning and
execution. The parent captures the complete reader/checker/helper chain before
import and owns receipt, tool, QEMU and input-closing admission.

The current QEMU inspection's twelve stable identity files must match the
provided pilot's `qemu-before` inventory for the same qualified prefix/tool
cohort. The ASLR-bearing raw `ldd` text is excluded from that comparison, not the
resolved library hashes. The observer's own before/after identity inventories
must also match. A mismatch is failure, not a reason to provision or waive drift.

## Image Planner

`image.py` exports `plan(image, row)`. The image is the maintained actual ELF
`Image` interface; the row must identify an unmutated, non-model O2/native/direct
positive pilot image. The planner imports the captured `cm4_mpu_fp_checks`
checker and requires all thirteen subject facts. It returns JSON-compatible
data, does not write a manifest, and never invokes a compiler, WSL or QEMU.

`control_tests(image, row)` returns `ElfSha256`, nine `Controls`, `Count=9`,
`TargetExecutions=0` and `Scope`. It tests the actual plan, wrong Pre/Post mask
decoder counterfeits through that plan, Pre/Post wide-instruction interiors via
`_point`, and duplicate SVC/PendSV/current-slot/workers symbols through the plan.
Records distinguish those layers and require exact acceptance/diagnostic pairs;
unexpected acceptance or an incidental rejection throws. Counterfeits copy the
actual Image dictionaries without replacing methods or patching the checker.
Original Image/row state and ELF/disassembly bytes must remain unchanged. These
are in-memory controls, not compiled mutations or target observations.

The plan's returned fields are:

- `Elf`, `ElfSha256`, `Consumer`, `Lazy`: host path and actual ELF identity,
  with typed consumer/policy selection. The parent performs any later WSL path
  conversion. Lazy/eager do not have distinct context-cohort layout keys.
- `Pre` and `Post`: each has an integer instruction `Address`, uppercase
  memory-order hex `Bytes`, and integer `Width`. These are complete decoded
  Thumb instructions, not source offsets or interiors of wide instructions.
- `CurrentSlot`: the real four-byte current-slot object's address, 0x20000000,
  within the exact 32-byte aperture.
- `Workers`: three integer addresses derived from the actual local privileged
  `workers` array's base and one-third of its ELF size. FiberV1's Context is its
  first member; no guessed Fiber stride is used.
- `Stacks`: three `{Begin, End}` pairs from actual section/linker geometry,
  respectively 0x20002000, 0x20004000 and 0x20006000, each 4096 bytes.
- `ReturnPC`: the actual SVC72 return-site label at an instruction boundary.
- `Proof`: actual symbol address/size/kind/binding/section and byte hashes,
  strong vector and readonly cohort-pointer admission, all thirteen FP facts,
  complete decoded PendSV records/hash, disassembly identity, return-veneer
  decoding and worker stride. BSS symbol hashes describe initial ELF storage,
  not runtime object contents. Source/prelink ownership remains the admitted
  pilot's separate proof; the planner does not infer it from final symbol names.

Strong Thumb SVC/PendSV vectors, the exact CM4 MPU8 private/storage cohorts,
actual five-operation public roots and eight forward operations are required.
Pure Context must not acquire FiberV1 or optional-configuration symbols. The
planner rejects alternate target/profile, LTO/archive, model and mutation rows
rather than widening admission to use them.

## Stop Semantics

`Pre` is `ExtendedSaveGate.Address`: the unconditional `TST LR,#16` before
`ITTT EQ` and the backend's first high-FP VSTM. It is outside an IT block. Raw
Handler CONTROL has already been captured, but r0 has already advanced to
PSP+32: the observer must read the privileged PSP register, not call r0 the
frame base. Do not treat deferred lazy low-FP memory as materialized payload.

`Post` is `PostCopyLspactGuard.Address`: the unconditional `TST r3,#1` after
the protected copy and cursor publication, before the actual scheduler callback.
The checker also binds the preceding load to FPCCR 0xE000EF34 and the nonzero
branch to the production E panic. Both stop bytes are bound to the ELF bytes
and decoded boundaries. A source-line offset is never a breakpoint selector.

## Bounded Execution Contract

The required observer inventory is four CPU executions and exactly 88 paired
Pre/Post observations: 60 extended-frame pairs and 28 basic-frame pairs. Each
unchanged image has 22 PendSV saves: worker0 eight extended saves, worker1 seven
extended saves and worker2 seven basic saves. The model image and the ten old
FP-payload mutant images are not rerun by this observer.

Admission must correlate each pair with the actual current-slot pointer,
worker, stack, EXC_RETURN and privileged PSP. The required FP observations are
pre-save CONTROL1, lazy extended LSPACT1 versus eager/basic LSPACT0, followed by
post-copy LSPACT0 and the permitted post-VSTM Handler CONTROL1/5 state. These
are requirements for each measured receipt, not results established by the
static plan. Breakpoint restoration and terminal/exit admission belong to the
parent transport/closing code and must not modify the payload or MPU metadata.

No execution or 88-pair qualification is claimed here until the complete run
and its fail-closed controls have been admitted. In particular, existing
post-save observations alone do not prove pre-save lazy state. Strict low-FP
self-selection, reference execution, new final parity, MPU16, other optimization
grids, other cores, hardware and CI remain outside this observer's scope.
