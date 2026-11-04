# Classic Final-Image Pilot Contract

## Scope

The pilot admits exactly the native CM4 and CM7/r0p1 hard-FP, eager-stacking,
no-MPU, VTOR-present, four-priority-bit, raw BASEPRI 16, ordinary-AAPCS
cohorts at `-O0`, `-Og`, `-O2`, `-Os`, and `-O3`, with direct object linkage
and without LTO. CM7 retains its PRIMASK-preserving 837070 policy. Each
invocation selects one exact profile/mode pair. It uses actual
Context providers, selected-port providers, a build-owned cohort expectation,
and a typed Context consumer. It does not execute that consumer.

The three complete roots are `fiber_port_start_first_context`,
`SVC_Handler`, and `PendSV_Handler`. The prelink bodies must match the
existing independently transcribed native protocol for that exact profile.
The single post-island tail NOP at O0 must remain present; other modes have
no such tail. Startup assembly takes its CPU/FPU target from the recorded
compiler flags, not from a contradictory fixed `.cpu` directive.
A decoded body or a
hash observed in this pilot is not a new expected protocol.

This is not a pinned-reference final-image comparison, a whole-provider
proof, a constructor/callee proof, or a CPU/board test. It satisfies no
required global parity cell. Policy equivalence, all-profile qualification,
archive extraction, LTO, and hosted CI remain separate obligations.

## Twin Links

Compile actual sources once. Link the same input object bytes using the same
script and ordered options twice. Except for output names, the only option
difference is `--emit-relocs`; both links disable the build ID. Preserve both
command records and all input/output hashes.

Require identical entry point, allocated section geometry/content, and
`PT_LOAD` address/permission/alignment/file-size/memory-size geometry plus
file-backed bytes. Zero-fill extents must agree. A metadata-only difference
outside the load image is permitted; loader-visible bytes must not be
excluded merely because they originated as metadata.

GNU ld documents that
[`--emit-relocs`](https://sourceware.org/binutils/docs/ld/Options.html#index-_002d_002demit_002drelocs)
retains relocation information in fully linked ELF files. That description
does not itself prove load-image invariance: the twin comparison supplies
the evidence for this specific build.

## Applied Relocations

Use a separate strict ARM little-endian ELF32 `ET_EXEC` reader. Do not
relax the existing `ET_REL` reader or manufacture an unrelocated byte stream
from the final ELF to make it acceptable to that reader.

Bind each final root to its actual prelink function, section, extent, raw
bytes and unapplied relocations. Retain mapping symbols, literal bytes,
padding, NOPs, local branches, and complete function extents. Every byte
must either remain unchanged or belong to an explicitly checked supported
relocation field. Reject unknown or unconsumed relocations.

The original implicit addend comes from the bound prelink object, not from
the already patched final instruction or word. Arm's
[AAELF32 idempotency rule](https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#562-idempotency)
explains why applying a `REL` relocation destroys that original addend.
Use the final relocation metadata only as an additional cross-check.

Independently decode supported Thumb branch destinations and PC-relative
literal addresses from instruction bits. Cross-check the disassembly text,
the prelink-derived relocation calculation, exact final symbol identity,
and actual destination bytes/mapping. Reject unsupported veneers,
interworking, ambiguous aliases, instruction-interior entry, or addresses
without unambiguous file-backed coverage. A BSS symbol may be a data target;
BSS must not supply literal instruction/data bytes.

The final symbol table is not independent authority for a callee's expected
placement. Bind each admitted callee to its actual defining input object,
input section and symbol offset/extent, and to a separately retained linker
input-section placement record produced by that same link. Require exact
unique object/section ownership and agreement with the final definition.
This establishes entry provenance, not callee-body semantics. Changing a
callee symbol and its caller's BL consistently must not bypass this check.

Nonempty allocated sections must not overlap. A NOBITS section must lie in
its owning load segment's zero-fill interval, not inside file-backed text.
Writable sections require writable owning segments. Consistently changing
both images' section/symbol metadata must not make file-backed code qualify
as writable BSS storage.

## Fail-Closed Evidence

Record commands before launch. Use the bounded process-tree runner; any
timeout, abnormal setup/capture/cleanup result, or nonzero tool exit fails
the pilot. Capture source/tool/helper/dependency bytes and verify closing
membership and hashes. Retain failures instead of relabelling them PASS.

Negative controls must reach reader/validator logic with consistent test
copies, rather than fail only an outer file hash. They must include a
mutation applied identically to both twin images: twin equality alone must
not authorize a changed instruction, call, literal, symbol or relocation.
No receipt may promote this bounded pilot to whole-program semantics or
required global parity coverage.

The fixture deliberately retains two unowned Thumb NOPs for coherent-callee
retarget controls. Negative tests must not depend on incidental padding that
an optimization level may eliminate. These NOPs are not production code.
