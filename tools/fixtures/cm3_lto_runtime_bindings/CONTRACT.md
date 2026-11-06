# Current CM3 O2-LTO Runtime Bindings

## Scope And Status

This additive component validates native CM3 p4/b16 soft-float, O2-lto, direct
runtime bindings on each actual saved-machine/final-image twin. It extends the
frozen final-link audit, not the ordinary producer or decoder. It is a foundation
for later bounded static-cell composition, not a whole-cell result. This
contract reports no measured implementation or successful replay.

The pure entry point is:

```python
inspect(image, core, link_audit, attributes_text, *,
        emit_relocs=True, machine_attributes_text=None)
```

`image` is the unchanged generic reader's soft-ABI FinalImage for one twin,
using that twin's own actual generated machine, final ELF, disassembly, startup
provider and map. `core` and `link_audit` are explicitly supplied authenticated
modules. Inspection performs no imports, filesystem admission, subprocesses or
target execution. The enclosing witness supplies immutable admitted reads and
real opening/closing checks. No Os-lto or archive route is admitted here.

## Current Evidence Admission

Before parser execution or output creation, independently caller-bind current
E9 inventory and native O2-lto capture receipts and artifact manifests. Recompute
the complete current manifest/registry plan and require source fingerprint:

```text
69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313
```

CaptureProducer must identify the current capture frontend with SHA-256:

```text
1191CDCDA9FC9312B09858D6439674DBCA19ABFCE5B0108F3575AEF3C65C0852
```

Use current native O2 Seed admission, not the old Os constructor or historical
reference admission. Authenticate the complete capture/seed/inventory trees,
all Original/Captured/generated/dependency/tool bindings and their actual source
buffers. Both current descriptors and every reachable inventory fact must agree.
The capture remains capture-only; its PASS is not runtime-binding authority.

The enclosing witness may reuse the frozen old link Witness constructor and
physical-identity/copy helpers, supplemented by modern Admission and current
capture.prepare() native O2 Seed validation. Merge legacy hash/membership and
modern physical/tree closing without dropping either authority. Bootstrap code
executes its authenticated bytes; no qualified globals or source are patched.

## Command And Reader Reuse

Reconstruct all 57 native capture commands, including cloned tools, workers,
streams, actual dependencies, slim IR sections and ordered full argv, before
consuming their inspection metadata. Reuse unchanged BEC9 Os Witness._commands
with an explicit O2 recipe facade: mode_flags is the frozen native API's
mode_flags, startup_flags copies its input unchanged, and link_flags delegates
to the native API's link_flags. The Os constructor and Os receipt authority
are not used. Pin the F2D4 native API and BEC9 witness before execution.

The actual O2 Sources rows do not contain SeedCompileFlags. Because the unchanged
method reads that field, any adapter must use a separate command-view copy that
adds only the independently admitted ordinary Seed CompileFlags. Bind each row
to its exact source, index and Seed descriptor first; recompute captured flags
through the O2 facade. Preserve the raw receipt and raw rows, retain explicit
projection provenance, and never claim the added field was captured originally.

The new envelope replaces only the audit-read composition, passing the frozen
link audit explicitly into the pure bindings inspector. Reuse the unchanged
ELF reader and bounded address-form/width helpers; no new decoder or relaxation
of ordinary owner predicates is authorized. Own ordinary/emitted load twins
must compare structurally. Ordinary absence of applied REL records is explicit,
not permission to omit original machine/startup relocation authority.

## Required Binding Facts

Invoke the frozen link audit on each supplied image with its actual machine
and final attributes. Retain all 26 definition records, seven original pointer
roles, emitted applied pointer records, fixed vectors, strong handlers, exact
private/storage cohort, LOCAL slot/anchor and GLOBAL post-LTO default panic.
Do not substitute a previously claimed audit result for recomputation.

Add four uniquely defined reverse functions from the actual generated machine:

- fiber_internal_runtime_select_scheduler_candidate
- fiber_internal_runtime_publish_current_context
- fiber_internal_runtime_require_current_context
- fiber_internal_task_return

Bind their raw original/final definitions, positive extents, Thumb entries,
executable mappings, non-overlap and exact whole-input-section map placement.
The combined surface has 30 definitions; this is not 30 original-TU owners.

Require the following selected-port caller/target/kind/multiplicity roles:

| Caller | Target | Original REL | Count |
| --- | --- | --- | --- |
| fiber_port_runtime_schedule | fiber_internal_runtime_require_current_context | R_ARM_THM_CALL, addend -4 | 1 |
| fiber_port_scheduler_pick_first_from_start | fiber_internal_runtime_select_scheduler_candidate | R_ARM_THM_CALL, addend -4 | 1 |
| fiber_port_scheduler_pick_next_from_pendsv | fiber_internal_runtime_select_scheduler_candidate | R_ARM_THM_CALL, addend -4 | 1 |
| fiber_port_scheduler_pick_next_from_pendsv | fiber_internal_runtime_publish_current_context | R_ARM_THM_CALL, addend -4 | 1 |
| fiber_port_init_context_frame | fiber_internal_task_return | R_ARM_ABS32, addend 0 | 1 |

Discover sites inside the exact named function extents in merged text; do not
use observed relocation offsets or whole-machine totals as expected answers.
Other common-runtime callers may legitimately reference these services.
Original targets are defined machine symbols, not necessarily SHN_UNDEF imports.
Require raw symbol identity, mapping, original addends, actual applied BL/pointer
destinations and exact emitted REL metadata. Reject unapproved tails, ambiguous
membership or retargeting; ordinary twins must lack applied REL metadata.

Bind one retained anchor byte read in each of fiber_port_runtime_prepare_start
and fiber_port_context_init. The anchor is LOCAL at an offset inside merged
read-only storage. Its literal REL may target an unnamed STT_SECTION: preserve
the raw empty name and metadata, labeling the referred section separately.
Combine the actual original ABS32 addend, section placement and LDRB displacement
to prove the effective byte address is exactly the mapped one-byte anchor.
Bind the producing literal load and consuming byte-read register relationship,
instruction/data mappings and preserved original/final bytes. Do not impose the
ordinary adjacent LDR-r3/LDRB-r3 form: O2-LTO can retain a base in r7 and consume
it later, and can use displacement 1. Register linkage is bounded retained-code
evidence, not a claim that a path executes or that callees preserve all semantics.

Audit startup's original .isr_vector ABS32 roles at offsets 4, 44 and 56 for
Reset, SVC and PendSV. Bind original zero addends and exact startup/machine
targets to their applied final Thumb pointers and map origins. The frozen audit
still owns the full vector template, entry/MSP, placement and load permissions.

## Closing And Nonclaims

Retain original/final bytes, raw symbols/REL records, resolved values, provider
identities, map placements and attribute evidence for both twins. Require exact
immutable reads, physical/input/output closure and intended-byte receipt seals.
The enclosing runner may reuse the 7AFE failure-revocation helpers: preserve the
primary error, force FAIL independently of fallible hooks, and permit only the
fixed two diagnostic-write attempts, never process or replay retries.

Runtime-binding success is component evidence only. RequiredCellSatisfied is
false and RequiredCellsSatisfied is literal integer zero; all 2,774 keys and
26 backlog records retain their inventory meaning. Whole-slot access isolation,
typed ABI probes, fresh negative links and whole-cell composition remain separate.
Full ABI, full semantic ABI, source/IR or source-to-machine semantics, original
TU ownership, canonical protocol, reference parity, policy equivalence, archive,
hosted CI, hardware and global qualification are not granted by this component.
