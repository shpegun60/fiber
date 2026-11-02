# Sensitive Port Compiler Closure

This maintained compiler proof uses only Python's standard library. It does not
install packages, execute a scheduler, emulate exception/security behavior, or
claim a full final-ELF/runtime/board qualification. Normal API consumers do not
need Python. The receipt records the actual Python executable and version.
This is the stronger additional raw-flag software-freeze policy, not a claim
that prior builds using the documented mandatory counterflags were invalid.

From the repository, in PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_sensitive_port_closure.ps1 -ArmGcc $ArmGcc -CmsisCore $CmsisCore -ImmutableInputs
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_sensitive_port_closure.ps1 -ArmGcc $ArmGcc -Profiles CM7
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_sensitive_port_closure.ps1 -ArmGcc $ArmGcc -Profiles C5TF -AuditOnly
```

The default is the explicit global inventory, O2/Os, normal native objects and
genuinely lowered slim LTO, with sectioned and unsectioned LTO code generation.
No fat native fallback is permitted. O0/Og/O3 are accepted by `-Optimizations`.
`-Profiles`, `-Bundles`, and `-NativeLtoSections` select an explicitly recorded
focused scope. Arrays can be passed through ordinary PowerShell invocation.
`-Cm0Vtor 0,1` explicitly expands CM0 and CM0MPU into both vector-table
configurations; VTOR=1 uses actual Cortex-M0+ CMSIS/CPU dialect. Default VTOR=0
preserves the existing finite inventory. Each cell records its actual VTOR fact;
VTOR=1 labels have a `-vtor1` suffix and independent baseline-import comparisons.
`-ImmutableInputs` copies the admitted port families, shared source, this fixture
and CMSIS before starting any compilation. Inventory/bytes are checked across
copy construction; actual compiles read only that verified copy. The snapshot
manifest distinguishes copied files from actual GCC dependencies, and all copied
bytes are checked again at completion. Later edits of the original worktree do
not change this proof's inputs or qualify those later revisions. Use this mode
for a broad run while other agents are editing. Compiler/toolchain headers and
binaries retain their separately hashed integration boundary.
An exact baseline is always built before a requested raw family. The default
raw bundle enables function instrumentation, all-function stack protection,
gcov arcs/coverage, undefined-behavior sanitization, trace-PC and `-pg` together.
Individual family bundles are also available. No instrumentation-disabling
counterflags are accepted. `-fno-function-sections` is the sole admitted `-fno-`
option, only in the requested native-LTO layout case.

Each actual selected C source and the four common runtime sources plus storage
cohort TU are compiled, without fixture replacements for production functions.
Port-only, common-only and whole selected/common native groups are inspected.
Paired Secure companion groups are compiled separately with real `-mcmse`.
The C55S staged group is a component compiler audit, not runtime activation.
Its private staged cohort does not implement the generic storage-expectation
TU, so that TU is not included in this role. Paired Secure pool roles have
explicit three-slot/1024-byte-stack fixture manifests, never production defaults.
The incomplete ARM_CM33F Secure FP source group is explicitly excluded; the
receipt contains the exact admitted C inventories, CPU/FP/MPU dialect and role.
The finite default inventory uses each recorded primary ABI and 8 MPU regions
where configurable. It is not every ABI/region/feature permutation.

Every port function is protected. Common roots include the three canonical
sensitive public operations and the task-return/panic chain. Relocations,
resolved same-section branches and locally initialized callback data extend
reachability. The callback analysis conservatively follows defined objects;
unresolved external providers remain explicit integration boundaries. Only exact cold exports
`fiber_init`, `fiber_scheduler_set_pick_next` and their private store helper
can retain raw hooks/counters when not reachable from a protected root. Shared
text sections do not imply shared sensitivity. A relocation site's real target
overrides objdump's unresolved branch placeholder. Unknown initializers fail;
common gcov registration is accepted only for exact cold counter identities and
the complete compiler-generated registration-only leaf/aggregator chain. Raw
hooks inside that cold registration chain do not make it sensitive. Hooks, counter objects, initializer
sections and exact protected normal imports are classified separately. External
integration callbacks/providers remain call-graph boundaries, not audited user
implementations; their transitive application code requires separate proof.
In particular, allowed `memcpy`/`memset` are normal integration imports, not
blanket-forbidden compiler hooks; their complete bodies need separate GRO proof.

Raw flags are present on every compilation. At the native grouping driver,
`-fprofile-arcs` and `-ftest-coverage` are not repeated: their counters already
exist in native bodies/slim IR, and repeating them injects `libgcov` even with
`-nostdlib -r`, confusing the source-group audit with a linked runtime library.
All other late instrumentation options remain enabled. A compiled unannotated
control must exhibit every requested family *after* lowering, including gcov;
missing families are harness failures, never a production PASS.

Maintained controls also prove direct and initialized-callback sensitive-to-
unannotated helper paths reject,
isolated cold instrumentation stays allowed beside a relocated external call,
an unknown compiled initializer rejects, and removing the actual canonical
bundle on actual common/port source exposes hooks and sanitizer calls. No
historical receipt is trusted.
For CM0, CM0MPU, CM3 and CM3MPU, an additional actual-dictionary copy removes
only `FIBER_API_ATTR_INLINE_SENSITIVE`, retaining all GRO and non-inline
annotations at O2/Os. Its complete actual selected C group must compile and expose a
function-instrumentation defect after lowering; no substitute helper is used.
The control covers normal and both native-LTO layouts. It is not requested at
O0/Og/O3: in particular, O0 can reject the deliberately mixed always-inline
policy before lowering, which is not an instrumentation counterexample. The
unmodified production group must still qualify every requested optimization.
Optimized Python direct/runpy/import invocations
must fail with exactly the expected diagnostic, including a counterfeit-error
negative. Inputs include actual compiler tools/plugin and full GCC dependency
closures (including CMSIS/toolchain headers), hashed before/after. Any input
drift or unknown/build/control failure makes the receipt FAIL. `-AuditOnly`
may return zero for collecting findings but never changes FAIL to PASS.
`CellCounts` exposes the exact planned, attempted, completed, passed, failed
and unqualified counts. `CompleteSuite` means the requested iteration finished,
not that every cell qualified; only `Status=PASS` establishes that. Every
unqualified cell has its own `unqualified.json` as well as the final error list.
An additional compiled gcov-shaped counterfeit constructor must also reject
beside legitimate cold counters. Failed assembly and LTO assembly are preserved.
Captured source/fixture/header bytes accompany before/after dependency hashes.

CM3's O2 unsectioned native-LTO baseline also compiles three variants of its
actual preprocessed `fiber_port.c`: natural pool removal, terminal pools plus
8192 unreachable bytes at each naked tail, and that identical pressure variant
with only its three pool directives removed. The pressure-positive must assemble;
the pressure-negative must fail only with exact literal-range diagnostics whose
saved assembly lines are actual `ldr =` instructions. Natural pool removal is
recorded independently and is not required to fail: post-attribute code layout
can put its implicit pools within range. This synthetic pressure control does
not claim a natural-layout production failure or execute the unreachable bytes.
The same matched control covers CM0's three and CM0MPU's four existing terminal
pools, independently for each selected VTOR setting. Thumb-1 accepts only its
specific `invalid offset, value too big (0x...)`/literal-range diagnostic, still
requiring an actual saved `ldr =` line; other assembler/linker failures reject.

`-Cm7PrefixRoot` explicitly recompiles a supplied historical flat CM7 source
copy for pre-fix evidence; it never substitutes a saved success receipt and is
marked historical in the result. Default qualification always uses current
repository sources. Every command, native disassembly, classification, receipt
and artifact SHA256 manifest is kept beneath the printed build root.
