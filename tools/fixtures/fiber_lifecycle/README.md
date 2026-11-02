# Fiber Lifecycle Qualification

`test_fiber_lifecycle.ps1` qualifies the Fiber V1 lifecycle consumer under the
actual mapping in `tools/runtime_sources.json`, read through the shared reader.
Engine, state, panic, optional configuration, legacy compatibility and facade
bridge are selected by explicit role. Receipts capture the manifest, both actual
readers and selected production sources; compilation uses their archived copies.
Every build writes `objects.json` with source, role, object and byte hashes.
Lifecycle dependency checks and compiled mutant replacements address objects by
source path, never by a numeric position in a common-source list.

Packaging is checked independently of the role manifest: the recursive file
inventory of `fiber/lifecycle` must contain exactly its five intended files.
Empty directories are allowed: Git archives do not track them and they are not
compilation inputs. A copied-tree positive control adds empty nested directories;
negative controls add `tests/straytest.c`, `hostfixture.c` and `hostfixture.cpp`.
All maintained fixture sources belong under `tools`. Actual O2/Os production
objects must define precisely the five public `fiber_v1_*` functions and one
local `fiber_v1_dispatch`, with no writable storage or other public definitions.
Compiled controls add an extra export, expose the adapter, and add an owned
current pointer; the same literal ABI/storage oracle must reject each.

Host processes execute production `fiber_v1.c` and the actual selected runtime.
Only the eight
forward CPU operations are fake. Each scenario starts a fresh process; tests do
not reset or replace private engine state. The fake constructor validates only
the Context prefix, making the full-container overlap check independently causal.

The `mixed-legacy` cohort always requests `legacy_compat` and uses `USE_LEGACY=1`.
It compares all three current APIs and retains an explicit typed record of the
five old public API identities through GC/LTO. With the old-owner mapping the
facade bridge necessarily calls the legacy engine: this is not independent
Context ownership, and the result records pure Context as not yet admissible.

After the manifest atomically selects Context-owned engine/state/panic/optional
configuration, an empty facade bridge and a nonempty legacy compatibility shim,
the runner also enables `context-fiber-only` with `USE_LEGACY=0`. That separate
host/real-ELF cohort omits `legacy_compat`, uses Context current in fake-port
comparisons, and rejects all five exact legacy public symbol names. The frozen
`fiber_internal_*` reverse ABI symbols are intentional and are not rejected.
O2/Os negative ELFs add the actual production legacy shim and the fixture's
typed public API consumer record; the same pure-image oracle must reject all
five reintroduced names. No private-provider roots or replacement port are used.
An incomplete/mixed ownership mapping fails instead of silently selecting a
partial pure cohort. Draft Context sources are never substituted for the actual
manifest-selected provider. Pure qualification requires a fresh activated-owner
receipt; old-owner receipts never establish that result.

Classic CM0/CM0+/CM4F/CM7 ELFs use actual port sources, CMSIS and the build-owned
storage expectation TU. They prove compilation, linkage and explicit Thread versus
privileged section placement, not execution, MPU enforcement, board behavior or
the transitive safety of arbitrary user policy. Both C11 and C++17 public static
consumers compile without CMSIS. The fixture policy alone uses the required
privileged sensitive/GRO annotation. No trampoline or new forward ABI is provided.

The runner archives source bytes, dependencies, tool identities, commands,
diagnostics, disassembly and hashes. Inputs are checked for drift at completion.
Mutations operate exclusively on archived copies and must compile and fail the
specific executable assertion, not merely emit any compiler/runtime error.
An optimized Python interpreter is rejected because maintained orchestration
must not change with optimization settings. No packages or tools are installed.
