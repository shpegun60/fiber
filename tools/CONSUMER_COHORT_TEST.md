# Caller Storage Cohort Regression (A16)

Normal allocation through `fiber/fiber_core.h` or `fiber/fiber_types.h` retains
one pointer to the exact public storage generation per translation unit. The
existing mandatory port-cohort definition provides that symbol. This adds no
function, per-context call, startup constructor, or switch-path instruction.

Concrete `fiber_port_types.h` headers publish facts and a symbol declaration
only. They intentionally do not couple private layout probes or staged gateway
queries to a runtime provider. A direct concrete-type allocator must additionally
include `fiber_port_storage_cohort_expectation.h` after the type header to obtain
the same guard. Bare concrete-type allocation alone is not stale-build guarded.

The linker must retain `KEEP(*(.fiber_port_context_cohort_expectation))`, the
existing build-owned expectation contract. Its aggregate size is now a nonzero
multiple of four bytes, not necessarily one pointer. Ordinary archive extraction
rules apply: a never-extracted archive member is not part of the linked program.
Every public storage-layout change requires a public revision bump. The four
protected v8-M MPU families use public revision 2 after the CONTROL semantic fix;
their symbols remain independent of private scheduler and CPU-policy identity.
Objects compiled before A16 introduced any storage relocation require a clean
rebuild. A linker cannot recover missing type information from such an object.

Run the standalone focused regression (never the complete matrix):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_consumer_cohort.ps1 -ArmGcc <gcc.exe> -CmsisCore <CMSIS/Include> -BuildRoot <output-directory>
```

The script fails rather than skips unavailable compilers or regressions. It
compiles every public type in C/C++ without CMSIS, checking facade, bare-type,
and explicit direct-type expectation dependency surfaces. It also compiles four
common sources without CMSIS or selected type/storage dependencies.

Actual CM33_MPU runtime/boot objects and build-owned expectations are linked
against allocation-only C/C++ consumers. A separate fresh opaque-API caller
invokes `fiber_init`; the allocator itself calls no public operation. The script
tests both 8/16-region directions, matching controls, same-size guarded revision-1
snapshots, facade/direct guarded inclusion, and object/archive consumer packaging
at `-O2`, `-Os`, and both with LTO. Every link uses section GC. Negative links
must fail only on the consumer's exact identity, derived by preprocessing its
public headers. Positive ELFs must preserve the 216/280-byte allocation, the
strong identity provider, and have no undefined symbols.

Commands, diagnostics, ELFs, archives, maps, disassembly, JSON results, and a
SHA-256 artifact manifest remain under a unique output subdirectory. These are
offline link/code-generation tests, not target execution or MPU-isolation proof.
