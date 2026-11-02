# C55S Private Object Cohort Links

`tools/test_m55_secure_cohort.ps1` uses existing Arm GCC/G++/binutils and CMSIS.
It compiles actual Secure identity, context-gateway and pool sources. No image
is executed and no hardware is programmed. The ordinary callers use C functions,
not forced `-u` roots for the private provider or data symbol.

The maintained gate makes 496 checks, including 32 compiled per-query
RETAIN-removal mutants (eight queries times O2/Os, with and without LTO):

- Actual complete companions and all eight independently rootable queries in C
  and C++, at O2/Os with and without LTO, under archive extraction and section GC.
- Query-only callers also exercise both mixed-LTO directions: LTO gateways with
  a native pool, and native gateways with an LTO pool.
- Individual stale identity/context/pool objects in both directions, count-only
  and capacity-only mismatches, and the 3/128 versus 2/208 equal-480-byte case.
  Matching ELF pool sections are independently checked numerically.
- Equivalent accepted constant expressions must generate the same exact key.
  Each linked provider is one strong read-only byte; complete companions retain
  exactly twelve NSC imports.
- Missing data despite a resolved C extraction helper, duplicate strong data,
  and a synthetic pre-guard twelve-entry provider fail for the intended reason.
  The pre-guard control links without the separate generation assertion.
- Synthetic encoding probes exercise the high half and all-ones value of each
  of twelve uint32 facts through the actual DEFINE/RETAIN macros. These change
  facts after the unchanged production assertions have run: they test operand
  encoding, not acceptance of an unsupported CPU or record manifest.

## Query-Owned Retention

A caller that names only one query does not isolate its cohort dependency:
extracting a production gateway object also exposes its sibling CMSE entries
as implicit linker roots. A sibling's RETAIN could therefore conceal removal
of the selected query's RETAIN. The added proof does not use `-u` for any
export, helper or data key, and does not change the existing complete or
query archive controls.

For each selected query, `select_query.h` is an explicitly fixture-only NSC
projection used while compiling a complete byte-identical copy of the actual
production C translation unit. The selected definition inherits its original
CMSE entry attribute. Sibling declarations retain the canonical sensitive and
general-register-only attributes, but are ordinary Secure C functions, not
implicit NSC roots. `query_only.ld.in` discards those sibling bodies before GC.
The selected body is not reconstructed. At O2 and Os its native function bytes
and exact relocation offsets/types/targets must match the unmodified actual
production object; sixteen comparisons cover all eight queries. LTO cases
compile the same copied production sources as real LTO archive members and
link through the actual GCC plugin, not through extracted native fallback code.
This fixture projection is not a twelve-entry production image or a substitute
for the unchanged full-surface and hostile-codegen tests.

Each of the 32 query/mode combinations makes four links:

- A matching actual archive must extract the real pool helper and one exact
  read-only byte key. Its import library must contain only the selected query,
  and its ELF must contain no sibling gateway body.
- Replacing only the archived pool with the foreign 2/208 geometry must fail
  solely on that query's own expected 3/128 key, not on generation presence or
  another undefined symbol. This independently proves the selected key edge.
- A bounded mutation removes only the selected function's RETAIN from the
  copied production source. Every sibling RETAIN stays unchanged. With the
  generation assertion omitted, this archive must link with exactly one NSC
  query and no extracted helper or key. This deliberate unprotected link
  demonstrates that no sibling can mask the mutation.
- The identical mutant archive and caller with the actual generation fragment
  restored must fail the unchanged matching-link admission check with exactly
  `Wrong exact key: <case>`. The ARM link must succeed and its import library
  must prove exactly one selected NSC before that rejection. Compiler errors,
  failed links, surviving siblings or any other validator failure do not count
  as a kill. The missing live exact key is the admission failure, not an
  invented claim that the generation ASSERT must reject every missing RETAIN.

Dead ordinary sibling references can extract a pool archive member before GC;
the helper may therefore satisfy DEFINED even when its body and key are later
discarded. The no-generation control asserts absence of a live helper/key,
not absence of initial archive extraction. The real-generation mutant exposes
this limitation while requiring the strict selected-key check to reject it.

Both matching/foreign links use actual production pool archive members. No
synthetic provider or external capacity expectation supplies an alternate
anchor. A missing macro, changed immutable function shape, unexpected native
bytes/relocations, unexpected link diagnostic, surviving sibling, or surviving
guarded removal mutant fails the gate. `mutation.json` preserves each original
path/hash, byte-identical copy hash, mutated hash and before/after definition.
Existing C/C++ ordinary callers and both mixed-LTO directions remain covered;
the production mutations themselves are C, matching the actual source language.

The generation linker fragment asserts guard presence only. It does not select
or extract a pool, discover hardware capacity, or impose an application-owned
exact capacity expectation on a wholly coherent alternate guarded archive.
Actual queries report that archive's capacity. Internal object agreement and
external build expectations are distinct contracts.

The fixture assigns a synthetic NSC address explicitly. A real Secure image
must use its board-owned NSC placement and the documented linker fragment; this
test address is not a board integration recipe. All commands, copied inputs,
ELFs/maps/imports/disassembly, expected failures and hashes are retained in the
unique evidence root. Focused links do not replace actual-FreeRTOS parity,
hostile compiler checks, initializer/lifecycle execution or the full matrix.
