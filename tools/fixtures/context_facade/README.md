# Additive Context Facade Gate

Run from the repository root with Python 3.10+ (standard library only), GCC/G++
for the host, ARM GCC/G++ including the LTO plugin, and real CMSIS Core headers:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_context_facade.ps1 `
  -ArmGcc $env:ARM_NONE_EABI_GCC -CmsisCore $env:CMSIS_CORE_INCLUDE `
  -HostGcc C:\msys64\ucrt64\bin\gcc.exe -Python (Get-Command python.exe).Source
```

`-BuildRoot` selects a parent for a unique preserved evidence directory. Missing
tools/inputs, unsupported warnings, surviving controls, and source/tool drift
fail the suite; nothing is silently skipped. The runner never installs packages,
programs hardware, invokes the catalog/matrix, or edits production sources.

## Executed Host Contract

The five actual common C sources (core, state, panic, optional configuration,
and compatibility facade) are compiled together with all eight mock port
operations, a C consumer and a C++ consumer. The consumer dialects alternate.
Each scenario gets a new process: no test-only production reset or copied runtime
model is used. O0/O2/Os and O2/Os LTO run 38 scenarios each:

- Both init paths forward the identical context/storage/entry/argument values.
- Mixed dispatcher registration, start, current, and yield share the current slot,
  hook/user pair, first-selection latch and configuration latch.
- K precedes k on start; both precede port preparation. The environment guard
  precedes null-hook rejection. Registration replacement before selection must
  invoke the distinct replacement function with its new user pointer.
- Successful start closes configuration before prepare, calls the first dispatcher
  with NULL, then publishes before the first-start port operation.
- Reentrant start/registration, repeated start/configuration, null first/later
  candidates, null publication, pre-start yield and entry return fail as specified.
- Later selection may return the current context. A failed later NULL selection
  leaves publication intact. Failed preparation cannot reopen configuration.

Panic and mock first transfer use C setjmp/longjmp; no C++ object with a
nontrivial destructor is crossed. This is host-mock execution, not Cortex-M
exception, frame, register, mask or scheduling execution qualification.

Seven compiled actual-source controls change start precedence, remove configuration
closure, break facade current/user/yield forwarding, change task-return panic,
or retain the previous dispatcher instead of accepting replacement.
Each must reach its exact maintained assertion and exit 90, not merely crash.

## ARM Compile And Link Contract

CM0 soft/no-VTOR, CM0+ soft with/without VTOR, CM4 hard FPv4-SP-D16 and CM7 hard
FPv5-D16 use the actual complete classic backend groups. CM0+ uses real
`core_cm0plus.h`, not the CM0 CMSIS model. These are target CPU/capability cells,
not F0/G0/G4/H7/H7S board qualifications. C/C++ Context-only static allocation and both mixed header
orders compile without a CMSIS include path. Type identity is checked without
casts, and the Context-only header cannot import the legacy callable API or
private runtime. Each allocating translation unit retains its storage identity.

At O2/Os, ordinary and native LTO, direct and archive links retain real strong
SVC/PendSV vectors, exactly one current slot and reverse-v1 anchor, all old/new
entry points, and no undefined symbols under section GC. Hard-FP final ELF ABI
tags and the actual VTOR private-cohort field are checked. Cross-VTOR CM0+
expectations must reject the opposite complete archive. Real stale
storage/private-cohort/reverse-v1 inputs must fail
with the exact unresolved identity, not an unrelated compiler or linker error.
This link script is synthetic, not an executable board startup image.

The expected missing name comes from `gcc-nm -u` on the actual stale input,
requiring exactly one import with the relevant identity prefix. Classification
then uses that complete name, never a prefix inferred from linker stderr. For
the reverse-v1 check, the real constructor is the stale consumer of v1 and the
mutated common object supplies v2. Receipt rows identify each consumer object
and the exact imported symbol.

Failure admission uses a closed GNU-ld line grammar: exit exactly 1, no stdout,
the tracked linker path, section relocation diagnostics for the exact imported
name, optional paired function headings, and one exact final collect2 trailer.
Only the paired standard native-LTO serial-job notice may accompany them. Any
additional line, including RAM overflow, unknown errors, warnings or notes, is
rejected rather than filtered using a diagnostic blacklist.

At CM0 O2 and native O2 LTO, the same actual compiled engine/consumer inputs link
with the identity missing alone, then with both that missing identity and real
RAM overflow under `overflow.ld`. The first is admitted and the second must be
rejected. Each pair also checks 17 counterfeit transcripts (wrong same-prefix
name, unrelated diagnostics, malformed/missing trailers, status and stdout
contamination) and kills five counterfeit classifiers, including the old
prefix-only approach and an always-reject classifier. These 46 diagnostic
controls are recorded separately from the 125 execution/codegen/cohort controls.
Earlier receipts remain historical weaker results; this revision does not
retroactively qualify their diagnostic admission.

At O0/Og/O2/Os/O3, ordinary and lowered native-LTO facade objects are checked under
raw instrumentation, stack protection, coverage, UBSan and trace-PC flags. No
counter-options mask the input flags. All five native facade bodies must exist,
be free of compiler hooks/FP instructions, and current/yield retain Thread-code
placement. The facade object must not acquire writable state/counters. Lowered
objects must contain native bodies without `.gnu.lto_*` IR/fat fallback sections.
Attribute aliases must match the canonical Fiber bundle including
GRO. Removing the actual sensitive annotations from declarations and definitions
must compile/lower and expose instrumentation in each tuple.

This is a facade-body/attribute proof, NOT a transitive raw closure claim for
init/set-dispatcher: those delegate to deliberately ordinary legacy cold wrappers
`fiber_init` and `fiber_scheduler_set_pick_next`, whose own raw compiler hooks
remain permitted by the current contract. No runtime ownership inversion, Fiber
lifecycle, entry trampoline, new profile, five-option pinned FreeRTOS equivalence,
or hardware qualification is implied.

## Provenance

The runner copies its exact scoped source/fixture/CMSIS inputs before compilation
and compiles from that immutable copy. It records compiler dependencies, commands,
tool versions/specs, compiler/linker/LTO executables, interpreter, actual target
libraries and hashes before/after. The driver `-###` LTO-plugin path must match
`-print-file-name` and its DLL is hashed. Consumed system headers are hashed before
their compile and rehashed at completion. `results.json`, `inputs.json`,
`dependencies.json`, commands, objects/ELFs/maps/disassembly logs and an artifact
hash manifest are retained on success or failure.

The expected CM0 no-VTOR pragma warning has no GCC option-specific downgrade.
Only that exact warning is accepted; other diagnostics remain fatal. Native-LTO
serial-job notices are also admitted by their exact format. PE LTO's absolute-zero
bookkeeping symbols are not counted as allocated runtime state; normal host
objects separately prove the current slot is one pointer-sized subsection.
