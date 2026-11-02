# Constructor-Only Reverse ABI Guard

Run `tools/test_reverse_abi_constructor.ps1` with `-ArmGcc`, optional
`-CmsisCore`, and optional `-BuildRoot`. This is a link/code-generation gate;
no board or emulator is used. Parent integration owns central dispatch.

## Production Proof

The runner performs exactly 32 production links:

`O2/Os x normal/LTO x direct/archive x v1/v2-only common x init-only/start-retained`.

The repaired source must pass sixteen matching links and reject sixteen
mismatches, each with exit 1 and only the exact missing
`fiber_internal_runtime_port_abi_v1_anchor`. Wrong/multiple missing symbols,
unrelated linker errors, crashes and successful links are not valid negatives.
Seven diagnostic parser controls maintain this distinction.

Public `fiber_init`, common runtime state and panic, and the complete CM7
port/boot/exception group are actual production sources. In production cases,
only the generated COMMON-v2 fixture changes a source definition: its one
runtime-state anchor definition receives the v2 spelling and value. Production
port sources are never transformed or forced into the link with `-u`.

Matching constructor-only images must keep the actual constructor and v1
anchor, but discard start adapters, first-start assembly and SVC/PendSV handlers.
The entry assembly must call actual init/construction; LTO may inline
`fiber_init`. Constructor-only mismatches must diagnose the constructor, not a
retained start guard. The linker KEEP's only the existing documented public
storage expectation, never start code or reverse anchor data.

An exact source inventory covers 22 constructor definitions: nineteen complete
profiles, staged C55S/C3FP, and transitional v8-M. Each actual constructor body
must contain one direct cold RETAIN call; comments/string literals do not count.
Where incoming r9 is captured explicitly, that capture must precede retention.
Parser controls exercise real, commented and string-only guard spellings.

Actual CM7 objects prove the constructor dependency and the two-object
constructor/start group dependency. A separate compiled reverse-header probe
requires a visible macro and exactly its v1 DATA dependency, not an undeclared
function call. The 22-profile audit is source-level; compilation of the other
profiles remains an aggregate responsibility, not a hidden all-profile claim.

## Compiled Guard-Absent Controls

Eight additional controls (four modes x direct/archive) are compiled afresh
from the same current sources and toolchain as production positives. A test-
local copy of CM7 boot source deletes exactly the single constructor RETAIN
call. Character-count and exact-reinsertion checks prove that one text deletion;
constructor-body inspection proves its location. The original snapshot must be
byte-identical, and original/mutant SHA-256 hashes are recorded. The existing
start read and all other production source objects remain unchanged.

The copied source is compiled with an explicit original-port `-iquote` path;
its dependency file must resolve the actual original private header. Both
archive and direct controls reuse the positives' actual common core, port and
exception objects, substituting only that freshly compiled mutant boot object.
The mutant constructor must have no v1 dependency, while its group still has
the original start-object dependency.

Each control must demonstrate the init-only/v2 link succeeding while start code
and the v1 anchor are absent. The same negative oracle must reject those
successful bad links. No committed binary archive, historic Temp receipt,
compiler path, or exact compiler executable hash is required. Tool binaries
are hashed for evidence, not compared against an allowlisted build.

Portability is bounded to an ARM GCC toolchain with matching GCC ar/nm LTO
support and GNU linker/objdump diagnostics and symbol syntax. O2, Os, LTO,
section GC and the Cortex-M7 soft-float target must be supported. This is not a
Clang/IAR or arbitrary-linker qualification claim. Historical pre-fix binary
evidence remains external, not an input to this maintained gate.

`-ControlOnly` is a development mode, labeled `CONTROL-ONLY-PASS`, with
`ProductionQualification=false`; it never substitutes for the default gate.

## Evidence

Each run records exact commands/exits, input hashes before/after, objects,
archives, maps, compile/link logs, final symbol/disassembly dumps, checks,
cases, and an artifact-hash manifest. The receipt hashes command/input/artifact
manifests and rejects input drift. Control-only and pre-fix developmental
receipts do not qualify repaired production sources.
