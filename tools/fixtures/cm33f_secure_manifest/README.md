# C3FS Staged Manifest/Construction Gate

`tools/test_cm33f_secure_manifest.ps1` creates a unique evidence directory;
requires existing ARM GCC/G++, CMSIS, the clean pinned FreeRTOS kernel, Python,
Unicorn2.1.4 and pyelftools0.33. It installs nothing and programs no board.

Eight O2/Os x hard/softfp x normal/LTO modes compile real C3FS query/initializer/pool
objects and C/C++ public/private/import probes. A real ordinary C consumer roots
the Secure archive's nine NSC functions; their calls extract the strong pool
helper, with no whole-archive or key/helper `-u`. Exactly nine veneers/imports,
one RO generation2 exact key, eight BSS bytes and 864 NOLOAD bytes for 3x256
backing, and no allocation/load/save export are checked. CPACR/nPRIV
preflight and complete final query envelopes are inspected. Input-object/final
ELF architecture facts supplement compiler/CMSIS manifests.
The same eight configurations also compile/link the actual private port/helper
graph with raw instrumentation, stack protector, UB sanitizer, profile arcs,
test coverage and trace-pc coverage. No profile/instrumentation stubs or disabling
counterflags are supplied to the port graph. These checks are C3FS-local, not a
claim that common code or other profiles have closed A32.

Actual `fiber_init`, constructor, private helpers and attachment instructions
execute in both ordinary and consistently fixed-r9 modes. A local-binding sample
label permits an independent captured-r9 oracle without conflating public-entry
r9 with nested C temporaries. Cold frame words, immutable metadata, canary,
repeated/bad attachment, stale queries, lifecycle closure and seal mutations are
checked. Actual unchanged pinned constructors execute in four non-LTO modes;
their debug GPR/Thumb-PC policy differs intentionally from Fiber's initialized
GPR/r9/normalized-PC policy. No test substitutes a constructor implementation.

`probe.c` explicitly supplies the staged cohort byte, reverse-v1 byte, labelled
optional-lifecycle test guard and eight labelled **NS query doubles**. It also
supplies general-register bytewise libc support and mandatory RAM/code hooks.
These are not a Secure pool, SG execution or fake full runtime. No generic
forward operation or runtime bundle is defined. Actual common functions are
compiled unchanged; only the placement marker on other discarded public APIs
is cleared on that common TU to avoid LTO section co-retention. `fiber_init`
and task-return carry no such marker and their tested bodies are unchanged.

Separate preflight runs execute actual Secure query bodies with explicit
CONTROL/CPACR register doubles and stop **before BXNS**. Valid/partial/missing
CP10/11 and nPRIV cases check exact return values or terminal UDF75, no manifest
helper before admission, no MMIO writes and balanced return stack. This does
not emulate Secure transitions, NSACR/FPCCR, SFPA/FPCA or FP stacking.

The real initializer and private pool boot operations additionally execute with
explicit system-register and MMIO doubles, not emulated architecture banking.
Every image covers valid boot state, whole poisoned-NOLOAD scrub, one-shot
markers, direct pool repeat/corruption, NS/SVC provenance, both FPCA and LSPACT
admission, BFHFNMINS, sticky post-commit failure, exact pool return1, exact
CONTROL2 (injected6/10/14), NSACR/FPCCR readbacks, lost marker writes and failed
scrub. Secure/NS CPACR, NS CONTROL and unrelated FP policy are preserved. No
FP-preservation or actual SG claim follows from these explicit register doubles.
Query execution starts with poisoned pool storage/markers and requires no pool
or MMIO write; capacity queries do not initialize backing.

Final production text uses ELF `$t/$d` mappings and a complete `objdump -z`
decode. Every code byte is accounted, no FP instruction is allowed anywhere in
this integer companion, and literals are counted separately. Initializer text
interval and complete instruction hashes are recorded. All nine real veneers
account for 72 bytes plus 24 checked zero alignment bytes. Missing initializer
or helper decode lines are rejected as independent decoder controls. Removing
GRO from actual identity source is also rejected by the whole-text oracle.

Negative links check missing context/storage/reverse providers, scalar caller
storage, missing C3FS imports and a genuinely differently configured manifest
object. Source-compiled controls remove one actual query-preflight call or GRO
protection, preserving hashes/commands and requiring the exact oracle rejection.
Initializer controls compile actual source with exactly one NS-FPCA predicate,
exact-pool-return predicate or exact-CONTROL predicate removed/weakened. They
must be rejected by actual machine-body execution. A separate no-provider link
checks the generation2 ASSERT diagnostic; it is not a replacement companion.
Manifest negatives reject FP/role/feature/geometry overrides. A real M55 target
object demonstrates the separate ISA-ceiling admission obligation.

`receipt.json`, `inputs.before/after.json`, `artifacts.json`, `checks.json`,
`executions.json`, `controls.json`, commands, actual source-derived `.i/.s`,
LTO intermediates, objects, ELF attributes, maps and imports preserve evidence.
Four hard/softfp O2/Os tuples additionally compile all four unmodified Secure
reference units with real FPU1/MPU0/TZ1 flags, preserving complete object bodies
and generated assembly, as well as the actual NS constructor comparison. Those
reference objects are not passed through an integer-only production oracle;
their genuine compiler CMSE FP cleanup remains visible.
Raw textual input snapshots are retained with original-path/hash mappings.
No complete runtime activation, full FreeRTOS equivalence, SG execution, FP
preservation, physical support or board result is claimed.
