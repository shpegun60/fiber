# C3FS Staged Manifest/Construction Gate

`tools/test_cm33f_secure_manifest.ps1` creates a unique evidence directory;
requires existing ARM GCC/G++, CMSIS, the clean pinned FreeRTOS kernel, Python,
Unicorn2.1.4 and pyelftools0.33. It installs nothing and programs no board.

Eight O2/Os x hard/softfp x normal/LTO modes compile real C3FS query/manifest
objects and C/C++ public/private/import probes. A real ordinary C consumer roots
the Secure archive's eight NSC functions; their calls extract the strong manifest
helper, with no whole-archive or key/helper `-u`. Exactly eight veneers/imports,
one RO exact key, no BSS pool and no lifecycle export are checked. CPACR/nPRIV
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

Negative links check missing context/storage/reverse providers, scalar caller
storage, missing C3FS imports and a genuinely differently configured manifest
object. Source-compiled controls remove one actual query-preflight call or GRO
protection, preserving hashes/commands and requiring the exact oracle rejection.
Manifest negatives reject FP/role/feature/geometry overrides. A real M55 target
object demonstrates the separate ISA-ceiling admission obligation.

`receipt.json`, `inputs.before/after.json`, `artifacts.json`, `checks.json`,
`executions.json`, `controls.json`, commands, actual source-derived `.i/.s`,
LTO intermediates, objects, ELF attributes, maps and imports preserve evidence.
Raw textual input snapshots are retained with original-path/hash mappings.
No complete runtime activation, full FreeRTOS equivalence, SG execution, FP
preservation, physical support or board result is claimed.
