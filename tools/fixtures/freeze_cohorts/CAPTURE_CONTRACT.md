# Ordinary Freeze Capture

`tools/freeze_capture.py` is a fresh-build component producer. This contract is
not an execution receipt or a claim that a requested batch has passed.

## Interface

```text
python tools/freeze_capture.py --gcc GCC --cmsis CMSIS_INCLUDE --git GIT --freertos KERNEL --python-modules MODULES --inventory INVENTORY --inventory-receipt-sha256 HASH --inventory-artifacts-sha256 HASH --request REQUEST.json --request-sha256 HASH --output-dir FRESH
```

All options are required. The interpreter is the actual running module, using
GetModuleFileNameW on Windows; it is not caller-selectable. Optimized Python is
rejected. Paths must be absolute, outside protected work, and without symlink or
reparse ancestors. No old producer, join, or discovery receipt is required.

The request is ASCII JSON with exactly these fields:

```json
{"SchemaVersion": 1, "Routes": ["CM3/O2/direct"]}
```

SchemaVersion is literal integer 1. Routes is an ordered, nonempty, unique list
selected from the 30 ordinary routes of dispatcher
`142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275`:
CM0, CM0PLUS, CM0PLUSVTOR, CM3, CM4, CM7, each in O0, Og, O2, Os, O3, direct only.
Unknown fields, duplicate/case-aliased JSON keys, boolean integer aliases, LTO,
archive routes and caller-selected scripts or argv are rejected.

## Public Python API

- `Rejected(ValueError)`: closed-request/admission failure.
- `routes()`: fresh dictionary of the 30 ordinary route records, with the same
  fields and values as the pinned dispatcher; no I/O or helper import.
- `validate_request(value)`: return a detached ordered list of route IDs after
  exact request validation; no I/O or helper import.
- `stage_arguments(route_id, stage, *, gcc, cmsis, git, freertos,
  python_modules, inventory, case_dir, native=None, reference=None)`: return
  `[fixed_script, *fixed_cli_arguments]`, without an interpreter/bootstrap.
  Stage is exactly Native, Reference or Join. Join requires both producer
  descriptors; producer stages reject descriptor arguments. No I/O occurs.
- `scope_report()`: fresh FAIL-default report with empty cases/pending and all
  broader claims false, literal zero required credit and no completed counters.
- `prepare(args)`: authenticate all opening inputs without creating output;
  return a Capture. Args has the eleven required CLI fields, with hyphens
  represented as underscores. Import and prepare do not execute commands.
- `Capture.command(argv, label, timeout=900)`: record ATTEMPT and terminal
  results. The managed runner is the instance's `runner` attribute, replaceable
  by pure test controls, never by CLI/request data. It implements
  `run(argv, *, cwd, env, timeout)` returning bytes/stdout, bytes/stderr,
  literal-int returncode, literal-bool timed_out and finite elapsed seconds.
- `Capture.run()`: create fresh output, execute fixed stages and finish; return
  bool. `Capture.finish(error=None)` closes/seals and returns bool; incomplete
  or empty work cannot PASS. `main(argv=None)` is the CLI entry point.

## Fixed Execution

For each request route, execute Native, Reference, then Join, sequentially:

| Profiles | Native | Reference | Join |
|---|---|---|---|
| CM0 family | classic_final_image/run.py | cm0_final_image/reference_run.py | cm0_final_join/join.py |
| CM3 | classic_final_image/run.py | cm3_final_image/reference_run.py | cm3_final_join/join.py |
| CM4, CM7 | classic_final_image/run.py | classic_final_image/reference_run.py | classic_final_join/join.py |

All paths in the table are below tools/fixtures. Producers, predicates, models
and joins are unchanged. Their hashes come from the exact pinned dispatcher,
loaded from the same authenticated bytes that are parsed/executed. Its inventory
admission, route helpers, immutable bootstrap and managed process runner are
reused without changing their globals or policy.

CLI tool paths are caller choices, not signature or vendor-trust assertions.
Record their bytes and physical identities before execution and recheck at
closing. The unchanged producers additionally capture tools/workers, verify the
GNU Arm GCC 14.3.1 baseline, authenticate actual reference commit
`a50edad08b29052631aa469d4df6e6ec7ff68878`, and bind worktree/captured/blob bytes.
CMSIS headers and pyelftools sources have opening membership/hash watches.

Execute local Python helpers from authenticated source buffers. Deterministic
aliases for producer source copies and parser copies retain the same admitted
bytes; aliases do not waive actual output or producer input closure. Record and
validate child bootstrap traces. There is no compiler, target or shell selected
through request data. Compiler/linker/inspection execution is confined to the
unchanged producers; joins do not execute Arm images, boards or emulators.

The source snapshot records each alias with Original, Copy and Sha256. Copy is
only a deterministic future source/parser-copy path, not an opening physical
input. After the producer finishes, every actual copied source/parser file is
checked against its artifact seal and admitted source bytes before join use.

## Admission And Evidence

Before creating output, authenticate request, inventory receipt and complete
artifact membership, captured manifest/registry and recomputed canonical plan.
Require the inventory to match the current manifest/registry. Deny output
overlap with repository, request, inventory, reference, CMSIS, parser and tool
roots. Watch this implementation and contract as inputs.

Each case uses cases/PROFILE-MODE/{Native,Reference,Join}. Capture command ATTEMPT
before invocation and terminal bytes, hashes, exit, timeout and cleanup after
every attempt, including exceptions. stdout text is never a PASS authority.

Check exact typed cohort/profile/mode/source-group facts, source/object paths and
hashes, recipe and actual compile/link argv, dependency records, two ordered
links, seven object checkpoints, complete owning prelink protocols, both own
load-image twins and join evidence. Preserve CM0 VTOR and threshold N/A facts,
CM3 soft p4/b16 facts, CM7 errata metadata, and the FP eager/upstream-lazy policy
difference. Do not compare native/reference image bytes for equality.

Each completed case and final batch rechecks original/captured/generated input
bytes and exact output memberships. Fail-stop on the first failed stage or
closure. Preserve completed and partial files, primary error, closing errors and
an explicit pending list. No automatic retry, overwritten old receipt, or
fallback recipe is permitted.

Emit per-case full Native/Reference/Join descriptors and a dispatcher-format
catalog of successfully closed cases. CatalogReady is true only after every
requested case and final closure pass. Partial catalog descriptors are retained
for investigation, not granted batch success. Seal against intended receipt and
manifest bytes; late failures must persist FAIL, not a stale PASS receipt.

## Counts And Limits

Every case has 9 native TUs, 73 native tool commands and two native links. CM0
family reference has 5 TUs/79 commands/5 prelink roots; other reference profiles
have 4 TUs/71 commands/3 prelink roots. Every producer has seven checkpoints.
Every join has three mechanisms and eight CM0-family or six other closed bodies.
Each case has three outer Python invocations. Tool counts include discovery,
compilation, linking, inspection and provenance commands, not just TUs.

For the six profiles times five modes minus CM0/O2: 29 cases, 391 TUs, 116 links,
406 checkpoints, 4288 tool commands, 202 closed bodies, 87 mechanisms and 87 outer
Python invocations. These are expected counts, not measured results.

All proof is component-scoped. RequiredCellsSatisfied is literal integer zero.
RequiredCellSatisfied, CompleteObjectProof, FullABIProof, APIProof,
FinalReferenceParity, InstructionEquivalence, PolicyEquivalence, CpuExecution,
BoardExecution and GlobalFreezeQualified remain false. Ordinary capture does not
promote historical LTO evidence, establish source/IR semantics, or qualify CI or
the global freeze matrix.
