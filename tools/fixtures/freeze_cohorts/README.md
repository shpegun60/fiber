# Freeze Cohort Inventory

`tools/freeze_cohorts.json` is inventory input, not a qualification receipt.
This initial file lists 27 canonical source groups (77 C files),
141 explicit cohort rows, including four paired rows: 145 artifacts in total.
The 26 backlog entries comprise 23 Pending and three ReferenceOnly obligations.
It does not claim complete enumeration of every admitted test vector, a global
optimization gate, hosted CI, runtime activation or STM32 hardware validation.
Unreconciled positive axes remain obligations in `scope_backlog`, not exclusions.

## Shape

Schema version 1 has exactly the agreed top-level keys: `schema_version`,
`reference_commit`, `compiler_baseline`, `required_object_modes`,
`required_final_modes`, `source_groups`, `cohorts`, `scope_backlog`.
All keys of each listed record shape are required. There are no PASS fields.

Each source group has `id`, `registry_id`, `role`, `sources`. Its explicit
C source list matches `sensitive_port_closure/run.py::profiles()`; all 27 registry
IDs are represented. No pending group with a null registry ID is introduced.
This source registry is not an oracle for supported defaults or exact tuples.

Each cohort has `id`, `scope`, `compiler_admission`, `runtime_selectable`,
`artifacts`, `policy`, `claim_refs`. IDs are opaque unique labels.
`scope` and `compiler_admission` independently use
`Claimed|Pending|ReferenceOnly` and `Admitted|Pending|ReferenceOnly`.
Compiler-admitted staged C55S/C3SO/C5SO/C3FT rows retain runtime selectability false.
Existing M23 NTZ software rows remain Claimed; its non-STM32 mapping is not a
reason to remove existing software obligations.

Every artifact has `role`, `source_group_id`, `abi_contract`, `target`,
`compile_flags`, `defines`, `upstream_sources`, `upstream_defines`.
NS plus Secure companion is one row containing two artifacts. The runtime owns
`forward8`; the companion owns `secure_companion`, never a second forward8 ABI.
Companion pool budgets are explicit string-valued defines. Different budgets
must be separately reconciled, not inferred from this initial 3/1024 binding.

All target keys are explicit: CPU, architecture, float ABI, FPU presence/use/unit,
stacking, VTOR, protected MPU region count, security role, PSPLIM slot/register,
MVE/PAC/BTI, errata policy, R9 ABI, NVIC priority width and scheduler BASEPRI.
Region zero means no protected context MPU image, not absence of silicon MPU.
FPU presence is the fixture manifest; use follows its compiler ABI. In
particular CM7 soft/FPU-present rows have FPU use false. Empty `fpu_unit` means no
explicit `-mfpu=` flag, including compiler-default MVE-FP generation; it does
not invent a physical FPU capability. Active FP rows explicitly define
`FIBER_FPU_LAZY` as a string matching eager/lazy.

`security_role` uses `classic|ntz|non_secure|secure_only|secure_companion|tfm`.
M23 NTZ has PSPLIM slot true, register false. Baseline cores use BASEPRI zero;
companion BASEPRI zero is not-applicable because it owns no scheduler threshold.
Mainline runtime thresholds follow the referenced fixture, including the
8-bit-width default of 2 versus the classic runtime model's explicit 128.
Errata values identify a selected workaround policy, not measured silicon
effectiveness. Fixed-R9 rows carry `-ffixed-r9`; ordinary AAPCS does not promise
inheritance of an outer application static-base seed.

## Finite Scope

Rows come from the main compile configs, parity manifests and referenced
admitted native, constructor-R9, MPU region/ABI and classic Context/Fiber vectors.
Each `claim_refs` record has `path`, `selector`, `proof_scope`: a text source
selector and the limited claim being inventoried, not a fresh execution result.
Repeated selection modes, consumers, optimizations, LTO/direct/archive forms
and mutation cases do not automatically create new processor tuples.
No Cartesian product of all possible defines is implied.

`policy` records explicitly selected semantic variants where inventoried;
an empty object retains source defaults from the referenced fixture/settings.
Declared hash/map/rewind policy values must be string `0` or `1` and match
their runtime defines. `provider=typed-fixture` describes fixture integration,
not an additional compiler define or an external Secure TF-M qualification.
Independent compile-flag and upstream-source order is normalized after duplicate
and conflicting target flags are rejected. Flag-order aliases and policy-only
labels cannot create duplicate artifact cohorts; evidence references belong
to the same exact artifact tuple instead.
The remaining positive identity/policy, measured-model, Secure pairing and
compiler-flag spelling reconciliation is explicitly pending. Do not interpret
the 141 rows as an exhaustive list or shrink the freeze requirement to this file.
Do not derive a new claim from an unexecuted candidate or a negative test.

`compile_flags` contains only target/R9 options, with no optimization or LTO.
Defines in both maps are JSON strings. Upstream paths are relative to the pinned
FreeRTOS root; other paths are relative to Fiber. Upstream lists map the CPU
mechanisms and TF-M adapter/companion source boundaries, not an entire kernel.
Header dependencies, fixture providers and link recipes remain source/receipt
closure obligations; this file is not a complete executable build recipe.

Object mode keys are O0/Og/O2/Os/O3. Final mode keys additionally include O2-lto
and Os-lto. These are required coverage keys, not recorded successful tests.
Each artifact requires five object cells and seven final modes in both direct
and archive forms: 145 * (5 + 7 * 2) = 2755 required cells.
Final LTO means the final executable image, never only a relocatable native
group. A future driver must bind exact inputs and complete expected/observed
inventories before any separate qualification decision.

Planned runtime proof includes the forward-eight ABI, reverse-v1 ownership,
current-slot isolation, strong handlers, exact context-cohort identity,
generated-assembly reference parity, final vectors and negative-link controls.
Common proof also requires CPU-neutral engine and source-provider identity.
Secure companions retain their distinct gateway ABI and paired-image contract;
they do not acquire the runtime forward-eight or reverse-v1 ABI by pairing.
These are planned requirements, not completed proof.

The stopped Secure-reference/closed-parity WIP runners and fixture trees are
not consumed by this planner. Production files and the existing CPU test
runners are unchanged by this inventory slice.

## Inventory CLI

The parent-owned standard-library validator requires an explicit local reference
root and a fresh external output directory:

```text
python tools/freeze_cohorts.py --repo ROOT --manifest ROOT/tools/freeze_cohorts.json --freertos PINNEDROOT --output-dir FRESHEXTERNAL
```

ROOT is the Fiber repository root. PINNEDROOT is the local pinned FreeRTOS
checkout, currently experiments/_reference/FreeRTOS-Kernel. FRESHEXTERNAL must
be a fresh output path outside the repository; do not reuse old receipts.

The CLI checks the reference HEAD pin and clean tracked/untracked/ignored state,
verifies every upstream source path against its pinned Git blob, and captures
source hashes. Byte comparison permits only exact equality or a whole-file
LF-to-CRLF expansion of a blob containing no CR bytes. Both raw worktree and
raw Git-blob SHA-256 hashes are retained with the comparison classification.
No semantic normalization, mixed line-ending conversion, whitespace cleanup or
other transform is accepted. A missing upstream file cannot satisfy this check.
The CLI does not invoke a compiler, native ARM image or QEMU.

Runtime source capture uses the complete canonical `tools/runtime_sources.py`
reader, validating the full manifest and selecting all six roles: `engine`,
`state`, `panic`, `optional_configuration`, `legacy_compat`, `facade_bridge`.
The canonical inputs include the manifest, both reader implementations and
selected sources; this is not an ad hoc subset of common runtime files.

`validate_coverage_keys()` recomputes the exact plan from the manifest and
rejects a supplied plan that differs. It accounts for every required cell,
cohort/source-group identity and source-inventory fingerprint, rejecting
missing, duplicate, foreign or cross-snapshot cells. Matching keys, declared
PASS statuses and proof-manifest hash strings do not validate CPU proof bytes.
The result remains `KEY_ACCOUNTING_NOT_CPU_PROOF`, with global qualification
false even when accounting is complete.

These are declared-fact, registry and source-identity checks, not compiler
dependency closure or processor execution. Global proof remains false even
when inventory validation succeeds.

The parent has locally exercised the CLI. The first exercise (e1) returned
FAIL on raw CRLF worktree versus LF blob bytes. After the bounded comparison
above was added, a fresh second exercise (e2) returned INVENTORY-PLAN-PASS only:
141 cohorts, 27 groups, 77 C files, four pairs, 145 artifacts and 2755 planned
cells. This is not object/final parity, processor execution, hosted CI or a
global freeze PASS. The final e5 snapshot and separate 128-control host run are
recorded in `PORT_ARCHITECTURE_AUDIT.md#exact-cohort-inventory-and-coverage-plan`;
neither promotes inventory keys to CPU proof. This documentation does not rerun
the CLI or qualify later source snapshots.

## Native Compile Preflight

`tools/freeze_compile.py` is a separate native-object preflight adapter.
It consumes an explicit successful inventory receipt and rejects source/receipt
drift before using ARM tools. Select cohort IDs explicitly or use
`--all-cohorts`; the default native mode list is O0/Og/O2/Os/O3. Target flags and
defines come from each artifact, not registry defaults. Generated `main.h`
describes exact fixture facts, including M0 versus M0+, FPU presence versus use,
NVIC width and the protected MPU image; it is not an STM32 board header.

```text
python tools/freeze_compile.py --repo ROOT --inventory INVENTORY_RECEIPT --freertos PINNEDROOT --arm-gcc GCC --cmsis-core CMSIS --output-dir FRESHEXTERNAL --all-cohorts
```

`--cohort ID` is repeatable instead of `--all-cohorts`, and `--mode O2` can
request an explicitly partial native preflight. Compiler input dependencies,
resolved compiler workers, native objects, relocatable groups, disassembly,
attributes and commands are retained. The native lowering uses the maintained
`sensitive_port_closure` compiler/dependency/ELF helpers, not its default tuples
or hardware fixture. A relocatable group is not a final executable.

Successful compilation is only `COMPILE-PREFLIGHT-PASS`. Every row still has
`RequiredCellSatisfied=false`: this adapter does not compare FreeRTOS assembly,
prove the forward/reverse ABI, link final direct/archive/LTO images or run a CPU.
It cannot emit observed PASS cells for the inventory coverage accountant.
Global parity, hosted CI, profile activation and hardware remain separate gates.

The current full declared-inventory run at `C:/fzcn-20261104-e2` passes 725
native cells, with 2,085 source objects, 725 relocatable groups, 6,355 commands
and zero closing drift. Forty receipt and 53 recipe pure controls pass
separately. Exact hashes, independent review and the still-open reference
recipe prerequisites are recorded in
`PORT_ARCHITECTURE_AUDIT.md#exact-cohort-native-compile-preflight`. This is
captured-source evidence, not exact-commit hosted CI or an exhaustive freeze.
