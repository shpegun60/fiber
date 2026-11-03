# CM4 Raw Compiler Gate

This scoped gate uses the maintained source-derived sensitive-closure ELF and
relocation classifier without changing its exclusions. It covers O0, Og, O2,
Os and O3; ordinary and actual slim-IR native LTO; function-sectioned and
unsectioned output; baseline and all six simultaneous raw compiler-hook
families. Four explicit profiles cover soft/no silicon FPU, soft on FPU
silicon, hard/eager and softfp/lazy. No compiler counterflags mask hooks.
The default run first verifies and copies the selected source, shared fixture
and CMSIS inputs. Only that immutable copy is consumed. Original-tree changes
are separately reported, not silently treated as qualification of new bytes.

The exact pre-repair CM4 source is read from immutable Git revision
bc520c5a722ca70a461561cf30a59eb4ad8a4b3d, copied outside the repository, then
compiled against the captured current shared contracts. Its normal raw helper
escapes and unsectioned O2 native-LTO literal failures must both reproduce.
Historical compilation is not a claim about the full historical repository.
The nested historical-port tree includes current canonical Context headers and
common providers, plus the explicit runtime-source manifest and both readers.
The copied reader validates the complete provider inventory and must return the
same requested role paths as the current snapshot. `prior-current-contracts.json`
records these current inputs separately from the Git-pinned port files in
`prior-source.json`; neither source existence nor a legacy-owner fallback selects
the common implementation. The raw-hook and literal-range failure oracles are
unchanged.

Actual preprocessed repaired source supplies pool-removal controls. Natural
removal is recorded, not required to fail. Matched controls append 8192
unreachable bytes after each terminal pool: retaining pools must lower; removing
only the pools must fail with exact saved-assembly literal-load range errors.

O2/Os hard and softfp compile the pinned clean FreeRTOS ARM_CM4F port. Ordered
first-start, first-restore, GPR and conditional high-FP transfer patterns retain
the existing parity mechanisms; no identical-assembly claim is made. The three
naked inline-assembly bodies must match the historical compiled assembly after
removing only the new terminal pool directives. Constructor R9 reuses the real
constructor and bounded restore-slice executor for all three float ABIs, ordinary
and fixed-R9 compilation, all eight maintained modes and its compiled mutants.
Its default legacy and genuine Fiber constructor cohorts are both mandatory:
96 production ELFs, 36 compiled negative ELFs and 528 construction calls, with
actual closed-configuration-service probes reported separately. The outer
immutable inventory explicitly includes the lifecycle consumer source, headers
and ledger; it never skips the Fiber cohort to preserve an obsolete count.

The R9 dependency versions are mandatory, never silently skipped. Its scoped
development-selection field is preserved in the nested receipt; the enclosing
gate qualifies only CM4, not the global constructor/profile inventory. No
hardware, actual exception/FP execution, arbitrary PIC/TLS ABI, external callback
closure, or all-profile raw-compiler support is claimed. The documented supported
counterflag build contract remains separate. Development options never produce
`CompleteSuite: true`. Commands, consumed input bytes/hashes, native outputs and
an artifact hash manifest are retained under the generated evidence directory.
