# CM3 O2-LTO Direct Static Cell

This additive composer verifies exactly `CM3/O2-lto/direct` for cohort
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`. It does not widen
an ordinary-mode verifier, change a frozen predicate, or execute target code.

## Authority And Replay

The caller supplies one SHA256-bound catalog containing exactly nine complete
bundle descriptors: Inventory, Native, Reference, Join, Bindings, ABIControls,
Isolation, CommonAttributes and PortPolicy. The current E9 inventory remains
the authority for all 2774 required keys and all 26 backlog entries. Native and
reference are independent current-source CM3 O2 slim-LTO captures. All native
component bundles must bind the identical native capture, inventory and Seed.

The composer authenticates complete artifact trees, retained input hashes,
physical identities and pinned helper buffers before using a receipt. Prior
PASS fields are interface checks, not replacements for replay. It reconstructs
the four component command journals, dependency sets, source mutations, slim
IR inspections, actual worker option chains and intended negative diagnostics.
It recomputes ELF predicates using one immutable source/binary reader scope.
Captured parser sources are the only allowed ELF parser imports. No compiler,
linker, target program, mutation campaign or board operation runs in this test.

Two bounded host `objdump -drwC -z` inspections read the original native emitted
LTRANS object and final ELF. They do not rebuild either artifact. Their raw
stdout/stderr, argv and terminal dispositions are retained. Zero literal pools
must not disappear from the whole-executable byte census.

## Whole-Cell Obligations

The common prerequisites are CPU-neutral source/compile isolation, reverse-v1
ownership and exact source/provider identity. The runtime obligations are the
eight-function forward surface, reverse v1, current-slot isolation, strong
handlers, exact profile/context cohort, generated-assembly reference parity,
final ELF/vector bindings and intended negative link controls.

Replay covers normal native own-machine/final bindings and load-image twins;
all six native/reference canonical start/SVC/PendSV bodies with their declared
FreeRTOS differences; the five link controls and five typed/slot probes; the
CPU-free common replacement images and original/replacement slot protocols;
the common hostile-attribute effects and their controls; and the selected-port
supported-policy component. The normal native emitted machine and final ELF
also pass the supported-policy complete executable census independently of
the replacement-policy image. Replacement builds do not prove generated-body
identity with the original image.

## Credit And Failure

Only after every obligation and late input/output closing succeeds may the
composer account for its one fixed required key. Every other required key and
all backlog records remain present and pending/reference-only as applicable.
An admission error grants no credit. Any replay, closing or seal failure
revokes the report and coverage, including a late failure after PASS bytes
were provisionally written. A failed attempt is never repaired in place.

This is a bounded static software-cell result, not full semantic ABI, whole
provider/instruction/policy equivalence, arbitrary callback safety, archive
qualification, hardware validation, hosted CI qualification or global freeze.
The five-operation public API and eight-operation port boundary are unchanged.

## Invocation

Run `compose.py` in a fresh, unoptimized `python -I -S -B` process with
`--catalog`, `--catalog-sha256` and a fresh disjoint `--output-dir`.
`test_model.py`, `test_replay.py` and `test_compose.py` are focused synthetic
controls; their success is not a substitute for the actual artifact replay.
