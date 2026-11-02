# CM33 Paired Raw Compiler Closure

This gate selects only ARM_CM33/non_secure and its ARM_CM33/secure companion.
The maintained sensitive-port ELF/relocation classifier runs baseline and all
six simultaneous raw hook families at O0/Og/O2/Os/O3, ordinary native objects
and real slim-IR native LTO, both with sectioned and unsectioned text output.
The 60-cell shared gate and 20 additional ordinary-unsectioned cells retain
data sections; no claim about disabling data sections is made. No
instrumentation-disabling counterflags or additional import allowances are used.
Compilation consumes an inventory-verified immutable source/CMSIS copy.

The pre-repair ARM_CM33 C/H files are obtained from the existing local Git
commit b181ee7 and archived, then compiled against the captured shared contracts.
The historical NS O0 raw always-inline failure and Secure unsectioned native-LTO
exact-key literal-pool overflow must reproduce. This is not qualification of
the complete historical repository. No network fetch or package installation
is performed, and absent historical objects fail rather than skip the proof.

Actual repaired source supplies four helper/caller-wrapper regression mutants.
Each must produce a classified instrumentation hook in the protected compiled
closure, not merely fail an arbitrary build. Matched Secure literal controls
insert unreachable layout pressure after the real exact-key read: MOVW/MOVT
must lower, while changing only its address materialization back to LDR =key
must fail with saved-assembly literal-range diagnostics at that exact key.
The synthetic padding is never a production modification or CPU execution proof.

Each of the eight queries must have its own real pool-helper call and exact-key
MOVW/MOVT relocations. The retained volatile byte read is unchanged. O2/Os
compile both historical and repaired naked transfer sources, requiring identical
complete function-section bytes and relocation tuples. Selected-port macro
definitions, except the repaired inline annotation bundle, must remain identical.

The shared classifier's active hooks, data callbacks, counter/init-array checks,
actual bundle-removal controls and Python guard controls remain in force.
Commands, diagnostics, consumed bytes, tool/source hashes, outputs and a complete
artifact manifest are retained. A passing receipt qualifies raw compiler closure
only. Actual pinned FreeRTOS O2/Os parity, paired lifecycle/CMSE execution,
external memcpy/memset and callback closure, board attribution and hardware
qualification are separate gates. No profile flag, context generation, frame,
callable ABI, GRO policy, CPU admission or instruction order is promoted here.
