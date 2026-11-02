# CM33 TF-M A32 Closure Gate

Only ARM_CM33_TFM/non_secure is qualified. The standard run verifies/copies the
selected source, shared classifier/constructor fixtures, own fixtures and CMSIS
before executing the copy. Consumed-copy drift is fatal. Later original-tree
changes are separately reported and are not represented as tested new bytes.

The real pre-repair source at Git revision
62dca07736a0f50f5f399dff3314dbdfc6e57ce8 must reproduce normal raw instrumentation
escapes, with a clean matched baseline. It is compiled against the captured
shared contracts; this is not a full historical-repository qualification.

O0/Og/O2/Os/O3, normal/actual slim-IR native LTO, function-sectioned/unsectioned
text, baseline/all-six-family raw flags and three profiles produce 120 cells:
unchanged default hash/map/rewind 1/0/1, explicit 0/0/0, and explicit 1/1/1.
This includes the live-MSP helper branch. Data sections stay enabled. This is closure
coverage, not all-four-policy runtime qualification. Active, transitive,
initialized-callback, initializer and actual canonical-removal controls reuse
the maintained ELF/relocation classifier. Additional actual-header mutants
remove only INLINE_SENSITIVE at O2/Os; GRO and all non-inline annotations must
remain, the mutant must compile/lower, and instrumentation must escape.

Compiled old/current naked assembly bodies must match exactly for every tested
optimization and policy, including their already-present terminal pools. A32
does not modify the transfer bodies or perform another A33 repair. Literal
geometry is read from the actual compiled selected-header object and checked
against independent numeric ABI expectations.

The pinned clean FreeRTOS a50edad08b29052631aa469d4df6e6ec7ff68878
ARM_CM33_NTZ portasm and ThirdParty/GCC/ARM_TFM mutex wrapper are actually
compiled at O2/Os. CPU mechanism checks preserve the existing ordered parity
requirements; the wrapper symbol/queue dependencies are checked separately.
The local mutex.h is a labelled declaration-only TF-M v2.0 boundary, never a
fake TF-M interface implementation. Reference first restore discards eight GPR
words; Fiber deliberately restores them. The static cooperative mutex remains
different from FreeRTOS semaphore ownership/blocking.

The actual constructor and bounded first/running R9 restore slices reuse the
maintained executor: eight modes, ordinary and fixed-R9, compiled wrong-frame,
caller-scratch and wrong-restore/switch controls. Ordinary AAPCS borrowing is
not a static-base guarantee. Only fixed-R9 requires strict inherited seeds.
Dependencies are pinned and mandatory, never silently skipped. The nested
constructor receipt remains explicitly a CM33TFM subset.

No physical exception/PSPLIM/TF-M/PSA/hardware execution, whole-application LTO,
arbitrary PIC/TLS ABI, external callback/memory-helper closure, current global
aggregate or global raw-compiler support is claimed. The documented supported
counterflag contract remains separate. Development flags cannot produce a
complete standard qualification. Commands, captured inputs, outputs and a
complete artifact hash manifest remain in the generated evidence directory.
