# C33S Private Companion Cohort

`tools/test_cm33_secure_cohort.ps1` separately compiles actual CM33 Secure
identity, context-gateway and pool sources. The ordinary C/C++ caller roots no
private helper or data key. The eight queries, twelve NSC imports, C33S key and
record/seal facts belong to this companion, not to C55S.

The A/B collision is count 3 / capacity 256 versus count 2 / capacity 400. Both
pool sections occupy 872 bytes including the initialized marker and alignment;
numeric section checks alone therefore do not establish object agreement.
Count-only, capacity-only, each stale object direction, expression normalization,
missing-data, duplicate-key and pre-guard generation controls remain separate.

The 496-check inventory includes 32 compiled query RETAIN-removal mutants at
O2/Os with and without LTO. A fixture-only NSC projection and discarded sibling
sections isolate one query. Native selected-body bytes/relocations must match
unaltered production; only siblings lose their implicit NSC-root role. Foreign
pools must fail on the selected query's exact key. Removing that query's sole
RETAIN must yield a successful single-query link without a live key, rejected
by the same strict matching admission. A linker DEFINED assertion alone is not
sufficient because discarded siblings can cause earlier archive extraction.

The generation fragment rejects wholly pre-guard providers, not coherent
alternate capacities. There is no external exact-capacity expectation here.
Post-include synthetic fact substitutions test key encoding only, not valid
CPU manifests. No image executes; board NSC placement and runtime/hardware
qualification remain separate. The compiler-ISA ceiling has its own gate.
