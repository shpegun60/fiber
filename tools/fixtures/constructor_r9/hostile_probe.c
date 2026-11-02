#include <stdint.h>

/* Deliberately NOT sensitive: prove hostile instrumentation is effective in
 * the same compiler/link invocation without instrumenting boundary stubs. */
__attribute__((noinline, used, externally_visible))
uint32_t r9_hostile_probe(uint32_t value) { return value + 1u; }
