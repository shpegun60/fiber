#include <stdint.h>
#ifndef FIXTURE_ENTRY
#define FIXTURE_ENTRY
#endif
FIXTURE_ENTRY uint32_t guard_fixture_preinit(void);
FIXTURE_ENTRY uint32_t guard_fixture_bfhfnmins_prepare(void);
FIXTURE_ENTRY uint32_t guard_fixture_bfhfnmins_check(void);
FIXTURE_ENTRY uint32_t guard_fixture_bfhfnmins_restore(void);
FIXTURE_ENTRY uint32_t guard_fixture_ready(void);
FIXTURE_ENTRY uint32_t guard_fixture_loaded(uint32_t handle);
FIXTURE_ENTRY uint32_t guard_fixture_pool(void);
#define GUARD_OWNER 0x12340000u
