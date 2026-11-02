#include "main.h"
#include "fiber_portmacro.h"

__attribute__((used, section(".portable_policy")))
const uint32_t fixture_portable_policy[] = {
    FIBER_PORT_SCHEDULER_BASEPRI,
    FIBER_REWIND_MSP,
    FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH,
    FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH,
    FIBER_STACK_CANARY,
    FIBER_ALLOW_PERMISSIVE_ADDRESS_MAP_HOOKS,
    FIBER_PORT_RUNTIME_SELECTABLE
};
