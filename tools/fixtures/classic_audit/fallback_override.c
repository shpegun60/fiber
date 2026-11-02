#include "fiber_port_boot.h"

const unsigned audit_override_anchor = 0;

/* Deliberately ordinary application definition after the public declaration. */
uintptr_t fiber_fallback_initial_msp(void)
{ return 0x2003F000u; }
