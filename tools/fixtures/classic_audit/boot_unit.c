/* Compile the real boot translation unit, exposing only a focused private
 * wrapper. No production guard or instruction is stubbed or rewritten. */
#include "fiber_port_boot.c"

#if !AUDIT_MPU
void audit_prepare_msp(void)
{ fiber_port_prepare_start_msp_plan(); }
void audit_boot_check(const FiberContext *ctx)
{ fiber_port_boot_check(&ctx->boot); }
#endif
