.syntax unified
.thumb
/* Only the fixture's real SG veneer, copied numerically from this build's
 * actual CMSE import. No production gateway is synthesized. */
.global running_secure_work
.set running_secure_work,RUNNING_SG_ADDRESS
