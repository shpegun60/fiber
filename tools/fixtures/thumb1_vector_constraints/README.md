# Thumb-1 Vector Register Constraints

This focused gate compiles the actual CM0 and CM0 MPU dictionaries, including
CMSIS, with and without VTOR at O0/Og/O2/Os/O3, ordinary/reserved-r9 and normal/
native-LTO builds. It executes each vector-load probe in Unicorn with zero and
nonzero vector sources, checking the loaded word, SP and all callee registers.

The C caller deliberately places the result in r8 and the dynamic base in r10.
The helper must use a low-register LDR and move to/from those legal caller
allocations. Four controls restore only the old general-register constraints in
real preprocessed code and must fail on the exact low-register diagnostic.

This is not whole-port exception emulation, raw-flag attribute closure,
FreeRTOS execution or a hardware receipt. The pinned-reference transfer parity
gate remains separate. Dependencies: Python 3, Unicorn and pyelftools.
Use the pinned versions in `../classic_audit/requirements.txt`.

The low-register constraint is `l` in the GCC ARM target dictionary:
[GCC machine constraints](https://gcc.gnu.org/onlinedocs/gcc/Machine-Constraints.html).
The correction is a Fiber vector-validation helper fix, not a change to the
pinned FreeRTOS SVC/PendSV save/restore sequence. The reference CM0 first-start
source does not rewind MSP because CM0+ VTOR is optional; Fiber's validated
rewind/remap policy is separately documented selected-port behavior.
