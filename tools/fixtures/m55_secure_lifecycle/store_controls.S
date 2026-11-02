.syntax unified
.thumb
.section .text.lifecycle_unknown_stl,"ax",%progbits
.global lifecycle_unknown_stl
.type lifecycle_unknown_stl,%function
.thumb_func
lifecycle_unknown_stl:
    stl r0,[r1]
    bx lr
.size lifecycle_unknown_stl,.-lifecycle_unknown_stl
.section .text.lifecycle_unknown_stlex,"ax",%progbits
.global lifecycle_unknown_stlex
.type lifecycle_unknown_stlex,%function
.thumb_func
lifecycle_unknown_stlex:
    stlex r2,r0,[r1]
    bx lr
.size lifecycle_unknown_stlex,.-lifecycle_unknown_stlex
.section .text.lifecycle_unknown_stc,"ax",%progbits
.global lifecycle_unknown_stc
.type lifecycle_unknown_stc,%function
.thumb_func
lifecycle_unknown_stc:
    /* A coprocessor-store encoding used only as a disassembly/filter control.
     * It is never executed and makes no M55 coprocessor-support claim. */
    .inst.w 0xed810000
    bx lr
.size lifecycle_unknown_stc,.-lifecycle_unknown_stc
