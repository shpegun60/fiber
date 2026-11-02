.syntax unified
.thumb
.text

.macro provider name
.balign 4
.global cohort_provider_control_\name
.type cohort_provider_control_\name, %function
.thumb_func
cohort_provider_control_\name:
.endm
.macro end_provider name
.size cohort_provider_control_\name, .-cohort_provider_control_\name
.endm

/* Static parser controls only. None of these functions is executed. */
provider valid
    bx lr
    nop
end_provider valid

provider udf
    udf #255
    bx lr
end_provider udf

provider undefined
    .inst.w 0xffffffff
    bx lr
end_provider undefined

provider m55_undefined_stc
    .inst.w 0xed810000
    bx lr
end_provider m55_undefined_stc

provider data
    .word 0x11223344
    bx lr
end_provider data

provider zero_gap
    bx lr
    .space 32, 0
end_provider zero_gap

provider store
    str r0, [r1]
    bx lr
end_provider store
