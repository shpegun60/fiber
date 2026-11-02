.syntax unified
.thumb

.section .vectors,"a",%progbits
.balign 128
.word __msp_top
.word Reset_Handler
.rept 14
.word Pool_Qemu_Fault_Handler
.endr

.section .text.Reset_Handler,"ax",%progbits
.global Reset_Handler
.type Reset_Handler,%function
.thumb_func
Reset_Handler:
    ldr r0, =__bss_start
    ldr r1, =__bss_end
    movs r2, #0
1:  cmp r0, r1
    bhs 2f
    str r2, [r0], #4
    b 1b
2:  ldr r0, =__pool_start
    ldr r1, =__pool_end
    movs r2, #0xa5
3:  cmp r0, r1
    bhs 4f
    strb r2, [r0], #1
    b 3b
4:  ldr r0, =0xe000ed08
    movs r1, #0
    str r1, [r0]
    ldr r0, =0xe000ed28
    mvns r1, r1
    str r1, [r0]
    ldr r0, =0xe000ed24
    ldr r1, [r0]
    orr r1, r1, #(1 << 18)
    str r1, [r0]
    dsb
    isb
    bl pool_qemu_main
5:  b 5b
.size Reset_Handler, .-Reset_Handler

.section .text.Pool_Qemu_Fault_Handler,"ax",%progbits
.global Pool_Qemu_Fault_Handler
.type Pool_Qemu_Fault_Handler,%function
.thumb_func
Pool_Qemu_Fault_Handler:
    tst lr, #4
    ite eq
    mrseq r0, msp
    mrsne r0, psp
    mov r1, lr
    b pool_qemu_fault
.size Pool_Qemu_Fault_Handler, .-Pool_Qemu_Fault_Handler
