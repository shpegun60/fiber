.syntax unified
.thumb
.macro seed reg,value
    ldr \reg,=\value
    orr \reg,\reg,r12
.endm
.section .text.running_window,"ax",%progbits
#ifdef RUNNING_SECURE
#define WINDOW running_secure_window
#define CHECKPOINT running_secure_window_checkpoint
#define RESUMED running_secure_window_resumed
#else
#define WINDOW running_ns_window
#define CHECKPOINT running_ns_window_checkpoint
#define RESUMED running_ns_window_resumed
#endif
.global WINDOW
.type WINDOW,%function
.thumb_func
WINDOW:
    push {r4-r11,lr}
    sub sp,sp,#4
    lsl r12,r0,#16
    seed r1,0x11000001
    seed r2,0x22000002
    seed r3,0x33000003
    seed r4,0x44000004
    seed r5,0x55000005
    seed r6,0x66000006
    seed r7,0x77000007
    seed r8,0x88000008
    seed r9,0x99000009
    seed r10,0xaa00000a
    seed r11,0xbb00000b
    mov r0,r12
    ldr lr,=0xee00000e
    orr lr,lr,r0
    ldr r12,=0xcc00000c
    orr r12,r12,r0
#ifdef RUNNING_SECURE
    ldr r0,=0xe002ed04
#else
    ldr r0,=0xe000ed04
#endif
    mov r1,#0x10000000
.global CHECKPOINT
CHECKPOINT:
    nop
    str r1,[r0]
    dsb
    isb
.global RESUMED
RESUMED:
    nop
    add sp,sp,#4
    pop {r4-r11,pc}
.size WINDOW,.-WINDOW
