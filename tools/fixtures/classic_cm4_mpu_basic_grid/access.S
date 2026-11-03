.syntax unified
.cpu cortex-m4
.thumb
.section .fixture_user_functions,"ax",%progbits
.global fixture_slot_write
.type fixture_slot_write,%function
.thumb_func
fixture_slot_write:
    movw r0,#0
    movt r0,#0x2000
    movs r1,#0
.global fixture_slot_write_access
fixture_slot_write_access:
    str r1,[r0]
    bx lr
.size fixture_slot_write,.-fixture_slot_write
.global fixture_peer_read
.type fixture_peer_read,%function
.thumb_func
fixture_peer_read:
    movw r0,#0x4080
    movt r0,#0x2000
.global fixture_peer_read_access
fixture_peer_read_access:
    ldr r0,[r0]
    bx lr
.size fixture_peer_read,.-fixture_peer_read
.section .note.GNU-stack,"",%progbits
