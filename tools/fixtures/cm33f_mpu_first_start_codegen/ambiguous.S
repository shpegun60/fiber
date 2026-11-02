.syntax unified
.thumb
.section .fiber_port_privileged_functions,"ax",%progbits
.local SVC_Handler
.type SVC_Handler,%function
.thumb_func
SVC_Handler:
    udf #9
.size SVC_Handler, .-SVC_Handler
