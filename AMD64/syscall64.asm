
.CODE

_syscall64 PROC

;swapgs
;mov     gs:[0], rsp
;mov     rsp, gs:[0]
;push    0
;push    qword ptr gs:[0]
;push    r11
;push    0
;push    rcx
;mov     rcx, r10
;sub     rsp, 8
;push    rbp
;sub     rsp, 158h
;lea     rbp, [rsp+8+78h]
;mov     [rbp+0C0h], rbx
;mov     [rbp+0C8h], rdi
;mov     [rbp+0D0h], rsi
jmp Opcodes

db 0ffbh dup(90h)

_syscall64 ENDP

;align 10h
Opcodes:
_Trampolines PROC
nop
OpcodeJmp db 9fh dup(00h)
SsdtOpcodeJmp db 1200h dup(00h)
ShadowSsdtOpcodeJmp db 1E00h dup(00h)
_Trampolines ENDP

END