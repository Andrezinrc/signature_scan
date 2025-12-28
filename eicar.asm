BITS 32
org 0x0
global _start

section .data
eicar db "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", 10
len   equ $ - eicar

section .text
_start:
    mov eax, 4
    mov ebx, 1
    mov ecx, eicar
    mov edx, len
    int 0x80

    mov eax, 1
    xor ebx, ebx
    int 0x80
