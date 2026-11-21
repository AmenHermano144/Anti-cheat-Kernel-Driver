; stack-switching trampoline and small asm primitives.
; breaks stack walkers across the call boundary and gives us a place to run
; short cpu-only mixers off the caller's stack.
;
; windows x64 abi - args in rcx, rdx, r8, r9; return in rax.

EXTERN g_AcImports:BYTE

.CODE

; ULONG64 AcResolveImportA(ULONG idx)
;   type-a resolver tail, in asm so the xor-decode sequence lives in .text
;   instead of being inlined into every caller's own function body. matches
;   the vgc 1.19.2 type-a shape exactly:
;
;     mov  rax, qword ptr [table + idx*24 + 0]   ; encoded ptr
;     xor  rax, qword ptr [table + idx*24 + 8]   ; per-descriptor key
;     ret
;
;   rcx = idx
;   returns the decoded api pointer in rax.
;
;   row stride is 24 bytes (3 qwords). we reach it with
;   lea r11, [rcx + rcx*2]  ; r11 = idx * 3
;   so the final mov can address [r10 + r11*8], no imul needed, and the
;   generated code stays branch-free.
PUBLIC AcResolveImportA
AcResolveImportA PROC
    lea     r10, [g_AcImports]
    lea     r11, [rcx + rcx*2]
    mov     rax, qword ptr [r10 + r11*8 + 0]
    xor     rax, qword ptr [r10 + r11*8 + 8]
    ret
AcResolveImportA ENDP

; ULONG64 AcStackSwitchCall(PVOID target, PVOID newStackTop, PVOID a0, PVOID a1)
;   rcx = target        -> moved to r10 (volatile)
;   rdx = newStackTop   -> becomes new rsp
;   r8  = a0            -> forwarded as callee rcx
;   r9  = a1            -> forwarded as callee rdx
;
; caller stack is restored exactly on return. no non-volatile reg touched
; except rdi (saved/restored). no unwind data on purpose.
PUBLIC AcStackSwitchCall
AcStackSwitchCall PROC
    push    rdi
    mov     rdi, rsp
    mov     r10, rcx
    mov     rsp, rdx
    sub     rsp, 20h            ; shadow space for callee
    and     rsp, -16            ; 16-byte align
    mov     rcx, r8
    mov     rdx, r9
    call    r10
    mov     rsp, rdi
    pop     rdi
    ret
AcStackSwitchCall ENDP

; ULONG64 AcSplitMix64(ULONG64 x)
;   splitmix64 finalizer. runs no mem reads, no branches.
PUBLIC AcSplitMix64
AcSplitMix64 PROC
    mov     rax, rcx
    mov     r10, rax
    shr     r10, 30
    xor     rax, r10
    mov     r10, 0bf58476d1ce4e5b9h
    imul    rax, r10
    mov     r10, rax
    shr     r10, 27
    xor     rax, r10
    mov     r10, 094d049bb133111ebh
    imul    rax, r10
    mov     r10, rax
    shr     r10, 31
    xor     rax, r10
    ret
AcSplitMix64 ENDP

; ULONG64 AcRdtscSerialized(VOID)
;   serialized tsc read with lfence pre/post. no cpuid trap, no hv-visible exit.
PUBLIC AcRdtscSerialized
AcRdtscSerialized PROC
    lfence
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    lfence
    ret
AcRdtscSerialized ENDP

; ULONG64 AcRdtscpAux(ULONG *outAux)
;   rdtscp read, writes aux (processor id / tsc_aux) to *outAux if non-null.
PUBLIC AcRdtscpAux
AcRdtscpAux PROC
    mov     r10, rcx
    rdtscp
    test    r10, r10
    jz      no_aux
    mov     dword ptr [r10], ecx
no_aux:
    shl     rdx, 32
    or      rax, rdx
    ret
AcRdtscpAux ENDP

; VOID AcCpuidTimed(ULONG leaf, ULONG subleaf, ULONG regs[4], ULONG64 *deltaOut)
;   wraps cpuid in lfence-serialized rdtsc pair, writes (eax, ebx, ecx, edx) and
;   the elapsed tsc delta. useful to detect hv exit latency without adding more
;   conditional branches in c.
;   rcx = leaf, rdx = subleaf, r8 = regs ptr, r9 = deltaOut
PUBLIC AcCpuidTimed
AcCpuidTimed PROC
    push    rbx
    push    rsi
    push    rdi
    mov     rsi, r8
    mov     rdi, r9

    mov     r10d, ecx           ; leaf
    mov     r11d, edx           ; subleaf

    lfence
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r8, rax             ; t0

    mov     eax, r10d
    mov     ecx, r11d
    cpuid
    mov     [rsi + 0],  eax
    mov     [rsi + 4],  ebx
    mov     [rsi + 8],  ecx
    mov     [rsi + 12], edx

    lfence
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r8

    test    rdi, rdi
    jz      done
    mov     [rdi], rax
done:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
AcCpuidTimed ENDP

END
