from ctypes import *


# Define ELF Header Constants
EI_NIDENT = 16

EI_CLASS = {0: "Invalid Class",
            1: "ELF32",
            2: "ELF64"}

EI_DATA = {0: "Invalid data encoding",
           1: "2's complement, little endian",
           2: "2's complement, big endian"}

EI_OSABI = {0: "Unix - System V",
            1: "HP-UX",
            2: "NetBSD",
            3: "Linux/ GNU ELF"}

E_TYPE = {0: "No file type",
          1: "REL - (Relocatable file)",
          2: "EXEC - (Executable File)",
          3: "DYN - (Shared Object File)",
          4: "CORE - (Core File)"}

E_MACHINE = {0: "No machine",
             3: "Intel 80386 (32-bit)",
             40: "ARM",
             62: "Advanced Micro Devices X86-64"}

# Define ELF Program Header Constants
P_TYPE = {0: "NULL",             #Program Header entry unused
          1: "LOAD",             # Loadable program segment
          2: "DYNAMIC",          #Dynamic Linking information
          3: "INTERP",           #Program Interpreter
          4: "NOTE",             #Auxiliary Information
          5: "SHLIB",            #Reserved
          6: "PHDR",             #Entry for header table itself
          7: "TLS",              #Thread-local storage segment
          8: "NUM",              #Number of defined types
          1685382480: "EH_FRAM", #GCC .eh_frame_hdr segment
          1685382481: "STACK"  , #Indicates stack executability
          1685382482: "RELRO"}   #Read-only after relocation

P_FLAGS = {0: " ",
           1: "X", #Executable
           2: "W", #Writeable
           4: "R"} #Readable



class Elf_Ehdr(Structure):
    '''Parent class for the Elf Header structures. Provides
       repr formatting as well as a parse method for human-readable
       printing.'''

    def parse(self):
        '''Parse Elf_Ehdr fields to allow human-readable sections.
           Example: OS: UNIX System V vice OS: 0'''

        self.elf_class = EI_CLASS[self.e_ident[4]]
        self.endian = EI_DATA[self.e_ident[5]]
        # catch exception where the 0 is truncated
        try:
            self.os = EI_OSABI[self.e_ident[7]]
        except:
            self.os = EI_OSABI[0]
        self.type = E_TYPE[self.e_type]
        self.machine = E_MACHINE[self.e_machine]


    def __repr__(self):
        '''Human-friendly display of the Elf_Ehdr structure.'''

        return  "Elf Header:\n" \
                "  {0:<30}: {1:<15}\n" \
                "  {2:<30}: {3:<15}\n" \
                "  {4:<30}: {5:<15}\n" \
                "  {6:<30}: {7:<15}\n" \
                "  {8:<30}: {9:<15}\n" \
                "  {10:<30}: {11:<15}\n" \
                "  {12:<30}: {13:<15}\n" \
                "  {14:<30}: {15:<15}\n" \
                .format("Class",self.elf_class,"Data",self.endian,
                        "OS",self.os,"Type",self.type,
                        "Machine",self.machine,"Entry",hex(self.e_entry),
                        "Program Header Entry Count",self.e_phnum,
                        "Program Header Entry Size",self.e_phentsize)


class Elf32_Ehdr(Elf_Ehdr):
    '''The 32-bit ELF header as defined by elf.h.
       Used to retreive the data from the ELF header
       in order to calculate the offsets of the various
       sections within an ELF binary.'''

    _fields_ = [("e_ident", c_char * EI_NIDENT),
                ("e_type", c_uint16),
                ("e_machine", c_uint16),
                ("e_version", c_uint32),
                ("e_entry", c_uint32),
                ("e_phoff", c_uint32),
                ("e_shoff", c_uint32),
                ("e_flags", c_uint32),
                ("e_ehsize", c_uint16),
                ("e_phentsize", c_uint16),
                ("e_phnum", c_uint16),
                ("e_shentsize", c_uint16),
                ("e_shnum", c_uint16),
                ("e_shstrndx", c_uint16)]


class Elf64_Ehdr(Elf_Ehdr):
    '''The 64-bit ELF header as defined by elf.h.
       Used to retreive the data from the elf header
       in order to calculate the offsets of the various
       sections within an ELF binary.'''

    _fields_ = [("e_ident", c_char * EI_NIDENT),
                ("e_type", c_uint16),
                ("e_machine", c_uint16),
                ("e_version", c_uint32),
                ("e_entry", c_uint64),
                ("e_phoff", c_uint64),
                ("e_shoff", c_uint64),
                ("e_flags", c_uint32),
                ("e_ehsize", c_uint16),
                ("e_phentsize", c_uint16),
                ("e_phnum", c_uint16),
                ("e_shentsize", c_uint16),
                ("e_shnum", c_uint16),
                ("e_shstrndx", c_uint16)]


class Elf_Phdr(Structure):
    '''Parent class for the ELF32/64
       Program Header Structs.'''

    def __repr__(self):
        '''Human-friendly display of the Elf_Phdr structure.'''

        self.flags = []
        for bit in [1,2,4]:
            self.flags.append(P_FLAGS[(self.p_flags & bit)])

        return  "Program Header:\n" \
                "     {0:<30}: {1:<15}\n" \
                "     {2:<30}: {3:<15}\n" \
                "     {4:<30}: {5:<15}\n" \
                "     {6:<30}: {7:<15}\n" \
                "     {8:<30}: {9:<15}\n" \
                "     {10:<30}: {11:<15}\n" \
                "     {12:<30}: {13:<15}\n" \
                .format("Section Type",P_TYPE[self.p_type],"Flags","".join(self.flags),
                        "Segment Offset",hex(self.p_offset),"Size in Memory",hex(self.p_memsz),
                        "File Size",hex(self.p_filesz),"Virtual Address",hex(self.p_vaddr),
                        "Physical Address",hex(self.p_paddr))


class Elf32_Phdr(Elf_Phdr):
    '''The 32-bit Program Header structure as defined
       by elf.h. Used to retreive data from the 
       program header structure within the ELF binary.'''

    _fields_ = [("p_type", c_uint32),
                ("p_offset", c_uint32),
                ("p_vaddr", c_uint32),
                ("p_paddr", c_uint32),
                ("p_filesz", c_uint32),
                ("p_memsz", c_uint32),
                ("p_flags", c_uint32),
                ("p_align", c_uint32)]

class Elf64_Phdr(Elf_Phdr):
    '''The 64-bit Program Header structure as defined
       by elf.h. Used to retreive data from the 
       program header structure within the ELF binary.'''

    _fields_ = [("p_type", c_uint32),
                ("p_flags", c_uint32),
                ("p_offset", c_uint64),
                ("p_vaddr", c_uint64),
                ("p_paddr", c_uint64),
                ("p_filesz", c_uint64),
                ("p_memsz", c_uint64),
                ("p_align", c_uint64)]
