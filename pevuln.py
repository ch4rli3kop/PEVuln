#!/usr/bin/python3
from capstone import *
from pefile import *
import sys, struct



# CODE = b"\x48\x83\xEC\x38\x48\x8D\x0D\xC5\x11\x00\x00\xE8\x90\xFF\xFF\xFF\x33\xD2\xC7\x44\x24\x20\x03\x00\x00\x00\x48\x8D\x0D\xBF\x11\x00\x00\x44\x8D\x4A\x02\x44\x8D\x42\x01\xE8\x72\xFF\xFF\xFF\x33\xC0\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x66\x66\x0F\x1F\x84\x00\x00\x00\x00\x00\x48\x3B\x0D\x41\x1F\x00\x00\xF2\x75\x12\x48\xC1\xC1\x10\x66\xF7\xC1\xFF\xFF\xF2\x75\x02\xF2\xC3\x48\xC1\xC9\x10\xE9\xAB\x02\x00\x00\xCC\xCC\xCC\x40\x53\x48\x83\xEC\x20\xB9\x01\x00\x00\x00\xE8"

# md = Cs(CS_ARCH_X86, CS_MODE_64)
# md.detail = True

# for i in md.disasm(CODE, 0x140001070):
#     print("%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

# to do : x86 or x64
# to do : identify exe, dll
# to do : if include debug info, or not
# to do : select achitecture and mode
# to do : create function class, fields : start_addr, last_addr, size... cfg

END = ["ret", "retn", "retf", "iret", "int3"]

class PEVuln(object):

    def __init__(self, TARGET):
        self.pe = PE(TARGET)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.BaseOfCode
        self.entrypoint = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.get_code_section()
    

    def get_base(self):
        return self.base

    def get_entrypoint(self):
        return self.entrypoint

    def get_pe(self):
        return self.pe

    def has_entrypoint(self, section_va, section_size):
        if section_va < self.entrypoint < section_va + section_size:
            return True
        else :
            return False


    def get_code_section(self):
        '''
        In generally ".text" section has instruction, but there are cases where it isn't.
        Therefore, I checked section name is the same as '.text' and found the section in which
        the program entry point was.
        '''
        for section in self.pe.sections:
            sec_name = section.Name.decode().rstrip('\x00')
            if sec_name == '.text':
                self.code = section.get_data()
                return section
            elif self.has_entrypoint(section.VirtualAddress, section.SizeOfRawData):
                self.code = section.get_data()
                return section
                

    def search_func_len(self, addr):
        '''
        '''
        insn_len = 0
        while True:
            code = self.code[addr:addr+0x100]
            for insn in self.md.disasm(code, self.base + addr):
                insn_len += 1
                print("%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
                if insn.mnemonic in END:
                    return insn_len
            addr += 0x100

    def get_functions(self, method='simple'):
        self.function = []                       # save function start address
        self.function.append(self.entrypoint)    # find first path at entry point
        if method == 'simple':
            '''
            Just until meeting ret and int 3, slice function
            '''
            while len(self.function) > 0 :
                addr = self.function.pop(0)
                print(addr)
                func_len = self.search_func_len(addr)
                base = self.imagebase + self.entrypoint
                #for insn in self.md.disasm( addr, base, count=)

        elif method == 'recursive':
            '''
            '''
            print('recursive')

    def test(self):
        print(self.get_functions())



def main():
    if len(sys.argv) > 1:
        TARGET = sys.argv[1]
    else:
        TARGET = '.\\test\\Example.exe'

    proc = PEVuln(TARGET)
    proc.test()


if __name__ == '__main__':
    main()