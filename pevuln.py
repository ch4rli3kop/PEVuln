#!/usr/bin/python3
from capstone import *
from pefile import *
import sys, struct


# CODE = b"\x48\x83\xEC\x38\x48\x8D\x0D\xC5\x11\x00\x00\xE8\x90\xFF\xFF\xFF\x33\xD2\xC7\x44\x24\x20\x03\x00\x00\x00\x48\x8D\x0D\xBF\x11\x00\x00\x44\x8D\x4A\x02\x44\x8D\x42\x01\xE8\x72\xFF\xFF\xFF\x33\xC0\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x66\x66\x0F\x1F\x84\x00\x00\x00\x00\x00\x48\x3B\x0D\x41\x1F\x00\x00\xF2\x75\x12\x48\xC1\xC1\x10\x66\xF7\xC1\xFF\xFF\xF2\x75\x02\xF2\xC3\x48\xC1\xC9\x10\xE9\xAB\x02\x00\x00\xCC\xCC\xCC\x40\x53\x48\x83\xEC\x20\xB9\x01\x00\x00\x00\xE8"

# md = Cs(CS_ARCH_X86, CS_MODE_64)
# md.detail = True

# for i in md.disasm(CODE, 0x140001070):
#     print("%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

# to do : pefile check
# to do : x86 or x64
# to do : identify exe, dll
# to do : if include debug info, or not
# to do : select achitecture and mode
# to do : create function class, fields : start_addr, last_addr, size... cfg

BCC = ["je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg",
       "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz", "loop", "loopne",
       "loope"]
CALL = ["call", "lcall"]
JMP = ["jmp", "jmpf", "ljmp"]
END = ["ret", "retn", "retf", "iret", "int3"]

class Block(object):
    def __init__(self):
        self.insn = []

    def append(self, data):
        self.insn.append(data)

class Function(object):
    def __init__(self, start_addr='', offset=''):
        self.start_addr = start_addr  # RVA
        self.offset = offset          # offset
        self.blocks = []

    def set_start_offset(offset):
        self.offset = offset

    def insert_block(self, block):
        self.blocks.append(block)

# class PEDisassembler(object):
#     def __init__(self, TARGET, arch='x86'):
#         self.pe = PE(TARGET)
#         self.imagebase = self.pe.OPTIONAL_HEADER.ImageBase
#         self.base = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.BaseOfCode
#         self.entrypoint = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
#         if arch == 'x86':
#             self.md = Cs(CS_ARCH_X86, CS_MODE_32)
#         else :
#             self.md = Cs(CS_ARCH_X86, CS_MODE_64)
#         self.get_code_section()

class PEVuln(object):

    def __init__(self, TARGET, arch='x86'):
        self.pe = PE(TARGET)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.BaseOfCode
        self.imagebase = self.pe.OPTIONAL_HEADER.ImageBase
        self.entrypoint = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if arch == 'x86':
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        else :
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.READ_SIZE = 16
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
                self.code_section = section
                break
            elif self.has_entrypoint(section.VirtualAddress, section.SizeOfRawData):
                self.code_section = section
                break

        self.code = self.code_section.get_data()

    def parsing_functions(self, method='recursive'):
        '''
        return Function object
        '''
        entrypoint = self.entrypoint
        offset = self.pe.get_offset_from_rva(entrypoint)

        # entry point start 함수 생성
        _functions = [Function(entrypoint, offset)]
        result = []

        # 코드 섹션
        code_section_start_offset = self.code_section.PointerToRawData
        function_end = False

        #Recursive Descent Algorithm
        while True:
            # function loop
            if not _functions:
                # finish recursive function searching
                break

            function = _functions.pop(0)

            # if function_end:
            #     break

            eip = function.offset - code_section_start_offset
            
            # generate block
            block = Block()
            block_end = False

            _blocks = [block]

            while True:
                # block loop
                if block_end or function_end:
                    break

                insn = ''
                buffer = self.code[eip:eip + self.READ_SIZE]
                # load instruction 1 line 
                for instruction in self.md.disasm(buffer, self.imagebase + self.pe.get_rva_from_offset(eip), count=1):
                    insn = instruction

                print("%x:\t%s\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str, insn.size))
                
                block.append(insn)
                
                instr = insn.mnemonic
                op_size = insn.size

                if instr in END:
                    # block end
                    function.insert_block(block)
                    result.append(function)
                    block = Block()
                    block_end = True
                    break

                elif instr in CALL + JMP:
                    # block not end
                    print('zzz')
                    new_start_addr = int(insn.op_str, 16) - self.imagebase
                    new_offset = self.pe.get_offset_from_rva(new_start_addr)
                    _functions.append(Function(new_start_addr, new_offset))
                    function_end = True

                eip += op_size

        print(result)



            #    parse_function(function)
                #self.code[]

    # def parsing_function(self, function):
    #     '''
    #     @parameter : Function() object
    #     @return : parsed funtion
    #     '''


        #return func

    # def search_func_len(self, addr):
    #     '''
    #     '''
    #     insn_len = 0
    #     while True:
    #         code = self.code[addr:addr+0x100]
    #         for insn in self.md.disasm(code, self.base + addr):
    #             insn_len += 1
    #             print("%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
    #             if insn.mnemonic in END:
    #                 return insn_len
    #         addr += 0x100

    def get_functions(self, method='recursive'):
        self.functions = []                      # save function start address
        self.functions.append(self.entrypoint)    # find first path at entry point
        print(hex(self.entrypoint))
        if method == 'recursive':
            '''
            '''
            print('recursive')


    def test(self):
        self.parsing_functions()



def main():
    if len(sys.argv) > 1:
        TARGET = sys.argv[1]
    else:
        TARGET = '.\\test\\x86\\Example.exe'

    proc = PEVuln(TARGET, 'x86')
    proc.test()


if __name__ == '__main__':
    main()