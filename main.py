import angr, claripy
from static_oob_detector import *

if __name__ == '__main__':
 #   target = 'test/simple5_x64'
    #target = 'test/simple3'
    target = 'test/result/starcraft_example'

    test3 = 0x0804921A
    test4 = 0x0804927E

    test3_x64 = 0x0004011A1
    test4_x64 = 0x0004011F8
    test5_x64 = 0x0004012CA
    test6_x64 = 0x00401344

    target_addr = 0x0401106


    p = StaticOOBDetector(target=target, func_addr=target_addr)
    p.print_tt()
    p.find_state()
    