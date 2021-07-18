import angr, pyvex, archinfo
import claripy
from angrutils import *
from capstone import *

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

#proj = angr.Project('D:\\Project\\PEVuln\\test\\true', auto_load_libs=False)
#proj = angr.Project('D:\\Project\\PEVuln\\test\\x86\\Example.exe', auto_load_libs=False)
#proj = angr.Project('D:\\Project\\PEVuln\\test\\cng.sys', auto_load_libs=False)
proj = angr.Project('./test/x86/static_exam (2)', auto_load_libs=False)

#main = proj.loader.main_object.get_symbol("main")
#print(dir(main))
#main = 0x401120
main = 0x080492FA 
start_state = proj.factory.blank_state(addr=main)
#cfgs = proj.analyses.CFGEmulated(fail_fast=True, starts=[main], initial_state=start_state)
cfgs = proj.analyses.CFGFast()
#plot_cfg(cfgs, 'true_cfg', asminst=True, remove_imports=True, remove_path_terminator=True)

print(list(cfgs.kb.functions))
input('<')
entry_func = cfgs.kb.functions[main]
print('\n=============')
print(entry_func.name  + ' : ' + hex(main))
print('basic block list : ' + str(list(entry_func.block_addrs)))
for insn in entry_func.blocks:
    print('-------------------')
    print('basic block #0x%x, 0x%x'% (insn.addr, insn.size))
    print('bytes : ' + str(insn._bytes))
    print('### Instructions ###')
    for i in md.disasm(insn._bytes, insn.addr):
        print("%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    print('### VEX IR ###')
    irsb = pyvex.lift(insn._bytes, insn.addr, archinfo.ArchX86())

    # pretty-print the basic block
    irsb.pp()

input('>')

for func in cfgs.kb.functions:
    #print(dir(func))
    #print(func.block_addrs)
    entry_func = cfgs.kb.functions[func]
    print('\n=============')
    print(entry_func.name  + ' : ' + hex(func))
    print('basic block list : ' + str(list(entry_func.block_addrs)))
    for insn in entry_func.blocks:
        print('-------------------')
        print('basic block #0x%x, 0x%x'% (insn.addr, insn.size))
        print('bytes : ' + str(insn._bytes))
        print('### Instructions ###')
        for i in md.disasm(insn._bytes, insn.addr):
            print("%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        print('### VEX IR ###')
        irsb = pyvex.lift(insn._bytes, insn.addr, archinfo.ArchX86())

        # pretty-print the basic block
        irsb.pp()
    #print(entry_func.block_addrs)
    # t = entry_func.transition_graph
    # print(t)


#idfer = proj.analyses.Identifier()
#for funcInfo in idfer.func_info:
#    print(hex(funcInfo.addr), funcInfo.name)

#block = proj.factory.block(0x4045c3)
#block.pp()