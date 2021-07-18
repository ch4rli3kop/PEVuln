import angr
from capstone import *
import pyvex

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

main = 0x401120
test2 = 0x080491E7

#proj = angr.Project('D:\\Project\\PEVuln\\test\\x86\\Example.exe', auto_load_libs=False)
proj = angr.Project('D:\\Project\\PEVuln\\test\\simple1', auto_load_libs=False)

irsb = proj.factory.block(test2).vex

sm = proj.factory.simgr()
#print(irsb.pp())
print('dd')
#tmp = irsb.next()
##print(tmp)
#print(irsb.next.pp())
#print(irsb.jumpkind)
#print(irsb.tyenv.types)
#print(irsb.next.pp())

# for stmt in irsb.statements:
#     stmt.pp()
#     if isinstance(stmt, pyvex.IRStmt.Store):
#         print('Data : ')
#         stmt.data.pp()
#         print('Type : ')
#         print(stmt.data.result_type)
#         print('')
#     if isinstance(stmt, pyvex.IRStmt.Exit):
#         print('Condition : ')
#         stmt.guard.pp()
#         print('Target : ')
#         stmt.dst.pp()

cfgs = proj.analyses.CFGFast()
test2 = 0x080491E7

func = cfgs.kb.functions[test2]
basic_blocks = func.block_addrs

# 경로가 나눠질 경우 path로 구해야 함
#print(basic_blocks)

state = proj.factory.call_state(addr=test2)
ebp = state.regs.esp - 0x4 # 고정
simgr = proj.factory.simgr(state)
size = 0x10

data = []

print('############################')

for block in basic_blocks:
    tmp = proj.factory.block(addr=block)
    #print(tmp.disassembly)
    #print(tmp.pp())
    #print(tmp.vex.pp())
    #print(tmp.instruction_addrs)
    #print(tmp.instructions)
    #print(tmp.vex_nostmt)
    #print(tmp.serialize())
    for stat in tmp.vex.statements:
        if isinstance(stat, pyvex.stmt.WrTmp):
            print(stat.data)
            print(dir(stat.data))
            print(stat.data.constants)
            print(stat.data.op)

        if isinstance(stat, pyvex.stmt.Put):
            print('PUT')
            print(stat.data)
            print(stat.data.constants)
            print(dir(stat.data))

        print(type(stat))
        print(dir(stat))
        print('ZZ')
    

#    print(tmp.vex.statements)

 #   print('CCC')
 #   print(dir(proj.factory.block(addr=block)))

    