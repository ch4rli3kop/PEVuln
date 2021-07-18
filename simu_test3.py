'''
1. Parsing CFG and Get all of constraint about if-else
'''

import angr, claripy

proj = angr.Project('./static_exam (2)', auto_load_libs=False)

main = 0x080491D6
find = 0x08049285

cfgs = proj.analyses.CFGFast()
entry_func = cfgs.kb.functions[main]

state = proj.factory.call_state(addr=main)
simgr = proj.factory.simgr(state)

block_addrs = []

#print(dir(entry_func))
#print(dir(entry_func.nodes))
for node in entry_func.nodes:
    block_addrs.append(node.addr)
    print(hex(node.addr))
    #print(dir(node))


def get_constraints(_state):
    state = _state
    result = []
    print(hex(state.addr))
    if state.addr not in block_addrs:
        print('return')
        return 

    succ = ''
    while True:
        succ = state.step()
        if len(succ.successors) == 2:
            break
        if len(succ.successors) == 0:
            result.append(state)
            return result
        state = succ.successors[0]
    print(state)
    for __state in succ.successors:
        a = get_constraints(__state)
        print(a)
        result.append(a)
    return result

print('###########\n', get_constraints(state))
print('succ ',simgr.successors)
print('bbl ',list(state.history.bbl_addrs))

while len(simgr.active) == 1:
    simgr.step()

print('dd ', list(state.history.jump_guards))


print('active ', simgr.active)
for state in simgr.active:
    #print('dd ', list(state.history.jump_guards))
    for guard in state.history.jump_guards:
        if str(guard) != "<Bool True>":
            print(str(guard))
    #print('bbl ',list(state.history.bbl_addrs))

    #print(state.history.recent_constraints)
    #state.inspect.b

    simgr1 = proj.factory.simgr(state)
    while len(simgr1.active) == 1:
        #print(simgr.active)
        simgr1.step()

    #print(simgr.active)
    for state2 in simgr1.active:
        #print('zz ',list(state2.history.jump_guards))
        #print(state2.history.recent_constraints)
        for _guard in state2.history.jump_guards:
            if str(_guard) != "<Bool True>":
                print(str(_guard))
        simgr3 = proj.factory.simgr(state2)
        while len(simgr3.active) == 1:
            #print(simgr.active)
            simgr3.step()

        #print(simgr.active)
        for state4 in simgr3.active:
            print('zz ',list(state4.history.jump_guards))
            print(state4.history.recent_constraints)
            for __guard in state4.history.jump_guards:
                if str(__guard) != "<Bool True>":
                    print(str(__guard))




# print(hex(main))
# print(entry_func.name  + ' : ', hex(main))
# state = proj.factory.call_state(addr=main)
# x = claripy.BVS("x", 32)
# y = claripy.BVS("y", 32)
# tmp = 0
# print('eip : ', state.regs.eip)
# while True:
#     tmp = state.step()
#     print('eip : ', state.regs.eip)
#     if len(tmp.successors) == 2:
#         break
#     state = tmp.successors[0]

# # argument
# # state.mem[state.regs.ebp + ]
state = proj.factory.call_state(addr=main)

# succ = state.step()
# print(succ.successors)
# state = succ.successors[0]
# state.mem[state.regs.ebp-0xc] = x
# state.mem[state.regs.ebp-0x10] = y

find = 0x0804928C
simgr = proj.factory.simgr(state)
# print('stash', simgr._stashes)

simgr.explore(find=find)
state = simgr.found[0]

print(state.history.recent_constraints)
# print(state.solver.all_variables)
# print(state.solver.eternal_tracked_variables)
# print(state.solver.temporal_tracked_variables)
# print('jump_guard ',state.history.jump_guard)
# print(state.history.jumpkind)
# print('depth ',state.history.depth)
# print(state.history.merge_conditions)
# print(state.posix.dumps(0))
# print(state.solver.eval(x))
# print(state.solver.eval(y))




# kb = angr.KnowledgeBase(proj)
# print(kb)
# vr = proj.analyses.VariableRecovery(entry_func, kb=kb)
# print(dir(vr))
# variable_manager = vr.variable_manager[entry_func.addr]
# print(dir(variable_manager))
# print(variable_manager.get_variables())
# print(variable_manager._variables)
# print(variable_manager._live_variables)
# print(variable_manager.get_variable_accesses)
# print(variable_manager.get_variable_type)
# print('## ', variable_manager._stack_region)


print(state.solver.all_variables)
print(state.solver.temporal_tracked_variables)
print(state.solver.eternal_tracked_variables)