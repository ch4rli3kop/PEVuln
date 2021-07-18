import angr, claripy


def debug_func(state):
    print('Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address)

def debug_write(state):
    print('EIP', state.regs.eip)
    print('Write', state.inspect.mem_write_expr, 'to', state.inspect.mem_write_address)

def debug_regs(state):
    print('EIP', state.regs.eip, 
state.inspect.reg_write_offset, state.inspect.reg_write_length,
state.inspect.reg_write_expr, state.inspect.reg_write_condition)
    print(state.regs.ebp)

def debug_symbolic(state):
    print('@@@@@@@ symbolic @@@@@@@@')
    print('EIP', state.regs.eip)

#proj = angr.Project('test/simple1', auto_load_libs=False)
proj = angr.Project('static_exam2', auto_load_libs=False)


func = 0x08049196
#test2 = 0x080491E7
test2 = 0x08049176

# full_init_state 하면 entry point (_start)부터 시작함
state = proj.factory.call_state(addr=test2)
state.options.add(angr.options.CONSTRAINT_TRACKING_IN_SOLVER)
state.options.add(angr.options.REVERSE_MEMORY_NAME_MAP)

print('ebp', state.regs.ebp)
print('eip', state.regs.eip)
print('esp', state.regs.esp)
ebp = state.regs.esp - 0x4
state.inspect.b('symbolic_variable', when=angr.BP_AFTER, action=debug_symbolic)

print(dir(state.regs))
simgr = proj.factory.simgr(state)
succ = simgr.step()
print(succ)
state2 = succ.active[0]
#successors[0]
print('ebp', state2.regs.ebp)
print('eip', state2.regs.eip)
print(state2)

print('############### 1 ##############')
succ = simgr.step()
print(succ)
state2 = succ.active[0]
#successors[0]
print('ebp', state2.regs.ebp)
print(type(state2.mem[state2.regs.ebp]))
print('ebp-4',state2.mem[ebp-4].uint32_t.resolved)
print('ebp-8',state2.mem[ebp-8].uint32_t.resolved)

print(state2.mem[state2.regs.ebp].uint32_t.resolved)
print(state2.mem[state2.regs.ebp + 0x4].uint32_t.resolved)
print('eip', state2.regs.eip)
print(state2)

print(state2.solver.all_variables)
print(state2.solver.temporal_tracked_variables)
print(state2.solver.eternal_tracked_variables)

print('############### 2 ##############')
succ = simgr.step()
print(succ)
state2 = succ.active[0]
#successors[0]
print('ebp', state2.regs.ebp)
print('state2.mem[ebp-4]',type(state2.mem[ebp-4]))
print('ebp-4',state2.mem[ebp-4].uint32_t.resolved)
print('ebp-8',state2.mem[ebp-8].uint32_t.resolved)

print(state2.mem[state2.regs.ebp].uint32_t.resolved)
print(state2.mem[state2.regs.ebp + 0x4].uint32_t.resolved)
print('eip', state2.regs.eip)
print(state2)

print(state2.solver.all_variables)
print(state2.solver.temporal_tracked_variables)
print(state2.solver.eternal_tracked_variables)
# TODO: 함수 종료 전까지 실행

#state.inspect.b('mem_read', when=angr.BP_AFTER, action=debug_func)
#state.inspect.b('mem_write', when=angr.BP_AFTER, action=debug_write)
#state.inspect.b('reg_write', when=angr.BP_AFTER, action=debug_regs)
#simgr.explore(find=0x8049219)
#print(state)

size = 0x14
