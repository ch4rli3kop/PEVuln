import angr, claripy
from variable_tracking import *

stack_variables = []
target = []
ebp = 0
def debug_func(state):
    print('Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address)


def print_vexir(basic_blocks):
    for block in basic_blocks:
        tmp = proj.factory.block(addr=block)
        print(tmp.vex.pp())


def debug_write(state):
    #print('EIP', state.regs.eip)
    #print('Write', state.inspect.mem_write_expr, 'to', state.inspect.mem_write_address)
    dst = state.inspect.mem_write_address
    #print('op', dir(dst.op))
    idx = 0
    if dst.op == '__add__':
     
        d = str(dst).split(' ')
        #print(d)
        for a in d:
            if 'mem' in a:
                idx = a
            elif '0x' in a:
                dst = a
        dst = dst[:-1]
        print(idx, dst)
        if dst == ebp:
            return
        for svar in stack_variables:
            if dst == svar['value']:
                return
        target.append({'index':idx, 'base_addr':dst})
        stack_variables.append({'type':'int', 'value':idx, 'size':4})
        stack_variables.append({'type':'char*', 'value':dst, 'size':0})
    
    else:
        dst = str(dst).split(' ')[1][:-1]
        print(ebp)
        if dst == ebp:
            return
        for svar in stack_variables:
            if dst == svar['value']:
                return
        stack_variables.append({'type':'int', 'value':dst, 'size':4})
    
        
#    dst = int(dst, 16)



def debug_regs(state):
    print('EIP', state.regs.eip, state.inspect.reg_write_offset, state.inspect.reg_write_length,
state.inspect.reg_write_expr, state.inspect.reg_write_condition)
    print(state.regs.ebp)

def debug_symbolic(state):
    print('@@@@@@@ symbolic @@@@@@@@')
    print('EIP', state.regs.eip)

target = 'test/simple3_x64'

proj = angr.Project('test/simple3_x64', auto_load_libs=False)
cfgs = proj.analyses.CFGFast()
test2 = 0x080491E7
test3 = 0x804927E
#test3 = 0x0804921A

test3_x64 = 0x0004011A1
test4_x64 = 0x0004011F8

func = cfgs.kb.functions[test4_x64]
basic_blocks = func.block_addrs
print_vexir(basic_blocks)
# 경로가 나눠질 경우 path로 구해야 함
#print(basic_blocks)

func = cfgs.kb.functions[test3]   # the address of target function
vr = proj.analyses.VariableRecovery(func)
variable_manager = vr.variable_manager[func.addr]
variables = variable_manager.get_variables()
print(variables)

#vr.print_test()

#if __name__ == '__main__':


state = proj.factory.call_state(addr=func.addr)
state.options.add(angr.options.CONSTRAINT_TRACKING_IN_SOLVER)
state.options.add(angr.options.REVERSE_MEMORY_NAME_MAP)


#state.inspect.b('symbolic_variable', when=angr.BP_AFTER, action=debug_symbolic)
state.inspect.b('mem_write', when=angr.BP_AFTER, action=debug_write)


ebp = state.regs.esp # 고정
ebp = str(ebp).split(' ')[1][:-1]
simgr = proj.factory.simgr(state)
frame_size = 0x24

data = []

print('[*] ebp : ', ebp)

while len(simgr.active) == 1:
        #print(simgr.active)
        simgr.step()

state1 = simgr.active[0]
#print(simgr.active)

#print(state1.solver.all_variables)
simgr2 = proj.factory.simgr(state1)
while len(simgr2.active) == 1:
    #    print(simgr2.active)
        simgr2.step()


#print(state1.history.recent_constraints)

print('##################################')
simgr2.step()

#def sort_stack(stack_variables):

# value 기준으로 dictionary 정렬
stack_variables = sorted(stack_variables, key=lambda t: (t['value']))
for i, svar in enumerate(stack_variables):
    if svar['type'] is not 'char*':
        continue
    if len(stack_variables)-1 > i:
        size = int(stack_variables[i+1]['value'],16) - int(svar['value'],16)
    else:
        size = int(ebp,16) + frame_size - int(svar['value'],16)
    svar['size'] = size
#print(stack_variables)

for svar in stack_variables:
    if 'mem' in svar['value']:
        continue
    offset = int(svar['value'], 16) - int(ebp, 16)
    svar['offset'] = 'ebp' + hex(offset)

print('Finding stack variables ...')
print(stack_variables)
#print(target)

constraints = state1.history.recent_constraints
print(constraints)

for t in target:
    svar = [] 
    for _svar in stack_variables:
        if t['base_addr'] == _svar['value']:
            svar = _svar

    for con in constraints:
        #print(con, t['index'])
        if t['index'] in str(con):
            print('\nFinding stack array ...')
            size = 0
            print('Addr : ', svar['value'], ', Size : ', svar['size'], ', Index : ', t['index'], ', Index Constraints : ', str(con))

