import angr, claripy
from variable_tracking import *

class StaticOOBDetector():
    def __init__(self, target: str, func_addr: int):
        self.proj = angr.Project(target, auto_load_libs=False)
        self.cfgs = self.proj.analyses.CFGFast()

        self.func = self.cfgs.kb.functions[func_addr]   # the address of target function
        self.vr =self.proj.analyses.VariableTracking(self.func, self.proj)
        self.variable_manager = self.vr.variable_manager[self.func.addr]
        
        self.variables = self.variable_manager.get_variables()
        self.stack_variables = self.vr.get_ch_stack_variables()
        self.pointer_variables = self.vr.get_ch_pointer_variables()
        print(self.pointer_variables)

# pointer_variables = {'expr', 'offset', 'index', 'size','variable_type', 'state_addr'}



    def find_state(self):
        init_state = self.proj.factory.call_state(addr=self.func.addr)
        # simgr = self.proj.factory.simgr(init_state)
        # simgr.explore()

        for target in self.pointer_variables:
            simgr = self.proj.factory.simgr(init_state)
            simgr.explore(find=target['state_addr'])
            # simgr.explore(find=0x000401362 )

            solution_state = simgr.found[0]
            print(self.stack_variables)
            print(self.pointer_variables)

            print('Found Array Access State!', hex(target['state_addr']))
            #print('recent_constraints ', solution_state.history.recent_constraints)
            #print('jump_guards ', solution_state.history.jump_guards.hardcopy)
            min = solution_state.solver.min(target['index'])
            max = solution_state.solver.max(target['index'])
            print('[index] ', 'min : ', min, 'max : ', max)
            if (min < 0 or max > target['size']) or (target['offset'] * -1) < max:
                print('Found Vulnerability!')
                self.found_vulner(target, min, max)

    def found_vulner(self, target, min, max):
        with open('test/result/result.txt', 'w') as f:
            result = 'State Addr : ' + hex(target['state_addr']) + '\n'
            result += 'Array : ' + '{\n'
            result += '\toffset : ' + hex(target['offset']) + '\n'
            result += '\tvariable_type : ' + target['variable_type'] + '\n'
            #result += '\tsize : ' + hex(target['size']) + '\n'
            #result += '}\n'
            result += 'Index : ' + '{\n'
            result += '\tmin : ' + hex(min) + '\n'
            result += '\tmax : ' + hex(max) + '\n'
            result += '}}\n'
            f.write(result)




    def print_tt(self):
        print('test')
        print(self.pointer_variables)
        #print(self.pointer_variables)