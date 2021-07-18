'''
   proj= angr.Project(sys.argv[1], load_options={'auto_load_libs': True})
   anargument = claripy.BVS('arg1', 64)
   argv = [sys.argv[1], anargument]
   state = proj.factory.entry_state(args=argv ,add_options={angr.options.TRACK_CONSTRAINTS, angr.options.TRACK_CONSTRAINT_ACTIONS, angr.options.TRACK_OP_ACTIONS})
   sm = proj.factory.simgr(state)
   simsuccessor = sm.step() 

   while(True) :
       if (hasattr(sm, 'deadended') and len(sm.deadended) > 0):
           break
       else:
           simsuccessor = sm.step()
           if len(simsuccessor.active) > 0:
               currentactive = simsuccessor.active[0]
               print "symbolic op is ", anargument.op
               print "symbolic args is ", anargument.args
               print "currentactive allvar ", currentactive.solver.all_variables
               print "currentactive constraints ", currentactive.solver.constraints
               print "currentactive temporalTrackedVar ", currentactive.solver.temporal_tracked_variables
   if (hasattr(sm, 'deadended') and len(sm.deadended) > 0):
       for deadended in sm.deadended:
           print "deadeneded output is %s. " % (deadended.posix.dumps(1))     
           print "deadeneded input is %s. " % (deadended.posix.dumps(0))
           print "constraints on deadended %s." % deadended.solver.constraints
'''

import angr, claripy

def debug_func(state):
    print('debuggg', state.inspect.constraints)

#proj = angr.Project('./test/x86/Example.exe', auto_load_libs=False)
proj = angr.Project('./test/x86/static_exam (2)', auto_load_libs=False)

main = 0x080492FA 
test2 = 0x0804928C
#state = proj.factory.full_init_state(addr=main)
#state = proj.factory.entry_state(addr=main, add_options={angr.options.TRACK_CONSTRAINTS, angr.options.TRACK_CONSTRAINT_ACTIONS, angr.options.TRACK_OP_ACTIONS})
state = proj.factory.entry_state(addr=test2)
#print(state)

state.inspect.b('constraints', when=angr.BP_AFTER, action=debug_func)

while True:
    print('eip : ', state.regs.eip)
    succ = state.step()
    if len(succ.successors) == 2:
        break
    state = succ.successors[0]

state1, state2 = succ.successors
print(state1, state2)

print('state1', state1.solver.constraints)

# state = proj.factory.entry_state(addr=main)
# simgr = proj.factory.simulation_manager(state)
# print(simgr)
# simgr.use_technique(angr.exploration_techniques.DFS())
# #find_addr = 0x401090
# #find_addr = 0x8049355
# simgr.explore()
# print(simgr.found)

