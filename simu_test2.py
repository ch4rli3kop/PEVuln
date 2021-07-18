import angr, claripy

proj = angr.Project('./test/x86/static_exam (3)', auto_load_libs=False)

test2 = 0x080492FA


cfgs = proj.analyses.CFGFast()
for func in cfgs.kb.functions:
    print('\n=============')
    entry_func = cfgs.kb.functions[func]
    print(entry_func.name  + ' : ', hex(func))
    state = proj.factory.blank_state(addr=func)
    simgr = proj.factory.simgr(state)
    
    while len(simgr.active) == 1:
        print(simgr.active)
        simgr.step()

    print(simgr.active)
    for state in simgr.active:
        print(state)
        print(state.history.recent_constraints)
        #state.inspect.b

        simgr1 = proj.factory.simgr(state)
        while len(simgr1.active) == 1:
            #print(simgr.active)
            simgr1.step()

        #print(simgr.active)
        for state2 in simgr1.active:
            print(state2)
            print(state2.history.recent_constraints)

    # while len(simgr.active) == 1:
    #     #print(simgr.active)
    #     simgr.step()

    # #print(simgr.active)
    # for state in simgr.active:
    #     print(state)
    #     print(state.history.recent_constraints)
