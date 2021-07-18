import angr

#proj = angr.Project('test/simple5_x64', auto_load_libs=False)
#proj = angr.Project('test/starcraft/starcraft_exmaple1 (4)', auto_load_libs=False)
proj = angr.Project('test/csgo/csgo_exmaple1 (5)', auto_load_libs=False)
#proj = angr.Project('test/simple3', auto_load_libs=False)
#proj = angr.Project('test/starcraft/StarCraft.exe', auto_load_libs=False)
#proj = angr.Project('test/csgo/dedicated.so', auto_load_libs=False)

cfg = proj.analyses.CFGFast(normalize=True)
#cfg = proj.analyses.CFGEmulated()
#ddg = proj.analyses.DDG(cfg=cfg)
test2 = 0x080491E7
test3 = 0x0804921A
test4 = 0x0804927E


test3_x64 = 0x0004011A1
test4_x64 = 0x0004011F8
test6_x64 = 0x00401344


test_addr = 0x004c5dd0
test_addr2 = 0x038CD0 + 0x400000
target_addr = 0x0401106
csgo_addr = 0x00401176
# init_state = proj.factory.blank_state(addr=test_addr2)
# simgr = proj.factory.simgr(init_state)
# simgr.explore(find=0x400000 +0x0038F6C)
# solution_state = simgr.found[0]
# print('jump_guards ', solution_state.history.jump_guards.hardcopy)

func = cfg.kb.functions[csgo_addr]   # the address of target function
#func = cfg.kb.functions[test_addr2]   # the address of target function
basic_blocks = list(func.block_addrs)
print(basic_blocks)
kb = angr.KnowledgeBase(proj)
vr = proj.analyses.VariableRecovery(func)
variable_manager = vr.variable_manager[func.addr]
variables = variable_manager.get_variables()

# cc_analysis = proj.analyses.CallingConvention(func, cfg=cfg, analyze_callsites=True)
# cc = cc_analysis.cc
# print(cc)

print(dir(vr))
print(variable_manager.get_phi_variables(basic_blocks[1]))
print(vr.get_variable_definitions(basic_blocks[0]))
for var in variables:
    if isinstance(var, angr.sim_variable.SimStackVariable):
        print('STACK ', var.name, 'ident : ', var.ident, 'offset : ',var.offset, 'addr : ',var.addr, 'base : ', var.base, 'base_addr : ', var.base_addr, 'category', var.category, 'size : ', var.size)
        print(variable_manager.get_variable_accesses(variable = var))
        print('TYPE ', variable_manager.get_variable_type(var))
    #elif isinstance(var, angr.sim_variable.SimRegisterVariable):
        
#        print('Register', var.name, 'ident : ', var.ident, 'reg : ', var.reg, 'size : ', var.size, 'candidate : ', var.candidate_names)
    #print(type(var))
    #print(dir(var))
#    print(var.name, var.reg, var.ident, var.size)

print('AAAAAAAAA', variable_manager.unify_variables())