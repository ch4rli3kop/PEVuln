import angr, claripy

import logging
from collections import defaultdict
from functools import reduce

from angr import BP, BP_AFTER
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr.code_location import CodeLocation
from angr.analyses.forward_analysis import ForwardAnalysis, FunctionGraphVisitor
from angr.analyses.variable_recovery import VariableRecovery
from angr.analyses.variable_recovery.variable_recovery_base import VariableRecoveryBase, VariableRecoveryStateBase
from angr.analyses.variable_recovery.annotations import StackLocationAnnotation

from operator import itemgetter

from networkx.generators.internet_as_graphs import uniform_int_from_avg

l = logging.getLogger(name=__name__)


class VariableRecoveryState(VariableRecoveryStateBase):
    """
    The abstract state of variable recovery analysis.

    :ivar angr.knowledge.variable_manager.VariableManager variable_manager: The variable manager.
    """

    def __init__(self, block_addr, analysis, arch, func, concrete_states, stack_region=None, register_region=None, ch_pointer_variables=None):

        super().__init__(block_addr, analysis, arch, func, stack_region=stack_region, register_region=register_region)

        self._concrete_states = concrete_states
        # register callbacks
        self.register_callbacks(self.concrete_states)
        if not ch_pointer_variables:
            self.ch_pointer_variables = ch_pointer_variables
        else:
            self.ch_pointer_variables = []

    def __repr__(self):
        return "<VRAbstractState: %d register variables, %d stack variables>" % (len(self.register_region), len(self.stack_region))

    @property
    def concrete_states(self):
        return self._concrete_states

    @concrete_states.setter
    def concrete_states(self, v):
        self._concrete_states = v

    def get_concrete_state(self, addr):
        """

        :param addr:
        :return:
        """

        for s in self.concrete_states:
            if s.ip._model_concrete.value == addr:
                return s

        return None

    def copy(self):

        state = VariableRecoveryState(self.block_addr,
                                      self._analysis,
                                      self.arch,
                                      self.function,
                                      self._concrete_states,
                                      stack_region=self.stack_region.copy(),
                                      register_region=self.register_region.copy(),
                                      ch_pointer_variables=self.ch_pointer_variables
                                      )

        return state

    def register_callbacks(self, concrete_states):
        """

        :param concrete_states:
        :return:
        """

        for concrete_state in concrete_states:
            # clear existing breakpoints
            # TODO: all breakpoints are removed. Fix this later by only removing breakpoints that we added
            for bp_type in ('reg_read', 'reg_write', 'mem_read', 'mem_write', 'instruction'):
                concrete_state.inspect._breakpoints[bp_type] = [ ]

            concrete_state.inspect.add_breakpoint('reg_read', BP(when=BP_AFTER, enabled=True,
                                                                 action=self._hook_register_read
                                                                 )
                                                  )
            concrete_state.inspect.add_breakpoint('reg_write', BP(enabled=True, action=self._hook_register_write))
            concrete_state.inspect.add_breakpoint('mem_read', BP(when=BP_AFTER, enabled=True,
                                                                 action=self._hook_memory_read
                                                                 )
                                                  )
            concrete_state.inspect.add_breakpoint('mem_write', BP(enabled=True, action=self._hook_memory_write))

    def merge(self, other, successor=None):
        """
        Merge two abstract states.

        :param VariableRecoveryState other: The other abstract state to merge.
        :return:                            The merged abstract state.
        :rtype:                             VariableRecoveryState
        """

        replacements = {}
        if successor in self.dominance_frontiers:
            replacements = self._make_phi_variables(successor, self, other)

        merged_concrete_states =  [ self._concrete_states[0] ] # self._merge_concrete_states(other)

        new_stack_region = self.stack_region.copy().replace(replacements)
        new_stack_region.merge(other.stack_region, replacements=replacements)

        new_register_region = self.register_region.copy().replace(replacements)
        new_register_region.merge(other.register_region, replacements=replacements)

        return VariableRecoveryState(successor, self._analysis, self.arch, self.function, merged_concrete_states,
                                     stack_region=new_stack_region,
                                     register_region=new_register_region
                                     )

    def _merge_concrete_states(self, other):
        """

        :param VariableRecoveryState other:
        :return:
        :rtype:                             list
        """

        merged = [ ]

        for s in self.concrete_states:
            other_state = other.get_concrete_state(s.ip._model_concrete.value)
            if other_state is not None:
                s = s.merge(other_state)
            merged.append(s)

        return merged

    #
    # SimInspect callbacks
    #

    def _hook_register_read(self, state):

        reg_read_offset = state.inspect.reg_read_offset
        if isinstance(reg_read_offset, claripy.ast.BV):
            if reg_read_offset.multivalued:
                # Multi-valued register offsets are not supported
                l.warning("Multi-valued register offsets are not supported.")
                return
            reg_read_offset = state.solver.eval(reg_read_offset)
        reg_read_length = state.inspect.reg_read_length

        if reg_read_offset == state.arch.sp_offset and reg_read_length == state.arch.bytes:
            # TODO: make sure the sp is not overwritten by something that we are not tracking
            return

        #if reg_read_offset == state.arch.bp_offset and reg_read_length == state.arch.bytes:
        #    # TODO:

        var_offset = self._normalize_register_offset(reg_read_offset)
        if var_offset not in self.register_region:
            # the variable being read doesn't exist before
            variable = SimRegisterVariable(reg_read_offset, reg_read_length,
                                           ident=self.variable_manager[self.func_addr].next_variable_ident('register'),
                                           region=self.func_addr,
                                           )
            self.register_region.add_variable(var_offset, variable)

            # record this variable in variable manager
            self.variable_manager[self.func_addr].add_variable('register', var_offset, variable)


    # def _hook_register_read(self, state):

    #     reg_read_offset = state.inspect.reg_read_offset
    #     if isinstance(reg_read_offset, claripy.ast.BV):
    #         if reg_read_offset.multivalued:
    #             # Multi-valued register offsets are not supported
    #             l.warning("Multi-valued register offsets are not supported.")
    #             return
    #         reg_read_offset = state.solver.eval(reg_read_offset)
    #     reg_read_length = state.inspect.reg_read_length

    #     if reg_read_offset == state.arch.sp_offset and reg_read_length == state.arch.bytes:
    #         # TODO: make sure the sp is not overwritten by something that we are not tracking
    #         return

    #     #if reg_read_offset == state.arch.bp_offset and reg_read_length == state.arch.bytes:
    #     #    # TODO:

    #     var_offset = self._normalize_register_offset(reg_read_offset)
    #     if var_offset not in self.register_region:
    #         # the variable being read doesn't exist before
    #         variable = SimRegisterVariable(reg_read_offset, reg_read_length,
    #                                        ident=self.variable_manager[self.func_addr].next_variable_ident('register'),
    #                                        region=self.func_addr,
    #                                        )
    #         self.register_region.add_variable(var_offset, variable)

    #         # record this variable in variable manager
    #         self.variable_manager[self.func_addr].add_variable('register', var_offset, variable)

    def _hook_register_write(self, state):

        reg_write_offset = state.inspect.reg_write_offset
        if isinstance(reg_write_offset, claripy.ast.BV):
            if reg_write_offset.multivalued:
                # Multi-valued register offsets are not supported
                l.warning("Multi-valued register offsets are not supported.")
                return
            reg_write_offset = state.solver.eval(reg_write_offset)

        if reg_write_offset == state.arch.sp_offset:
            # it's updating stack pointer. skip
            return

        reg_write_expr = state.inspect.reg_write_expr
        reg_write_length = len(reg_write_expr) // 8

        # annotate it
        # reg_write_expr = reg_write_expr.annotate(VariableSourceAnnotation.from_state(state))

        state.inspect.reg_write_expr = reg_write_expr

        existing_vars = self.variable_manager[self.func_addr].find_variables_by_stmt(state.scratch.bbl_addr,
                                                                                     state.scratch.stmt_idx,
                                                                                     'register')
        if not existing_vars:
            # create the variable
            variable = SimRegisterVariable(reg_write_offset, reg_write_length,
                                           ident=self.variable_manager[self.func_addr].next_variable_ident('register'),
                                           region=self.func_addr,
                                           )
            var_offset = self._normalize_register_offset(reg_write_offset)
            self.register_region.set_variable(var_offset, variable)
            # record this variable in variable manager
            self.variable_manager[self.func_addr].set_variable('register', var_offset, variable)
            self.variable_manager[self.func_addr].write_to(variable, 0, self._codeloc_from_state(state))

        # is it writing a pointer to a stack variable into the register?
        # e.g. lea eax, [ebp-0x40]
        stack_offset = self._addr_to_stack_offset(reg_write_expr)
        if stack_offset is not None:
            # it is!
            # unfortunately we don't know the size. We use size None for now.

            if stack_offset not in self.stack_region:
                lea_size = 1
                new_var = SimStackVariable(stack_offset, lea_size, base='bp',
                                            ident=self.variable_manager[self.func_addr].next_variable_ident('stack'),
                                            region=self.func_addr,
                                            )
                self.stack_region.add_variable(stack_offset, new_var)

                # record this variable in variable manager
                self.variable_manager[self.func_addr].add_variable('stack', stack_offset, new_var)

            base_offset = self.stack_region.get_base_addr(stack_offset)
            assert base_offset is not None
            for var in self.stack_region.get_variables_by_offset(stack_offset):
                self.variable_manager[self.func_addr].reference_at(var, stack_offset - base_offset,
                                                                   self._codeloc_from_state(state)
                                                                   )


    # def _hook_register_write(self, state):

    #     reg_write_offset = state.inspect.reg_write_offset
    #     if isinstance(reg_write_offset, claripy.ast.BV):
    #         if reg_write_offset.multivalued:
    #             # Multi-valued register offsets are not supported
    #             l.warning("Multi-valued register offsets are not supported.")
    #             return
    #         reg_write_offset = state.solver.eval(reg_write_offset)

    #     if reg_write_offset == state.arch.sp_offset:
    #         # it's updating stack pointer. skip
    #         return

    #     reg_write_expr = state.inspect.reg_write_expr
    #     reg_write_length = len(reg_write_expr) // 8

    #     # annotate it
    #     # reg_write_expr = reg_write_expr.annotate(VariableSourceAnnotation.from_state(state))

    #     state.inspect.reg_write_expr = reg_write_expr

    #     existing_vars = self.variable_manager[self.func_addr].find_variables_by_stmt(state.scratch.bbl_addr,
    #                                                                                  state.scratch.stmt_idx,
    #                                                                                  'register')
    #     if not existing_vars:
    #         # create the variable
    #         variable = SimRegisterVariable(reg_write_offset, reg_write_length,
    #                                        ident=self.variable_manager[self.func_addr].next_variable_ident('register'),
    #                                        region=self.func_addr,
    #                                        )
    #         var_offset = self._normalize_register_offset(reg_write_offset)
    #         self.register_region.set_variable(var_offset, variable)
    #         # record this variable in variable manager
    #         self.variable_manager[self.func_addr].set_variable('register', var_offset, variable)
    #         self.variable_manager[self.func_addr].write_to(variable, 0, self._codeloc_from_state(state))

    #     # is it writing a pointer to a stack variable into the register?
    #     # e.g. lea eax, [ebp-0x40]
    #     stack_offset = self._addr_to_stack_offset(reg_write_expr)
    #     if stack_offset is not None:
    #         # it is!
    #         # unfortunately we don't know the size. We use size None for now.

    #         if stack_offset not in self.stack_region:
    #             lea_size = 1
    #             new_var = SimStackVariable(stack_offset, lea_size, base='bp',
    #                                         ident=self.variable_manager[self.func_addr].next_variable_ident('stack'),
    #                                         region=self.func_addr,
    #                                         )
    #             self.stack_region.add_variable(stack_offset, new_var)

    #             # record this variable in variable manager
    #             self.variable_manager[self.func_addr].add_variable('stack', stack_offset, new_var)

    #         base_offset = self.stack_region.get_base_addr(stack_offset)
    #         assert base_offset is not None
    #         for var in self.stack_region.get_variables_by_offset(stack_offset):
    #             self.variable_manager[self.func_addr].reference_at(var, stack_offset - base_offset,
    #                                                                self._codeloc_from_state(state)
    #                                                                )


    def _hook_memory_read(self, state):

        mem_read_address = state.inspect.mem_read_address
        mem_read_length = state.inspect.mem_read_length

        stack_offset = self._addr_to_stack_offset(mem_read_address)

        if stack_offset is None:
            # it's not a stack access
            # TODO:
            pass

        else:
            if stack_offset not in self.stack_region:
                # this stack offset is not covered by any existing stack variable
                ident_sort = 'argument' if stack_offset > 0 else 'stack'
                variable = SimStackVariable(stack_offset, mem_read_length, base='bp',
                                            ident=self.variable_manager[self.func_addr].next_variable_ident(ident_sort),
                                            region=self.func_addr,
                                            )
                self.stack_region.add_variable(stack_offset, variable)

                # record this variable in variable manager
                self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)

            base_offset = self.stack_region.get_base_addr(stack_offset)
            assert base_offset is not None

            existing_variables = self.stack_region.get_variables_by_offset(stack_offset)

            if len(existing_variables) > 1:
                # create a phi node for all other variables
                l.warning("Reading memory with overlapping variables: %s. Ignoring all but the first one.",
                          existing_variables)

            if existing_variables:
                variable = next(iter(existing_variables))
                self.variable_manager[self.func_addr].read_from(variable, stack_offset - base_offset,
                                                                self._codeloc_from_state(state))


    # def _hook_memory_read(self, state):

    #     mem_read_address = state.inspect.mem_read_address
    #     mem_read_length = state.inspect.mem_read_length

    #     stack_offset = self._addr_to_stack_offset(mem_read_address)

    #     if stack_offset is None:
    #         # it's not a stack access
    #         # TODO:
    #         pass

    #     else:
    #         if stack_offset not in self.stack_region:
    #             # this stack offset is not covered by any existing stack variable
    #             ident_sort = 'argument' if stack_offset > 0 else 'stack'
    #             variable = SimStackVariable(stack_offset, mem_read_length, base='bp',
    #                                         ident=self.variable_manager[self.func_addr].next_variable_ident(ident_sort),
    #                                         region=self.func_addr,
    #                                         )
    #             self.stack_region.add_variable(stack_offset, variable)

    #             # record this variable in variable manager
    #             self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)

    #         base_offset = self.stack_region.get_base_addr(stack_offset)
    #         assert base_offset is not None

    #         existing_variables = self.stack_region.get_variables_by_offset(stack_offset)

    #         if len(existing_variables) > 1:
    #             # create a phi node for all other variables
    #             l.warning("Reading memory with overlapping variables: %s. Ignoring all but the first one.",
    #                       existing_variables)

    #         if existing_variables:
    #             variable = next(iter(existing_variables))
    #             self.variable_manager[self.func_addr].read_from(variable, stack_offset - base_offset,
    #                                                             self._codeloc_from_state(state))

    def _hook_memory_write(self, state):

        mem_write_address = state.inspect.mem_write_address
        mem_write_expr = state.inspect.mem_write_expr
        mem_write_length = len(mem_write_expr) // 8

        stack_offset = self._addr_to_stack_offset(mem_write_address)

        if stack_offset is None:
            # it's not a stack access
            # TODO:
            pass

        else:
            # we always add a new variable to keep it SSA
            variable = SimStackVariable(stack_offset, mem_write_length, base='bp',
                                        ident=self.variable_manager[self.func_addr].next_variable_ident('stack'),
                                        region=self.func_addr,
                                        )
            self.stack_region.set_variable(stack_offset, variable)

            # record this variable in variable manager
            self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)

            base_offset = self.stack_region.get_base_addr(stack_offset)
            assert base_offset is not None
            for variable in self.stack_region.get_variables_by_offset(stack_offset):
                self.variable_manager[self.func_addr].write_to(variable, stack_offset - base_offset, self._codeloc_from_state(state))


    # def _hook_memory_write(self, state):

    #     mem_write_address = state.inspect.mem_write_address
    #     mem_write_expr = state.inspect.mem_write_expr
    #     mem_write_length = len(mem_write_expr) // 8

    #     variable_expr = None
    #     variable_type = None
    #     variable_range = None
    #     variable_size = None
    #     #stack_offset, uninitialized_value = self._addr_to_stack_offset(mem_write_address)
    #     stack_offset = self._addr_to_stack_offset(mem_write_address)

    #     # calculate size and identify type
    #     size = mem_write_length
    #     if size == 4: # TODO: signed or unsigned ?
    #         variable_type = 'int32'
    #         variable_range = {'min':0, 'max':0xffffffff}
    #     elif size == 1: # TODO: signed or unsigned ?
    #         variable_type = 'byte'
    #         variable_range = {'min':0, 'max':0xff}
    #     elif size == 2: # TODO: signed or unsigned ?
    #         variable_type = 'short'
    #         variable_range = {'min':0, 'max':0xffff}

    #     # find pointer
    #     # base addr

    #     if mem_write_address.op == '__add__':
    #         variable_type = 'byte *' # TODO: identify int array
    #         variable_size = None # later calculated value
    #         variable_range = None
    #         variable_expr = mem_write_address.args
    #         self.variable_manager[self.func_addr].add_pointer_variable({'expr':variable_expr, 'size':variable_size, 'variable_type':variable_type, 'state_addr':state.addr})
    #         #print({'expr':variable_expr, 'size':size, 'variable_type':variable_type})

    #     if stack_offset is None:
    #         # it's not a stack access
    #         # TODO:
    #         pass

    #     # Check variable offset if it appears lately
    #     elif stack_offset not in self.stack_region:
            
    #         variable = SimStackVariable(stack_offset, mem_write_length, base='bp',
    #                                     ident=self.variable_manager[self.func_addr].next_variable_ident('stack'),
    #                                     region=self.func_addr, variable_type=variable_type, variable_expr=variable_expr ,variable_range=variable_range
    #                                     )
    #         self.stack_region.set_variable(stack_offset, variable)

    #         # record this variable in variable manager
    #         self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)

    #         base_offset = self.stack_region.get_base_addr(stack_offset)
    #         assert base_offset is not None
    #         for variable in self.stack_region.get_variables_by_offset(stack_offset):
    #             self.variable_manager[self.func_addr].write_to(variable, stack_offset - base_offset, self._codeloc_from_state(state))

    #
    # Util methods
    #

    def _normalize_register_offset(self, offset):  #pylint:disable=no-self-use

        # TODO:

        return offset

    @staticmethod
    def _codeloc_from_state(state):
        return CodeLocation(state.scratch.bbl_addr, state.scratch.stmt_idx, ins_addr=state.scratch.ins_addr)

    def _to_signed(self, n):

        if n >= 2 ** (self.arch.bits - 1):
            # convert it to a negative number
            return n - 2 ** self.arch.bits

        return n

    # adddddded
    # this function has a bug when arch is x86
    # i think that `push ebp` is translated to 8bytes

    def _addr_to_stack_offset(self, addr):
        """
        Convert an address to a stack offset.

        :param claripy.ast.Base addr:  The address to convert from.
        :return:                       A stack offset if the addr comes from the stack pointer, or None if the address
                                       does not come from the stack pointer.
        """

        def _parse(addr):
            if addr.op == '__add__':
                # __add__ might have multiple arguments
                parsed = [ _parse(arg) for arg in addr.args ]
                annotated = [ True for annotated, _ in parsed if annotated is True ]
                if len(annotated) != 1:
                    # either nothing is annotated, or more than one element is annotated
                    raise ValueError()

                return True, sum([ offset for _, offset in parsed ])
            elif addr.op == '__sub__':
                # __sub__ might have multiple arguments

                parsed = [ _parse(arg) for arg in addr.args ]
                first_annotated, first_offset = parsed[0]
                if first_annotated is False:
                    # the first argument is not annotated. we don't support it.
                    raise ValueError()
                if any([ annotated for annotated, _ in parsed[1:] ]):
                    # more than one argument is annotated. we don't support it.
                    raise ValueError()

                return True, first_offset - sum([ offset for _, offset in parsed[1:] ])
            else:
                anno = next(iter(anno for anno in addr.annotations if isinstance(anno, StackLocationAnnotation)), None)
                if anno is None:
                    if addr.op == 'BVV':
                        return False, addr._model_concrete.value
                    raise ValueError()
                return True, anno.offset

        # find the annotated AST
        try: annotated, offset = _parse(addr)
        except ValueError: return None

        if not annotated:
            return None

        return self._to_signed(offset)



    # def _addr_to_stack_offset(self, addr):
    #     """
    #     Convert an address to a stack offset.

    #     :param claripy.ast.Base addr:  The address to convert from.
    #     :return:                       A stack offset if the addr comes from the stack pointer, or None if the address
    #                                    does not come from the stack pointer.
    #     """
    #     uninitialized_value = None

    #     def _parse(addr):
    #         # adddddded
    #         # when uninitialized memory exists
    #         args = []
    #         for arg in addr.args:
    #             if 'UNINITIALIZED' not in str(arg):
    #                 args.append(arg)
    #             else:
    #                 uninitialized_value = arg
    #         if addr.op == '__add__':
    #             # __add__ might have multiple arguments
    #             parsed = [ _parse(arg) for arg in args ]
    #             annotated = [ True for annotated, _ in parsed if annotated is True ]
    #             if len(annotated) != 1:
    #                 # either nothing is annotated, or more than one element is annotated
    #                 raise ValueError()

    #             return True, sum([ offset for _, offset in parsed ])
    #         elif addr.op == '__sub__':
    #             # __sub__ might have multiple arguments

    #             parsed = [ _parse(arg) for arg in args ]
    #             first_annotated, first_offset = parsed[0]
    #             if first_annotated is False:
    #                 # the first argument is not annotated. we don't support it.
    #                 raise ValueError()
    #             if any([ annotated for annotated, _ in parsed[1:] ]):
    #                 # more than one argument is annotated. we don't support it.
    #                 raise ValueError()

    #             return True, first_offset - sum([ offset for _, offset in parsed[1:] ])
    #         else:
    #             anno = next(iter(anno for anno in addr.annotations if isinstance(anno, StackLocationAnnotation)), None)
    #             if anno is None:
    #                 if addr.op == 'BVV':
    #                     return False, addr._model_concrete.value
    #                 if addr.op == 'BVS':
    #                     # when `addr + index` form is here
    #                     print('EEEE')
    #                 raise ValueError()
    #             # adddddded
    #             # This is right only when x86.
    #             if str(addr) == '<BV32 0x7fff0000>':
    #                 return True, 4
    #             return True, anno.offset

    #     # find the annotated AST
    #     try: annotated, offset = _parse(addr)
    #     except ValueError: return None, None

    #     if not annotated:
    #         return None, None

    #     return self._to_signed(offset), uninitialized_value

class VariableTracking(ForwardAnalysis, VariableRecoveryBase):

    def __init__(self, func, max_iterations=20):
        """

        :param knowledge.Function func:  The function to analyze.
        """
        self.func = func
        function_graph_visitor = FunctionGraphVisitor(func)
        self.ch_stack_variables = []

        VariableRecoveryBase.__init__(self, func, max_iterations)
        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=function_graph_visitor)

        self._node_iterations = defaultdict(int)

        self._analyze()
        #self._another_analyze()


    #
    # Main analysis routines
    #
    def _another_analyze(self):
        self._calculate_buffer_size()
        self._update_variable_size()

    def _update_variable_size(self):
        print(self.ch_stack_variables)
        
        ch_stack_variables = self.ch_stack_variables
    
        #print(self.variables)
        #print(self.pointer_variables)

        # first analysis
        suspicious_array = []
        for i, svar in enumerate(ch_stack_variables):            
            tmp_type = svar.ch_variable_type
            if len(ch_stack_variables)-1 > i :
            
                next = ch_stack_variables[i+1].offset
                p_size = next - svar.offset 
                if p_size > svar.size:
                    suspicious_array.append(svar)

            #     #if tmp_type
            #     if stack_variables[i+1].offset :
            #         size = stack_variables[i+1].offset - svar.offset
            # else:
            #     size = None
            # svar.size = size   

        # last analysis
        print('suspicious : ', suspicious_array)

        for pointer_variable in self.ch_pointer_variables:
            exprs = pointer_variable['expr']
            for expr in exprs:
                print('zzz')

        return True

    def get_ch_stack_variables(self):
        return self.ch_stack_variables


    def _calculate_buffer_size(self):
        self.ch_pointer_variables = self.variable_manager[self.func.addr].get_ch_pointer_variables()
        self.variables = self.variable_manager[self.func.addr].get_variables()
        self.ch_stack_variables = self._filter_ch_stack_variables(self.variables)
        #print(self.stack_variables)
        for i, svar in enumerate(self.ch_stack_variables):
            if svar.ch_variable_type is not 'byte *':
                continue
            if len(self.ch_stack_variables)-1 > i:
                size = self.ch_stack_variables[i+1].offset - svar.offset
            else:
                size = None
            svar.size = size

    def _filter_ch_stack_variables(self, variables):
        for svar in variables:
            if isinstance(svar, angr.sim_variable.SimStackVariable):
                if -0x100 < svar.offset < 0x10000:
                    self.ch_stack_variables.append(svar)

        ch_stack_variables = self._sort_by_offset(self.ch_stack_variables)
        
        return ch_stack_variables

    def _sort_by_offset(self, variables):
        if len(variables) <= 1:
            return variables
        pivot = variables[len(variables) // 2].offset
        less, more, equal = [], [], []
        for svar in variables:
            if svar.offset < pivot:
                less.append(svar)
            elif svar.offset > pivot:
                more.append(svar)
            else:
                equal.append(svar)
        return self._sort_by_offset(less) + equal + self._sort_by_offset(more)

    def _pre_analysis(self):
        self.initialize_dominance_frontiers()

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):

        concrete_state = self.project.factory.blank_state(
            addr=node.addr,
            mode='fastpath'  # we don't want to do any solving
        )

        # annotate the stack pointer
        # adddddded
        # TODO: by arch, initialize stacklocationsize 4 or 8
        concrete_state.regs.sp = concrete_state.regs.sp.annotate(StackLocationAnnotation(8))

        # give it enough stack space
        concrete_state.regs.bp = concrete_state.regs.sp + 0x100000

        return VariableRecoveryState(node.addr, self, self.project.arch, self.function, [ concrete_state ])

    def _merge_states(self, node, *states):

        if len(states) == 1:
            return states[0]

        return reduce(lambda s_0, s_1: s_0.merge(s_1, successor=node.addr), states[1:], states[0])

    def _run_on_node(self, node, state):
        """
        Take an input abstract state, execute the node, and derive an output state.

        :param angr.Block node:             The node to work on.
        :param VariableRecoveryState state: The input state.
        :return:                            A tuple of (changed, new output state).
        :rtype:                             tuple
        """

        l.debug('Analyzing block %#x, iteration %d.', node.addr, self._node_iterations[node])

        concrete_state = state.get_concrete_state(node.addr)

        if concrete_state is None:
            # didn't find any state going to here
            l.error("_run_on_node(): cannot find any state for address %#x.", node.addr)
            return False, state

        state = state.copy()
        self._instates[node.addr] = state

        if self._node_iterations[node] >= self._max_iterations:
            l.debug('Skip node %s as we have iterated %d times on it.', node, self._node_iterations[node])
            return False, state

        state.register_callbacks([ concrete_state ])

        successors = self.project.factory.successors(concrete_state,
                                                     addr=node.addr,
                                                     size=node.size,
                                                     opt_level=1,
                                                     cross_insn_opt=False,
                                                     )
        output_states = successors.all_successors

        state.concrete_states = [ state for state in output_states if not state.ip.symbolic ]

        self._outstates[node.addr] = state

        self._node_iterations[node] += 1

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        # TODO: only re-assign variable names to those that are newly changed
        self.variable_manager.initialize_variable_names()

        for addr, state in self._outstates.items():
            self.variable_manager[self.function.addr].set_live_variables(addr,
                                                                         state.register_region,
                                                                         state.stack_region
                                                                         )
from angr.analyses import AnalysesHub
AnalysesHub.register_default('VariableTracking', VariableTracking)
