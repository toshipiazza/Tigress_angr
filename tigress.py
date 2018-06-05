import claripy
import angr
import logging
import os

from llvmlite   import ir
from utils      import *


l = logging.getLogger("tigress")


def main(path, module):

    # challenges all feed input to strtoul, and dump output hash via
    # printf; we hook them both here for ease of implementation
    l.info("Exploring all possible paths")
    p = angr.Project(path)
    p.hook_symbol('strtoul', Strtol())
    p.hook_symbol('printf',  Printf())
    s = p.factory.entry_state(args=[path, 'dummy'])
    sm = p.factory.simulation_manager(s)
    sm.explore()

    # Now we have multiple deadended paths, we can emit equivalent code
    # by looking up that path's predicate and the resulting hash's SMT
    # equation:
    # if <path_predicate_1>: return hash_1
    # if <path_predicate_2>: return hash_2
    mod = ir.Module(name=module)
    fun = ir.Function(mod, ir.FunctionType(ir.IntType(64), (ir.IntType(64),)),
                      name="SECRET")
    bld = ir.IRBuilder(fun.append_basic_block())
    sel = ir.Constant(ir.IntType(64), int(0)) # this case should never happen
    for i in sm.deadended:
        l.info("Converting ast to branch on deadended path")
        sel = bld.select(LLVM(fun, bld, reduce(claripy.And, i.guards, claripy.true)),
                         LLVM(fun, bld, i.state.scratch.hash.ast),
                         sel)
    bld.ret(sel)

    # get a reference to the compiled SECRET function
    engine = create_execution_engine()
    compile_ir(str(mod))
    SECRET = engine.get_function_address("SECRET")
    SECRET = CFUNCTYPE(c_uint64, c_uint64)(SECRET)

    # bring us to REPL where we can interact with SECRET
    import IPython
    IPython.embed()


class Strtol(angr.SimProcedure):

    def run(self, nptr, endptr, base):
        # return a symbolic variable (this is easier
        # than using a symbolic argv since it's already
        # an int)
        l.info("Returning symbolic input")
        self.return_type = angr.sim_type.SimTypeInt(
                self.state.arch, True)
        return claripy.BVS('input', 64)


class Printf(angr.SimProcedure):

    def run(self, fmt, arg):
        # we save the argument in the path
        l.info("Recording the final hash")
        self.state.scratch.hash = arg
        self.exit(1)


if __name__ == '__main__':
    import sys
    logging.getLogger('angr').setLevel('WARNING')
    logging.getLogger('tigress').setLevel('INFO')
    main(sys.argv[1], os.path.basename(sys.argv[1]))
