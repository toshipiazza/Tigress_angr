#!/usr/bin/env python

import claripy
import angr
import logging

from llvmlite   import ir
from utils      import *


def main(path, module, out_l, out_o):
    l = logging.getLogger("tigress")
    l.info(module)

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
    # if path_predicate_1(input): return hash_1(input)
    # if path_predicate_2(input): return hash_2(input)
    # unreachable()
    mod = ir.Module(name=module)
    fun = ir.Function(mod, ir.FunctionType(ir.IntType(64), (ir.IntType(64),)),
                      name="SECRET")
    bld = ir.IRBuilder(fun.append_basic_block())
    for i in sm.deadended:
        l.info("Converting ast to branch on deadended path")
        with bld.if_then(LLVM(fun, bld, reduce(claripy.And, i.guards, claripy.true))):
             bld.ret(LLVM(fun, bld, i.state.scratch.hash.ast))
    if not bld.terminated:
        bld.unreachable()

    l.info("Constructing execution engine")
    # get a reference to the compiled SECRET function
    target_machine, engine = create_execution_engine()
    mod = compile_ir(engine, str(mod), opt=False)
    SECRET = engine.get_function_address("SECRET")
    SECRET = CFUNCTYPE(c_uint64, c_uint64)(SECRET)

    if out_o is not None:
        with open(out_o, "wb") as f:
            f.write(target_machine.emit_object(mod))
    if out_l is not None:
        with open(out_l, "w")  as f:
            f.write(str(mod))

    # bring us to REPL where we can interact with SECRET
    # import IPython
    # IPython.embed()


class Strtol(angr.SimProcedure):

    def run(self, nptr, endptr, base):
        # return a symbolic variable (this is easier
        # than using a symbolic argv)
        logging.getLogger('tigress.strtol').info("Returning symbolic input")
        self.return_type = angr.sim_type.SimTypeInt(
                self.state.arch, True)
        return claripy.BVS('input', 64)


class Printf(angr.SimProcedure):

    def run(self, fmt, arg):
        # we save the argument in the path
        logging.getLogger('tigress.printf').info("Recording the final hash")
        self.state.scratch.hash = arg
        self.exit(1)


if __name__ == '__main__':
    import argparse
    import os

    logging.getLogger('angr').setLevel('WARNING')
    logging.getLogger('tigress').setLevel('INFO')

    parser = argparse.ArgumentParser(
            description="(Partial) solution to tigress protection challenges")
    parser.add_argument('binary')
    parser.add_argument('-o', type=str)
    parser.add_argument('-l', type=str)
    parser.set_defaults(opt=True)
    args = parser.parse_args()
    main(args.binary, os.path.basename(args.binary), args.l, args.o)
