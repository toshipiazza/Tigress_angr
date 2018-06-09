#!/usr/bin/env python

import claripy
import angr
import logging

from llvmlite   import ir
from llvmlite   import binding
from utils      import *


def main(path, module):
    l = logging.getLogger("tigress")
    l.info(module)

    # challenges all feed input to strtoul, and dump output hash via
    # printf; we hook them both here for ease of implementation
    l.info("Exploring all possible paths")
    p = angr.Project(path)
    input = claripy.BVS('input', 64)
    p.hook_symbol('strtoul', Strtol(input))
    p.hook_symbol('printf',  Printf())
    s = p.factory.entry_state(args=[path, 'dummy'],
                              add_options=angr.options.unicorn)
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
        pred = reduce(claripy.And, i.guards, claripy.true)
        l.debug(pred)
        with bld.if_then(LLVM(fun, bld, pred)):
            l.debug(i.state.scratch.hash.ast)
            bld.ret(LLVM(fun, bld, i.state.scratch.hash.ast))
    bld.unreachable()

    l.info("Constructing execution engine and compiling IR")
    mod = compile_ir(str(mod))
    with open("output/" + module + ".ll", "w")  as f:
        f.write(str(mod))
    with open("output/" + module + ".o", "wb")  as f:
        target = binding.Target.from_default_triple()
        target_machine = target.create_target_machine()
        f.write(target_machine.emit_object(mod))
    l.debug(str(mod))


class Strtol(angr.SimProcedure):

    def __init__(self, input):
        super(Strtol, self).__init__()
        self._input = input

    def run(self, nptr, endptr, base):
        # return a symbolic variable (this is easier
        # than using a symbolic argv)
        logging.getLogger('tigress.strtol').info("Returning symbolic input")
        self.return_type = angr.sim_type.SimTypeInt(
                self.state.arch, True)
        return self._input


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

    parser = argparse.ArgumentParser()
    parser.add_argument('binary')
    args = parser.parse_args()
    main(args.binary, os.path.basename(args.binary))
