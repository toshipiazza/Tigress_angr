#!/usr/bin/env python

import claripy
import angr
import logging
import functools

from llvmlite import ir
from llvmlite import binding
from utils import *


def main(path, module):
    l = logging.getLogger("tigress")
    l.info(module)

    # call the SECRET function, which will explore all paths
    p = angr.Project(path)
    cc = p.factory.cc(
        func_ty=angr.sim_type.SimTypeFunction([angr.sim_type.SimTypeLong()],
                                              angr.sim_type.SimTypeLong()))

    s = p.factory.call_state(
        p.loader.find_symbol("SECRET").rebased_addr,
        claripy.BVS('input', 64),
        cc=cc,
        add_options=angr.options.unicorn)
    simgr = p.factory.simulation_manager(s)
    simgr.run()

    # Now we have multiple deadended paths, we can emit equivalent code
    # by looking up that path's predicate and the resulting hash's SMT
    # equation:
    # if path_predicate_1(input): return hash_1(input)
    # if path_predicate_2(input): return hash_2(input)
    # unreachable()
    mod = ir.Module(name=module)
    fun = ir.Function(
        mod,
        ir.FunctionType(ir.IntType(64), (ir.IntType(64), )),
        name="SECRET")
    bld = ir.IRBuilder(fun.append_basic_block())
    for i in simgr.deadended:
        l.info("Converting ast to branch on deadended path")
        pred = functools.reduce(claripy.And, i.simplify(), claripy.true)
        # l.debug("Predicate: {}".format(pred))
        with bld.if_then(LLVM(fun, bld, pred)):
            # l.debug(cc.get_return_val(i))
            bld.ret(LLVM(fun, bld, cc.get_return_val(i)))
    bld.unreachable()

    l.info("Constructing execution engine and compiling IR")
    mod = compile_ir(str(mod))
    with open("output/" + module + ".ll", "w") as f:
        f.write(str(mod))
    with open("output/" + module + ".o", "wb") as f:
        target = binding.Target.from_default_triple()
        target_machine = target.create_target_machine()
        f.write(target_machine.emit_object(mod))
    l.debug(str(mod))


if __name__ == '__main__':
    import argparse
    import os
    import sys
    sys.setrecursionlimit(10000)

    logging.getLogger('angr').setLevel('WARNING')
    logging.getLogger('tigress').setLevel('DEBUG')

    parser = argparse.ArgumentParser()
    parser.add_argument('binary')
    args = parser.parse_args()
    main(args.binary, os.path.basename(args.binary))
