#!/usr/bin/env python

import claripy
import angr
import logging
import tigress


def main(obfuscated, deobfuscated, num_tests):
    l = logging.getLogger("tigress")

    # call the SECRET function, which will explore all paths
    p = angr.Project(obfuscated)
    cc = p.factory.cc(
        func_ty=angr.sim_type.SimTypeFunction([angr.sim_type.SimTypeLong()],
                                              angr.sim_type.SimTypeLong()))

    input = claripy.BVS('input', 64)
    s = p.factory.call_state(
        p.loader.find_symbol("SECRET").rebased_addr,
        input,
        cc=cc,
        add_options=angr.options.unicorn)
    simgr = p.factory.simulation_manager(s)
    simgr.run()

    wrong = 0
    total = 0
    for i in simgr.deadended:
        # Generates up to num_tests satisfying inputs to get
        # to this deadended path
        l.info("Generating test cases for deadended path")
        for test in i.solver.eval_upto(input, num_tests):
            if run_binary(obfuscated, test) != run_binary(deobfuscated, test):
                l.warn("Test case {} failed!".format(test))
                wrong += 1
            total += 1
    l.warn("Success rate: {}/{} ({}%)".format(total-wrong, total, float(total-wrong)/total*100))


def run_binary(binary, arg):
    from subprocess import Popen, PIPE
    p = Popen([binary, str(arg)], stdout=PIPE)
    stdout, _ = p.communicate()
    return int(stdout)


if __name__ == '__main__':
    import argparse
    import os

    logging.getLogger('angr').setLevel('WARNING')
    logging.getLogger('tigress').setLevel('INFO')

    parser = argparse.ArgumentParser()
    parser.add_argument('obfuscated')
    parser.add_argument('deobfuscated')
    parser.add_argument('--num_tests', type=int)
    parser.set_defaults(num_tests=100)
    args = parser.parse_args()
    main(args.obfuscated, args.deobfuscated, args.num_tests)
