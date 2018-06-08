#!/usr/bin/env python

import claripy
import angr
import logging
import tigress

def main(obfuscated, deobfuscated, num_tests):
    l = logging.getLogger("tigress")

    # challenges all feed input to strtoul, and dump output hash via
    # printf; we hook them both here for ease of implementation
    l.info("Exploring all possible paths")
    p = angr.Project(obfuscated)
    p.hook_symbol('strtoul', tigress.Strtol())
    p.hook_symbol('printf',  tigress.Printf())
    s = p.factory.entry_state(args=[obfuscated, 'dummy'],
                              add_options=angr.options.unicorn)
    sm = p.factory.simulation_manager(s)
    sm.explore()

    wrong = 0
    total = 0
    for i in sm.deadended:
        # Generates up to num_tests satisfying inputs to get
        # to this deadended path
        l.info("Generating test cases for deadended path")
        for test in i.solver.eval_upto(tigress.input_, num_tests):
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
