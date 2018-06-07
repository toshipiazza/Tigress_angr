import claripy
import logging

from z3       import *
from llvmlite import ir
from llvmlite import binding
from IPython  import embed

binding.initialize()
binding.initialize_native_target()
binding.initialize_native_asmprinter()
binding.load_library_permanently('libgcc_s.so.1')

l = logging.getLogger("tigress.utils")


def z3_to_llvm(fun, bld, ast):
    args = z3_args(ast)
    kind = ast.decl().kind()
    if kind == Z3_OP_TRUE:
        return ir.Constant(ir.IntType(1), 1)
    elif kind == Z3_OP_FALSE:
        return ir.Constant(ir.IntType(1), 0)
    elif kind == Z3_OP_BNUM:
        return ir.Constant(ir.IntType(ast.size()), ast.as_long())
    elif kind == Z3_OP_UNINTERPRETED:
        # the only symbolic thing should be our input
        assert fun.args[0].type.width == ast.size()
        return fun.args[0]
    elif kind == Z3_OP_BNOT:
        ret = bld.not_(z3_to_llvm(fun, bld, args[0]))
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BMUL:
        # note: signed multiplication
        ret = bld.mul(z3_to_llvm(fun, bld, args[0]),
                      z3_to_llvm(fun, bld, args[1]))
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BUDIV:
        ret = bld.udiv(z3_to_llvm(fun, bld, args[0]),
                       z3_to_llvm(fun, bld, args[1]))
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BADD:
        ret = bld.add(z3_to_llvm(fun, bld, args[0]),
                      z3_to_llvm(fun, bld, args[1]))
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BAND or kind == Z3_OP_AND:
        return bld.and_(z3_to_llvm(fun, bld, args[0]),
                        z3_to_llvm(fun, bld, args[1]))
    elif kind == Z3_OP_BOR or kind == Z3_OP_OR:
        return bld.or_(z3_to_llvm(fun, bld, args[0]),
                       z3_to_llvm(fun, bld, args[1]))
    elif kind == Z3_OP_BUREM_I or kind == Z3_OP_BUREM:
        ret = bld.urem(z3_to_llvm(fun, bld, args[0]),
                       z3_to_llvm(fun, bld, args[1]))
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BXOR:
        ret = bld.xor(z3_to_llvm(fun, bld, args[0]),
                      z3_to_llvm(fun, bld, args[1]))
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BSHL:
        ret = bld.shl(z3_to_llvm(fun, bld, args[0]),
                      z3_to_llvm(fun, bld, args[1]))
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BLSHR:
        ret = bld.lshr(z3_to_llvm(fun, bld, args[0]),
                       z3_to_llvm(fun, bld, args[1]))
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_EXTRACT:
        parms = ast.params()
        tmp0 = z3_to_llvm(fun, bld, args[0])
        tmp1 = bld.lshr(tmp0, ir.Constant(tmp0.type, parms[1]))
        tmp2 = bld.trunc(tmp1, ir.IntType(int(parms[0] - parms[1] + 1)))
        assert tmp2.type.width == ast.size()
        return tmp2
    elif kind == Z3_OP_CONCAT:
        curr = z3_to_llvm(fun, bld, args[0])
        for next in args[1:]:
            tmp0 = z3_to_llvm(fun, bld, next)
            next = bld.zext(tmp0, ir.IntType(tmp0.type.width + curr.type.width))
            curr = bld.zext(curr, ir.IntType(tmp0.type.width + curr.type.width))
            curr = bld.shl(curr, ir.Constant(curr.type, int(tmp0.type.width)))
            curr = bld.or_(curr, next)
        assert curr.type.width == ast.size()
        return curr
    elif kind == Z3_OP_DISTINCT:
        ret = bld.icmp_unsigned("!=",
                                z3_to_llvm(fun, bld, args[0]),
                                z3_to_llvm(fun, bld, args[1]))
        return ret
    elif kind == Z3_OP_EQ:
        ret = bld.icmp_unsigned("==",
                                z3_to_llvm(fun, bld, args[0]),
                                z3_to_llvm(fun, bld, args[1]))
        return ret
    elif kind == Z3_OP_ULEQ:
        ret = bld.icmp_unsigned("<=",
                                z3_to_llvm(fun, bld, args[0]),
                                z3_to_llvm(fun, bld, args[1]))
        return ret
    elif kind == Z3_OP_UGEQ:
        ret = bld.icmp_unsigned(">=",
                                z3_to_llvm(fun, bld, args[0]),
                                z3_to_llvm(fun, bld, args[1]))
        return ret
    elif kind == Z3_OP_SLEQ:
        ret = bld.icmp_signed("<=",
                              z3_to_llvm(fun, bld, args[0]),
                              z3_to_llvm(fun, bld, args[1]))
        return ret
    elif kind == Z3_OP_SGEQ:
        ret = bld.icmp_signed(">=",
                              z3_to_llvm(fun, bld, args[0]),
                              z3_to_llvm(fun, bld, args[1]))
        return ret
    elif kind == Z3_OP_ITE:
        ret = bld.select(z3_to_llvm(fun, bld, args[0]),
                         z3_to_llvm(fun, bld, args[1]),
                         z3_to_llvm(fun, bld, args[2]))
        assert ret.type.width == ast.size()
        return ret
    else:
        embed()
        raise NotImplementedError(ast.decl().name())


def z3_args(ast):
    return [ ast.arg(i) for i in range(ast.num_args()) ]


def LLVM(fun, bld, ast):
    z = claripy.backends.z3.convert(ast)
    l.info("Converting z3 expression to LLVM IR")
    l.debug("{}".format(z))
    return z3_to_llvm(fun, bld, z)


def create_execution_engine():
    target = binding.Target.from_default_triple()
    target_machine = target.create_target_machine()
    backing_mod = binding.parse_assembly("")
    engine = binding.create_mcjit_compiler(backing_mod, target_machine)
    return target_machine, engine


def compile_ir(engine, llvm_ir, opt=True):
    mod = binding.parse_assembly(llvm_ir)
    mod.verify()

    if opt:
        pmb = binding.create_pass_manager_builder()
        pmb.opt_level = 2
        pm = binding.create_module_pass_manager()
        pmb.populate(pm)
        pm.run(mod)

    engine.add_module(mod)
    engine.finalize_object()
    engine.run_static_constructors()
    return mod
