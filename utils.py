import claripy
import logging

from z3        import *
from llvmlite  import ir
from llvmlite  import binding
from functools import partial, reduce

binding.initialize()
binding.initialize_native_target()
binding.initialize_native_asmprinter()

l = logging.getLogger("tigress.utils")


def z3_to_llvm(fun, bld, ast):
    args = list(map(partial(z3_to_llvm, fun, bld), z3_args(ast)))
    kind = ast.decl().kind()
    if kind == Z3_OP_TRUE:
        assert len(args) == 0
        return ir.Constant(ir.IntType(1), 1)
    elif kind == Z3_OP_FALSE:
        return ir.Constant(ir.IntType(1), 0)
        assert len(args) == 0
    elif kind == Z3_OP_BNUM:
        return ir.Constant(ir.IntType(ast.size()), ast.as_long())
    elif kind == Z3_OP_UNINTERPRETED:
        # the only symbolic thing should be our input
        assert fun.args[0].type.width == ast.size()
        return fun.args[0]
    elif kind == Z3_OP_BNOT:
        assert len(args) == 1
        ret = bld.not_(args[0])
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BMUL:
        # note: signed multiplication
        assert len(args) == 2
        ret = bld.mul(args[0], args[1])
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BUDIV:
        assert len(args) == 2
        ret = bld.udiv(args[0], args[1])
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BADD:
        assert len(args) == 2
        ret = bld.add(args[0], args[1])
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BAND:
        assert len(args) == 2
        return bld.and_(args[0], args[1])
    elif kind == Z3_OP_BOR:
        assert len(args) == 2
        return bld.or_(args[0], args[1])
    elif kind == Z3_OP_AND:
        return reduce(bld.and_, args)
    elif kind == Z3_OP_OR:
        return reduce(bld.or_, args)
    elif kind == Z3_OP_BUREM_I or kind == Z3_OP_BUREM:
        assert len(args) == 2
        ret = bld.urem(args[0], args[1])
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BXOR:
        assert len(args) == 2
        ret = bld.xor(args[0], args[1])
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BSHL:
        assert len(args) == 2
        ret = bld.shl(args[0], args[1])
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_BLSHR:
        assert len(args) == 2
        ret = bld.lshr(args[0], args[1])
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_EXTRACT:
        assert len(args) == 1
        parms = ast.params()
        tmp1 = bld.lshr(args[0], ir.Constant(args[0].type, parms[1]))
        tmp2 = bld.trunc(tmp1, ir.IntType(int(parms[0] - parms[1] + 1)))
        assert tmp2.type.width == ast.size()
        return tmp2
    elif kind == Z3_OP_CONCAT:
        curr = args[0]
        for tmp0 in args[1:]:
            next = bld.zext(tmp0, ir.IntType(tmp0.type.width + curr.type.width))
            curr = bld.zext(curr, ir.IntType(tmp0.type.width + curr.type.width))
            curr = bld.shl(curr, ir.Constant(curr.type, int(tmp0.type.width)))
            curr = bld.or_(curr, next)
        assert curr.type.width == ast.size()
        return curr
    elif kind == Z3_OP_DISTINCT:
        assert len(args) == 2
        return bld.icmp_unsigned("!=", args[0], args[1])
    elif kind == Z3_OP_EQ:
        assert len(args) == 2
        return bld.icmp_unsigned("==", args[0], args[1])
    elif kind == Z3_OP_ULEQ:
        assert len(args) == 2
        return bld.icmp_unsigned("<=", args[0], args[1])
    elif kind == Z3_OP_UGEQ:
        assert len(args) == 2
        return bld.icmp_unsigned(">=", args[0], args[1])
    elif kind == Z3_OP_SLEQ:
        assert len(args) == 2
        return bld.icmp_signed("<=", args[0], args[1])
    elif kind == Z3_OP_SGEQ:
        assert len(args) == 2
        return bld.icmp_signed(">=", args[0], args[1])
    elif kind == Z3_OP_ITE:
        assert len(args) == 3
        ret = bld.select(args[0], args[1], args[2])
        assert ret.type.width == ast.size()
        return ret
    elif kind == Z3_OP_NOT:
        assert len(args) == 1
        return bld.not_(args[0])
    else:
        raise NotImplementedError(ast.decl().name())


def z3_args(ast):
    return [ ast.arg(i) for i in range(ast.num_args()) ]


def LLVM(fun, bld, ast):
    l.info("Converting z3 expression to LLVM IR")
    z = claripy.backends.z3.convert(ast)
    l.debug("{}".format(z))
    return z3_to_llvm(fun, bld, z)


def compile_ir(llvm_ir):
    mod = binding.parse_assembly(llvm_ir)
    mod.verify()
    pmb = binding.create_pass_manager_builder()
    pmb.opt_level = 2
    pm = binding.create_module_pass_manager()
    pmb.populate(pm)
    pm.run(mod)
    return mod
