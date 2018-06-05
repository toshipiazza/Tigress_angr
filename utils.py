import claripy

from llvmlite import binding
binding.initialize()
binding.initialize_native_target()
binding.initialize_native_asmprinter()

if False:
    def AstToLLVM(fun, bld, ast):
        # TODO: we do not currently handle floating point
        if ast.op == 'BVS':
            # the only symbolic thing should be our input
            return fun.args[0]
        elif ast.op == 'BoolV':
            return ir.Constant(ir.IntType(1), int(ast.args[0]))
        elif ast.op == 'BVV':
            return ir.Constant(ir.IntType(int(ast.args[1])), int(ast.args[0]))
        elif ast.op == 'Extract':
            tmp0 = AstToLLVM(fun, bld, ast.args[2])
            tmp1 = bld.lshr(tmp0, ir.Constant(tmp0.type, ast.args[1]))
            tmp2 = bld.trunc(tmp1, ir.IntType(int(ast.args[0] - ast.args[1] + 1)))
            return tmp2
        elif ast.op == 'Not' or ast.op == '__invert__':
            return bld.not_(AstToLLVM(fun, bld, ast.args[0]))
        elif ast.op == '__add__':
            return bld.add(AstToLLVM(fun, bld, ast.args[0]),
                           AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == '__sub__':
            return bld.sub(AstToLLVM(fun, bld, ast.args[0]),
                           AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == '__mul__':
            return bld.mul(AstToLLVM(fun, bld, ast.args[0]),
                           AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == '__floordiv__' or ast.op == '__div__':
            return bld.sdiv(AstToLLVM(fun, bld, ast.args[0]),
                            AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == '__xor__':
            return bld.xor(AstToLLVM(fun, bld, ast.args[0]),
                           AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == '__or__':
            return bld.or_(AstToLLVM(fun, bld, ast.args[0]),
                           AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == '__and__' or ast.op == 'And':
            return bld.and_(AstToLLVM(fun, bld, ast.args[0]),
                            AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == '__lshift__':
            return bld.shl(AstToLLVM(fun, bld, ast.args[0]),
                           AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == '__ne__':
            return bld.icmp_unsigned("!=",
                    AstToLLVM(fun, bld, ast.args[0]),
                    AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == '__eq__':
            return bld.icmp_unsigned("==",
                    AstToLLVM(fun, bld, ast.args[0]),
                    AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == 'ULE':
            return bld.icmp_unsigned("<=",
                    AstToLLVM(fun, bld, ast.args[0]),
                    AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == 'UGE':
            return bld.icmp_unsigned(">=",
                    AstToLLVM(fun, bld, ast.args[0]),
                    AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == 'ULT':
            return bld.icmp_unsigned("<",
                    AstToLLVM(fun, bld, ast.args[0]),
                    AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == 'UGT':
            return bld.icmp_unsigned(">",
                    AstToLLVM(fun, bld, ast.args[0]),
                    AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == 'LShR':
            return bld.lshr(AstToLLVM(fun, bld, ast.args[0]),
                            AstToLLVM(fun, bld, ast.args[1]))
        elif ast.op == 'If':
            return bld.select(AstToLLVM(fun, bld, ast.args[0]),
                              AstToLLVM(fun, bld, ast.args[1]),
                              AstToLLVM(fun, bld, ast.args[2]))
        elif ast.op == 'Concat':
            curr = AstToLLVM(fun, bld, ast.args[0])
            for next in ast.args[1:]:
                tmp0 = AstToLLVM(fun, bld, next)
                next = bld.zext(tmp0, ir.IntType(tmp0.type.width + curr.type.width))
                curr = bld.zext(curr, ir.IntType(tmp0.type.width + curr.type.width))
                curr = bld.shl(curr, ir.Constant(curr.type, int(tmp0.type.width)))
                curr = bld.or_(curr, next)
            assert curr.type.width == ast.size()
            return curr
        else:
            raise NotImplementedError(ast.op)


def Z3ToLLVM(fun, bld, ast):
    pass


def LLVM(fun, bld, ast):
    return Z3ToLLVM(fun, bld, claripy.backends.z3.convert(ast))


def create_execution_engine():
    target = binding.Target.from_default_triple()
    target_machine = target.create_target_machine()
    backing_mod = binding.parse_assembly("")
    engine = binding.create_mcjit_compiler(backing_mod, target_machine)
    return engine


def compile_ir(engine, llvm_ir):
    mod = binding.parse_assembly(llvm_ir)
    mod.verify()
    engine.add_module(mod)
    engine.finalize_object()
    engine.run_static_constructors()
    return mod

