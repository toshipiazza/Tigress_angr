import claripy

from z3       import *
from llvmlite import ir
from llvmlite import binding

binding.initialize()
binding.initialize_native_target()
binding.initialize_native_asmprinter()
binding.load_library_permanently('libgcc_s.so.1')


def Z3ToLLVM(fun, bld, ast):
    return ir.Constant(ir.IntType(64), 1)


def LLVM(fun, bld, ast):
    z = claripy.backends.z3.convert(ast)
    z = simplify(z) # TODO: is this useful?
    return Z3ToLLVM(fun, bld, z)


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
