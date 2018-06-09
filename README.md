Tigress Protection
==================

Another partial solution to the Tigress protection [challenges][tigress], inspired by the
work done by Jonathan Salwan and Quarkslab, [here][Quarkslab]. Whereas Quarkslab's
solution relies on Triton, ours is implemented via angr and llvmlite.

Samples and challenges are taken directly from the [aforementioned][Quarkslab] repository
as well.

In summary, the script runs in two phases:

1. angr explores until there are no more paths to explore; we should end up with multiple
   deadended paths.
2. For each deadended path, we emit an if-then construct in llvm of the following form:
    ```
    if path_predicate_1(input): return hash_1(input)
    if path_predicate_2(input): return hash_2(input)
    unreachable()
    ```
    where `path_predicate_[1-2]` and `hash_[1-2]` are SMT equations.

Note: this currently solves tigress challenges 0 and 1; challenge 2 requires angr to
support `rt_sigreturn` and other yet-unsupported system calls, and challenges 3 and up
have not been tested.

## Installation

angr is required, which runs best in a virtual environment. llvmlite as of this writing
requires llvm-6.0; it may be possible that [this][llvmpatch] patch is required as well.

## How to Run

In order deobfuscate a binary (for example, tigress-0-challenge-2), use the following
command:

```
$ ./tigress.py ./tigress-challenges/tigress-0-challenge-2
```

This will create two files in the `output` directory: `tigress-0-challenge-2.ll` and
`tigress-0-challenge-2.o`. You may compile the given object file against the template.c
file for a fully functioning binary.

In order to verify the deobfuscated binary, Quarkslab employs a simple fuzzing technique.
Instead, for each "deadended" path found by angr, we use z3 to generate a number of inputs
to reach that path and verify this against the obfuscated binary. With this we achieve
100% branch coverage :)

```
$ ./testing_equality.py tigress-challenges/tigress-0-challenge-2 output/tigress-0-challenge-2
```

## Musings and Random Thoughts

Some thoughts, in no particular order:

- Quarkslab's solution only deobfuscates the binary perfectly if there exists at most one
  symbolic branch--it takes one path, and then visits the other branch afterwards by
  inverting the path predicate. If Quarkslab's solution instead used a worklist algorithm,
  it would pretty much converge to our solution (XREF: samples/sample_multiple_paths)
- Triton concretizes symbolic reads and writes; in hashes which require symbolic memory I
  would expect Quarkslab's solution to break. angr reportedly uses a similar algorithm to
  Mayhem, which concretizes symbolic writes, but handles symbolic reads up to a point, so
  it *should* theoretically handle more hash functions :)
    - If this is still a concern, i.e. symbolic writes need to be handled to maintain
      correctness of a hash algorithm, we can use the memsight plugin for angr, for
      example, which handles memory fully symbolically.
    - XREF: samples/sample_symbolic_memory_easy and samples/sample_symbolic_memory_hard,
      which exhibit code sequences which perform symbolic reads. One of the algorithms is
      a straight up crc32

[tigress]: tigress.cs.arizona.edu
[Quarkslab]: https://github.com/JonathanSalwan/Tigress_protection
[llvmpatch]: https://github.com/numba/llvmlite/blob/master/conda-recipes/0001-Transforms-Add-missing-header-for-InstructionCombini.patch
