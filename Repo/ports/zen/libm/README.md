# Native Alix math runtime

The ordinary Alix C runtime now supplies all 171 ISO C11 real math functions,
all 66 complex functions, and the full floating-point environment API. Float,
double and native x87 80-bit long double use their own implementations.
`user/lib/libc_runtime.mk` integrates the numeric objects into USER_COMMON;
ordinary `make` needs no download, LLVM checkout or host math archive.

Portable sources are pinned to musl 1.2.5. FreeBSD releng/14.2 implementations
replace incomplete extended complex inverse, logarithm, exponential and square
root functions. Extended hyperbolic algorithms preserve the upstream special
cases while replacing binary64 classifications with ld80 classifications.
Native `frexpl` remains in `user/lib/math.c`. Source hashes, adaptation notes
and copyright notices are retained under `user/lib/vendor/{musl,freebsd}`.

The library advertises `MATH_ERREXCEPT`. Native `sqrtf` and `scalbnf` also retain
the established errno behavior, including exact-subnormal scaling and directed
finite overflow results. No long-double function narrows its argument to double
on the native ABI. `float_t` and `double_t` follow `FLT_EVAL_METHOD`.

`make zen-math-runtime` packages the same vendored runtime into
`ports/zen/upstream/libm-alix-build/lib/libalix-math.a` for the existing Clang,
Rust and C++ integration. It no longer rebuilds a separate seven-function LLVM
implementation. The old LLVM adapter sources remain as historical comparison
fixtures; normal native links use the complete runtime.

Validation:

```sh
make libc-complete-test
python3 tests/libc_c11_api_test.py
python3 tests/libc_complete_qemu_test.py
```

The API gate checks compiled definitions and public declarations against the
496-function C11 inventory. The native fixture checks 708 independent numeric
vectors generated at 100 decimal digits with pinned mpmath 1.3.0, plus extended
precision/range, signed zero, exceptional values, fused cancellation, rounding
modes and FP-state isolation across eight explicitly pinned CPUs. Required
markers are `LIBC_MATH_VECTORS: PASS checks=708 precision=100` and
`LIBC_COMPLETE_TEST: PASS`, including `cpu_mask=0xFF`.

These checks establish the tested contracts; they are not an exhaustive
correct-rounding proof or formal ISO/IEC conformance certification. Optional
Annex K interfaces and POSIX/GNU completeness are outside this C11 inventory.
