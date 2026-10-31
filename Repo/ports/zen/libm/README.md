# Native Alix libm

`make zen-math-runtime` builds the optional static native x86-64 archive
`ports/zen/upstream/libm-alix-build/lib/libalix-math.a`. The implementation
reuses LLVM libc at revision `ca7933e47d3a3451d81e72ac174dcb5aa28b59d1`;
it does not depend on libc++, Gecko, a host math archive or a Linux ABI.
Normal Alix `make` does not fetch or build the optional upstream source.

The archive currently exports `nearbyint[f/l]`, `sqrtf`, `fabsf`, `fabsl` and
`scalbnf`. Existing user-libm functions, including the real x87 `atan2l`, remain
in USER_COMMON. The public `float_t` and `double_t` declarations follow the
compiler's actual `FLT_EVAL_METHOD`, including x87 extended evaluation.

`ports/zen/toolchain/alix-clang` supplies this archive for both C and C++ links.
Ordinary Makefile C targets using GNU ld directly must append the archive after
their own objects, within their native libgcc group. USER_COMMON-only links do
not silently acquire optional numeric libraries. The Rust native linker also
supplies this archive and Cargo tracks its contents as an external link input.

The adapters in `user/lib/llvm_nearbyint.cpp` and `user/lib/llvm_math.cpp` reuse
LLVM's arithmetic and normalization. Nearby rounding gets the hardware mode
from native `fegetround` instead of LLVM's generic inexact arithmetic probe.
Float scaling bounds extreme exponents before the upstream general path,
preserving the mathematical result while generating real overflow/underflow
flags for directed finite endpoints. The POSIX wrappers set native thread-local
errno for domain/range errors and preserve it for exact subnormal scaling.
LLVM's private full-build fenv types/exception encoding do not cross the Alix
ABI. The two objects require only native `fegetround` and `__errno_location`.

Validation:

```sh
python3 tests/nearbyint_contract_test.py
SANITIZE=1 python3 tests/nearbyint_contract_test.py
python3 tests/math_support_contract_test.py
SANITIZE=1 python3 tests/math_support_contract_test.py
make zen-nearbyint-test zen-math-support-test
```

The nearbyint host suite passes 99,625 cases and the additional math suite
passes 99,644 cases, each with all four rounding modes. Native nearbyint already
passed 32,742 x87/SSE cases. The archive split is now accepted in Alix: the newly
linked support fixture passed 39,861 cases, nearbyint passed all 32,742 cases,
and the freshly linked C++ and eight-CPU Rust runtime fixtures also passed.
See `build/test-out/math-support-qemu.log` and `math-nearbyint-qemu.log`.
The support fixture compares scaling to actual x87 scaling plus float
conversion, checks extended absolute values, and validates special values,
errno and exception flags. Require both `MATH_NEARBYINT_TEST: PASS` and
`MATH_SUPPORT_TEST: PASS` when changing this native library.

Further libm additions should reuse the pinned subtree where supported.
Float/double transcendental functions need its range-reduction tables and
multiword helpers. The pinned generic sources do not provide 80-bit `sinl`,
`cosl`, `expl`, `logl` or `powl`; `atan2l.cpp` explicitly rejects extended
precision. Do not replace working extended-precision functions with narrowing
wrappers merely because a similarly named upstream file exists.
