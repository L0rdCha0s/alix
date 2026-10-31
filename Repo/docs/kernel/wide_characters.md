# Native wide-character interfaces

Alix uses unsigned 16-bit `wchar_t`, 32-bit unsigned `wint_t`, and an 8-byte
`mbstate_t` containing two 32-bit fields. `WEOF` is outside the wchar range.
`include/wchar.h` and `include/wctype.h` declare the native interfaces; callers
and runtime objects must use the existing `-fshort-wchar` target ABI.

`user/lib/wchar.c` implements wide string/memory operations over arbitrary
16-bit code units, including surrogate values. Comparison is elementwise,
not bytewise. C/POSIX collation is code-unit order, with an identity transform.
Classification and case mapping implement the installed ASCII C/POSIX locale;
non-ASCII values have no character class and remain unchanged by case mapping.
This does not claim Unicode classification or UTF-8 locale support.

Multibyte conversion accepts exactly bytes/code units 0 through 127. Other
values fail with `EILSEQ` without writing the offending output element. The
encoding is stateless: valid states are zero, an incomplete zero-byte call does
not accumulate bytes, and explicit nonzero invalid states fail with `EINVAL`.
NULL-source `mbrtowc` resets and returns zero without touching its output;
NULL-output `wcrtomb` resets and returns one, ignoring the supplied character.
Functions with implicit state use thread-local storage.

Restartable string conversions honor source and destination bounds. Completion
sets the source pointer to NULL only when the terminator is converted; a full
destination leaves it at the next unconverted unit. An encoding error leaves
it at the offending unit. NULL-destination length queries ignore destination
capacity, respect an explicit source bound and preserve the source pointer.
No output terminator is included in the returned count.

Wide integer conversion uses the real native narrow integer parsers and maps
the end pointer back to wide input. A non-ASCII unit terminates numeric grammar;
it does not cause a multibyte conversion error. Floating wrappers live in
`user/lib/wcstofloat.c` and link with the optional real LLVM narrow floating
parser in `libalix-cxx-support.a`. They are not unresolved dependencies of the
ordinary C runtime. Allocation failure is reported with `ENOMEM`.

`wcsftime` preserves raw wide literal units and delegates formatting directives
to the real C-locale calendar formatter. Non-ASCII bytes produced by a directive
cannot be decoded in the current locale and cause `EILSEQ`. Wide FILE operations
and printf-family implementations are separate in the stdio work; declarations
alone do not establish implementation or runtime acceptance of those APIs.

`python3 tests/wchar_contract_test.py` executes production code with real
16-bit wchar objects under ASan/UBSan. It checks all 65,536 code units, all byte
values, classification, encoding errors, state resets, source pointers,
overlapping moves, element ordering, guard-page boundaries, integer/floating
parsing, formatting and allocation failure. Host symbol/type names are
namespaced so the test never calls macOS's incompatible 32-bit wide ABI.

`tests/wchar_test.c` is the native eight-CPU fixture, requiring
`WCHAR_TEST: PASS workers=8 cpu_mask=0xFF codeunits=65536 ascii=1 guards=1 pointers=1`.
`tests/wchar_float_test.c` additionally requires the optional numeric archive
and checks actual 80-bit extended precision through `wcstold`. Host checks and
cross-compilation do not replace executing these fixtures inside Alix.
