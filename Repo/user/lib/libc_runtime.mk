# Native C11 runtime. All third-party sources are pinned and vendored.
USER_MUSL_DIR := user/lib/vendor/musl
USER_MUSL_MATH_NAMES := __cos.c __cosdf.c __cosl.c __expo2.c __expo2f.c __fpclassify.c __fpclassifyf.c \
	__fpclassifyl.c __invtrigl.c __math_divzero.c __math_divzerof.c __math_invalid.c __math_invalidf.c __math_invalidl.c \
	__math_oflow.c __math_oflowf.c __math_uflow.c __math_uflowf.c __math_xflow.c __math_xflowf.c __polevll.c \
	__rem_pio2.c __rem_pio2_large.c __rem_pio2f.c __rem_pio2l.c __signbit.c __signbitf.c __signbitl.c \
	__sin.c __sindf.c __sinl.c __tan.c __tandf.c __tanl.c acos.c \
	acosf.c acosh.c acoshf.c acoshl.c acosl.c asin.c asinf.c \
	asinh.c asinhf.c asinhl.c asinl.c atan.c atan2.c atan2f.c \
	atan2l.c atanf.c atanh.c atanhf.c atanhl.c atanl.c cbrt.c \
	cbrtf.c cbrtl.c ceil.c ceilf.c ceill.c copysign.c copysignf.c \
	copysignl.c cos.c cosf.c cosh.c coshf.c coshl.c cosl.c \
	erf.c erff.c erfl.c exp.c exp2.c exp2f.c exp2f_data.c \
	exp2l.c exp_data.c expf.c expl.c expm1.c expm1f.c expm1l.c \
	fabs.c fabsf.c fabsl.c fdim.c fdimf.c fdiml.c floor.c \
	floorf.c floorl.c fma.c fmaf.c fmal.c fmax.c fmaxf.c \
	fmaxl.c fmin.c fminf.c fminl.c fmod.c fmodf.c fmodl.c \
	frexp.c frexpf.c hypot.c hypotf.c hypotl.c ilogb.c \
	ilogbf.c ilogbl.c ldexp.c ldexpf.c ldexpl.c lgamma.c lgamma_r.c \
	lgammaf.c lgammaf_r.c lgammal.c llrint.c llrintf.c llrintl.c llround.c \
	llroundf.c llroundl.c log.c log10.c log10f.c log10l.c log1p.c \
	log1pf.c log1pl.c log2.c log2_data.c log2f.c log2f_data.c log2l.c \
	log_data.c logb.c logbf.c logbl.c logf.c logf_data.c logl.c \
	lrint.c lrintf.c lrintl.c lround.c lroundf.c lroundl.c modf.c \
	modff.c modfl.c nan.c nanf.c nanl.c nearbyint.c nearbyintf.c \
	nearbyintl.c nextafter.c nextafterf.c nextafterl.c nexttoward.c nexttowardf.c nexttowardl.c \
	pow.c pow_data.c powf.c powf_data.c powl.c remainder.c remainderf.c \
	remainderl.c remquo.c remquof.c remquol.c rint.c rintf.c rintl.c \
	round.c roundf.c roundl.c scalbln.c scalblnf.c scalblnl.c scalbn.c \
	scalbnf.c scalbnl.c signgam.c sin.c sincos.c sincosf.c sincosl.c \
	sinf.c sinh.c sinhf.c sinhl.c sinl.c sqrt.c sqrt_data.c \
	sqrtf.c sqrtl.c tan.c tanf.c tanh.c tanhf.c tanhl.c \
	tanl.c tgamma.c tgammaf.c tgammal.c trunc.c truncf.c truncl.c
USER_MUSL_COMPLEX_REPLACED := cacoshl casinhl catanhl cacosl casinl catanl ccoshl csinhl ctanhl cexpl clogl csqrtl
USER_MUSL_SOURCES := $(addprefix $(USER_MUSL_DIR)/math/,$(USER_MUSL_MATH_NAMES))
USER_MUSL_SOURCES += $(filter-out $(addprefix $(USER_MUSL_DIR)/complex/,$(addsuffix .c,$(USER_MUSL_COMPLEX_REPLACED))),$(wildcard $(USER_MUSL_DIR)/complex/*.c))
USER_MUSL_OBJECTS := $(patsubst user/%.c,$(USER_OBJDIR)/%.o,$(USER_MUSL_SOURCES))
USER_SCAN_SOURCES := $(wildcard $(USER_MUSL_DIR)/scan/*.c)
USER_SCAN_OBJECTS := $(patsubst user/%.c,$(USER_OBJDIR)/%.o,$(USER_SCAN_SOURCES))
USER_FREEBSD_SOURCES := $(wildcard user/lib/vendor/freebsd/*.c)
USER_FREEBSD_OBJECTS := $(patsubst user/%.c,$(USER_OBJDIR)/%.o,$(USER_FREEBSD_SOURCES))
USER_C11_NAMES := fenv threads stdlib_extra uchar scanf wcstofloat stdio_files math_errno atomic tempfile
USER_C11_OBJECTS := $(addprefix $(USER_OBJDIR)/lib/,$(addsuffix .o,$(USER_C11_NAMES)))
USER_COMPILER_COMPLEX := $(USER_OBJDIR)/lib/compiler_complex.o
USER_PRNG_OBJECT := $(USER_OBJDIR)/lib/vendor/musl/prng/random.o
USER_COMMON_OBJECTS += $(USER_MUSL_OBJECTS) $(USER_SCAN_OBJECTS) $(USER_FREEBSD_OBJECTS) $(USER_C11_OBJECTS) $(USER_COMPILER_COMPLEX) $(USER_PRNG_OBJECT)
USER_NUMERIC_FLAGS := -fno-strict-aliasing -O2 -frounding-math -ffp-contract=off -Wno-unused-but-set-variable -Wno-parentheses -Wno-unknown-pragmas

$(USER_MUSL_OBJECTS) $(USER_SCAN_OBJECTS) $(USER_FREEBSD_OBJECTS): user/lib/libc_runtime.mk
$(USER_PRNG_OBJECT): user/lib/vendor/musl/prng/random.c include/alix_mutex.h
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c -o $@ $<
$(USER_OBJDIR)/lib/vendor/musl/%.o: user/lib/vendor/musl/%.c
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) $(USER_NUMERIC_FLAGS) -I$(USER_MUSL_DIR)/internal -include $(USER_MUSL_DIR)/internal/alix_musl.h -c -o $@ $<
$(USER_OBJDIR)/lib/vendor/musl/scan/%.o: user/lib/vendor/musl/scan/%.c
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) $(USER_NUMERIC_FLAGS) -I$(USER_MUSL_DIR)/scan -c -o $@ $<
$(USER_OBJDIR)/lib/vendor/freebsd/%.o: user/lib/vendor/freebsd/%.c
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) $(USER_NUMERIC_FLAGS) -Iuser/lib/vendor/freebsd -I$(USER_MUSL_DIR)/internal -include $(USER_MUSL_DIR)/internal/alix_musl.h -c -o $@ $<
$(USER_OBJDIR)/lib/vendor/musl/math/sqrtf.o: USER_CFLAGS += -Dsqrtf=__alix_sqrtf
$(USER_OBJDIR)/lib/vendor/musl/math/scalbnf.o: USER_CFLAGS += -Dscalbnf=__alix_scalbnf
$(USER_COMPILER_COMPLEX): user/lib/libc_runtime.mk
	@mkdir -p $(dir $@)
	$(LD) -r -o $@ --undefined=__mulsc3 --undefined=__muldc3 --undefined=__mulxc3 --undefined=__divsc3 --undefined=__divdc3 --undefined=__divxc3 $(shell $(CC) -print-libgcc-file-name)

$(USER_OBJDIR)/tests/libc_complete_test.o: tests/libc_complete_test.c Makefile user/lib/libc_runtime.mk
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -frounding-math -c -o $@ $<
$(USER_OBJDIR)/libc_complete_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/libc_complete_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/libc_complete_test.o
.PHONY: libc-runtime-objects libc-runtime-manifest libc-complete-test
libc-runtime-objects: $(USER_COMMON_OBJECTS)
libc-runtime-manifest:
	@python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' $(USER_COMMON_OBJECTS)
libc-complete-test: $(USER_OBJDIR)/libc_complete_test.elf

.PHONY: libc-api-test libc-complete-qemu-test
libc-api-test: libc-runtime-objects
	python3 tests/libc_c11_api_test.py
libc-complete-qemu-test: all libc-complete-test $(USER_OBJDIR)/libc_complete_owned_test.elf
	python3 tests/libc_complete_qemu_test.py
