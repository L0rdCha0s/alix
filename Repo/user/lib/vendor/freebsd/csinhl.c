/* origin: FreeBSD /usr/src/lib/msun/src/s_csinh.c */
/*-
 * Copyright (c) 2005 Bruce D. Evans and Steven G. Kargl
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Hyperbolic sine of a complex argument z = x + i y.
 *
 * sinhl(z) = sinhl(x+iy)
 *         = sinhl(x) cosl(y) + i coshl(x) sinl(y).
 *
 * Exceptional values are noted in the comments within the source code.
 * These values and the return value were taken from n1124.pdf.
 */

#include "alix_freebsd.h"
#include "k_expl.h"

static const long double huge = 0x1p16383L;

long double complex csinhl(long double complex z)
{
	long double x, y, h;

	x = creall(z);
	y = cimagl(z);



	/* Handle the nearly-non-exceptional cases where x and y are finite. */
	if (isfinite(x) && isfinite(y)) {
		if (y == 0)
			return CMPLXL(sinhl(x), y);
		if (fabsl(x) < 25)    /* small x: normal case */
			return CMPLXL(sinhl(x) * cosl(y), coshl(x) * sinl(y));

		/* |x| >= 22, so coshl(x) ~= expl(|x|) */
		if (fabsl(x) < 11356.0L) {
			/* x < 710: expl(|x|) won't overflow */
			h = expl(fabsl(x)) * 0.5;
			return CMPLXL(copysignl(h, x) * cosl(y), h * sinl(y));
		} else if (fabsl(x) < 22755.0L) {
			/* x < 1455: scale to avoid overflow */
			z = __ldexp_cexpl(CMPLXL(fabsl(x), y), -1);
			return CMPLXL(creall(z) * copysignl(1, x), cimagl(z));
		} else {
			/* x >= 1455: the result always overflows */
			h = huge * x;
			return CMPLXL(h * cosl(y), h * h * sinl(y));
		}
	}

	/*
	 * sinhl(+-0 +- I Inf) = sign(d(+-0, dNaN))0 + I dNaN.
	 * The sign of 0 in the result is unspecified.  Choice = normally
	 * the same as dNaN.  Raise the invalid floating-point exception.
	 *
	 * sinhl(+-0 +- I NaN) = sign(d(+-0, NaN))0 + I d(NaN).
	 * The sign of 0 in the result is unspecified.  Choice = normally
	 * the same as d(NaN).
	 */
	if (x == 0 && !isfinite(y))
		return CMPLXL(copysignl(0, x * (y - y)), y - y);

	/*
	 * sinhl(+-Inf +- I 0) = +-Inf + I +-0.
	 *
	 * sinhl(NaN +- I 0)   = d(NaN) + I +-0.
	 */
	if (y == 0 && !isfinite(x)) {
		if (!isnan(x))
			return CMPLXL(x, y);
		return CMPLXL(x, copysignl(0, y));
	}

	/*
	 * sinhl(x +- I Inf) = dNaN + I dNaN.
	 * Raise the invalid floating-point exception for finite nonzero x.
	 *
	 * sinhl(x + I NaN) = d(NaN) + I d(NaN).
	 * Optionally raises the invalid floating-point exception for finite
	 * nonzero x.  Choice = don't raise (except for signaling NaNs).
	 */
	if (isfinite(x) && !isfinite(y))
		return CMPLXL(y - y, x * (y - y));

	/*
	 * sinhl(+-Inf + I NaN)  = +-Inf + I d(NaN).
	 * The sign of Inf in the result is unspecified.  Choice = normally
	 * the same as d(NaN).
	 *
	 * sinhl(+-Inf +- I Inf) = +Inf + I dNaN.
	 * The sign of Inf in the result is unspecified.  Choice = always +.
	 * Raise the invalid floating-point exception.
	 *
	 * sinhl(+-Inf + I y)   = +-Inf cosl(y) + I Inf sinl(y)
	 */
	if (!isfinite(x) && !isnan(x)) {
		if (!isfinite(y))
			return CMPLXL(x * x, x * (y - y));
		return CMPLXL(x * cosl(y), INFINITY * sinl(y));
	}

	/*
	 * sinhl(NaN + I NaN)  = d(NaN) + I d(NaN).
	 *
	 * sinhl(NaN +- I Inf) = d(NaN) + I d(NaN).
	 * Optionally raises the invalid floating-point exception.
	 * Choice = raise.
	 *
	 * sinhl(NaN + I y)    = d(NaN) + I d(NaN).
	 * Optionally raises the invalid floating-point exception for finite
	 * nonzero y.  Choice = don't raise (except for signaling NaNs).
	 */
	return CMPLXL((x * x) * (y - y), (x + x) * (y - y));
}
