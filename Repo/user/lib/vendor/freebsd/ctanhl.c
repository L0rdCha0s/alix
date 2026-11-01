/* origin: FreeBSD /usr/src/lib/msun/src/s_ctanh.c */
/*-
 * Copyright (c) 2011 David Schultz
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
 * Hyperbolic tangent of a complex argument z = x + i y.
 *
 * The algorithm is from:
 *
 *   W. Kahan.  Branch Cuts for Complex Elementary Functions or Much
 *   Ado About Nothing's Sign Bit.  In The State of the Art in
 *   Numerical Analysis, pp. 165 ff.  Iserles and Powell, eds., 1987.
 *
 * Method:
 *
 *   Let t    = tanl(x)
 *       beta = 1/cosl^2(y)
 *       s    = sinhl(x)
 *       rho  = coshl(x)
 *
 *   We have:
 *
 *   tanh(z) = sinhl(z) / coshl(z)
 *
 *             sinhl(x) cosl(y) + i coshl(x) sinl(y)
 *           = ---------------------------------
 *             coshl(x) cosl(y) + i sinhl(x) sinl(y)
 *
 *             coshl(x) sinhl(x) / cosl^2(y) + i tanl(y)
 *           = -------------------------------------
 *                    1 + sinhl^2(x) / cosl^2(y)
 *
 *             beta rho s + i t
 *           = ----------------
 *               1 + beta s^2
 *
 * Modifications:
 *
 *   I omitted the original algorithm's handling of overflow in tanl(x) after
 *   verifying with nearpi.c that this can't happen in IEEE single or long double
 *   precision.  I also handle large x differently.
 */

#include "alix_freebsd.h"
#include "k_expl.h"

long double complex ctanhl(long double complex z)
{
	long double x, y;
	long double t, beta, s, rho, denom;

	x = creall(z);
	y = cimagl(z);


	/*
	 * ctanhl(NaN + i 0) = NaN + i 0
	 *
	 * ctanhl(NaN + i y) = NaN + i NaN               for y != 0
	 *
	 * The imaginary part has the sign of x*sinl(2*y), but there's no
	 * special effort to get this right.
	 *
	 * ctanhl(+-Inf +- i Inf) = +-1 +- 0
	 *
	 * ctanhl(+-Inf + i y) = +-1 + 0 sinl(2y)         for y finite
	 *
	 * The imaginary part of the sign is unspecified.  This special
	 * case is only needed to avoid a spurious invalid exception when
	 * y is infinite.
	 */
	if (!isfinite(x)) {
		if (isnan(x))        /* x is NaN */
			return CMPLXL(x, (y == 0 ? y : x * y));
		x = copysignl(1, x);      /* x = copysignl(1, x) */
		return CMPLXL(x, copysignl(0, isinf(y) ? y : sinl(y) * cosl(y)));
	}

	/*
	 * ctanhl(+-0 + i NAN) = +-0 + i NaN
	 * ctanhl(+-0 +- i Inf) = +-0 + i NaN
	 * ctanhl(x + i NAN) = NaN + i NaN
	 * ctanhl(x +- i Inf) = NaN + i NaN
	 */
	if (!isfinite(y))
		return CMPLXL(x ? y - y : x, y - y);

	/*
	 * ctanhl(+-huge + i +-y) ~= +-1 +- i 2sin(2y)/expl(2x), using the
	 * approximation sinhl^2(huge) ~= expl(2*huge) / 4.
	 * We use a modified formula to avoid spurious overflow.
	 */
	if (fabsl(x) >= 25) { /* x >= 22 */
		long double exp_mx = expl(-fabsl(x));
		return CMPLXL(copysignl(1, x), 4 * sinl(y) * cosl(y) * exp_mx * exp_mx);
	}

	/* Kahan's algorithm */
	t = tanl(y);
	beta = 1.0 + t * t;     /* = 1 / cosl^2(y) */
	s = sinhl(x);
	rho = sqrtl(1 + s * s);  /* = coshl(x) */
	denom = 1 + beta * s * s;
	return CMPLXL((beta * rho * s) / denom, t / denom);
}
