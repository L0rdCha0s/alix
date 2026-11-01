#include <fenv.h>
#include <math.h>

/* nearbyint is the same as rint, but it must not raise the inexact exception */

double nearbyint(double x)
{
	/* Alix preserves the native signaling-NaN/invalid contract. */
	if (isnan(x)) return x + x;
#ifdef FE_INEXACT
	#pragma STDC FENV_ACCESS ON
	int e;

	e = fetestexcept(FE_INEXACT);
#endif
	x = rint(x);
#ifdef FE_INEXACT
	if (!e)
		feclearexcept(FE_INEXACT);
#endif
	return x;
}
