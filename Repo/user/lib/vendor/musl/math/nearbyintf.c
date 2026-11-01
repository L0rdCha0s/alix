#include <fenv.h>
#include <math.h>

float nearbyintf(float x)
{
	/* Alix preserves the native signaling-NaN/invalid contract. */
	if (isnan(x)) return x + x;
#ifdef FE_INEXACT
	#pragma STDC FENV_ACCESS ON
	int e;

	e = fetestexcept(FE_INEXACT);
#endif
	x = rintf(x);
#ifdef FE_INEXACT
	if (!e)
		feclearexcept(FE_INEXACT);
#endif
	return x;
}
