#include <math.h>
#include "libm.h"

_Thread_local int __signgam = 0;

weak_alias(__signgam, signgam);
