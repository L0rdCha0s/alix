#include "wchar.h"
#include "errno.h"
#include "float.h"
#include "serial.h"

int main(void)
{
    wchar_t *end=NULL;errno=EDOM;
    if(sizeof(wchar_t)!=2 || LDBL_MANT_DIG!=64 ||
       wcstof(L"1.25!",&end)!=1.25f || *end!='!' || errno!=EDOM ||
       wcstod(L"-0x1.ap2!",&end)!=-6.5 || *end!='!' ||
       wcstold(L"0x1.000000000000001p0!",&end)!=1.0L+0x1p-60L || *end!='!')
    {
        serial_printf("WCHAR_FLOAT_TEST: FAIL numeric parser or native ABI\n");
        return 1;
    }
    serial_printf("WCHAR_FLOAT_TEST: PASS wchar_bits=16 long_double_mantissa=64 endptr=1\n");
    return 0;
}
