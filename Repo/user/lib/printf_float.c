/* Floating formatting adapted from musl v1.2.5 src/stdio/vfprintf.c.
 * Copyright (c) 2005-2020 Rich Felker, et al. MIT; see printf_float_LICENSE.txt.
 * Upstream SHA256: 5ae7748a197b3c334f2b6791f8613940f27d3bac6f27bcfa73706222fff4ffa8
 * Alix changes: callback sink, heap-owned workspace, int64 precision arithmetic
 * and padding without signed-int overflow. No host formatting implementation.
 */
#include "printf_float.h"
#include "stdlib.h"
#include "errno.h"
#include "math.h"
#include <stdint.h>
#include <limits.h>
#include <float.h>

#define MAX(a,b) ((a)>(b) ? (a) : (b))
#define MIN(a,b) ((a)<(b) ? (a) : (b))
#define ALT_FORM ALIX_PRINTF_ALT
#define ZERO_PAD ALIX_PRINTF_ZERO
#define LEFT_ADJ ALIX_PRINTF_LEFT
#define PAD_POS ALIX_PRINTF_SPACE
#define MARK_POS ALIX_PRINTF_PLUS
#define PRINTF_FLOAT_BIG_WORDS ((LDBL_MANT_DIG+28)/29 + 1 + (LDBL_MAX_EXP+LDBL_MANT_DIG+28+8)/9)

#if LDBL_MANT_DIG == 53
_Static_assert(sizeof(long double) == sizeof(double), "long-double ABI must match compiler constants");
#endif

typedef struct
{
    alix_printf_float_output_t output;
    uint32_t big[PRINTF_FLOAT_BIG_WORDS];
    char buffer[9 + LDBL_MANT_DIG/4];
    char exponent[3 * sizeof(int)];
} printf_float_work_t;

static void out(printf_float_work_t *work, const char *data, size_t length)
{
    work->output.write(work->output.context, data, length);
}

static void pad(printf_float_work_t *work, char character, int width, int length, int flags)
{
    if ((flags & (LEFT_ADJ | ZERO_PAD)) || length >= width) return;
    work->output.pad(work->output.context, character, width - length);
}

static const char xdigits[] = "0123456789ABCDEF";
static char *fmt_u(uintmax_t value, char *end)
{
    while (value) { *--end = (char)('0' + value % 10); value /= 10; }
    return end;
}

static int printf_float_core(printf_float_work_t *f, long double y, int w, int precision, int fl, int t)
{
	int64_t p = precision; /* %g adjusts precision by a possibly negative exponent. */
	uint32_t *big = f->big;
	uint32_t *a, *d, *r, *z;
	int e2=0, e, i, l;
	int64_t j; /* Precision minus a negative exponent must not overflow int. */
	char *buf = f->buffer, *s;
	const char *prefix="-0X+0X 0X-0x+0x 0x";
	int pl;
	char *ebuf = f->exponent + sizeof(f->exponent), *estr;

	pl=1;
	if (signbit(y)) {
		y=-y;
	} else if (fl & MARK_POS) {
		prefix+=3;
	} else if (fl & PAD_POS) {
		prefix+=6;
	} else prefix++, pl=0;

	if (!isfinite(y)) {
		char *s = (t&32)?"inf":"INF";
		if (y!=y) s=(t&32)?"nan":"NAN";
		pad(f, ' ', w, 3+pl, fl&~ZERO_PAD);
		out(f, prefix, pl);
		out(f, s, 3);
		pad(f, ' ', w, 3+pl, fl^LEFT_ADJ);
		return MAX(w, 3+pl);
	}

	y = frexpl(y, &e2) * 2;
	if (y) e2--;

	if ((t|32)=='a') {
		long double round = 8.0;
		int re;

		if (t&32) prefix += 9;
		pl += 2;

		if (p<0 || p>=LDBL_MANT_DIG/4-1) re=0;
		else re=LDBL_MANT_DIG/4-1-p;

		if (re) {
			round *= 1<<(LDBL_MANT_DIG%4);
			while (re--) round*=16;
			if (*prefix=='-') {
				y=-y;
				y-=round;
				y+=round;
				y=-y;
			} else {
				y+=round;
				y-=round;
			}
		}

		estr=fmt_u(e2<0 ? -e2 : e2, ebuf);
		if (estr==ebuf) *--estr='0';
		*--estr = (e2<0 ? '-' : '+');
		*--estr = t+('p'-'a');

		s=buf;
		do {
			int x=y;
			*s++=xdigits[x]|(t&32);
			y=16*(y-x);
			if (s-buf==1 && (y||p>0||(fl&ALT_FORM))) *s++='.';
		} while (y);

		if (p > INT_MAX-2-(ebuf-estr)-pl)
			return -1;
		if (p && s-buf-2 < p)
			l = (p+2) + (ebuf-estr);
		else
			l = (s-buf) + (ebuf-estr);

		pad(f, ' ', w, pl+l, fl);
		out(f, prefix, pl);
		pad(f, '0', w, pl+l, fl^ZERO_PAD);
		out(f, buf, s-buf);
		pad(f, '0', l-(ebuf-estr)-(s-buf), 0, 0);
		out(f, estr, ebuf-estr);
		pad(f, ' ', w, pl+l, fl^LEFT_ADJ);
		return MAX(w, pl+l);
	}
	if (p<0) p=6;

	if (y) y *= 0x1p28, e2-=28;

	if (e2<0) a=r=z=big;
	else a=r=z=big+PRINTF_FLOAT_BIG_WORDS - LDBL_MANT_DIG - 1;

	do {
		*z = y;
		y = 1000000000*(y-*z++);
	} while (y);

	while (e2>0) {
		uint32_t carry=0;
		int sh=MIN(29,e2);
		for (d=z-1; d>=a; d--) {
			uint64_t x = ((uint64_t)*d<<sh)+carry;
			*d = x % 1000000000;
			carry = x / 1000000000;
		}
		if (carry) *--a = carry;
		while (z>a && !z[-1]) z--;
		e2-=sh;
	}
	while (e2<0) {
		uint32_t carry=0, *b;
		int sh=MIN(9,-e2), need=1+(p+LDBL_MANT_DIG/3U+8)/9;
		for (d=a; d<z; d++) {
			uint32_t rm = *d & ((1u<<sh)-1);
			*d = (*d>>sh) + carry;
			carry = (1000000000>>sh) * rm;
		}
		if (!*a) a++;
		if (carry) *z++ = carry;
		/* Avoid (slow!) computation past requested precision */
		b = (t|32)=='f' ? r : a;
		if (z-b > need) z = b+need;
		e2+=sh;
	}

	if (a<z) for (i=10, e=9*(r-a); *a>=(unsigned)i; i*=10, e++);
	else e=0;

	/* Perform rounding: j is precision after the radix (possibly neg) */
	j = (int64_t)p - ((t|32)!='f')*e - ((t|32)=='g' && p);
	if (j < 9*(z-r-1)) {
		uint32_t x;
		/* We avoid C's broken division of negative numbers */
		d = r + 1 + ((j+9*LDBL_MAX_EXP)/9 - LDBL_MAX_EXP);
		j += 9*LDBL_MAX_EXP;
		j %= 9;
		for (i=10, j++; j<9; i*=10, j++);
		x = *d % i;
		/* Are there any significant digits past j? */
		if (x || d+1!=z) {
			long double round = 2/LDBL_EPSILON;
			long double small;
			if ((*d/i & 1) || (i==1000000000 && d>a && (d[-1]&1)))
				round += 2;
			if (x<(unsigned)i/2) small=0x0.8p0;
			else if (x==(unsigned)i/2 && d+1==z) small=0x1.0p0;
			else small=0x1.8p0;
			if (pl && *prefix=='-') round*=-1, small*=-1;
			*d -= x;
			/* Decide whether to round by probing round+small */
			if (round+small != round) {
				*d = *d + i;
				while (*d > 999999999) {
					*d--=0;
					if (d<a) *--a=0;
					(*d)++;
				}
				for (i=10, e=9*(r-a); *a>=(unsigned)i; i*=10, e++);
			}
		}
		if (z>d+1) z=d+1;
	}
	for (; z>a && !z[-1]; z--);
	
	if ((t|32)=='g') {
		if (!p) p++;
		if (p>e && e>=-4) {
			t--;
			p-=e+1;
		} else {
			t-=2;
			p--;
		}
		if (!(fl&ALT_FORM)) {
			/* Count trailing zeros in last place */
			if (z>a && z[-1]) for (i=10, j=0; z[-1]%i==0; i*=10, j++);
			else j=9;
			if ((t|32)=='f')
				p = MIN(p,MAX(0,9*(z-r-1)-j));
			else
				p = MIN(p,MAX(0,9*(z-r-1)+e-j));
		}
	}
	if (p > INT_MAX-1-(p || (fl&ALT_FORM)))
		return -1;
	l = 1 + p + (p || (fl&ALT_FORM));
	if ((t|32)=='f') {
		if (e > INT_MAX-l) return -1;
		if (e>0) l+=e;
	} else {
		estr=fmt_u(e<0 ? -e : e, ebuf);
		while(ebuf-estr<2) *--estr='0';
		*--estr = (e<0 ? '-' : '+');
		*--estr = t;
		if (ebuf-estr > INT_MAX-l) return -1;
		l += ebuf-estr;
	}

	if (l > INT_MAX-pl) return -1;
	pad(f, ' ', w, pl+l, fl);
	out(f, prefix, pl);
	pad(f, '0', w, pl+l, fl^ZERO_PAD);

	if ((t|32)=='f') {
		if (a>r) a=r;
		for (d=a; d<=r; d++) {
			char *s = fmt_u(*d, buf+9);
			if (d!=a) while (s>buf) *--s='0';
			else if (s==buf+9) *--s='0';
			out(f, s, buf+9-s);
		}
		if (p || (fl&ALT_FORM)) out(f, ".", 1);
		for (; d<z && p>0; d++, p-=9) {
			char *s = fmt_u(*d, buf+9);
			while (s>buf) *--s='0';
			out(f, s, MIN(9,p));
		}
		if (p > 0) f->output.pad(f->output.context, '0', p);
	} else {
		if (z<=a) z=a+1;
		for (d=a; d<z && p>=0; d++) {
			char *s = fmt_u(*d, buf+9);
			if (s==buf+9) *--s='0';
			if (d!=a) while (s>buf) *--s='0';
			else {
				out(f, s++, 1);
				if (p>0||(fl&ALT_FORM)) out(f, ".", 1);
			}
			out(f, s, MIN(buf+9-s, p));
			p -= buf+9-s;
		}
		if (p > 0) f->output.pad(f->output.context, '0', p);
		out(f, estr, ebuf-estr);
	}

	pad(f, ' ', w, pl+l, fl^LEFT_ADJ);

	return MAX(w, pl+l);
}

int alix_printf_float(const alix_printf_float_output_t *output, long double value,
                      int width, int precision, unsigned flags, char conversion)
{
    printf_float_work_t *work = calloc(1, sizeof(*work));
    if (!work) { errno = ENOMEM; return -1; }
    work->output = *output;
    if (flags & ALIX_PRINTF_LEFT) flags &= ~ALIX_PRINTF_ZERO;
    int result = printf_float_core(work, value, width, precision, (int)flags, conversion);
    free(work);
    if (result < 0) errno = EOVERFLOW;
    return result;
}
