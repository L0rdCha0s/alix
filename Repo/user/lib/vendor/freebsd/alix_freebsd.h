#ifndef ALIX_FREEBSD_MATH_H
#define ALIX_FREEBSD_MATH_H
#include "complex_impl.h"
#define __unused __attribute__((unused))
#define ENTERI() ((void)0)
#define ENTERIT(type) ((void)0)
#define RETURNI(value) return (value)
#define nan_mix(x,y) (((x)+0.0L)+((y)+0))
#define GET_LDBL_EXPSIGN(out,value) do { union ldshape u_ = {.f=(value)}; (out)=u_.i.se; } while(0)
#define SET_LDBL_EXPSIGN(value,exponent) do { union ldshape u_ = {.f=(value)}; u_.i.se=(exponent); (value)=u_.f; } while(0)
#define EXTRACT_LDBL80_WORDS(exponent,mantissa,value) do { union ldshape u_ = {.f=(value)}; (exponent)=u_.i.se; (mantissa)=u_.i.m; } while(0)
#define rnintl(value) rintl(value)
#define irint(value) ((int)(value))
#define _2sumF(a,b) do { __typeof(a) w_ = (a)+(b); (b)=((a)-w_)+(b); (a)=w_; } while(0)
#define _2sum(a,b) do { __typeof(a) s_=(a)+(b), v_=s_-(a); (b)=((a)-(s_-v_))+((b)-v_); (a)=s_; } while(0)
void sincosl(long double, long double *, long double *);
#endif
