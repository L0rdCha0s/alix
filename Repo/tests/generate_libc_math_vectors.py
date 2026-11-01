#!/usr/bin/env python3
"""Regenerate independent 100-digit numeric vectors (mpmath 1.3.0)."""
from pathlib import Path
import mpmath as mp

assert mp.__version__ == "1.3.0", "Use pinned mpmath 1.3.0 for reproducible fixtures"
mp.mp.dps = 100
OUT = Path(__file__).resolve().parent / 'fixtures/libc_math_vectors.h'
lines = ['/* Generated with mpmath 1.3.0 at 100 decimal digits. */',
         'static bool math_vector_tests(void)', '{', '    CHECK(fesetround(FE_TONEAREST)==0);']
checks = 0

def literal(value):
    text = mp.nstr(value, 45)
    if '.' not in text and 'e' not in text: text += '.0'
    return text + 'L'

def check(expression):
    global checks
    lines.append('    CHECK(' + expression + ');')
    checks += 1

kinds = [('f', 'float', '3e-6L', 'FLT_EPSILON'), ('', 'double', '1e-14L', 'DBL_EPSILON'),
         ('l', 'long double', '4e-18L', 'LDBL_EPSILON')]
unary = {
    'acos': ('acos', ['-0.75','-0.25','0','0.5','0.875']),
    'asin': ('asin', ['-0.75','-0.25','0','0.5','0.875']),
    'atan': ('atan', ['-3.5','-0.25','0','0.5','8']),
    'acosh': ('acosh', ['1','1.25','2','8']),
    'asinh': ('asinh', ['-3.5','-0.25','0','0.5','8']),
    'atanh': ('atanh', ['-0.75','-0.25','0','0.5','0.875']),
    'cos': ('cos', ['-3.5','-0.25','0','0.5','8']),
    'sin': ('sin', ['-3.5','-0.25','0','0.5','8']),
    'tan': ('tan', ['-3.5','-0.25','0','0.5','8']),
    'cosh': ('cosh', ['-3.5','-0.25','0','0.5','8']),
    'sinh': ('sinh', ['-3.5','-0.25','0','0.5','8']),
    'tanh': ('tanh', ['-3.5','-0.25','0','0.5','8']),
    'exp': ('exp', ['-3.5','-0.25','0','0.5','8']),
    'exp2': (lambda x: mp.power(2,x), ['-3.5','-0.25','0','0.5','8']),
    'expm1': ('expm1', ['-3.5','-0.25','0','0.5','8']),
    'log': ('log', ['0.125','0.5','1','1.25','8']),
    'log10': ('log10', ['0.125','0.5','1','1.25','8']),
    'log1p': ('log1p', ['-0.75','-0.25','0','0.5','8']),
    'log2': (lambda x:mp.log(x,2), ['0.125','0.5','1','1.25','8']),
    'cbrt': (lambda x: mp.sign(x)*mp.root(abs(x),3), ['-3.5','-0.25','0','0.5','8']),
    'fabs': (abs, ['-3.5','-0.25','0','0.5','8']),
    'sqrt': ('sqrt', ['0','0.25','0.5','1.25','8']),
    'erf': ('erf', ['-3.5','-0.25','0','0.5','8']),
    'erfc': ('erfc', ['-3.5','-0.25','0','0.5','8']),
    'lgamma': ('loggamma', ['0.125','0.5','1','1.25','8']),
    'tgamma': ('gamma', ['0.125','0.5','1','1.25','8']),
    'ceil': ('ceil', ['-3.5','-0.25','0','0.5','8']),
    'floor': ('floor', ['-3.5','-0.25','0','0.5','8']),
    'trunc': (lambda x:mp.floor(x) if x>=0 else mp.ceil(x), ['-3.5','-0.25','0','0.5','8']),
    'round': (lambda x:mp.sign(x)*mp.floor(abs(x)+mp.mpf('0.5')), ['-3.5','-0.25','0','0.5','8']),
    'nearbyint': ('nint', ['-3.5','-0.25','0','0.5','8']),
    'rint': ('nint', ['-3.5','-0.25','0','0.5','8']),
    'logb': (lambda x:mp.floor(mp.log(abs(x),2)), ['-3.5','-0.25','0.5','8']),
}
for name,(operation,values) in unary.items():
    fn = getattr(mp,operation) if isinstance(operation,str) else operation
    for text in values:
        x=mp.mpf(text); expected=literal(fn(x))
        for suffix,kind,tolerance,_ in kinds:
            check(f'close_to({name}{suffix}(({kind}){literal(x)}),{expected},{tolerance})')
binary = {'atan2':mp.atan2, 'hypot':lambda x,y:mp.sqrt(x*x+y*y), 'pow':mp.power,
          'fmod':lambda x,y:x-(mp.floor(x/y) if x/y>=0 else mp.ceil(x/y))*y,
          'remainder':lambda x,y:x-mp.nint(x/y)*y,
          'copysign':lambda x,y:abs(x)*mp.sign(y), 'fdim':lambda x,y:max(x-y,0),
          'fmax':max, 'fmin':min}
for name,fn in binary.items():
    for x,y in [(mp.mpf('1.25'),mp.mpf('0.5')),(mp.mpf('3.5'),mp.mpf('2.25'))]:
        for suffix,kind,tolerance,_ in kinds:
            check(f'close_to({name}{suffix}(({kind}){literal(x)},({kind}){literal(y)}),{literal(fn(x,y))},{tolerance})')
for suffix,kind,tolerance,epsilon in kinds:
    for name in ['lrint','llrint','lround','llround']:
        check(f'{name}{suffix}(({kind})-3.5)==-4')
    check(f'ilogb{suffix}(({kind})8)==3')
    for name in ['ldexp','scalbn','scalbln']:
        check(f'{name}{suffix}(({kind})1.25,5)==40')
    check(f'nextafter{suffix}(({kind})1,({kind})2)==({kind})1+{epsilon}')
    check(f'nexttoward{suffix}(({kind})1,2.0L)==({kind})1+{epsilon}')
    check(f'isnan(nan{suffix}("payload"))')
    check(f'fma{suffix}(({kind})1.25,({kind})2.5,({kind})-0.25)==({kind})2.875')
    lines += ['    {',f'        {kind} integral; int exponent;',
              f'        CHECK(frexp{suffix}(({kind})1.25,&exponent)==({kind})0.625 && exponent==1);',
              f'        CHECK(modf{suffix}(({kind})-3.5,&integral)==({kind})-0.5 && integral==({kind})-3);',
              f'        int quotient; CHECK(remquo{suffix}(({kind})7,({kind})2,&quotient)==({kind})-1 && (quotient&7)==4);', '    }']
    checks += 3
complex_ops = {'cacos':mp.acos,'casin':mp.asin,'catan':mp.atan,'ccos':mp.cos,'csin':mp.sin,'ctan':mp.tan,
               'cacosh':mp.acosh,'casinh':mp.asinh,'catanh':mp.atanh,'ccosh':mp.cosh,'csinh':mp.sinh,
               'ctanh':mp.tanh,'cexp':mp.exp,'clog':mp.log,'conj':mp.conj,'cproj':lambda z:z,
               'csqrt':mp.sqrt,'cpow':lambda z:mp.power(z,mp.mpc('1.5','-0.25'))}
for name,fn in complex_ops.items():
    for x,y in [('1.25','0.5'),('-0.25','1.5')]:
        z=mp.mpc(x,y); expected=fn(z)
        for suffix,kind,tolerance,_ in kinds:
            constructor={'f':'CMPLXF','':'CMPLX','l':'CMPLXL'}[suffix]
            extra=f',{constructor}(1.5,-0.25)' if name=='cpow' else ''
            expression=f'{name}{suffix}({constructor}({x},{y}){extra})'
            lines += ['    {',f'        {kind} complex value={expression};',
                      f'        CHECK(close_to(creal{suffix}(value),{literal(expected.real)},{tolerance}) && close_to(cimag{suffix}(value),{literal(expected.imag)},{tolerance}));','    }']
            checks += 1
for name,fn in {'cabs':abs,'carg':mp.arg,'creal':lambda z:z.real,'cimag':lambda z:z.imag}.items():
    z=mp.mpc('1.25','0.5')
    for suffix,kind,tolerance,_ in kinds:
        constructor={'f':'CMPLXF','':'CMPLX','l':'CMPLXL'}[suffix]
        check(f'close_to({name}{suffix}({constructor}(1.25,0.5)),{literal(fn(z))},{tolerance})')
lines += [f'    serial_printf("LIBC_MATH_VECTORS: PASS checks={checks} precision=100");','    return true;','}', '']
OUT.write_text('\n'.join(lines))
print(f'Generated {checks} independent numeric checks: {OUT}')
