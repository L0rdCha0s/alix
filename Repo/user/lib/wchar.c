#include "wchar.h"
#include "wctype.h"
#include "errno.h"
#include "stdlib.h"
#include "string.h"
#include "stdint.h"

_Static_assert(sizeof(wchar_t) == 2 && (wchar_t)-1 > 0, "Alix wchar_t ABI is unsigned 16-bit");

size_t wcslen(const wchar_t *text) { const wchar_t *end=text; while(*end) ++end; return (size_t)(end-text); }
size_t wcsnlen(const wchar_t *text,size_t limit) { size_t n=0; while(n<limit && text[n]) ++n; return n; }
wchar_t *wmemcpy(wchar_t *out,const wchar_t *in,size_t count) { for(size_t i=0;i<count;++i) out[i]=in[i]; return out; }
wchar_t *wmemmove(wchar_t *out,const wchar_t *in,size_t count)
{
    if((uintptr_t)out<(uintptr_t)in) return wmemcpy(out,in,count);
    if(out!=in) while(count) { --count; out[count]=in[count]; }
    return out;
}
wchar_t *wmemset(wchar_t *out,wchar_t value,size_t count) { for(size_t i=0;i<count;++i) out[i]=value; return out; }
int wmemcmp(const wchar_t *a,const wchar_t *b,size_t count)
{
    for(size_t i=0;i<count;++i) if(a[i]!=b[i]) return a[i]<b[i] ? -1 : 1;
    return 0;
}
wchar_t *wmemchr(const wchar_t *text,wchar_t value,size_t count)
{
    for(size_t i=0;i<count;++i) if(text[i]==value) return (wchar_t *)(text+i);
    return NULL;
}
wchar_t *wcpcpy(wchar_t *out,const wchar_t *in) { while((*out=*in)!=0) { ++out; ++in; } return out; }
wchar_t *wcscpy(wchar_t *out,const wchar_t *in) { wcpcpy(out,in); return out; }
wchar_t *wcpncpy(wchar_t *out,const wchar_t *in,size_t count)
{
    if(!count) return out;
    size_t n=0;
    while(n<count && in[n]) { out[n]=in[n]; ++n; }
    wchar_t *end=out+n;
    while(n<count) out[n++]=0;
    return end;
}
wchar_t *wcsncpy(wchar_t *out,const wchar_t *in,size_t count) { wcpncpy(out,in,count); return out; }
wchar_t *wcscat(wchar_t *out,const wchar_t *in) { wcpcpy(out+wcslen(out),in); return out; }
wchar_t *wcsncat(wchar_t *out,const wchar_t *in,size_t count)
{
    wchar_t *end=out+wcslen(out);
    size_t n=0; while(n<count && in[n]) { end[n]=in[n]; ++n; }
    end[n]=0; return out;
}
int wcscmp(const wchar_t *a,const wchar_t *b) { while(*a && *a==*b) { ++a; ++b; } return *a==*b ? 0 : *a<*b ? -1 : 1; }
int wcsncmp(const wchar_t *a,const wchar_t *b,size_t count)
{
    for(size_t i=0;i<count;++i) { if(a[i]!=b[i]) return a[i]<b[i] ? -1 : 1; if(!a[i]) break; }
    return 0;
}
wchar_t *wcschr(const wchar_t *text,wchar_t value) { do { if(*text==value) return (wchar_t *)text; } while(*text++); return NULL; }
wchar_t *wcsrchr(const wchar_t *text,wchar_t value)
{
    const wchar_t *found=NULL;
    do { if(*text==value) found=text; } while(*text++);
    return (wchar_t *)found;
}
size_t wcsspn(const wchar_t *text,const wchar_t *accept) { size_t n=0; while(text[n] && wcschr(accept,text[n])) ++n; return n; }
size_t wcscspn(const wchar_t *text,const wchar_t *reject) { size_t n=0; while(text[n] && !wcschr(reject,text[n])) ++n; return n; }
wchar_t *wcspbrk(const wchar_t *text,const wchar_t *accept) { while(*text) { if(wcschr(accept,*text)) return (wchar_t *)text; ++text; } return NULL; }
wchar_t *wcsstr(const wchar_t *text,const wchar_t *needle)
{
    if(!*needle) return (wchar_t *)text;
    for(;*text;++text)
    {
        size_t n=0; while(needle[n] && text[n] && text[n]==needle[n]) ++n;
        if(!needle[n]) return (wchar_t *)text;
    }
    return NULL;
}
wchar_t *wcstok(wchar_t *text,const wchar_t *delimiters,wchar_t **saved)
{
    if(!saved) { errno=EINVAL; return NULL; }
    if(!text) text=*saved;
    if(!text) return NULL;
    text+=wcsspn(text,delimiters);
    if(!*text) { *saved=NULL; return NULL; }
    wchar_t *end=text+wcscspn(text,delimiters);
    if(*end) { *end=0; *saved=end+1; } else *saved=NULL;
    return text;
}
wchar_t *wcsdup(const wchar_t *text)
{
    size_t length=wcslen(text);
    if(length>=SIZE_MAX/sizeof(wchar_t)) { errno=ENOMEM; return NULL; }
    wchar_t *copy=malloc((length+1)*sizeof(*copy));
    if(!copy) { errno=ENOMEM; return NULL; }
    return wmemcpy(copy,text,length+1);
}
int wcscoll(const wchar_t *a,const wchar_t *b) { return wcscmp(a,b); }
size_t wcsxfrm(wchar_t *out,const wchar_t *in,size_t count)
{
    size_t length=wcslen(in);
    if(count) wmemcpy(out,in,length<count ? length+1 : count);
    return length;
}

static int wide_state_valid(const mbstate_t *state) { return !state || (!state->value && !state->count); }
static void wide_state_reset(mbstate_t *state) { if(state) { state->value=0; state->count=0; } }
int mbsinit(const mbstate_t *state) { return wide_state_valid(state); }
wint_t btowc(int byte) { return byte>=0 && byte<128 ? (wint_t)byte : WEOF; }
int wctob(wint_t value) { return value<128 ? (int)value : -1; }

size_t mbrtowc(wchar_t *out,const char *input,size_t size,mbstate_t *state)
{
    static _Thread_local mbstate_t internal;
    if(!state) state=&internal;
    if(!input) { wide_state_reset(state); return 0; }
    if(!wide_state_valid(state)) { errno=EINVAL; return (size_t)-1; }
    if(!size) return (size_t)-2;
    unsigned char byte=(unsigned char)*input;
    if(byte>=128) { errno=EILSEQ; return (size_t)-1; }
    if(out) *out=(wchar_t)byte;
    return byte ? 1 : 0;
}
size_t mbrlen(const char *input,size_t size,mbstate_t *state)
{
    static _Thread_local mbstate_t internal;
    return mbrtowc(NULL,input,size,state ? state : &internal);
}
size_t wcrtomb(char *out,wchar_t value,mbstate_t *state)
{
    static _Thread_local mbstate_t internal;
    if(!state) state=&internal;
    if(!out) { wide_state_reset(state); return 1; }
    if(!wide_state_valid(state)) { errno=EINVAL; return (size_t)-1; }
    if(value>=128) { errno=EILSEQ; return (size_t)-1; }
    *out=(char)value; return 1;
}

size_t mbsnrtowcs(wchar_t *out,const char **source,size_t bytes,size_t capacity,mbstate_t *state)
{
    static _Thread_local mbstate_t internal;
    if(!state) state=&internal;
    if(!source || (!*source && bytes) || !wide_state_valid(state)) { errno=EINVAL; return (size_t)-1; }
    const char *input=*source;
    size_t count=0;
    while(count<bytes && (!out || count<capacity))
    {
        unsigned char byte=(unsigned char)input[count];
        if(byte>=128) { if(out) *source=input+count; errno=EILSEQ; return (size_t)-1; }
        if(out) out[count]=(wchar_t)byte;
        if(!byte) { if(out) *source=NULL; return count; }
        ++count;
    }
    if(out && count) *source=input+count;
    return count;
}
size_t mbsrtowcs(wchar_t *out,const char **source,size_t capacity,mbstate_t *state)
{
    return mbsnrtowcs(out,source,SIZE_MAX,capacity,state);
}
size_t wcsnrtombs(char *out,const wchar_t **source,size_t characters,size_t capacity,mbstate_t *state)
{
    static _Thread_local mbstate_t internal;
    if(!state) state=&internal;
    if(!source || (!*source && characters) || !wide_state_valid(state)) { errno=EINVAL; return (size_t)-1; }
    const wchar_t *input=*source;
    size_t count=0;
    while(count<characters && (!out || count<capacity))
    {
        wchar_t value=input[count];
        if(value>=128) { if(out) *source=input+count; errno=EILSEQ; return (size_t)-1; }
        if(out) out[count]=(char)value;
        if(!value) { if(out) *source=NULL; return count; }
        ++count;
    }
    if(out && count) *source=input+count;
    return count;
}
size_t wcsrtombs(char *out,const wchar_t **source,size_t capacity,mbstate_t *state)
{
    return wcsnrtombs(out,source,SIZE_MAX,capacity,state);
}
int mbtowc(wchar_t *out,const char *input,size_t size)
{
    if(!input) return 0;
    mbstate_t state={0}; size_t count=mbrtowc(out,input,size,&state);
    if(count==(size_t)-2) errno=EILSEQ;
    return count>(size_t)1 ? -1 : (int)count;
}
int mblen(const char *input,size_t size) { return mbtowc(NULL,input,size); }
int wctomb(char *out,wchar_t value)
{
    if(!out) return 0;
    mbstate_t state={0}; return wcrtomb(out,value,&state)==(size_t)-1 ? -1 : 1;
}
size_t mbstowcs(wchar_t *out,const char *input,size_t size)
{
    mbstate_t state={0}; return mbsrtowcs(out,&input,size,&state);
}
size_t wcstombs(char *out,const wchar_t *input,size_t size)
{
    mbstate_t state={0}; return wcsrtombs(out,&input,size,&state);
}

int iswalpha(wint_t c) { return (c>='a' && c<='z') || (c>='A' && c<='Z'); }
int iswdigit(wint_t c) { return c>='0' && c<='9'; }
int iswalnum(wint_t c) { return iswalpha(c) || iswdigit(c); }
int iswblank(wint_t c) { return c==' ' || c=='\t'; }
int iswcntrl(wint_t c) { return c<32 || c==127; }
int iswgraph(wint_t c) { return c>32 && c<127; }
int iswlower(wint_t c) { return c>='a' && c<='z'; }
int iswprint(wint_t c) { return c>=32 && c<127; }
int iswpunct(wint_t c) { return iswgraph(c) && !iswalnum(c); }
int iswspace(wint_t c) { return c==' ' || (c>='\t' && c<='\r'); }
int iswupper(wint_t c) { return c>='A' && c<='Z'; }
int iswxdigit(wint_t c) { return iswdigit(c) || (c>='a' && c<='f') || (c>='A' && c<='F'); }
wint_t towlower(wint_t c) { return iswupper(c) ? c+('a'-'A') : c; }
wint_t towupper(wint_t c) { return iswlower(c) ? c-('a'-'A') : c; }
wctype_t wctype(const char *name)
{
    static const char *const names[]={"alnum","alpha","blank","cntrl","digit","graph","lower","print","punct","space","upper","xdigit"};
    if(name) for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i) if(!strcmp(name,names[i])) return i+1;
    return 0;
}
int iswctype(wint_t c,wctype_t kind)
{
    switch(kind)
    {
        case 1:return iswalnum(c); case 2:return iswalpha(c); case 3:return iswblank(c); case 4:return iswcntrl(c);
        case 5:return iswdigit(c); case 6:return iswgraph(c); case 7:return iswlower(c); case 8:return iswprint(c);
        case 9:return iswpunct(c); case 10:return iswspace(c); case 11:return iswupper(c); case 12:return iswxdigit(c);
        default:return 0;
    }
}
wctrans_t wctrans(const char *name) { return name && !strcmp(name,"tolower") ? 1 : name && !strcmp(name,"toupper") ? 2 : 0; }
wint_t towctrans(wint_t c,wctrans_t kind) { return kind==1 ? towlower(c) : kind==2 ? towupper(c) : c; }

/* Numeric conversions recognize only C-locale ASCII grammar. A non-ASCII
 * code unit is a parsing terminator, not a multibyte conversion failure. */
char *__alix_wide_ascii_prefix(const wchar_t *text)
{
    if(!text) { errno=EINVAL; return NULL; }
    size_t length=0;
    while(text[length] && text[length]<128)
    { if(length==SIZE_MAX-1) { errno=ENOMEM; return NULL; } ++length; }
    char *copy=malloc(length+1);
    if(!copy) { errno=ENOMEM; return NULL; }
    for(size_t i=0;i<length;++i) copy[i]=(char)text[i];
    copy[length]=0; return copy;
}
#define WIDE_INTEGER(function,type,narrow) \
type function(const wchar_t *text,wchar_t **end,int base) \
{ \
    if(end) *end=(wchar_t *)text; \
    char *copy=__alix_wide_ascii_prefix(text); if(!copy) return 0; \
    char *stopped=copy; type result=narrow(copy,&stopped,base); \
    if(end) *end=(wchar_t *)text+(stopped-copy); \
    int error=errno; free(copy); errno=error; return result; \
}
WIDE_INTEGER(wcstol,long,strtol)
WIDE_INTEGER(wcstoll,long long,strtoll)
WIDE_INTEGER(wcstoul,unsigned long,strtoul)
WIDE_INTEGER(wcstoull,unsigned long long,strtoull)
#undef WIDE_INTEGER

size_t wcsftime(wchar_t *out,size_t capacity,const wchar_t *format,const struct tm *date)
{
    if(!capacity) return 0;
    if(!out || !format || !date) { errno=EINVAL; return 0; }
    int original_errno=errno;
    char *temporary=malloc(capacity);
    if(!temporary) { errno=ENOMEM; return 0; }
    size_t used=0;
    while(*format)
    {
        if(*format!='%')
        {
            if(used+1>=capacity) goto failed;
            out[used++]=*format++; continue;
        }
        ++format;
        char directive[4]={'%',0,0,0};
        unsigned index=1;
        if(*format=='E' || *format=='O') directive[index++]=(char)*format++;
        if(!*format || *format>=128) { errno=EINVAL; goto failed; }
        wchar_t code=*format++;
        directive[index]=(char)code;
        errno=0;
        size_t count=strftime(temporary,capacity-used,directive,date);
        int empty=(code=='z' && date->tm_isdst<0) ||
                  (code=='Z' && (date->tm_isdst<0 || !date->tm_zone || !*date->tm_zone));
        if(!count && (!empty || errno)) goto failed;
        for(size_t i=0;i<count;++i)
        {
            if((unsigned char)temporary[i]>=128) { errno=EILSEQ; goto failed; }
            out[used++]=(unsigned char)temporary[i];
        }
    }
    out[used]=0; free(temporary); errno=original_errno; return used;
failed:
    out[0]=0; free(temporary); return 0;
}
