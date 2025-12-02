#ifndef CTYPE_H
#define CTYPE_H

#ifdef TTF_HOST_BUILD
#include_next <ctype.h>
#else
#include "types.h"

int toupper(int ch);
int tolower(int ch);
int isdigit(int ch);
int isprint(int ch);
int isspace(int ch);
int isalpha(int ch);
int isalnum(int ch);
#endif

#endif /* CTYPE_H */
