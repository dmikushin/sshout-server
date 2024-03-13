#ifndef _BASE64_H
#define _BASE64_H

#include <stddef.h>

#define BASE64_ADD_PADDING 0x1

extern int base64_encode(const void *, size_t, char *, size_t, int);
extern int base64_decode(const char *, size_t, void *, size_t);

#endif
