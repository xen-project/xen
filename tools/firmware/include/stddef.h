#ifndef _STDDEF_H_
#define _STDDEF_H_

typedef __SIZE_TYPE__ size_t;

#define NULL ((void*)0)

#define offsetof(t, m) __builtin_offsetof(t, m)

#endif
