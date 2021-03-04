#ifndef _STDINT_H_
#define _STDINT_H_

#if defined(__LP64__) || defined(__P64__)
#error "32bit only header"
#endif

typedef unsigned char uint8_t;
typedef signed char int8_t;

typedef unsigned short uint16_t;
typedef signed short int16_t;

typedef unsigned int uint32_t;
typedef signed int int32_t;

typedef unsigned long long uint64_t;
typedef signed long long int64_t;

#define INT8_MIN        (-0x7f-1)
#define INT16_MIN       (-0x7fff-1)
#define INT32_MIN       (-0x7fffffff-1)
#define INT64_MIN       (-0x7fffffffffffffffll-1)

#define INT8_MAX        0x7f
#define INT16_MAX       0x7fff
#define INT32_MAX       0x7fffffff
#define INT64_MAX       0x7fffffffffffffffll

#define UINT8_MAX       0xff
#define UINT16_MAX      0xffff
#define UINT32_MAX      0xffffffffu
#define UINT64_MAX      0xffffffffffffffffull

typedef uint32_t uintptr_t;

#define UINTPTR_MAX     UINT32_MAX

#endif
