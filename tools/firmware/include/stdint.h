#ifndef _STDINT_H_
#define _STDINT_H_

typedef __INT8_TYPE__        int8_t;
typedef __UINT8_TYPE__      uint8_t;
typedef __INT16_TYPE__      int16_t;
typedef __UINT16_TYPE__    uint16_t;
typedef __INT32_TYPE__      int32_t;
typedef __UINT32_TYPE__    uint32_t;
typedef __INT64_TYPE__      int64_t;
typedef __UINT64_TYPE__    uint64_t;

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

typedef __UINTPTR_TYPE__  uintptr_t;

#define UINTPTR_MAX     __UINTPTR_MAX__

#endif
