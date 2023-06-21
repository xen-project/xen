/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __XEN_STDINT_H__
#define __XEN_STDINT_H__

#ifndef __INT8_TYPE__ /* GCC <= 4.4 */

/*
 * Define the types using GCC internal notation.  Clang understands this too.
 * https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html
 */
typedef   signed __attribute__((__mode__(__QI__)))     int8_t;
typedef unsigned __attribute__((__mode__(__QI__)))    uint8_t;
typedef   signed __attribute__((__mode__(__HI__)))    int16_t;
typedef unsigned __attribute__((__mode__(__HI__)))   uint16_t;
typedef   signed __attribute__((__mode__(__SI__)))    int32_t;
typedef unsigned __attribute__((__mode__(__SI__)))   uint32_t;
typedef   signed __attribute__((__mode__(__DI__)))    int64_t;
typedef unsigned __attribute__((__mode__(__DI__)))   uint64_t;

#else

typedef __INT8_TYPE__        int8_t;
typedef __UINT8_TYPE__      uint8_t;
typedef __INT16_TYPE__      int16_t;
typedef __UINT16_TYPE__    uint16_t;
typedef __INT32_TYPE__      int32_t;
typedef __UINT32_TYPE__    uint32_t;
typedef __INT64_TYPE__      int64_t;
typedef __UINT64_TYPE__    uint64_t;

#endif

#endif /* __XEN_STDINT_H__ */
