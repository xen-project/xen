/******************************************************************************
 * asm-x86/guest/hypercall.h
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#ifndef __X86_XEN_HYPERCALL_H__
#define __X86_XEN_HYPERCALL_H__

#ifdef CONFIG_XEN_GUEST

/*
 * Hypercall primatives for 64bit
 *
 * Inputs: %rdi, %rsi, %rdx, %r10, %r8, %r9 (arguments 1-6)
 */

#define _hypercall64_1(type, hcall, a1)                                 \
    ({                                                                  \
        long res, tmp__;                                                \
        asm volatile (                                                  \
            "call hypercall_page + %c[offset]"                          \
            : "=a" (res), "=D" (tmp__)                                  \
            : [offset] "i" (hcall * 32),                                \
              "1" ((long)(a1))                                          \
            : "memory" );                                               \
        (type)res;                                                      \
    })

#define _hypercall64_2(type, hcall, a1, a2)                             \
    ({                                                                  \
        long res, tmp__;                                                \
        asm volatile (                                                  \
            "call hypercall_page + %c[offset]"                          \
            : "=a" (res), "=D" (tmp__), "=S" (tmp__)                    \
            : [offset] "i" (hcall * 32),                                \
              "1" ((long)(a1)), "2" ((long)(a2))                        \
            : "memory" );                                               \
        (type)res;                                                      \
    })

#define _hypercall64_3(type, hcall, a1, a2, a3)                         \
    ({                                                                  \
        long res, tmp__;                                                \
        asm volatile (                                                  \
            "call hypercall_page + %c[offset]"                          \
            : "=a" (res), "=D" (tmp__), "=S" (tmp__), "=d" (tmp__)      \
            : [offset] "i" (hcall * 32),                                \
              "1" ((long)(a1)), "2" ((long)(a2)), "3" ((long)(a3))      \
            : "memory" );                                               \
        (type)res;                                                      \
    })

#define _hypercall64_4(type, hcall, a1, a2, a3, a4)                     \
    ({                                                                  \
        long res, tmp__;                                                \
        register long _a4 asm ("r10") = ((long)(a4));                   \
        asm volatile (                                                  \
            "call hypercall_page + %c[offset]"                          \
            : "=a" (res), "=D" (tmp__), "=S" (tmp__), "=d" (tmp__),     \
              "=&r" (tmp__)                                             \
            : [offset] "i" (hcall * 32),                                \
              "1" ((long)(a1)), "2" ((long)(a2)), "3" ((long)(a3)),     \
              "4" (_a4)                                                 \
            : "memory" );                                               \
        (type)res;                                                      \
    })

#endif /* CONFIG_XEN_GUEST */
#endif /* __X86_XEN_HYPERCALL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
