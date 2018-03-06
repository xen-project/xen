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

#include <xen/types.h>

#include <public/xen.h>
#include <public/sched.h>
#include <public/hvm/hvm_op.h>

#include <public/vcpu.h>

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

/*
 * Primitive Hypercall wrappers
 */
static inline long xen_hypercall_sched_op(unsigned int cmd, void *arg)
{
    return _hypercall64_2(long, __HYPERVISOR_sched_op, cmd, arg);
}

static inline long xen_hypercall_memory_op(unsigned int cmd, void *arg)
{
    return _hypercall64_2(long, __HYPERVISOR_memory_op, cmd, arg);
}

static inline int xen_hypercall_vcpu_op(unsigned int cmd, unsigned int vcpu,
                                        void *arg)
{
    return _hypercall64_3(long, __HYPERVISOR_vcpu_op, cmd, vcpu, arg);
}

static inline long xen_hypercall_event_channel_op(unsigned int cmd, void *arg)
{
    return _hypercall64_2(long, __HYPERVISOR_event_channel_op, cmd, arg);
}

static inline long xen_hypercall_grant_table_op(unsigned int cmd, void *arg,
                                                unsigned int count)
{
    return _hypercall64_3(long, __HYPERVISOR_grant_table_op, cmd, arg, count);
}

static inline long xen_hypercall_hvm_op(unsigned int op, void *arg)
{
    return _hypercall64_2(long, __HYPERVISOR_hvm_op, op, arg);
}

/*
 * Higher level hypercall helpers
 */
static inline void xen_hypercall_console_write(
    const char *buf, unsigned int count)
{
    (void)_hypercall64_3(long, __HYPERVISOR_console_io,
                         CONSOLEIO_write, count, buf);
}

static inline long xen_hypercall_shutdown(unsigned int reason)
{
    struct sched_shutdown s = { .reason = reason };
    return xen_hypercall_sched_op(SCHEDOP_shutdown, &s);
}

static inline long xen_hypercall_evtchn_send(evtchn_port_t port)
{
    struct evtchn_send send = { .port = port };

    return xen_hypercall_event_channel_op(EVTCHNOP_send, &send);
}

static inline long xen_hypercall_evtchn_unmask(evtchn_port_t port)
{
    struct evtchn_unmask unmask = { .port = port };

    return xen_hypercall_event_channel_op(EVTCHNOP_unmask, &unmask);
}

static inline long xen_hypercall_hvm_get_param(uint32_t index, uint64_t *value)
{
    struct xen_hvm_param xhv = {
        .domid = DOMID_SELF,
        .index = index,
    };
    long ret = xen_hypercall_hvm_op(HVMOP_get_param, &xhv);

    if ( ret == 0 )
        *value = xhv.value;

    return ret;
}

static inline long xen_hypercall_set_evtchn_upcall_vector(
    unsigned int cpu, unsigned int vector)
{
    struct xen_hvm_evtchn_upcall_vector a = {
        .vcpu = cpu,
        .vector = vector,
    };

    return xen_hypercall_hvm_op(HVMOP_set_evtchn_upcall_vector, &a);
}

#else /* CONFIG_XEN_GUEST */

#include <public/sched.h>

static inline void xen_hypercall_console_write(
    const char *buf, unsigned int count)
{
    ASSERT_UNREACHABLE();
}

static inline long xen_hypercall_shutdown(unsigned int reason)
{
    ASSERT_UNREACHABLE();
    return 0;
}

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
