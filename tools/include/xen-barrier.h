/* SPDX-License-Identifier: LGPL-2.1-only */
/******************************************************************************
 * xen-barrier.h
 *
 * Definition of CPU barriers, part of libxenctrl.
 *
 * Copyright (c) 2003-2004, K A Fraser.
 */

#ifndef XEN_BARRIER_H
#define XEN_BARRIER_H

/*
 *  DEFINITIONS FOR CPU BARRIERS
 */

#define xen_barrier() asm volatile ( "" : : : "memory")

#if defined(__i386__)
#define xen_mb()  asm volatile ( "lock addl $0, -4(%%esp)" ::: "memory" )
#define xen_rmb() xen_barrier()
#define xen_wmb() xen_barrier()
#elif defined(__x86_64__)
#define xen_mb()  asm volatile ( "lock addl $0, -32(%%rsp)" ::: "memory" )
#define xen_rmb() xen_barrier()
#define xen_wmb() xen_barrier()
#elif defined(__arm__)
#define xen_mb()   asm volatile ("dmb" : : : "memory")
#define xen_rmb()  asm volatile ("dmb" : : : "memory")
#define xen_wmb()  asm volatile ("dmb" : : : "memory")
#elif defined(__aarch64__)
#define xen_mb()   asm volatile ("dmb sy" : : : "memory")
#define xen_rmb()  asm volatile ("dmb sy" : : : "memory")
#define xen_wmb()  asm volatile ("dmb sy" : : : "memory")
#else
#error "Define barriers"
#endif

#endif /* XEN_BARRIER_H */
