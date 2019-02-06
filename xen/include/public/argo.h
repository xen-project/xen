/******************************************************************************
 * Argo : Hypervisor-Mediated data eXchange
 *
 * Derived from v4v, the version 2 of v2v.
 *
 * Copyright (c) 2010, Citrix Systems
 * Copyright (c) 2018-2019, BAE Systems
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef __XEN_PUBLIC_ARGO_H__
#define __XEN_PUBLIC_ARGO_H__

#include "xen.h"

#define XEN_ARGO_DOMID_ANY       DOMID_INVALID

/* Fixed-width type for "argo port" number. Nothing to do with evtchns. */
typedef uint32_t xen_argo_port_t;

typedef struct xen_argo_addr
{
    xen_argo_port_t aport;
    domid_t domain_id;
    uint16_t pad;
} xen_argo_addr_t;

typedef struct xen_argo_ring
{
    /* Guests should use atomic operations to access rx_ptr */
    uint32_t rx_ptr;
    /* Guests should use atomic operations to access tx_ptr */
    uint32_t tx_ptr;
    /*
     * Header space reserved for later use. Align the start of the ring to a
     * multiple of the message slot size.
     */
    uint8_t reserved[56];
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    uint8_t ring[];
#elif defined(__GNUC__)
    uint8_t ring[0];
#endif
} xen_argo_ring_t;

#endif
