/*****************************************************************************
 *
 * Utility functions for Xen network devices.
 *
 * Copyright (c) 2005 XenSource Ltd.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
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
 */

#ifndef _ASM_XEN_NET_DRIVER_UTIL_H
#define _ASM_XEN_NET_DRIVER_UTIL_H


#include <xen/xenbus.h>


/**
 * Read the 'mac' node at the given device's node in the store, and parse that
 * as colon-separated octets, placing result the given mac array.  mac must be
 * a preallocated array of length ETH_ALEN (as declared in linux/if_ether.h).
 * Return 0 on success, or -errno on error.
 */
int xen_net_read_mac(struct xenbus_device *dev, u8 mac[]);


#endif /* _ASM_XEN_NET_DRIVER_UTIL_H */
