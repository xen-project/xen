/*
 * OS specific bits for xenstored
 * Copyright (C) 2014 Citrix Systems R&D.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#if defined(__linux__)
#define XENSTORED_KVA_DEV  "/proc/xen/xsd_kva"
#define XENSTORED_PORT_DEV "/proc/xen/xsd_port"
#elif defined(__NetBSD__)
#define XENSTORED_KVA_DEV  "/dev/xsd_kva"
#define XENSTORED_PORT_DEV "/kern/xen/xsd_port"
#elif defined(__FreeBSD__)
#define XENSTORED_KVA_DEV  "/dev/xen/xenstored"
#define XENSTORED_PORT_DEV "/dev/xen/xenstored"
#endif
