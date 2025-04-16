/* SPDX-License-Identifier: MIT */
/*
 * Xen Device Tree boot information
 *
 * Information for configuring Xen domains created at boot time.
 */

#ifndef __XEN_PUBLIC_BOOTFDT_H__
#define __XEN_PUBLIC_BOOTFDT_H__

/*
 * Domain Capabilities specified in the "capabilities" property.  Use of
 * this property allows splitting up the monolithic dom0 into separate,
 * less privileged components.  A regular domU has no capabilities
 * (which is the default if nothing is specified).  A traditional dom0
 * has all three capabilities.
 */

/* Control/Privileged domain capable of affecting other domains. */
#define DOMAIN_CAPS_CONTROL  (1U << 0)
/*
 * Hardware domain controlling physical hardware.  Typically providing
 * backends to other domains.
 */
#define DOMAIN_CAPS_HARDWARE (1U << 1)
/* Xenstore domain. */
#define DOMAIN_CAPS_XENSTORE (1U << 2)
#define DOMAIN_CAPS_MASK     (DOMAIN_CAPS_CONTROL | DOMAIN_CAPS_HARDWARE | \
                              DOMAIN_CAPS_XENSTORE)

#endif /* __XEN_PUBLIC_BOOTFDT_H__ */
