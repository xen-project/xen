/******************************************************************************
 * features.c
 *
 * Xen feature flags.
 *
 * Copyright (c) 2006, Ian Campbell, XenSource Inc.
 */
#include <linux/types.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <asm/hypervisor.h>
#include <xen/features.h>

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

u8 xen_features[XENFEAT_NR_SUBMAPS * 32] __read_mostly;
/* Not a GPL symbol: used in ubiquitous macros, so too restrictive. */
EXPORT_SYMBOL(xen_features);

void setup_xen_features(void)
{
	xen_feature_info_t fi;
	int i, j;

	for (i = 0; i < XENFEAT_NR_SUBMAPS; i++) {
		fi.submap_idx = i;
		if (HYPERVISOR_xen_version(XENVER_get_features, &fi) < 0)
			break;
		for (j=0; j<32; j++)
			xen_features[i*32+j] = !!(fi.submap & 1<<j);
	}
}
