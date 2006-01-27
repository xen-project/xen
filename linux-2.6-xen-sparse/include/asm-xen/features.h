/******************************************************************************
 * features.h
 *
 * Query the features reported by Xen.
 *
 * Copyright (c) 2006, Ian Campbell
 */

#ifndef __ASM_XEN_FEATURES_H__
#define __ASM_XEN_FEATURES_H__

#include <asm-xen/xen-public/version.h>

extern void setup_xen_features(void);

extern unsigned long xen_features[XENFEAT_NR_SUBMAPS];

#define xen_feature(flag)	(test_bit(_XENFEAT_ ## flag, xen_features))

#endif
