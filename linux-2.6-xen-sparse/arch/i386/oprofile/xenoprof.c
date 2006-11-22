/**
 * @file xenoprof.c
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon <levon@movementarian.org>
 *
 * Modified by Aravind Menon and Jose Renato Santos for Xen
 * These modifications are:
 * Copyright (C) 2005 Hewlett-Packard Co.
 *
 * x86-specific part
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 */

#include <linux/oprofile.h>

#include <xen/xenoprof.h>
#include "op_counter.h"

unsigned int num_events = 0;
struct op_counter_config counter_config[OP_MAX_COUNTER];

int xenoprof_create_files(struct super_block * sb, struct dentry * root)
{
	unsigned int i;

	for (i = 0; i < num_events; ++i) {
		struct dentry * dir;
		char buf[2];
 
		snprintf(buf, 2, "%d", i);
		dir = oprofilefs_mkdir(sb, root, buf);
		oprofilefs_create_ulong(sb, dir, "enabled",
					&counter_config[i].enabled);
		oprofilefs_create_ulong(sb, dir, "event",
					&counter_config[i].event);
		oprofilefs_create_ulong(sb, dir, "count",
					&counter_config[i].count);
		oprofilefs_create_ulong(sb, dir, "unit_mask",
					&counter_config[i].unit_mask);
		oprofilefs_create_ulong(sb, dir, "kernel",
					&counter_config[i].kernel);
		oprofilefs_create_ulong(sb, dir, "user",
					&counter_config[i].user);
	}

	return 0;
}
