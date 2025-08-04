/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 Renesas Electronics Corporation
 */

#ifndef __XENTOP_PCPU_H__
#define __XENTOP_PCPU_H__

#include <sys/time.h>

int update_pcpu_stats(const struct timeval *now, unsigned int delay);
int get_pcpu_count(void);
float get_pcpu_usage(int cpu_index);
int has_pcpu_data(void);
void free_pcpu_stats(void);

#endif /* __XENTOP_PCPU_H__ */
