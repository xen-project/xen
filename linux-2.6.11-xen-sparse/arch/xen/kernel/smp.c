/* Copyright (C) 2004, Christian Limpach */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/threads.h>

/*
 * the frequency of the profiling timer can be changed
 * by writing a multiplier value into /proc/profile.
 */
int setup_profiling_timer(unsigned int multiplier)
{
	printk("setup_profiling_timer\n");

	return 0;
}
