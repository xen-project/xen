/******************************************************************************
 * balloon.h
 *
 * Xen balloon driver - enables returning/claiming memory to/from Xen.
 *
 * Copyright (c) 2003, B Dragovic
 * Copyright (c) 2003-2004, M Williamson, K Fraser
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __ASM_BALLOON_H__
#define __ASM_BALLOON_H__

/*
 * Inform the balloon driver that it should allow some slop for device-driver
 * memory activities.
 */
extern void
balloon_update_driver_allowance(
	long delta);

/* Allocate an empty low-memory page range. */
extern struct page *
balloon_alloc_empty_page_range(
	unsigned long nr_pages);

/* Deallocate an empty page range, adding to the balloon. */
extern void
balloon_dealloc_empty_page_range(
	struct page *page, unsigned long nr_pages);

/*
 * Prevent the balloon driver from changing the memory reservation during
 * a driver critical region.
 */
extern spinlock_t balloon_lock;
#define balloon_lock(__flags)   spin_lock_irqsave(&balloon_lock, __flags)
#define balloon_unlock(__flags) spin_unlock_irqrestore(&balloon_lock, __flags)

#endif /* __ASM_BALLOON_H__ */

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
