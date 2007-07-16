/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef __ASM_PPC_XENOPROF_H__
#define __ASM_PPC_XENOPROF_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <public/xen.h>

/* All the classic PPC parts use these */
static inline unsigned int ctr_read(unsigned int i)
{
	switch(i) {
	case 0:
		return mfpmc1();
	case 1:
		return mfpmc2();
	case 2:
		return mfpmc3();
	case 3:
		return mfpmc4();
	case 4:
		return mfpmc5();
	case 5:
		return mfpmc6();
	case 6:
		return mfpmc7();
	case 7:
		return mfpmc8();
	default:
		return 0;
	}
}

static inline void ctr_write(unsigned int i, unsigned int val)
{
	switch(i) {
	case 0:
		mtpmc1(val);
		break;
	case 1:
		mtpmc2(val);
		break;
	case 2:
		mtpmc3(val);
		break;
	case 3:
		mtpmc4(val);
		break;
	case 4:
		mtpmc5(val);
		break;
	case 5:
		mtpmc6(val);
		break;
    case 6:
        mtpmc7(val);
        break;
    case 7:
        mtpmc8(val);
        break;
    default:
        break;
    }
}

static inline void print_perf_status(void)
{
    ulong mmcr0 = mfmmcr0();
    ulong mmcr1 = mfmmcr1();
    ulong mmcra = mfmmcra();
    ulong sdar = mfsdar();
    ulong siar = mfsiar();
    printk("MMCR0 0x%0lX\n",mmcr0);
    printk("MMCR1 0x%0lX\n",mmcr1);
    printk("MMCRA 0x%0lX\n",mmcra);
    printk("SIAR 0x%0lX\n",siar);
    printk("SDAR 0x%0lX\n",sdar);
}

#endif
