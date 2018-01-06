/******************************************************************************
 * arch/x86/guest/vixen.c
 *
 * Support for detecting and running under Xen HVM.
 *
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2017-2018 Amazon.com, Inc. or its affiliates.
 */

#include <asm/guest/vixen.h>
#include <public/version.h>

static int in_vixen;
static uint8_t global_si_data[4 << 10] __attribute__((aligned(4096)));
static shared_info_t *global_si = (void *)global_si_data;

void __init init_vixen(void)
{
    int major, minor, version;

    if ( !xen_guest )
    {
        printk("Disabling Vixen because we are not running under Xen\n");
        in_vixen = -1;
        return;
    }

    version = HYPERVISOR_xen_version(XENVER_version, NULL);
    major = version >> 16;
    minor = version & 0xffff;

    printk("Vixen running under Xen %d.%d\n", major, minor);

    in_vixen = 1;
}

void __init early_vixen_init(void)
{
    struct xen_add_to_physmap xatp;
    long rc;

    if ( !is_vixen() )
	return;

    /* Setup our own shared info area */
    xatp.domid = DOMID_SELF;
    xatp.idx = 0;
    xatp.space = XENMAPSPACE_shared_info;
    xatp.gpfn = virt_to_mfn(global_si);

    rc = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
    if ( rc < 0 )
        printk("Setting shared info page failed: %ld\n", rc);

    memset(&global_si->native.evtchn_mask[0], 0x00,
           sizeof(global_si->native.evtchn_mask));
}

bool is_vixen(void)
{
    return in_vixen > 0;
}

u64 vixen_get_cpu_freq(void)
{
    volatile vcpu_time_info_t *timep = &global_si->native.vcpu_info[0].time;
    vcpu_time_info_t time;
    uint32_t version;
    u64 imm;

    do {
	version = timep->version;
	rmb();
	time = *timep;
    } while ((version & 1) || version != time.version);

    imm = (1000000000ULL << 32) / time.tsc_to_system_mul;

    if (time.tsc_shift < 0) {
	return imm << -time.tsc_shift;
    } else {
	return imm >> time.tsc_shift;
    }
}
