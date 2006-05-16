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
 */

#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/smp.h>
#include <linux/oprofile.h>
#include <linux/sysdev.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/vmalloc.h>
#include <asm/nmi.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/pgtable.h>
#include <xen/evtchn.h>
#include "op_counter.h"

#include <xen/interface/xen.h>
#include <xen/interface/xenoprof.h>

static int xenoprof_start(void);
static void xenoprof_stop(void);

void * vm_map_xen_pages(unsigned long maddr, int vm_size, pgprot_t prot);

static int xenoprof_enabled = 0;
static unsigned int num_events = 0;
static int is_primary = 0;
static int active_defined;

/* sample buffers shared with Xen */
xenoprof_buf_t * xenoprof_buf[MAX_VIRT_CPUS];
/* Shared buffer area */
char * shared_buffer;
/* Number of buffers in shared area (one per VCPU) */
int nbuf;
/* Mappings of VIRQ_XENOPROF to irq number (per cpu) */
int ovf_irq[NR_CPUS];
/* cpu model type string - copied from Xen memory space on XENOPROF_init command */
char cpu_type[XENOPROF_CPU_TYPE_SIZE];

#ifdef CONFIG_PM

static int xenoprof_suspend(struct sys_device * dev, pm_message_t state)
{
	if (xenoprof_enabled == 1)
		xenoprof_stop();
	return 0;
}


static int xenoprof_resume(struct sys_device * dev)
{
	if (xenoprof_enabled == 1)
		xenoprof_start();
	return 0;
}


static struct sysdev_class oprofile_sysclass = {
	set_kset_name("oprofile"),
	.resume		= xenoprof_resume,
	.suspend	= xenoprof_suspend
};


static struct sys_device device_oprofile = {
	.id	= 0,
	.cls	= &oprofile_sysclass,
};


static int __init init_driverfs(void)
{
	int error;
	if (!(error = sysdev_class_register(&oprofile_sysclass)))
		error = sysdev_register(&device_oprofile);
	return error;
}


static void __exit exit_driverfs(void)
{
	sysdev_unregister(&device_oprofile);
	sysdev_class_unregister(&oprofile_sysclass);
}

#else
#define init_driverfs() do { } while (0)
#define exit_driverfs() do { } while (0)
#endif /* CONFIG_PM */

unsigned long long oprofile_samples = 0;

static irqreturn_t 
xenoprof_ovf_interrupt(int irq, void * dev_id, struct pt_regs * regs)
{
	int head, tail, size;
	struct xenoprof_buf * buf;
	int cpu;

	cpu = smp_processor_id();
	buf = xenoprof_buf[cpu];

	head = buf->event_head;
	tail = buf->event_tail;
	size = buf->event_size;

	if (tail > head) {
		while (tail < size) {
			oprofile_add_pc(buf->event_log[tail].eip,
					buf->event_log[tail].mode,
					buf->event_log[tail].event);
			oprofile_samples++;
			tail++;
		}
		tail = 0;
	}
	while (tail < head) {
		oprofile_add_pc(buf->event_log[tail].eip,
				buf->event_log[tail].mode,
				buf->event_log[tail].event);
		oprofile_samples++;
		tail++;
	}

	buf->event_tail = tail;

	return IRQ_HANDLED;
}


static void unbind_virq(void)
{
	int i;

	for_each_cpu(i) {
		if (ovf_irq[i] >= 0) {
			unbind_from_irqhandler(ovf_irq[i], NULL);
			ovf_irq[i] = -1;
		}
	}
}


static int bind_virq(void)
{
	int i, result;

	for_each_cpu(i) {
		result = bind_virq_to_irqhandler(VIRQ_XENOPROF,
						 i,
						 xenoprof_ovf_interrupt,
						 SA_INTERRUPT,
						 "xenoprof",
						 NULL);

		if (result < 0) {
			unbind_virq();
			return result;
		}

		ovf_irq[i] = result;
	}
		
	return 0;
}


static int xenoprof_setup(void)
{
	int ret;
	int i;

	ret = bind_virq();
	if (ret)
		return ret;

	if (is_primary) {
		struct xenoprof_counter counter;

		/* Define dom0 as an active domain if not done yet */
		if (!active_defined) {
			domid_t domid;
			ret = HYPERVISOR_xenoprof_op(XENOPROF_reset_active_list, NULL);
			if (ret)
				goto err;
			domid = 0;
			ret = HYPERVISOR_xenoprof_op(XENOPROF_set_active, &domid);
			if (ret)
				goto err;
			active_defined = 1;
		}

		ret = HYPERVISOR_xenoprof_op(XENOPROF_reserve_counters, NULL);
		if (ret)
			goto err;
		for (i=0; i<num_events; i++) {
			counter.ind       = i;
			counter.count     = (uint64_t)counter_config[i].count;
			counter.enabled   = (uint32_t)counter_config[i].enabled;
			counter.event     = (uint32_t)counter_config[i].event;
			counter.kernel    = (uint32_t)counter_config[i].kernel;
			counter.user      = (uint32_t)counter_config[i].user;
			counter.unit_mask = (uint64_t)counter_config[i].unit_mask;
			HYPERVISOR_xenoprof_op(XENOPROF_counter, 
					       &counter);
		}
		ret = HYPERVISOR_xenoprof_op(XENOPROF_setup_events, NULL);

		if (ret)
			goto err;
	}

	ret = HYPERVISOR_xenoprof_op(XENOPROF_enable_virq, NULL);
	if (ret)
		goto err;

	xenoprof_enabled = 1;
	return 0;
 err:
	unbind_virq();
	return ret;
}


static void xenoprof_shutdown(void)
{
	xenoprof_enabled = 0;

	HYPERVISOR_xenoprof_op(XENOPROF_disable_virq, NULL);

	if (is_primary) {
		HYPERVISOR_xenoprof_op(XENOPROF_release_counters, NULL);
		active_defined = 0;
	}

	unbind_virq();

}


static int xenoprof_start(void)
{
	int ret = 0;

	if (is_primary)
		ret = HYPERVISOR_xenoprof_op(XENOPROF_start, NULL);

	return ret;
}


static void xenoprof_stop(void)
{
	if (is_primary)
		HYPERVISOR_xenoprof_op(XENOPROF_stop, NULL);
}


static int xenoprof_set_active(int * active_domains,
			       unsigned int adomains)
{
	int ret = 0;
	int i;
	int set_dom0 = 0;
	domid_t domid;

	if (!is_primary)
		return 0;

	if (adomains > MAX_OPROF_DOMAINS)
		return -E2BIG;

	ret = HYPERVISOR_xenoprof_op(XENOPROF_reset_active_list, NULL);
	if (ret)
		return ret;

	for (i=0; i<adomains; i++) {
		domid = active_domains[i];
		if (domid != active_domains[i]) {
			ret = -EINVAL;
			goto out;
		}
		ret = HYPERVISOR_xenoprof_op(XENOPROF_set_active, &domid);
		if (ret)
			goto out;
		if (active_domains[i] == 0)
			set_dom0 = 1;
	}
	/* dom0 must always be active but may not be in the list */ 
	if (!set_dom0) {
		domid = 0;
		ret = HYPERVISOR_xenoprof_op(XENOPROF_set_active, &domid);
	}

out:
	if (ret)
		HYPERVISOR_xenoprof_op(XENOPROF_reset_active_list, NULL);
	active_defined = !ret;
	return ret;
}


struct op_counter_config counter_config[OP_MAX_COUNTER];

static int xenoprof_create_files(struct super_block * sb, struct dentry * root)
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


struct oprofile_operations xenoprof_ops = {
	.create_files 	= xenoprof_create_files,
	.set_active	= xenoprof_set_active,
	.setup 		= xenoprof_setup,
	.shutdown	= xenoprof_shutdown,
	.start		= xenoprof_start,
	.stop		= xenoprof_stop
};


/* in order to get driverfs right */
static int using_xenoprof;

int __init oprofile_arch_init(struct oprofile_operations * ops)
{
	struct xenoprof_init init;
	struct xenoprof_buf * buf;
	int vm_size;
	int npages;
	int ret;
	int i;

	init.max_samples = 16;
	ret = HYPERVISOR_xenoprof_op(XENOPROF_init, &init);

	if (!ret) {
		pgprot_t prot = __pgprot(_KERNPG_TABLE);

		num_events = init.num_events;
		is_primary = init.is_primary;
		nbuf = init.nbuf;

		/* just in case - make sure we do not overflow event list 
                   (i.e. counter_config list) */
		if (num_events > OP_MAX_COUNTER)
			num_events = OP_MAX_COUNTER;

		npages = (init.bufsize * nbuf - 1) / PAGE_SIZE + 1;
		vm_size = npages * PAGE_SIZE;

		shared_buffer = (char *)vm_map_xen_pages(init.buf_maddr,
							 vm_size, prot);
		if (!shared_buffer) {
			ret = -ENOMEM;
			goto out;
		}

		for (i=0; i< nbuf; i++) {
			buf = (struct xenoprof_buf*) 
				&shared_buffer[i * init.bufsize];
			BUG_ON(buf->vcpu_id >= MAX_VIRT_CPUS);
			xenoprof_buf[buf->vcpu_id] = buf;
		}

		/*  cpu_type is detected by Xen */
		cpu_type[XENOPROF_CPU_TYPE_SIZE-1] = 0;
		strncpy(cpu_type, init.cpu_type, XENOPROF_CPU_TYPE_SIZE - 1);
		xenoprof_ops.cpu_type = cpu_type;

		init_driverfs();
		using_xenoprof = 1;
		*ops = xenoprof_ops;

		for (i=0; i<NR_CPUS; i++)
			ovf_irq[i] = -1;

		active_defined = 0;
	}
 out:
	printk(KERN_INFO "oprofile_arch_init: ret %d, events %d, "
	       "is_primary %d\n", ret, num_events, is_primary);
	return ret;
}


void __exit oprofile_arch_exit(void)
{
	if (using_xenoprof)
		exit_driverfs();

	if (shared_buffer) {
		vunmap(shared_buffer);
		shared_buffer = NULL;
	}
	if (is_primary)
		HYPERVISOR_xenoprof_op(XENOPROF_shutdown, NULL);
}
