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
 * Separated out arch-generic part
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
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
#include <xen/xenoprof.h>
#include "../../../arch/i386/oprofile/op_counter.h"

#include <xen/driver_util.h>
#include <xen/interface/xen.h>
#include <xen/interface/xenoprof.h>
#include "../../../drivers/oprofile/cpu_buffer.h"
#include "../../../drivers/oprofile/event_buffer.h"

#define MAX_XENOPROF_SAMPLES 16

static int xenoprof_start(void);
static void xenoprof_stop(void);

static int xenoprof_enabled = 0;
extern unsigned int num_events;
static int is_primary = 0;
static int active_defined;

/* sample buffers shared with Xen */
xenoprof_buf_t * xenoprof_buf[MAX_VIRT_CPUS];
/* Shared buffer area */
char * shared_buffer = NULL;
/* Number of buffers in shared area (one per VCPU) */
int nbuf;
/* Mappings of VIRQ_XENOPROF to irq number (per cpu) */
int ovf_irq[NR_CPUS];
/* cpu model type string - copied from Xen memory space on XENOPROF_init command */
char cpu_type[XENOPROF_CPU_TYPE_SIZE];

/* Passive sample buffers shared with Xen */
xenoprof_buf_t *p_xenoprof_buf[MAX_OPROF_DOMAINS][MAX_VIRT_CPUS];
/* Passive shared buffer area */
char *p_shared_buffer[MAX_OPROF_DOMAINS];

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
unsigned long long p_oprofile_samples = 0;

unsigned int pdomains;
struct xenoprof_passive passive_domains[MAX_OPROF_DOMAINS];

static void xenoprof_add_pc(xenoprof_buf_t *buf, int is_passive)
{
	int head, tail, size;

	head = buf->event_head;
	tail = buf->event_tail;
	size = buf->event_size;

	if (tail > head) {
		while (tail < size) {
			oprofile_add_pc(buf->event_log[tail].eip,
					buf->event_log[tail].mode,
					buf->event_log[tail].event);
			if (!is_passive)
				oprofile_samples++;
			else
				p_oprofile_samples++;
			tail++;
		}
		tail = 0;
	}
	while (tail < head) {
		oprofile_add_pc(buf->event_log[tail].eip,
				buf->event_log[tail].mode,
				buf->event_log[tail].event);
		if (!is_passive)
			oprofile_samples++;
		else
			p_oprofile_samples++;
		tail++;
	}

	buf->event_tail = tail;
}

static void xenoprof_handle_passive(void)
{
	int i, j;
	int flag_domain, flag_switch = 0;
	
	for (i = 0; i < pdomains; i++) {
		flag_domain = 0;
		for (j = 0; j < passive_domains[i].nbuf; j++) {
			xenoprof_buf_t *buf = p_xenoprof_buf[i][j];
			if (buf->event_head == buf->event_tail)
				continue;
			if (!flag_domain) {
				if (!oprofile_add_domain_switch(passive_domains[i].
								domain_id))
					goto done;
				flag_domain = 1;
			}
			xenoprof_add_pc(buf, 1);
			flag_switch = 1;
		}
	}
done:
	if (flag_switch)
		oprofile_add_domain_switch(COORDINATOR_DOMAIN);
}

static irqreturn_t 
xenoprof_ovf_interrupt(int irq, void * dev_id, struct pt_regs * regs)
{
	struct xenoprof_buf * buf;
	int cpu;
	static unsigned long flag;

	cpu = smp_processor_id();
	buf = xenoprof_buf[cpu];

	xenoprof_add_pc(buf, 0);

	if (is_primary && !test_and_set_bit(0, &flag)) {
		xenoprof_handle_passive();
		smp_mb__before_clear_bit();
		clear_bit(0, &flag);
	}

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


static int map_xenoprof_buffer(int max_samples)
{
	struct xenoprof_get_buffer get_buffer;
	struct xenoprof_buf *buf;
	int npages, ret, i;
	struct vm_struct *area;

	if ( shared_buffer )
		return 0;

	get_buffer.max_samples = max_samples;

	if ( (ret = HYPERVISOR_xenoprof_op(XENOPROF_get_buffer, &get_buffer)) )
		return ret;

	nbuf = get_buffer.nbuf;
	npages = (get_buffer.bufsize * nbuf - 1) / PAGE_SIZE + 1;

	area = alloc_vm_area(npages * PAGE_SIZE);
	if (area == NULL)
		return -ENOMEM;

	if ( (ret = direct_kernel_remap_pfn_range(
		      (unsigned long)area->addr,
		      get_buffer.buf_maddr >> PAGE_SHIFT,
		      npages * PAGE_SIZE, __pgprot(_KERNPG_TABLE), DOMID_SELF)) ) {
		vunmap(area->addr);
		return ret;
	}

	shared_buffer = area->addr;
	for (i=0; i< nbuf; i++) {
		buf = (struct xenoprof_buf*) 
			&shared_buffer[i * get_buffer.bufsize];
		BUG_ON(buf->vcpu_id >= MAX_VIRT_CPUS);
		xenoprof_buf[buf->vcpu_id] = buf;
	}

	return 0;
}


static int xenoprof_setup(void)
{
	int ret;
	int i;

	if ( (ret = map_xenoprof_buffer(MAX_XENOPROF_SAMPLES)) )
		return ret;

	if ( (ret = bind_virq()) )
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

static int xenoprof_set_passive(int * p_domains,
                                unsigned int pdoms)
{
	int ret;
	int i, j;
	int npages;
	struct xenoprof_buf *buf;
	struct vm_struct *area;
	pgprot_t prot = __pgprot(_KERNPG_TABLE);

	if (!is_primary)
        	return 0;

	if (pdoms > MAX_OPROF_DOMAINS)
		return -E2BIG;

	ret = HYPERVISOR_xenoprof_op(XENOPROF_reset_passive_list, NULL);
	if (ret)
		return ret;

	for (i = 0; i < pdoms; i++) {
		passive_domains[i].domain_id = p_domains[i];
		passive_domains[i].max_samples = 2048;
		ret = HYPERVISOR_xenoprof_op(XENOPROF_set_passive,
					     &passive_domains[i]);
		if (ret)
			goto out;

		npages = (passive_domains[i].bufsize * passive_domains[i].nbuf - 1) / PAGE_SIZE + 1;

		area = alloc_vm_area(npages * PAGE_SIZE);
		if (area == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		ret = direct_kernel_remap_pfn_range(
			(unsigned long)area->addr,
			passive_domains[i].buf_maddr >> PAGE_SHIFT,
			npages * PAGE_SIZE, prot, DOMID_SELF);
		if (ret) {
			vunmap(area->addr);
			goto out;
		}

		p_shared_buffer[i] = area->addr;

		for (j = 0; j < passive_domains[i].nbuf; j++) {
			buf = (struct xenoprof_buf *)
				&p_shared_buffer[i][j * passive_domains[i].bufsize];
			BUG_ON(buf->vcpu_id >= MAX_VIRT_CPUS);
			p_xenoprof_buf[i][buf->vcpu_id] = buf;
		}

	}

	pdomains = pdoms;
	return 0;

out:
	for (j = 0; j < i; j++) {
		vunmap(p_shared_buffer[j]);
		p_shared_buffer[j] = NULL;
	}

 	return ret;
}

struct oprofile_operations xenoprof_ops = {
	.create_files 	= xenoprof_create_files,
	.set_active	= xenoprof_set_active,
	.set_passive    = xenoprof_set_passive,
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
	int ret, i;

	ret = HYPERVISOR_xenoprof_op(XENOPROF_init, &init);

	if (!ret) {
		num_events = init.num_events;
		is_primary = init.is_primary;

		/* just in case - make sure we do not overflow event list 
		   (i.e. counter_config list) */
		if (num_events > OP_MAX_COUNTER)
			num_events = OP_MAX_COUNTER;

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
	printk(KERN_INFO "oprofile_arch_init: ret %d, events %d, "
	       "is_primary %d\n", ret, num_events, is_primary);
	return ret;
}


void __exit oprofile_arch_exit(void)
{
	int i;

	if (using_xenoprof)
		exit_driverfs();

	if (shared_buffer) {
		vunmap(shared_buffer);
		shared_buffer = NULL;
	}
	if (is_primary) {
		for (i = 0; i < pdomains; i++)
			if (p_shared_buffer[i]) {
		                vunmap(p_shared_buffer[i]);
                		p_shared_buffer[i] = NULL;
			}
		HYPERVISOR_xenoprof_op(XENOPROF_shutdown, NULL);
        }

}
