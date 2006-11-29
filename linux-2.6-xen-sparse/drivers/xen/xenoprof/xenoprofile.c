/**
 * @file xenoprofile.c
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
#include <asm/pgtable.h>
#include <xen/evtchn.h>
#include <xen/xenoprof.h>
#include <xen/driver_util.h>
#include <xen/interface/xen.h>
#include <xen/interface/xenoprof.h>
#include "../../../drivers/oprofile/cpu_buffer.h"
#include "../../../drivers/oprofile/event_buffer.h"

#define MAX_XENOPROF_SAMPLES 16

/* sample buffers shared with Xen */
xenoprof_buf_t * xenoprof_buf[MAX_VIRT_CPUS];
/* Shared buffer area */
struct xenoprof_shared_buffer shared_buffer;

/* Passive sample buffers shared with Xen */
xenoprof_buf_t *p_xenoprof_buf[MAX_OPROF_DOMAINS][MAX_VIRT_CPUS];
/* Passive shared buffer area */
struct xenoprof_shared_buffer p_shared_buffer[MAX_OPROF_DOMAINS];

static int xenoprof_start(void);
static void xenoprof_stop(void);

static int xenoprof_enabled = 0;
static int xenoprof_is_primary = 0;
static int active_defined;

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


static void exit_driverfs(void)
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

	if (xenoprof_is_primary && !test_and_set_bit(0, &flag)) {
		xenoprof_handle_passive();
		smp_mb__before_clear_bit();
		clear_bit(0, &flag);
	}

	return IRQ_HANDLED;
}


static void unbind_virq(void)
{
	int i;

	for_each_online_cpu(i) {
		if (ovf_irq[i] >= 0) {
			unbind_from_irqhandler(ovf_irq[i], NULL);
			ovf_irq[i] = -1;
		}
	}
}


static int bind_virq(void)
{
	int i, result;

	for_each_online_cpu(i) {
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


static void unmap_passive_list(void)
{
	int i;
	for (i = 0; i < pdomains; i++)
		xenoprof_arch_unmap_shared_buffer(&p_shared_buffer[i]);
	pdomains = 0;
}


static int map_xenoprof_buffer(int max_samples)
{
	struct xenoprof_get_buffer get_buffer;
	struct xenoprof_buf *buf;
	int ret, i;

	if ( shared_buffer.buffer )
		return 0;

	get_buffer.max_samples = max_samples;
	ret = xenoprof_arch_map_shared_buffer(&get_buffer, &shared_buffer);
	if (ret)
		return ret;
	nbuf = get_buffer.nbuf;

	for (i=0; i< nbuf; i++) {
		buf = (struct xenoprof_buf*) 
			&shared_buffer.buffer[i * get_buffer.bufsize];
		BUG_ON(buf->vcpu_id >= MAX_VIRT_CPUS);
		xenoprof_buf[buf->vcpu_id] = buf;
	}

	return 0;
}


static int xenoprof_setup(void)
{
	int ret;

	if ( (ret = map_xenoprof_buffer(MAX_XENOPROF_SAMPLES)) )
		return ret;

	if ( (ret = bind_virq()) )
		return ret;

	if (xenoprof_is_primary) {
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
		xenoprof_arch_counter();
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

	if (xenoprof_is_primary) {
		HYPERVISOR_xenoprof_op(XENOPROF_release_counters, NULL);
		active_defined = 0;
	}

	unbind_virq();

	xenoprof_arch_unmap_shared_buffer(&shared_buffer);
	if (xenoprof_is_primary)
		unmap_passive_list();
}


static int xenoprof_start(void)
{
	int ret = 0;

	if (xenoprof_is_primary)
		ret = HYPERVISOR_xenoprof_op(XENOPROF_start, NULL);
	if (!ret)
		xenoprof_arch_start();
	return ret;
}


static void xenoprof_stop(void)
{
	if (xenoprof_is_primary)
		HYPERVISOR_xenoprof_op(XENOPROF_stop, NULL);
	xenoprof_arch_stop();
}


static int xenoprof_set_active(int * active_domains,
			       unsigned int adomains)
{
	int ret = 0;
	int i;
	int set_dom0 = 0;
	domid_t domid;

	if (!xenoprof_is_primary)
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
	struct xenoprof_buf *buf;

	if (!xenoprof_is_primary)
        	return 0;

	if (pdoms > MAX_OPROF_DOMAINS)
		return -E2BIG;

	ret = HYPERVISOR_xenoprof_op(XENOPROF_reset_passive_list, NULL);
	if (ret)
		return ret;
	unmap_passive_list();

	for (i = 0; i < pdoms; i++) {
		passive_domains[i].domain_id = p_domains[i];
		passive_domains[i].max_samples = 2048;
		ret = xenoprof_arch_set_passive(&passive_domains[i],
						&p_shared_buffer[i]);
		if (ret)
			goto out;
		for (j = 0; j < passive_domains[i].nbuf; j++) {
			buf = (struct xenoprof_buf *)
				&p_shared_buffer[i].buffer[j * passive_domains[i].bufsize];
			BUG_ON(buf->vcpu_id >= MAX_VIRT_CPUS);
			p_xenoprof_buf[i][buf->vcpu_id] = buf;
		}
	}

	pdomains = pdoms;
	return 0;

out:
	for (j = 0; j < i; j++)
		xenoprof_arch_unmap_shared_buffer(&p_shared_buffer[i]);

 	return ret;
}

struct oprofile_operations xenoprof_ops = {
#ifdef HAVE_XENOPROF_CREATE_FILES
	.create_files 	= xenoprof_create_files,
#endif
	.set_active	= xenoprof_set_active,
	.set_passive    = xenoprof_set_passive,
	.setup 		= xenoprof_setup,
	.shutdown	= xenoprof_shutdown,
	.start		= xenoprof_start,
	.stop		= xenoprof_stop
};


/* in order to get driverfs right */
static int using_xenoprof;

int __init xenoprofile_init(struct oprofile_operations * ops)
{
	struct xenoprof_init init;
	int ret, i;

	ret = HYPERVISOR_xenoprof_op(XENOPROF_init, &init);
	if (!ret) {
		xenoprof_arch_init_counter(&init);
		xenoprof_is_primary = init.is_primary;

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
	printk(KERN_INFO "%s: ret %d, events %d, xenoprof_is_primary %d\n",
	       __func__, ret, init.num_events, xenoprof_is_primary);
	return ret;
}


void xenoprofile_exit(void)
{
	if (using_xenoprof)
		exit_driverfs();

	xenoprof_arch_unmap_shared_buffer(&shared_buffer);
	if (xenoprof_is_primary) {
		unmap_passive_list();
		HYPERVISOR_xenoprof_op(XENOPROF_shutdown, NULL);
        }
}
