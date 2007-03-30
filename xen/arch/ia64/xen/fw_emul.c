/*
 * fw_emul.c:
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */
#include <xen/config.h>
#include <asm/system.h>
#include <asm/pgalloc.h>

#include <linux/efi.h>
#include <asm/pal.h>
#include <asm/sal.h>
#include <asm/sn/sn_sal.h>
#include <asm/xenmca.h>

#include <public/sched.h>
#include "hpsim_ssc.h"
#include <asm/vcpu.h>
#include <asm/vmx_vcpu.h>
#include <asm/dom_fw.h>
#include <asm/uaccess.h>
#include <xen/console.h>
#include <xen/hypercall.h>
#include <xen/softirq.h>
#include <xen/time.h>

static DEFINE_SPINLOCK(efi_time_services_lock);

extern unsigned long running_on_sim;

struct sal_mc_params {
	u64 param_type;
	u64 i_or_m;
	u64 i_or_m_val;
	u64 timeout;
	u64 rz_always;
} sal_mc_params[SAL_MC_PARAM_CPE_INT + 1];

struct sal_vectors {
	u64 vector_type;
	u64 handler_addr1;
	u64 gp1;
	u64 handler_len1;
	u64 handler_addr2;
	u64 gp2;
	u64 handler_len2;
} sal_vectors[SAL_VECTOR_OS_BOOT_RENDEZ + 1];

struct smp_call_args_t {
	u64 type;
	u64 ret;
	u64 target;
	struct domain *domain;
	int corrected;
	int status;
	void *data;
}; 

extern sal_log_record_header_t	*sal_record;
DEFINE_SPINLOCK(sal_record_lock);

extern spinlock_t sal_queue_lock;

#define IA64_SAL_NO_INFORMATION_AVAILABLE	-5

#if defined(IA64_SAL_DEBUG_INFO)
static const char * const rec_name[] = { "MCA", "INIT", "CMC", "CPE" };

# define IA64_SAL_DEBUG(fmt...)	printk("sal_emulator: " fmt)
#else
# define IA64_SAL_DEBUG(fmt...)
#endif

void get_state_info_on(void *data) {
	struct smp_call_args_t *arg = data;
	int flags;

	spin_lock_irqsave(&sal_record_lock, flags);
	memset(sal_record, 0, ia64_sal_get_state_info_size(arg->type));
	arg->ret = ia64_sal_get_state_info(arg->type, (u64 *)sal_record);
	IA64_SAL_DEBUG("SAL_GET_STATE_INFO(%s) on CPU#%d returns %ld.\n",
	               rec_name[arg->type], smp_processor_id(), arg->ret);
	if (arg->corrected) {
		sal_record->severity = sal_log_severity_corrected;
		IA64_SAL_DEBUG("%s: IA64_SAL_CLEAR_STATE_INFO(SAL_INFO_TYPE_MCA)"
		               " force\n", __FUNCTION__);
	}
	if (arg->ret > 0) {
	  	/*
		 * Save current->domain and set to local(caller) domain for
		 * xencomm_paddr_to_maddr() which calculates maddr from
		 * paddr using mpa value of current->domain.
		 */
		struct domain *save;
		save = current->domain;
		current->domain = arg->domain;
		if (xencomm_copy_to_guest((void*)arg->target,
		                          sal_record, arg->ret, 0)) {
			printk("SAL_GET_STATE_INFO can't copy to user!!!!\n");
			arg->status = IA64_SAL_NO_INFORMATION_AVAILABLE;
			arg->ret = 0;
		}
	  	/* Restore current->domain to saved value. */
		current->domain = save;
	}
	spin_unlock_irqrestore(&sal_record_lock, flags);
}

void clear_state_info_on(void *data) {
	struct smp_call_args_t *arg = data;

	arg->ret = ia64_sal_clear_state_info(arg->type);
	IA64_SAL_DEBUG("SAL_CLEAR_STATE_INFO(%s) on CPU#%d returns %ld.\n",
	               rec_name[arg->type], smp_processor_id(), arg->ret);

}
  
struct sal_ret_values
sal_emulator (long index, unsigned long in1, unsigned long in2,
	      unsigned long in3, unsigned long in4, unsigned long in5,
	      unsigned long in6, unsigned long in7)
{
	struct ia64_sal_retval ret_stuff;
	unsigned long r9  = 0;
	unsigned long r10 = 0;
	long r11 = 0;
	long status;

	status = 0;
	switch (index) {
	    case SAL_FREQ_BASE:
		if (!running_on_sim)
			status = ia64_sal_freq_base(in1,&r9,&r10);
		else switch (in1) {
		      case SAL_FREQ_BASE_PLATFORM:
			r9 = 200000000;
			break;

		      case SAL_FREQ_BASE_INTERVAL_TIMER:
			r9 = 700000000;
			break;

		      case SAL_FREQ_BASE_REALTIME_CLOCK:
			r9 = 1;
			break;

		      default:
			status = -1;
			break;
		}
		break;
	    case SAL_PCI_CONFIG_READ:
		if (current->domain == dom0) {
			u64 value;
			// note that args 2&3 are swapped!!
			status = ia64_sal_pci_config_read(in1,in3,in2,&value);
			r9 = value;
		}
		else
		     printk("NON-PRIV DOMAIN CALLED SAL_PCI_CONFIG_READ\n");
		break;
	    case SAL_PCI_CONFIG_WRITE:
		if (current->domain == dom0) {
			if (((in1 & ~0xffffffffUL) && (in4 == 0)) ||
			    (in4 > 1) ||
			    (in2 > 8) || (in2 & (in2-1)))
				printk("*** SAL_PCI_CONF_WRITE?!?(adr=0x%lx,typ=0x%lx,sz=0x%lx,val=0x%lx)\n",
					in1,in4,in2,in3);
			// note that args are in a different order!!
			status = ia64_sal_pci_config_write(in1,in4,in2,in3);
		}
		else
		     printk("NON-PRIV DOMAIN CALLED SAL_PCI_CONFIG_WRITE\n");
		break;
	    case SAL_SET_VECTORS:
 		if (in1 == SAL_VECTOR_OS_BOOT_RENDEZ) {
 			if (in4 != 0 || in5 != 0 || in6 != 0 || in7 != 0) {
 				/* Sanity check: cs_length1 must be 0,
 				   second vector is reserved.  */
 				status = -2;
 			}
 			else {
				struct domain *d = current->domain;
				d->arch.sal_data->boot_rdv_ip = in2;
				d->arch.sal_data->boot_rdv_r1 = in3;
			}
 		}
 		else
		{
			if (in1 > sizeof(sal_vectors)/sizeof(sal_vectors[0])-1)
				BUG();
			sal_vectors[in1].vector_type	= in1;
			sal_vectors[in1].handler_addr1	= in2;
			sal_vectors[in1].gp1		= in3;
			sal_vectors[in1].handler_len1	= in4;
			sal_vectors[in1].handler_addr2	= in5;
			sal_vectors[in1].gp2		= in6;
			sal_vectors[in1].handler_len2	= in7;
		}
		break;
	    case SAL_GET_STATE_INFO:
		if (current->domain == dom0) {
			sal_queue_entry_t *e;
			unsigned long flags;
			struct smp_call_args_t arg;

			spin_lock_irqsave(&sal_queue_lock, flags);
			if (!sal_queue || list_empty(&sal_queue[in1])) {
				sal_log_record_header_t header;
				XEN_GUEST_HANDLE(void) handle =
					*(XEN_GUEST_HANDLE(void)*)&in3;

				IA64_SAL_DEBUG("SAL_GET_STATE_INFO(%s) "
				               "no sal_queue entry found.\n",
				               rec_name[in1]);
				memset(&header, 0, sizeof(header));

				if (copy_to_guest(handle, &header, 1)) {
					printk("sal_emulator: "
					       "SAL_GET_STATE_INFO can't copy "
					       "empty header to user: 0x%lx\n",
					       in3);
				}
				status = IA64_SAL_NO_INFORMATION_AVAILABLE;
				r9 = 0;
				spin_unlock_irqrestore(&sal_queue_lock, flags);
				break;
			}
			e = list_entry(sal_queue[in1].next,
			               sal_queue_entry_t, list);
			spin_unlock_irqrestore(&sal_queue_lock, flags);

			IA64_SAL_DEBUG("SAL_GET_STATE_INFO(%s <= %s) "
			               "on CPU#%d.\n",
			               rec_name[e->sal_info_type],
			               rec_name[in1], e->cpuid);

			arg.type = e->sal_info_type;
			arg.target = in3;
			arg.corrected = !!((in1 != e->sal_info_type) && 
			                (e->sal_info_type == SAL_INFO_TYPE_MCA));
			arg.domain = current->domain;
			arg.status = 0;

			if (e->cpuid == smp_processor_id()) {
				IA64_SAL_DEBUG("SAL_GET_STATE_INFO: local\n");
				get_state_info_on(&arg);
			} else {
				int ret;
				IA64_SAL_DEBUG("SAL_GET_STATE_INFO: remote\n");
				ret = smp_call_function_single(e->cpuid,
				                               get_state_info_on,
				                               &arg, 0, 1);
				if (ret < 0) {
					printk("SAL_GET_STATE_INFO "
					       "smp_call_function_single error:"
					       " %d\n", ret);
					arg.ret = 0;
					arg.status =
					     IA64_SAL_NO_INFORMATION_AVAILABLE;
				}
			}
			r9 = arg.ret;
			status = arg.status;
			if (r9 == 0) {
				spin_lock_irqsave(&sal_queue_lock, flags);
				list_del(&e->list);
				spin_unlock_irqrestore(&sal_queue_lock, flags);
				xfree(e);
			}
		} else {
			status = IA64_SAL_NO_INFORMATION_AVAILABLE;
			r9 = 0;
		}
		break;
	    case SAL_GET_STATE_INFO_SIZE:
		r9 = ia64_sal_get_state_info_size(in1);
		break;
	    case SAL_CLEAR_STATE_INFO:
		if (current->domain == dom0) {
			sal_queue_entry_t *e;
			unsigned long flags;
			struct smp_call_args_t arg;

			spin_lock_irqsave(&sal_queue_lock, flags);
			if (list_empty(&sal_queue[in1])) {
				IA64_SAL_DEBUG("SAL_CLEAR_STATE_INFO(%s) "
				               "no sal_queue entry found.\n",
				               rec_name[in1]);
				status = IA64_SAL_NO_INFORMATION_AVAILABLE;
				r9 = 0;
				spin_unlock_irqrestore(&sal_queue_lock, flags);
				break;
			}
			e = list_entry(sal_queue[in1].next,
			               sal_queue_entry_t, list);

			list_del(&e->list);
			spin_unlock_irqrestore(&sal_queue_lock, flags);

			IA64_SAL_DEBUG("SAL_CLEAR_STATE_INFO(%s <= %s) "
			               "on CPU#%d.\n",
			               rec_name[e->sal_info_type],
			               rec_name[in1], e->cpuid);
			

			arg.type = e->sal_info_type;
			arg.status = 0;
			if (e->cpuid == smp_processor_id()) {
				IA64_SAL_DEBUG("SAL_CLEAR_STATE_INFO: local\n");
				clear_state_info_on(&arg);
			} else {
				int ret;
				IA64_SAL_DEBUG("SAL_CLEAR_STATE_INFO: remote\n");
				ret = smp_call_function_single(e->cpuid,
					clear_state_info_on, &arg, 0, 1);
				if (ret < 0) {
					printk("sal_emulator: "
					       "SAL_CLEAR_STATE_INFO "
					       "smp_call_function_single error:"
					       " %d\n", ret);
					arg.ret = 0;
					arg.status =
					     IA64_SAL_NO_INFORMATION_AVAILABLE;
				}
			}
			r9 = arg.ret;
			status = arg.status;
			xfree(e);
		}
		break;
	    case SAL_MC_RENDEZ:
		printk("*** CALLED SAL_MC_RENDEZ.  IGNORED...\n");
		break;
	    case SAL_MC_SET_PARAMS:
		if (in1 > sizeof(sal_mc_params)/sizeof(sal_mc_params[0]))
			BUG();
		sal_mc_params[in1].param_type	= in1;
		sal_mc_params[in1].i_or_m	= in2;
		sal_mc_params[in1].i_or_m_val	= in3;
		sal_mc_params[in1].timeout	= in4;
		sal_mc_params[in1].rz_always	= in5;
		break;
	    case SAL_CACHE_FLUSH:
		if (1) {
			/*  Flush using SAL.
			    This method is faster but has a side effect on
			    other vcpu running on this cpu.  */
			status = ia64_sal_cache_flush (in1);
		}
		else {
			/*  Flush with fc all the domain.
			    This method is slower but has no side effects.  */
			domain_cache_flush (current->domain, in1 == 4 ? 1 : 0);
			status = 0;
		}
		break;
	    case SAL_CACHE_INIT:
		printk("*** CALLED SAL_CACHE_INIT.  IGNORED...\n");
		break;
	    case SAL_UPDATE_PAL:
		printk("*** CALLED SAL_UPDATE_PAL.  IGNORED...\n");
		break;
	    case SAL_XEN_SAL_RETURN:
	        if (!test_and_set_bit(_VPF_down, &current->pause_flags))
			vcpu_sleep_nosync(current);
		break;
	    case SN_SAL_GET_MASTER_NASID:
		status = -1;
		if (current->domain == dom0) {
			printk("*** Emulating SN_SAL_GET_MASTER_NASID ***\n");
			SAL_CALL_NOLOCK(ret_stuff, SN_SAL_GET_MASTER_NASID,
					0, 0, 0, 0, 0, 0, 0);
			status = ret_stuff.status;
			r9 = ret_stuff.v0;
			r10 = ret_stuff.v1;
			r11 = ret_stuff.v2;
		}
		break;
	    case SN_SAL_GET_KLCONFIG_ADDR:
		status = -1;
		if (current->domain == dom0) {
			printk("*** Emulating SN_SAL_GET_KLCONFIG_ADDR ***\n");
			SAL_CALL_NOLOCK(ret_stuff, SN_SAL_GET_KLCONFIG_ADDR,
					in1, 0, 0, 0, 0, 0, 0);
			status = ret_stuff.status;
			r9 = ret_stuff.v0;
			r10 = ret_stuff.v1;
			r11 = ret_stuff.v2;
		}
		break;
	    case SN_SAL_GET_SAPIC_INFO:
		status = -1;
		if (current->domain == dom0) {
			printk("*** Emulating SN_SAL_GET_SAPIC_INFO ***\n");
			SAL_CALL_NOLOCK(ret_stuff, SN_SAL_GET_SAPIC_INFO, in1,
					0, 0, 0, 0, 0, 0);
			status = ret_stuff.status;
			r9 = ret_stuff.v0;
			r10 = ret_stuff.v1;
			r11 = ret_stuff.v2;
		}
		break;
	    case SN_SAL_GET_SN_INFO:
		status = -1;
		if (current->domain == dom0) {
			printk("*** Emulating SN_SAL_GET_SN_INFO ***\n");
			SAL_CALL_NOLOCK(ret_stuff, SN_SAL_GET_SN_INFO, in1,
					0, 0, 0, 0, 0, 0);
			status = ret_stuff.status;
			r9 = ret_stuff.v0;
			r10 = ret_stuff.v1;
			r11 = ret_stuff.v2;
		}
		break;
	    case SN_SAL_IOIF_GET_HUBDEV_INFO:
		status = -1;
		if (current->domain == dom0) {
			printk("*** Emulating SN_SAL_IOIF_GET_HUBDEV_INFO ***\n");
			SAL_CALL_NOLOCK(ret_stuff, SN_SAL_IOIF_GET_HUBDEV_INFO,
					in1, in2, 0, 0, 0, 0, 0);
			status = ret_stuff.status;
			r9 = ret_stuff.v0;
			r10 = ret_stuff.v1;
			r11 = ret_stuff.v2;
		}
		break;
	    default:
		printk("*** CALLED SAL_ WITH UNKNOWN INDEX (%lx).  "
		       "IGNORED...\n", index);
		status = -1;
		break;
	}
	return ((struct sal_ret_values) {status, r9, r10, r11});
}

cpumask_t cpu_cache_coherent_map;

struct cache_flush_args {
	u64 cache_type;
	u64 operation;
	u64 progress;
	long status;
};

static void
remote_pal_cache_flush(void *v)
{
	struct cache_flush_args *args = v;
	long status;
	u64 progress = args->progress;

	status = ia64_pal_cache_flush(args->cache_type, args->operation,
				      &progress, NULL);
	if (status != 0)
		args->status = status;
}

struct ia64_pal_retval
xen_pal_emulator(unsigned long index, u64 in1, u64 in2, u64 in3)
{
	unsigned long r9  = 0;
	unsigned long r10 = 0;
	unsigned long r11 = 0;
	long status = PAL_STATUS_UNIMPLEMENTED;
	unsigned long flags;
	int processor;

	if (running_on_sim)
		return pal_emulator_static(index);

	// pal code must be mapped by a TR when pal is called, however
	// calls are rare enough that we will map it lazily rather than
	// at every context switch
	//efi_map_pal_code();
	switch (index) {
	    case PAL_MEM_ATTRIB:
		status = ia64_pal_mem_attrib(&r9);
		break;
	    case PAL_FREQ_BASE:
		status = ia64_pal_freq_base(&r9);
		if (status == PAL_STATUS_UNIMPLEMENTED) {
			status = ia64_sal_freq_base(0, &r9, &r10);
			r10 = 0;
		}
		break;
	    case PAL_PROC_GET_FEATURES:
		status = ia64_pal_proc_get_features(&r9,&r10,&r11);
		break;
	    case PAL_BUS_GET_FEATURES:
		status = ia64_pal_bus_get_features(
				(pal_bus_features_u_t *) &r9,
				(pal_bus_features_u_t *) &r10,
				(pal_bus_features_u_t *) &r11);
		break;
	    case PAL_FREQ_RATIOS:
		status = ia64_pal_freq_ratios(
				(struct pal_freq_ratio *) &r9,
				(struct pal_freq_ratio *) &r10,
				(struct pal_freq_ratio *) &r11);
		break;
	    case PAL_PTCE_INFO:
		{
			// return hard-coded xen-specific values because ptc.e
			// is emulated on xen to always flush everything
			// these values result in only one ptc.e instruction
			status = 0; r9 = 0; r10 = (1L << 32) | 1L; r11 = 0;
		}
		break;
	    case PAL_VERSION:
		status = ia64_pal_version(
				(pal_version_u_t *) &r9,
				(pal_version_u_t *) &r10);
		break;
	    case PAL_VM_PAGE_SIZE:
		status = ia64_pal_vm_page_size(&r9,&r10);
		break;
	    case PAL_DEBUG_INFO:
		status = ia64_pal_debug_info(&r9,&r10);
		break;
	    case PAL_CACHE_SUMMARY:
		status = ia64_pal_cache_summary(&r9,&r10);
		break;
	    case PAL_VM_SUMMARY:
		if (VMX_DOMAIN(current)) {
			pal_vm_info_1_u_t v1;
			pal_vm_info_2_u_t v2;
			status = ia64_pal_vm_summary((pal_vm_info_1_u_t *)&v1,
			                             (pal_vm_info_2_u_t *)&v2);
			v1.pal_vm_info_1_s.max_itr_entry = NITRS - 1;
			v1.pal_vm_info_1_s.max_dtr_entry = NDTRS - 1;
			v2.pal_vm_info_2_s.impl_va_msb -= 1;
			v2.pal_vm_info_2_s.rid_size =
				current->domain->arch.rid_bits;
			r9 = v1.pvi1_val;
			r10 = v2.pvi2_val;
		} else {
			/* Use xen-specific values.
			   hash_tag_id is somewhat random! */
			static const pal_vm_info_1_u_t v1 =
				{.pal_vm_info_1_s =
				 { .vw = 1,
				   .phys_add_size = 44,
				   .key_size = 16,
				   .max_pkr = 15,
				   .hash_tag_id = 0x30,
				   .max_dtr_entry = NDTRS - 1,
				   .max_itr_entry = NITRS - 1,
#ifdef VHPT_GLOBAL
				   .max_unique_tcs = 3,
				   .num_tc_levels = 2
#else
				   .max_unique_tcs = 2,
				   .num_tc_levels = 1
#endif
				 }};
			pal_vm_info_2_u_t v2;
			v2.pvi2_val = 0;
			v2.pal_vm_info_2_s.rid_size =
				current->domain->arch.rid_bits;
			v2.pal_vm_info_2_s.impl_va_msb = 50;
			r9 = v1.pvi1_val;
			r10 = v2.pvi2_val;
			status = PAL_STATUS_SUCCESS;
		}
		break;
	    case PAL_VM_INFO:
		if (VMX_DOMAIN(current)) {
			status = ia64_pal_vm_info(in1, in2, 
			                          (pal_tc_info_u_t *)&r9, &r10);
			break;
		}
#ifdef VHPT_GLOBAL
		if (in1 == 0 && in2 == 2) {
			/* Level 1: VHPT  */
			const pal_tc_info_u_t v =
				{ .pal_tc_info_s = {.num_sets = 128,
						    .associativity = 1,
						    .num_entries = 128,
						    .pf = 1,
						    .unified = 1,
						    .reduce_tr = 0,
						    .reserved = 0}};
			r9 = v.pti_val;
			/* Only support PAGE_SIZE tc.  */
			r10 = PAGE_SIZE;
			status = PAL_STATUS_SUCCESS;
		}
#endif
	        else if (
#ifdef VHPT_GLOBAL 
	                in1 == 1 /* Level 2. */
#else
			in1 == 0 /* Level 1. */
#endif
			 && (in2 == 1 || in2 == 2))
		{
			/* itlb/dtlb, 1 entry.  */
			const pal_tc_info_u_t v =
				{ .pal_tc_info_s = {.num_sets = 1,
						    .associativity = 1,
						    .num_entries = 1,
						    .pf = 1,
						    .unified = 0,
						    .reduce_tr = 0,
						    .reserved = 0}};
			r9 = v.pti_val;
			/* Only support PAGE_SIZE tc.  */
			r10 = PAGE_SIZE;
			status = PAL_STATUS_SUCCESS;
		}
	        else
			status = PAL_STATUS_EINVAL;
		break;
	    case PAL_RSE_INFO:
		status = ia64_pal_rse_info(
				&r9,
				(pal_hints_u_t *) &r10);
		break;
	    case PAL_REGISTER_INFO:
		status = ia64_pal_register_info(in1, &r9, &r10);
		break;
	    case PAL_CACHE_FLUSH:
		if (in3 != 0) /* Initially progress_indicator must be 0 */
			panic_domain(NULL, "PAL_CACHE_FLUSH ERROR, "
				     "progress_indicator=%lx", in3);

		/* Always call Host Pal in int=0 */
		in2 &= ~PAL_CACHE_FLUSH_CHK_INTRS;

		if (in1 != PAL_CACHE_TYPE_COHERENT) {
			struct cache_flush_args args = {
				.cache_type = in1,
				.operation = in2,
				.progress = 0,
				.status = 0
			};
			smp_call_function(remote_pal_cache_flush,
					  (void *)&args, 1, 1);
			if (args.status != 0)
				panic_domain(NULL, "PAL_CACHE_FLUSH ERROR, "
					     "remote status %lx", args.status);
		}

		/*
		 * Call Host PAL cache flush
		 * Clear psr.ic when call PAL_CACHE_FLUSH
		 */
		r10 = in3;
		local_irq_save(flags);
		processor = current->processor;
		status = ia64_pal_cache_flush(in1, in2, &r10, &r9);
		local_irq_restore(flags);

		if (status != 0)
			panic_domain(NULL, "PAL_CACHE_FLUSH ERROR, "
			             "status %lx", status);

		if (in1 == PAL_CACHE_TYPE_COHERENT) {
			cpus_setall(current->arch.cache_coherent_map);
			cpu_clear(processor, current->arch.cache_coherent_map);
			cpus_setall(cpu_cache_coherent_map);
			cpu_clear(processor, cpu_cache_coherent_map);
		}
		break;
	    case PAL_PERF_MON_INFO:
		{
			unsigned long pm_buffer[16];
			status = ia64_pal_perf_mon_info(
					pm_buffer,
					(pal_perf_mon_info_u_t *) &r9);
			if (status != 0) {
				while(1)
				printk("PAL_PERF_MON_INFO fails ret=%ld\n", status);
				break;
			}
			if (copy_to_user((void __user *)in1,pm_buffer,128)) {
				while(1)
				printk("xen_pal_emulator: PAL_PERF_MON_INFO "
					"can't copy to user!!!!\n");
				status = PAL_STATUS_UNIMPLEMENTED;
				break;
			}
		}
		break;
	    case PAL_CACHE_INFO:
		{
			pal_cache_config_info_t ci;
			status = ia64_pal_cache_config_info(in1,in2,&ci);
			if (status != 0) break;
			r9 = ci.pcci_info_1.pcci1_data;
			r10 = ci.pcci_info_2.pcci2_data;
		}
		break;
	    case PAL_VM_TR_READ:	/* FIXME: vcpu_get_tr?? */
		printk("PAL_VM_TR_READ NOT IMPLEMENTED, IGNORED!\n");
		break;
	    case PAL_HALT_INFO:
	        {
		    /* 1000 cycles to enter/leave low power state,
		       consumes 10 mW, implemented and cache/TLB coherent.  */
		    unsigned long res = 1000UL | (1000UL << 16) | (10UL << 32)
			    | (1UL << 61) | (1UL << 60);
		    if (copy_to_user ((void *)in1, &res, sizeof (res)))
			    status = PAL_STATUS_EINVAL;    
		    else
			    status = PAL_STATUS_SUCCESS;
	        }
		break;
	    case PAL_HALT:
		if (current->domain == dom0) {
			printk ("Domain0 halts the machine\n");
			console_start_sync();
			(*efi.reset_system)(EFI_RESET_SHUTDOWN,0,0,NULL);
		} else {
			set_bit(_VPF_down, &current->pause_flags);
			vcpu_sleep_nosync(current);
			status = PAL_STATUS_SUCCESS;
		}
		break;
	    case PAL_HALT_LIGHT:
		if (VMX_DOMAIN(current)) {
			/* Called by VTI.  */
			if (!is_unmasked_irq(current)) {
				do_sched_op_compat(SCHEDOP_block, 0);
				do_softirq();
			}
			status = PAL_STATUS_SUCCESS;
		}
		break;
	    case PAL_PLATFORM_ADDR:
		if (VMX_DOMAIN(current))
			status = PAL_STATUS_SUCCESS;
		break;
	    case PAL_LOGICAL_TO_PHYSICAL:
		/* Optional, no need to complain about being unimplemented */
		break;
	    default:
		printk("xen_pal_emulator: UNIMPLEMENTED PAL CALL %lu!!!!\n",
				index);
		break;
	}
	return ((struct ia64_pal_retval) {status, r9, r10, r11});
}

// given a current domain (virtual or metaphysical) address, return the virtual address
static unsigned long
efi_translate_domain_addr(unsigned long domain_addr, IA64FAULT *fault,
			  struct page_info** page)
{
	struct vcpu *v = current;
	unsigned long mpaddr = domain_addr;
	unsigned long virt;
	*fault = IA64_NO_FAULT;

again:
 	if (v->domain->arch.sal_data->efi_virt_mode) {
		*fault = vcpu_tpa(v, domain_addr, &mpaddr);
		if (*fault != IA64_NO_FAULT) return 0;
	}

	virt = (unsigned long)domain_mpa_to_imva(v->domain, mpaddr);
	*page = virt_to_page(virt);
	if (get_page(*page, current->domain) == 0) {
		if (page_get_owner(*page) != current->domain) {
			// which code is appropriate?
			*fault = IA64_FAULT;
			return 0;
		}
		goto again;
	}

	return virt;
}

static efi_status_t
efi_emulate_get_time(
	unsigned long tv_addr, unsigned long tc_addr,
	IA64FAULT *fault)
{
	unsigned long tv, tc = 0;
	struct page_info *tv_page = NULL;
	struct page_info *tc_page = NULL;
	efi_status_t status = 0;
	efi_time_t *tvp;
	struct tm timeptr;
	unsigned long xtimesec;

	tv = efi_translate_domain_addr(tv_addr, fault, &tv_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;
	if (tc_addr) {
		tc = efi_translate_domain_addr(tc_addr, fault, &tc_page);
		if (*fault != IA64_NO_FAULT)
			goto errout;
	}

	spin_lock(&efi_time_services_lock);
	status = (*efi.get_time)((efi_time_t *) tv, (efi_time_cap_t *) tc);
	tvp = (efi_time_t *)tv;
	xtimesec = mktime(tvp->year, tvp->month, tvp->day, tvp->hour,
	                  tvp->minute, tvp->second);
	xtimesec += current->domain->time_offset_seconds;
	timeptr = gmtime(xtimesec);
	tvp->second = timeptr.tm_sec;
	tvp->minute = timeptr.tm_min;
	tvp->hour   = timeptr.tm_hour;
	tvp->day    = timeptr.tm_mday;
	tvp->month  = timeptr.tm_mon + 1;
	tvp->year   = timeptr.tm_year + 1900;
	spin_unlock(&efi_time_services_lock);

errout:
	if (tc_page != NULL)
		put_page(tc_page);
	if (tv_page != NULL)
		put_page(tv_page);

	return status;
}

static efi_status_t
efi_emulate_set_time(
	unsigned long tv_addr, IA64FAULT *fault)
{
	unsigned long tv;
	struct page_info *tv_page = NULL;
	efi_status_t status = 0;

	if (current->domain != dom0)
		return EFI_UNSUPPORTED;

	tv = efi_translate_domain_addr(tv_addr, fault, &tv_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;

	spin_lock(&efi_time_services_lock);
	status = (*efi.set_time)((efi_time_t *)tv);
	spin_unlock(&efi_time_services_lock);

errout:
	if (tv_page != NULL)
		put_page(tv_page);

	return status;
}

static efi_status_t
efi_emulate_get_wakeup_time(
	unsigned long e_addr, unsigned long p_addr,
	unsigned long tv_addr, IA64FAULT *fault)
{
	unsigned long enabled, pending, tv;
	struct page_info *e_page = NULL, *p_page = NULL,
	                 *tv_page = NULL;
	efi_status_t status = 0;

	if (current->domain != dom0)
		return EFI_UNSUPPORTED;

	if (!e_addr || !p_addr || !tv_addr)
		return EFI_INVALID_PARAMETER;

	enabled = efi_translate_domain_addr(e_addr, fault, &e_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;
	pending = efi_translate_domain_addr(p_addr, fault, &p_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;
	tv = efi_translate_domain_addr(tv_addr, fault, &tv_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;

	spin_lock(&efi_time_services_lock);
	status = (*efi.get_wakeup_time)((efi_bool_t *)enabled,
	                                (efi_bool_t *)pending,
	                                (efi_time_t *)tv);
	spin_unlock(&efi_time_services_lock);

errout:
	if (e_page != NULL)
		put_page(e_page);
	if (p_page != NULL)
		put_page(p_page);
	if (tv_page != NULL)
		put_page(tv_page);

	return status;
}

static efi_status_t
efi_emulate_set_wakeup_time(
	unsigned long enabled, unsigned long tv_addr,
	IA64FAULT *fault)
{
	unsigned long tv = 0;
	struct page_info *tv_page = NULL;
	efi_status_t status = 0;

	if (current->domain != dom0)
		return EFI_UNSUPPORTED;

	if (tv_addr) {
		tv = efi_translate_domain_addr(tv_addr, fault, &tv_page);
		if (*fault != IA64_NO_FAULT)
			goto errout;
	}

	spin_lock(&efi_time_services_lock);
	status = (*efi.set_wakeup_time)((efi_bool_t)enabled,
	                                (efi_time_t *)tv);
	spin_unlock(&efi_time_services_lock);

errout:
	if (tv_page != NULL)
		put_page(tv_page);

	return status;
}

static efi_status_t
efi_emulate_get_variable(
	unsigned long name_addr, unsigned long vendor_addr,
	unsigned long attr_addr, unsigned long data_size_addr,
	unsigned long data_addr, IA64FAULT *fault)
{
	unsigned long name, vendor, attr = 0, data_size, data;
	struct page_info *name_page = NULL, *vendor_page = NULL,
	                 *attr_page = NULL, *data_size_page = NULL,
	                 *data_page = NULL;
	efi_status_t status = 0;

	if (current->domain != dom0)
		return EFI_UNSUPPORTED;

	name = efi_translate_domain_addr(name_addr, fault, &name_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;
	vendor = efi_translate_domain_addr(vendor_addr, fault, &vendor_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;
	data_size = efi_translate_domain_addr(data_size_addr, fault,
	                                      &data_size_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;
	data = efi_translate_domain_addr(data_addr, fault, &data_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;
	if (attr_addr) {
		attr = efi_translate_domain_addr(attr_addr, fault, &attr_page);
		if (*fault != IA64_NO_FAULT)
			goto errout;
	}

	status = (*efi.get_variable)((efi_char16_t *)name,
	                             (efi_guid_t *)vendor,
	                             (u32 *)attr,
	                             (unsigned long *)data_size,
	                             (void *)data);

errout:
	if (name_page != NULL)
		put_page(name_page);
	if (vendor_page != NULL)
		put_page(vendor_page);
	if (attr_page != NULL)
		put_page(attr_page);
	if (data_size_page != NULL)
		put_page(data_size_page);
	if (data_page != NULL)
		put_page(data_page);

	return status;
}

static efi_status_t
efi_emulate_get_next_variable(
	unsigned long name_size_addr, unsigned long name_addr,
	unsigned long vendor_addr, IA64FAULT *fault)
{
	unsigned long name_size, name, vendor;
	struct page_info *name_size_page = NULL, *name_page = NULL,
	                 *vendor_page = NULL;
	efi_status_t status = 0;

	if (current->domain != dom0)
		return EFI_UNSUPPORTED;

	name_size = efi_translate_domain_addr(name_size_addr, fault,
	                                      &name_size_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;
	name = efi_translate_domain_addr(name_addr, fault, &name_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;
	vendor = efi_translate_domain_addr(vendor_addr, fault, &vendor_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;

	status = (*efi.get_next_variable)((unsigned long *)name_size,
	                                  (efi_char16_t *)name,
	                                  (efi_guid_t *)vendor);

errout:
	if (name_size_page != NULL)
		put_page(name_size_page);
	if (name_page != NULL)
		put_page(name_page);
	if (vendor_page != NULL)
		put_page(vendor_page);

	return status;
}

static efi_status_t
efi_emulate_set_variable(
	unsigned long name_addr, unsigned long vendor_addr, 
	unsigned long attr, unsigned long data_size, 
	unsigned long data_addr, IA64FAULT *fault)
{
	unsigned long name, vendor, data;
	struct page_info *name_page = NULL, *vendor_page = NULL,
	                 *data_page = NULL;
	efi_status_t status = 0;

	if (current->domain != dom0)
		return EFI_UNSUPPORTED;

	name = efi_translate_domain_addr(name_addr, fault, &name_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;
	vendor = efi_translate_domain_addr(vendor_addr, fault, &vendor_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;
	data = efi_translate_domain_addr(data_addr, fault, &data_page);
	if (*fault != IA64_NO_FAULT)
		goto errout;

	status = (*efi.set_variable)((efi_char16_t *)name,
	                             (efi_guid_t *)vendor,
	                             attr,
	                             data_size,
	                             (void *)data);

errout:
	if (name_page != NULL)
		put_page(name_page);
	if (vendor_page != NULL)
		put_page(vendor_page);
	if (data_page != NULL)
		put_page(data_page);

	return status;
}

static efi_status_t
efi_emulate_set_virtual_address_map(
	unsigned long memory_map_size, unsigned long descriptor_size,
	u32 descriptor_version, efi_memory_desc_t *virtual_map)
{
	void *efi_map_start, *efi_map_end, *p;
	efi_memory_desc_t entry, *md = &entry;
	u64 efi_desc_size;

	unsigned long *vfn;
	struct domain *d = current->domain;
	efi_runtime_services_t *efi_runtime = d->arch.efi_runtime;
	fpswa_interface_t *fpswa_inf = d->arch.fpswa_inf;

	if (descriptor_version != EFI_MEMDESC_VERSION) {
		printk ("efi_emulate_set_virtual_address_map: memory "
		        "descriptor version unmatched (%d vs %d)\n",
		        (int)descriptor_version, EFI_MEMDESC_VERSION);
		return EFI_INVALID_PARAMETER;
	}

	if (descriptor_size != sizeof(efi_memory_desc_t)) {
		printk ("efi_emulate_set_virtual_address_map: memory descriptor size unmatched\n");
		return EFI_INVALID_PARAMETER;
	}

	if (d->arch.sal_data->efi_virt_mode)
		return EFI_UNSUPPORTED;

	efi_map_start = virtual_map;
	efi_map_end   = efi_map_start + memory_map_size;
	efi_desc_size = sizeof(efi_memory_desc_t);

	for (p = efi_map_start; p < efi_map_end; p += efi_desc_size) {
		if (copy_from_user(&entry, p, sizeof(efi_memory_desc_t))) {
			printk ("efi_emulate_set_virtual_address_map: copy_from_user() fault. addr=0x%p\n", p);
			return EFI_UNSUPPORTED;
		}

		/* skip over non-PAL_CODE memory descriptors; EFI_RUNTIME is included in PAL_CODE. */
                if (md->type != EFI_PAL_CODE)
                        continue;

#define EFI_HYPERCALL_PATCH_TO_VIRT(tgt,call) \
	do { \
		vfn = (unsigned long *) domain_mpa_to_imva(d, tgt); \
		*vfn++ = FW_HYPERCALL_##call##_INDEX * 16UL + md->virt_addr; \
		*vfn++ = 0; \
	} while (0)

		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->get_time,EFI_GET_TIME);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->set_time,EFI_SET_TIME);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->get_wakeup_time,EFI_GET_WAKEUP_TIME);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->set_wakeup_time,EFI_SET_WAKEUP_TIME);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->set_virtual_address_map,EFI_SET_VIRTUAL_ADDRESS_MAP);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->get_variable,EFI_GET_VARIABLE);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->get_next_variable,EFI_GET_NEXT_VARIABLE);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->set_variable,EFI_SET_VARIABLE);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->get_next_high_mono_count,EFI_GET_NEXT_HIGH_MONO_COUNT);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->reset_system,EFI_RESET_SYSTEM);

		vfn = (unsigned long *) domain_mpa_to_imva(d, (unsigned long) fpswa_inf->fpswa);
		*vfn++ = FW_HYPERCALL_FPSWA_PATCH_INDEX * 16UL + md->virt_addr;
		*vfn   = 0;
		fpswa_inf->fpswa = (void *) (FW_HYPERCALL_FPSWA_ENTRY_INDEX * 16UL + md->virt_addr);
		break;
	}

	/* The virtual address map has been applied. */
	d->arch.sal_data->efi_virt_mode = 1;

	return EFI_SUCCESS;
}

efi_status_t
efi_emulator (struct pt_regs *regs, IA64FAULT *fault)
{
	struct vcpu *v = current;
	efi_status_t status;

	*fault = IA64_NO_FAULT;

	switch (regs->r2) {
	    case FW_HYPERCALL_EFI_RESET_SYSTEM:
	        {
		    u8 reason;
		    unsigned long val = vcpu_get_gr(v,32);
		    switch (val)
		    {
		    case EFI_RESET_SHUTDOWN:
			    reason = SHUTDOWN_poweroff;
			    break;
		    case EFI_RESET_COLD:
		    case EFI_RESET_WARM:
		    default:
			    reason = SHUTDOWN_reboot;
			    break;
		    }
		    domain_shutdown (current->domain, reason);
		}
		status = EFI_UNSUPPORTED;
		break;
	    case FW_HYPERCALL_EFI_GET_TIME:
		status = efi_emulate_get_time (
				vcpu_get_gr(v,32),
				vcpu_get_gr(v,33),
				fault);
		break;
	    case FW_HYPERCALL_EFI_SET_TIME:
		status = efi_emulate_set_time (
				vcpu_get_gr(v,32),
				fault);
		break;
	    case FW_HYPERCALL_EFI_GET_WAKEUP_TIME:
		status = efi_emulate_get_wakeup_time (
				vcpu_get_gr(v,32),
				vcpu_get_gr(v,33),
				vcpu_get_gr(v,34),
				fault);
		break;
	    case FW_HYPERCALL_EFI_SET_WAKEUP_TIME:
		status = efi_emulate_set_wakeup_time (
				vcpu_get_gr(v,32),
				vcpu_get_gr(v,33),
				fault);
		break;
	    case FW_HYPERCALL_EFI_GET_VARIABLE:
		status = efi_emulate_get_variable (
				vcpu_get_gr(v,32),
				vcpu_get_gr(v,33),
				vcpu_get_gr(v,34),
				vcpu_get_gr(v,35),
				vcpu_get_gr(v,36),
				fault);
		break;
	    case FW_HYPERCALL_EFI_GET_NEXT_VARIABLE:
		status = efi_emulate_get_next_variable (
				vcpu_get_gr(v,32),
				vcpu_get_gr(v,33),
				vcpu_get_gr(v,34),
				fault);
		break;
	    case FW_HYPERCALL_EFI_SET_VARIABLE:
		status = efi_emulate_set_variable (
				vcpu_get_gr(v,32),
				vcpu_get_gr(v,33),
				vcpu_get_gr(v,34),
				vcpu_get_gr(v,35),
				vcpu_get_gr(v,36),
				fault);
		break;
	    case FW_HYPERCALL_EFI_SET_VIRTUAL_ADDRESS_MAP:
		status = efi_emulate_set_virtual_address_map (
				vcpu_get_gr(v,32),
				vcpu_get_gr(v,33),
 				(u32) vcpu_get_gr(v,34),
				(efi_memory_desc_t *) vcpu_get_gr(v,35));
		break;
	    case FW_HYPERCALL_EFI_GET_NEXT_HIGH_MONO_COUNT:
		// FIXME: need fixes in efi.h from 2.6.9
		status = EFI_UNSUPPORTED;
		break;
	    default:
		printk("unknown ia64 fw hypercall %lx\n", regs->r2);
		status = EFI_UNSUPPORTED;
	}

	return status;
}

void
do_ssc(unsigned long ssc, struct pt_regs *regs)
{
	unsigned long arg0, arg1, arg2, arg3, retval;
	char buf[2];
/**/	static int last_fd, last_count;	// FIXME FIXME FIXME
/**/					// BROKEN FOR MULTIPLE DOMAINS & SMP
/**/	struct ssc_disk_stat { int fd; unsigned count;} *stat, last_stat;

	arg0 = vcpu_get_gr(current,32);
	switch(ssc) {
	    case SSC_PUTCHAR:
		buf[0] = arg0;
		buf[1] = '\0';
		printk(buf);
		break;
	    case SSC_GETCHAR:
		retval = ia64_ssc(0,0,0,0,ssc);
		vcpu_set_gr(current,8,retval,0);
		break;
	    case SSC_WAIT_COMPLETION:
		if (arg0) {	// metaphysical address

			arg0 = translate_domain_mpaddr(arg0, NULL);
/**/			stat = (struct ssc_disk_stat *)__va(arg0);
///**/			if (stat->fd == last_fd) stat->count = last_count;
/**/			stat->count = last_count;
//if (last_count >= PAGE_SIZE) printk("ssc_wait: stat->fd=%d,last_fd=%d,last_count=%d\n",stat->fd,last_fd,last_count);
///**/			retval = ia64_ssc(arg0,0,0,0,ssc);
/**/			retval = 0;
		}
		else retval = -1L;
		vcpu_set_gr(current,8,retval,0);
		break;
	    case SSC_OPEN:
		arg1 = vcpu_get_gr(current,33);	// access rights
if (!running_on_sim) { printk("SSC_OPEN, not implemented on hardware.  (ignoring...)\n"); arg0 = 0; }
		if (arg0) {	// metaphysical address
			arg0 = translate_domain_mpaddr(arg0, NULL);
			retval = ia64_ssc(arg0,arg1,0,0,ssc);
		}
		else retval = -1L;
		vcpu_set_gr(current,8,retval,0);
		break;
	    case SSC_WRITE:
	    case SSC_READ:
//if (ssc == SSC_WRITE) printk("DOING AN SSC_WRITE\n");
		arg1 = vcpu_get_gr(current,33);
		arg2 = vcpu_get_gr(current,34);
		arg3 = vcpu_get_gr(current,35);
		if (arg2) {	// metaphysical address of descriptor
			struct ssc_disk_req *req;
			unsigned long mpaddr;
			long len;

			arg2 = translate_domain_mpaddr(arg2, NULL);
			req = (struct ssc_disk_req *) __va(arg2);
			req->len &= 0xffffffffL;	// avoid strange bug
			len = req->len;
/**/			last_fd = arg1;
/**/			last_count = len;
			mpaddr = req->addr;
//if (last_count >= PAGE_SIZE) printk("do_ssc: read fd=%d, addr=%p, len=%lx ",last_fd,mpaddr,len);
			retval = 0;
			if ((mpaddr & PAGE_MASK) != ((mpaddr+len-1) & PAGE_MASK)) {
				// do partial page first
				req->addr = translate_domain_mpaddr(mpaddr, NULL);
				req->len = PAGE_SIZE - (req->addr & ~PAGE_MASK);
				len -= req->len; mpaddr += req->len;
				retval = ia64_ssc(arg0,arg1,arg2,arg3,ssc);
				arg3 += req->len; // file offset
/**/				last_stat.fd = last_fd;
/**/				(void)ia64_ssc(__pa(&last_stat),0,0,0,SSC_WAIT_COMPLETION);
//if (last_count >= PAGE_SIZE) printk("ssc(%p,%lx)[part]=%x ",req->addr,req->len,retval);
			}
			if (retval >= 0) while (len > 0) {
				req->addr = translate_domain_mpaddr(mpaddr, NULL);
				req->len = (len > PAGE_SIZE) ? PAGE_SIZE : len;
				len -= PAGE_SIZE; mpaddr += PAGE_SIZE;
				retval = ia64_ssc(arg0,arg1,arg2,arg3,ssc);
				arg3 += req->len; // file offset
// TEMP REMOVED AGAIN				arg3 += req->len; // file offset
/**/				last_stat.fd = last_fd;
/**/				(void)ia64_ssc(__pa(&last_stat),0,0,0,SSC_WAIT_COMPLETION);
//if (last_count >= PAGE_SIZE) printk("ssc(%p,%lx)=%x ",req->addr,req->len,retval);
			}
			// set it back to the original value
			req->len = last_count;
		}
		else retval = -1L;
		vcpu_set_gr(current,8,retval,0);
//if (last_count >= PAGE_SIZE) printk("retval=%x\n",retval);
		break;
	    case SSC_CONNECT_INTERRUPT:
		arg1 = vcpu_get_gr(current,33);
		arg2 = vcpu_get_gr(current,34);
		arg3 = vcpu_get_gr(current,35);
		if (!running_on_sim) { printk("SSC_CONNECT_INTERRUPT, not implemented on hardware.  (ignoring...)\n"); break; }
		(void)ia64_ssc(arg0,arg1,arg2,arg3,ssc);
		break;
	    case SSC_NETDEV_PROBE:
		vcpu_set_gr(current,8,-1L,0);
		break;
	    default:
		panic_domain(regs,
		             "%s: bad ssc code %lx, iip=0x%lx, b0=0x%lx\n",
		             __func__, ssc, regs->cr_iip, regs->b0);
		break;
	}
	vcpu_increment_iip(current);
}
