/*
 * Region register and region id management
 *
 * Copyright (C) 2001-2004 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com
 *	Bret Mckee (bret.mckee@hp.com)
 *
 */


#include <linux/config.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <asm/page.h>
#include <asm/regionreg.h>
#include <asm/vhpt.h>
#include <asm/vcpu.h>

/* Defined in xemasm.S  */
extern void ia64_new_rr7(unsigned long rid, void *shared_info, void *shared_arch_info, unsigned long shared_info_va, unsigned long va_vhpt);

/* RID virtualization mechanism is really simple:  domains have less rid bits
   than the host and the host rid space is shared among the domains.  (Values
   in parenthesis are usual default values).

   The host rid space is partitionned into MAX_RID_BLOCKS (= 64)
   blocks of 2**IA64_MIN_IMPL_RID_BITS (= 18) rids.  The first block is also
   partitionned into MAX_RID_BLOCKS small blocks.  Small blocks are used for
   metaphysical rids.  Small block 0 can't be allocated and is reserved for
   Xen own rids during boot.

   Blocks and small blocks are allocated together and a domain may
   have one or more consecutive blocks (and small blocks).
*/

/* Minimum number of RID bits for a domain.  The current value is 18, which is
   the minimum defined by the itanium architecture, but it can be lowered
   to increase the number of domain.  */
#define	IA64_MIN_IMPL_RID_BITS	(IA64_MIN_IMPL_RID_MSB+1)
/* Maximum number of RID bits.  This is definitly 24.  */
#define	IA64_MAX_IMPL_RID_BITS	24

/* Maximum number of blocks.  */
#define	MAX_RID_BLOCKS	(1 << (IA64_MAX_IMPL_RID_BITS-IA64_MIN_IMPL_RID_BITS))

/* Default number of rid bits for domains.  */
static unsigned int domain_rid_bits_default = IA64_MIN_IMPL_RID_BITS;
integer_param("dom_rid_bits", domain_rid_bits_default); 

#if 0
// following already defined in include/asm-ia64/gcc_intrin.h
// it should probably be ifdef'd out from there to ensure all region
// register usage is encapsulated in this file
static inline unsigned long
ia64_get_rr (unsigned long rr)
{
	    unsigned long r;
	    __asm__ __volatile__ (";;mov %0=rr[%1];;":"=r"(r):"r"(rr):"memory");
	    return r;
}

static inline void
ia64_set_rr (unsigned long rr, unsigned long rrv)
{
	    __asm__ __volatile__ (";;mov rr[%0]=%1;;"::"r"(rr),"r"(rrv):"memory");
}
#endif

static unsigned long allocate_metaphysical_rr(struct domain *d, int n)
{
	ia64_rr rrv;

	rrv.rrval = 0;	// Or else may see reserved bit fault
	rrv.rid = d->arch.starting_mp_rid + n;
	rrv.ps = PAGE_SHIFT;
	rrv.ve = 0;
	/* Mangle metaphysical rid */
	rrv.rrval = vmMangleRID(rrv.rrval);
	return rrv.rrval;
}

/*************************************
  Region Block setup/management
*************************************/

static int implemented_rid_bits = 0;
static int mp_rid_shift;
static struct domain *ridblock_owner[MAX_RID_BLOCKS] = { 0 };

void init_rid_allocator (void)
{
	int log_blocks;
	pal_vm_info_2_u_t vm_info_2;

	/* Get machine rid_size.  */
	BUG_ON (ia64_pal_vm_summary (NULL, &vm_info_2) != 0);
	implemented_rid_bits = vm_info_2.pal_vm_info_2_s.rid_size;

	/* We need at least a few space...  */
	BUG_ON (implemented_rid_bits <= IA64_MIN_IMPL_RID_BITS);

	/* And we can accept too much space.  */
	if (implemented_rid_bits > IA64_MAX_IMPL_RID_BITS)
		implemented_rid_bits = IA64_MAX_IMPL_RID_BITS;

	/* Due to RID mangling, we expect 24 RID bits!
	   This test should be removed if RID mangling is removed/modified.  */
	if (implemented_rid_bits != 24) {
		printk ("RID mangling expected 24 RID bits, got only %d!\n",
			implemented_rid_bits);
		BUG();
	}

	/* Allow the creation of at least domain 0.  */
	if (domain_rid_bits_default > implemented_rid_bits - 1)
		domain_rid_bits_default = implemented_rid_bits - 1;

	/* Check for too small values.  */
	if (domain_rid_bits_default < IA64_MIN_IMPL_RID_BITS) {
		printk ("Default domain rid bits %d is too small, use %d\n",
			domain_rid_bits_default, IA64_MIN_IMPL_RID_BITS);
		domain_rid_bits_default = IA64_MIN_IMPL_RID_BITS;
	}

	log_blocks = (implemented_rid_bits - IA64_MIN_IMPL_RID_BITS);

	printk ("Maximum number of domains: %d; %d RID bits per domain\n",
		(1 << (implemented_rid_bits - domain_rid_bits_default)) - 1,
		domain_rid_bits_default);
	
	mp_rid_shift = IA64_MIN_IMPL_RID_BITS - log_blocks;
	BUG_ON (mp_rid_shift < 3);
}


/*
 * Allocate a power-of-two-sized chunk of region id space -- one or more
 *  "rid blocks"
 */
int allocate_rid_range(struct domain *d, unsigned long ridbits)
{
	int i, j, n_rid_blocks;

	if (ridbits == 0)
		ridbits = domain_rid_bits_default;

	if (ridbits >= IA64_MAX_IMPL_RID_BITS)
		ridbits = IA64_MAX_IMPL_RID_BITS - 1;
	
	if (ridbits < IA64_MIN_IMPL_RID_BITS)
		ridbits = IA64_MIN_IMPL_RID_BITS;

	// convert to rid_blocks and find one
	n_rid_blocks = 1UL << (ridbits - IA64_MIN_IMPL_RID_BITS);
	
	// skip over block 0, reserved for "meta-physical mappings (and Xen)"
	for (i = n_rid_blocks; i < MAX_RID_BLOCKS; i += n_rid_blocks) {
		if (ridblock_owner[i] == NULL) {
			for (j = i; j < i + n_rid_blocks; ++j) {
				if (ridblock_owner[j])
					break;
			}
			if (ridblock_owner[j] == NULL)
				break;
		}
	}
	
	if (i >= MAX_RID_BLOCKS)
		return 0;
	
	// found an unused block:
	//   (i << min_rid_bits) <= rid < ((i + n) << min_rid_bits)
	// mark this block as owned
	for (j = i; j < i + n_rid_blocks; ++j)
		ridblock_owner[j] = d;
	
	// setup domain struct
	d->arch.rid_bits = ridbits;
	d->arch.starting_rid = i << IA64_MIN_IMPL_RID_BITS;
	d->arch.ending_rid = (i+n_rid_blocks) << IA64_MIN_IMPL_RID_BITS;
	
	d->arch.starting_mp_rid = i << mp_rid_shift;
	d->arch.ending_mp_rid = (i + 1) << mp_rid_shift;

	d->arch.metaphysical_rr0 = allocate_metaphysical_rr(d, 0);
	d->arch.metaphysical_rr4 = allocate_metaphysical_rr(d, 1);

	dprintk(XENLOG_DEBUG, "### domain %p: rid=%x-%x mp_rid=%x\n",
		d, d->arch.starting_rid, d->arch.ending_rid,
		d->arch.starting_mp_rid);
	
	return 1;
}


int deallocate_rid_range(struct domain *d)
{
	int i;
	int rid_block_end = d->arch.ending_rid >> IA64_MIN_IMPL_RID_BITS;
	int rid_block_start = d->arch.starting_rid >> IA64_MIN_IMPL_RID_BITS;

	/* Sanity check.  */
	if (d->arch.rid_bits == 0)
		return 1;

	
	for (i = rid_block_start; i < rid_block_end; ++i) {
	        ASSERT(ridblock_owner[i] == d);
		ridblock_owner[i] = NULL;
	}

	d->arch.rid_bits = 0;
	d->arch.starting_rid = 0;
	d->arch.ending_rid = 0;
	d->arch.starting_mp_rid = 0;
	d->arch.ending_mp_rid = 0;
	return 1;
}

static void
set_rr(unsigned long rr, unsigned long rrval)
{
	ia64_set_rr(rr, vmMangleRID(rrval));
	ia64_srlz_d();
}

// validates and changes a single region register
// in the currently executing domain
// Passing a value of -1 is a (successful) no-op
// NOTE: DOES NOT SET VCPU's rrs[x] value!!
int set_one_rr(unsigned long rr, unsigned long val)
{
	struct vcpu *v = current;
	unsigned long rreg = REGION_NUMBER(rr);
	ia64_rr rrv, newrrv, memrrv;
	unsigned long newrid;

	if (val == -1) return 1;

	rrv.rrval = val;
	newrrv.rrval = 0;
	newrid = v->arch.starting_rid + rrv.rid;

	if (newrid > v->arch.ending_rid) {
		printk("can't set rr%d to %lx, starting_rid=%x,"
			"ending_rid=%x, val=%lx\n", (int) rreg, newrid,
			v->arch.starting_rid,v->arch.ending_rid,val);
		return 0;
	}

	memrrv.rrval = rrv.rrval;
	newrrv.rid = newrid;
	newrrv.ve = 1;  // VHPT now enabled for region 7!!
	newrrv.ps = PAGE_SHIFT;

	if (rreg == 0) {
		v->arch.metaphysical_saved_rr0 = vmMangleRID(newrrv.rrval);
		if (!PSCB(v,metaphysical_mode))
			set_rr(rr,newrrv.rrval);
	} else if (rreg == 7) {
		ia64_new_rr7(vmMangleRID(newrrv.rrval),v->domain->shared_info,
			     v->arch.privregs, v->domain->arch.shared_info_va,
		             __va_ul(vcpu_vhpt_maddr(v)));
	} else {
		set_rr(rr,newrrv.rrval);
	}
	return 1;
}

// set rr0 to the passed rid (for metaphysical mode so don't use domain offset
int set_metaphysical_rr0(void)
{
	struct vcpu *v = current;
//	ia64_rr rrv;
	
//	rrv.ve = 1; 	FIXME: TURN ME BACK ON WHEN VHPT IS WORKING
	ia64_set_rr(0,v->arch.metaphysical_rr0);
	ia64_srlz_d();
	return 1;
}

void init_all_rr(struct vcpu *v)
{
	ia64_rr rrv;

	rrv.rrval = 0;
	//rrv.rrval = v->domain->arch.metaphysical_rr0;
	rrv.ps = PAGE_SHIFT;
	rrv.ve = 1;
if (!v->vcpu_info) { panic("Stopping in init_all_rr\n"); }
	VCPU(v,rrs[0]) = -1;
	VCPU(v,rrs[1]) = rrv.rrval;
	VCPU(v,rrs[2]) = rrv.rrval;
	VCPU(v,rrs[3]) = rrv.rrval;
	VCPU(v,rrs[4]) = rrv.rrval;
	VCPU(v,rrs[5]) = rrv.rrval;
	rrv.ve = 0; 
	VCPU(v,rrs[6]) = rrv.rrval;
//	v->shared_info->arch.rrs[7] = rrv.rrval;
}


/* XEN/ia64 INTERNAL ROUTINES */

// loads a thread's region register (0-6) state into
// the real physical region registers.  Returns the
// (possibly mangled) bits to store into rr7
// iff it is different than what is currently in physical
// rr7 (because we have to to assembly and physical mode
// to change rr7).  If no change to rr7 is required, returns 0.
//
void load_region_regs(struct vcpu *v)
{
	unsigned long rr0, rr1,rr2, rr3, rr4, rr5, rr6, rr7;
	// TODO: These probably should be validated
	unsigned long bad = 0;

	if (VCPU(v,metaphysical_mode)) {
		rr0 = v->domain->arch.metaphysical_rr0;
		ia64_set_rr(0x0000000000000000L, rr0);
		ia64_srlz_d();
	}
	else {
		rr0 =  VCPU(v,rrs[0]);
		if (!set_one_rr(0x0000000000000000L, rr0)) bad |= 1;
	}
	rr1 =  VCPU(v,rrs[1]);
	rr2 =  VCPU(v,rrs[2]);
	rr3 =  VCPU(v,rrs[3]);
	rr4 =  VCPU(v,rrs[4]);
	rr5 =  VCPU(v,rrs[5]);
	rr6 =  VCPU(v,rrs[6]);
	rr7 =  VCPU(v,rrs[7]);
	if (!set_one_rr(0x2000000000000000L, rr1)) bad |= 2;
	if (!set_one_rr(0x4000000000000000L, rr2)) bad |= 4;
	if (!set_one_rr(0x6000000000000000L, rr3)) bad |= 8;
	if (!set_one_rr(0x8000000000000000L, rr4)) bad |= 0x10;
	if (!set_one_rr(0xa000000000000000L, rr5)) bad |= 0x20;
	if (!set_one_rr(0xc000000000000000L, rr6)) bad |= 0x40;
	if (!set_one_rr(0xe000000000000000L, rr7)) bad |= 0x80;
	if (bad) {
		panic_domain(0,"load_region_regs: can't set! bad=%lx\n",bad);
	}
}
