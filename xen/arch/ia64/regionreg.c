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


#define	IA64_MIN_IMPL_RID_BITS	(IA64_MIN_IMPL_RID_MSB+1)
#define	IA64_MAX_IMPL_RID_BITS	24

#define MIN_RIDS	(1 << IA64_MIN_IMPL_RID_BITS)
#define	MIN_RID_MAX	(MIN_RIDS - 1)
#define	MIN_RID_MASK	(MIN_RIDS - 1)
#define	MAX_RIDS	(1 << (IA64_MAX_IMPL_RID_BITS))
#define	MAX_RID		(MAX_RIDS - 1)
#define	MAX_RID_BLOCKS	(1 << (IA64_MAX_IMPL_RID_BITS-IA64_MIN_IMPL_RID_BITS))
#define RIDS_PER_RIDBLOCK MIN_RIDS

// This is the one global memory representation of the default Xen region reg
ia64_rr xen_rr;

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

// use this to allocate a rid out of the "Xen reserved rid block"
unsigned long allocate_reserved_rid(void)
{
	static unsigned long currentrid = XEN_DEFAULT_RID;
	unsigned long t = currentrid;

	unsigned long max = RIDS_PER_RIDBLOCK;

	if (++currentrid >= max) return(-1UL);
	return t;
}


// returns -1 if none available
unsigned long allocate_metaphysical_rid(void)
{
	unsigned long rid = allocate_reserved_rid();
}

int deallocate_metaphysical_rid(unsigned long rid)
{
	// fix this when the increment allocation mechanism is fixed.
	return 1;
}


void init_rr(void)
{
	xen_rr.rrval = 0;
	xen_rr.ve = 0;
	xen_rr.rid = allocate_reserved_rid();
	xen_rr.ps = PAGE_SHIFT;

	printf("initialized xen_rr.rid=0x%lx\n", xen_rr.rid);
}

/*************************************
  Region Block setup/management
*************************************/

static int implemented_rid_bits = 0;
static struct domain *ridblock_owner[MAX_RID_BLOCKS] = { 0 };

void get_impl_rid_bits(void)
{
	// FIXME (call PAL)
//#ifdef CONFIG_MCKINLEY
	implemented_rid_bits = IA64_MAX_IMPL_RID_BITS;
//#else
//#error "rid ranges won't work on Merced"
//#endif
	if (implemented_rid_bits <= IA64_MIN_IMPL_RID_BITS ||
	    implemented_rid_bits > IA64_MAX_IMPL_RID_BITS)
		BUG();
}


/*
 * Allocate a power-of-two-sized chunk of region id space -- one or more
 *  "rid blocks"
 */
int allocate_rid_range(struct domain *d, unsigned long ridbits)
{
	int i, j, n_rid_blocks;

	if (implemented_rid_bits == 0) get_impl_rid_bits();
	
	if (ridbits >= IA64_MAX_IMPL_RID_BITS)
	ridbits = IA64_MAX_IMPL_RID_BITS - 1;
	
	if (ridbits < IA64_MIN_IMPL_RID_BITS)
	ridbits = IA64_MIN_IMPL_RID_BITS;

	// convert to rid_blocks and find one
	n_rid_blocks = ridbits - IA64_MIN_IMPL_RID_BITS + 1;
	
	// skip over block 0, reserved for "meta-physical mappings (and Xen)"
	for (i = n_rid_blocks; i < MAX_RID_BLOCKS; i += n_rid_blocks) {
		if (ridblock_owner[i] == NULL) {
			for (j = i; j < i + n_rid_blocks; ++j) {
				if (ridblock_owner[j]) break;
			}
			if (ridblock_owner[j] == NULL) break;
		}
	}
	
	if (i >= MAX_RID_BLOCKS) return 0;
	
	// found an unused block:
	//   (i << min_rid_bits) <= rid < ((i + n) << min_rid_bits)
	// mark this block as owned
	for (j = i; j < i + n_rid_blocks; ++j) ridblock_owner[j] = d;
	
	// setup domain struct
	d->rid_bits = ridbits;
	d->starting_rid = i << IA64_MIN_IMPL_RID_BITS;
	d->ending_rid = (i+n_rid_blocks) << IA64_MIN_IMPL_RID_BITS;
	
	return 1;
}


int deallocate_rid_range(struct domain *d)
{
	int i;
	int rid_block_end = d->ending_rid >> IA64_MIN_IMPL_RID_BITS;
	int rid_block_start = d->starting_rid >> IA64_MIN_IMPL_RID_BITS;

	return 1;  // KLUDGE ALERT
	//
	// not all domains will have allocated RIDs (physical mode loaders for instance)
	//
	if (d->rid_bits == 0) return 1;

#ifdef DEBUG
	for (i = rid_block_start; i < rid_block_end; ++i) {
	        ASSERT(ridblock_owner[i] == d);
	    }
#endif
	
	for (i = rid_block_start; i < rid_block_end; ++i)
	ridblock_owner[i] = NULL;
	
	d->rid_bits = 0;
	d->starting_rid = 0;
	d->ending_rid = 0;
	return 1;
}


// This function is purely for performance... apparently scrambling
//  bits in the region id makes for better hashing, which means better
//  use of the VHPT, which means better performance
// Note that the only time a RID should be mangled is when it is stored in
//  a region register; anytime it is "viewable" outside of this module,
//  it should be unmangled

//This appears to work in Xen... turn it on later so no complications yet
//#define CONFIG_MANGLE_RIDS
#ifdef CONFIG_MANGLE_RIDS
static inline unsigned long
vmMangleRID(unsigned long RIDVal)
{
	union bits64 { unsigned char bytes[4]; unsigned long uint; };

	union bits64 t;
	unsigned char tmp;

	t.uint = RIDVal;
	tmp = t.bytes[1];
	t.bytes[1] = t.bytes[3];
	t.bytes[3] = tmp;

	return t.uint;
}

// since vmMangleRID is symmetric, use it for unmangling also
#define vmUnmangleRID(x)	vmMangleRID(x)
#else
// no mangling/unmangling
#define vmMangleRID(x)	(x)
#define vmUnmangleRID(x) (x)
#endif

static inline void
set_rr_no_srlz(unsigned long rr, unsigned long rrval)
{
	ia64_set_rr(rr, vmMangleRID(rrval));
}

void
set_rr(unsigned long rr, unsigned long rrval)
{
	ia64_set_rr(rr, vmMangleRID(rrval));
	ia64_srlz_d();
}

unsigned long
get_rr(unsigned long rr)
{
	return vmUnmangleRID(ia64_get_rr(rr));
}

static inline int validate_page_size(unsigned long ps)
{
	switch(ps) {
	    case 12: case 13: case 14: case 16: case 18:
	    case 20: case 22: case 24: case 26: case 28:
		return 1;
	    default:
		return 0;
	}
}

// validates and changes a single region register
// in the currently executing domain
// Passing a value of -1 is a (successful) no-op
// NOTE: DOES NOT SET VCPU's rrs[x] value!!
int set_one_rr(unsigned long rr, unsigned long val)
{
	struct exec_domain *ed = current;
	unsigned long rreg = REGION_NUMBER(rr);
	ia64_rr rrv, newrrv, memrrv;
	unsigned long newrid;

	if (val == -1) return 1;

	rrv.rrval = val;
	newrrv.rrval = 0;
	newrid = ed->domain->starting_rid + rrv.rid;

	if (newrid > ed->domain->ending_rid) return 0;

	memrrv.rrval = rrv.rrval;
	if (rreg == 7) {
		newrrv.rid = newrid;
		newrrv.ve = VHPT_ENABLED_REGION_7;
		newrrv.ps = IA64_GRANULE_SHIFT;
		ia64_new_rr7(vmMangleRID(newrrv.rrval),ed->vcpu_info);
	}
	else {
		newrrv.rid = newrid;
		// FIXME? region 6 needs to be uncached for EFI to work
		if (rreg == 6) newrrv.ve = VHPT_ENABLED_REGION_7;
		else newrrv.ve = VHPT_ENABLED_REGION_0_TO_6;
		newrrv.ps = PAGE_SHIFT;
		set_rr(rr,newrrv.rrval);
	}
	return 1;
}

// set rr0 to the passed rid (for metaphysical mode so don't use domain offset
int set_metaphysical_rr(unsigned long rr, unsigned long rid)
{
	ia64_rr rrv;
	
	rrv.rrval = 0;
	rrv.rid = rid;
	rrv.ps = PAGE_SHIFT;
//	rrv.ve = 1; 	FIXME: TURN ME BACK ON WHEN VHPT IS WORKING
	rrv.ve = 0;
	set_rr(rr,rrv.rrval);
}

// validates/changes region registers 0-6 in the currently executing domain
// Note that this is the one and only SP API (other than executing a privop)
// for a domain to use to change region registers
int set_all_rr( u64 rr0, u64 rr1, u64 rr2, u64 rr3,
		     u64 rr4, u64 rr5, u64 rr6, u64 rr7)
{
	if (!set_one_rr(0x0000000000000000L, rr0)) return 0;
	if (!set_one_rr(0x2000000000000000L, rr1)) return 0;
	if (!set_one_rr(0x4000000000000000L, rr2)) return 0;
	if (!set_one_rr(0x6000000000000000L, rr3)) return 0;
	if (!set_one_rr(0x8000000000000000L, rr4)) return 0;
	if (!set_one_rr(0xa000000000000000L, rr5)) return 0;
	if (!set_one_rr(0xc000000000000000L, rr6)) return 0;
	if (!set_one_rr(0xe000000000000000L, rr7)) return 0;
	return 1;
}

void init_all_rr(struct exec_domain *ed)
{
	ia64_rr rrv;

	rrv.rrval = 0;
	rrv.rid = ed->domain->metaphysical_rid;
	rrv.ps = PAGE_SHIFT;
	rrv.ve = 1;
if (!ed->vcpu_info) { printf("Stopping in init_all_rr\n"); dummy(); }
	ed->vcpu_info->arch.rrs[0] = -1;
	ed->vcpu_info->arch.rrs[1] = rrv.rrval;
	ed->vcpu_info->arch.rrs[2] = rrv.rrval;
	ed->vcpu_info->arch.rrs[3] = rrv.rrval;
	ed->vcpu_info->arch.rrs[4] = rrv.rrval;
	ed->vcpu_info->arch.rrs[5] = rrv.rrval;
	ed->vcpu_info->arch.rrs[6] = rrv.rrval;
//	ed->shared_info->arch.rrs[7] = rrv.rrval;
}


/* XEN/ia64 INTERNAL ROUTINES */

unsigned long physicalize_rid(struct exec_domain *ed, unsigned long rid)
{
	ia64_rr rrv;
	    
	rrv.rrval = rid;
	rrv.rid += ed->domain->starting_rid;
	return rrv.rrval;
}

unsigned long
virtualize_rid(struct exec_domain *ed, unsigned long rid)
{
	ia64_rr rrv;
	    
	rrv.rrval = rid;
	rrv.rid -= ed->domain->starting_rid;
	return rrv.rrval;
}

// loads a thread's region register (0-6) state into
// the real physical region registers.  Returns the
// (possibly mangled) bits to store into rr7
// iff it is different than what is currently in physical
// rr7 (because we have to to assembly and physical mode
// to change rr7).  If no change to rr7 is required, returns 0.
//
unsigned long load_region_regs(struct exec_domain *ed)
{
	unsigned long rr0, rr1,rr2, rr3, rr4, rr5, rr6;
	unsigned long oldrr7, newrr7;
	// TODO: These probably should be validated

	if (ed->vcpu_info->arch.metaphysical_mode) {
		ia64_rr rrv;

		rrv.rid = ed->domain->metaphysical_rid;
		rrv.ps = PAGE_SHIFT;
		rrv.ve = 1;
		rr0 = rr1 = rr2 = rr3 = rr4 = rr5 = rr6 = newrr7 = rrv.rrval;
	}
	else {
		rr0 = physicalize_rid(ed, ed->vcpu_info->arch.rrs[0]);
		rr1 = physicalize_rid(ed, ed->vcpu_info->arch.rrs[1]);
		rr2 = physicalize_rid(ed, ed->vcpu_info->arch.rrs[2]);
		rr3 = physicalize_rid(ed, ed->vcpu_info->arch.rrs[3]);
		rr4 = physicalize_rid(ed, ed->vcpu_info->arch.rrs[4]);
		rr5 = physicalize_rid(ed, ed->vcpu_info->arch.rrs[5]);
		rr6 = physicalize_rid(ed, ed->vcpu_info->arch.rrs[6]);
		newrr7 = physicalize_rid(ed, ed->vcpu_info->arch.rrs[7]);
	}

	set_rr_no_srlz(0x0000000000000000L, rr0);
	set_rr_no_srlz(0x2000000000000000L, rr1);
	set_rr_no_srlz(0x4000000000000000L, rr2);
	set_rr_no_srlz(0x6000000000000000L, rr3);
	set_rr_no_srlz(0x8000000000000000L, rr4);
	set_rr_no_srlz(0xa000000000000000L, rr5);
	set_rr_no_srlz(0xc000000000000000L, rr6);
	ia64_srlz_d();
	oldrr7 = get_rr(0xe000000000000000L);
	if (oldrr7 != newrr7) {
		newrr7 = (newrr7 & ~0xff) | (PAGE_SHIFT << 2) | 1;
		return vmMangleRID(newrr7);
	}
	else return 0;
}
