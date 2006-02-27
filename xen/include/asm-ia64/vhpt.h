#ifndef ASM_VHPT_H
#define ASM_VHPT_H

#define VHPT_ENABLED 1
#define VHPT_ENABLED_REGION_0_TO_6 1
#define VHPT_ENABLED_REGION_7 0

/* Size of the VHPT.  */
#define	VHPT_SIZE_LOG2			24

/* Number of entries in the VHPT.  The size of an entry is 4*8B == 32B */
#define	VHPT_NUM_ENTRIES		(1 << (VHPT_SIZE_LOG2 - 5))

#define VHPT_CACHE_MASK			(VHPT_NUM_ENTRIES - 1)
#define	VHPT_CACHE_ENTRY_SIZE		64

#define	VHPT_PAGE_SHIFT			VHPT_SIZE_LOG2

// FIXME: These should be automatically generated

#define	VLE_PGFLAGS_OFFSET		0
#define	VLE_ITIR_OFFSET			8
#define	VLE_TITAG_OFFSET		16
#define	VLE_CCHAIN_OFFSET		24

#define	VCE_TITAG_OFFSET		0
#define	VCE_CCNEXT_OFFSET		8
#define	VCE_CCPREV_OFFSET		16
#define	VCE_PGFLAGS_OFFSET		24
#define	VCE_ITIR_OFFSET			32
#define	VCE_FNEXT_OFFSET		32
#define	VCE_CCHEAD_OFFSET		40
#define	VCE_VADDR_OFFSET		48

//FIXME: change and declare elsewhere
#define	CAUSE_VHPT_CC_HANDLED		0

#ifndef __ASSEMBLY__

//
// VHPT collison chain entry (part of the "V-Cache")
// DO NOT CHANGE THE SIZE OF THIS STRUCTURE (see vhpt.S banked regs calculations)
//
struct vcache_entry {
    union {
        struct {
            unsigned long tag  : 63; // 0-62
            unsigned long ti   :  1; // 63
        };
        unsigned long ti_tag;
    };

    struct vcache_entry *CCNext;    // collision chain next
    struct vcache_entry *CCPrev;    // collision chain previous

    union {
        struct {
            unsigned long p    :  1; // 0
            unsigned long      :  1; // 1
            unsigned long ma   :  3; // 2-4
            unsigned long a    :  1; // 5
            unsigned long d    :  1; // 6
            unsigned long pl   :  2; // 7-8
            unsigned long ar   :  3; // 9-11
            unsigned long ppn  : 38; // 12-49
            unsigned long      :  2; // 50-51
            unsigned long ed   :  1; // 52

            unsigned long translation_type :  2; // 53-54 -- hack
            unsigned long Counter :  9; // 55-63
        };
        unsigned long page_flags;
    };

    union {
        struct {
            unsigned long      :  2; // 0-1
            unsigned long ps   :  6; // 2-7
            unsigned long key  : 24; // 8-31
            unsigned long      : 32; // 32-63
        };
        unsigned long itir;

        //
        // the free list pointer when entry not in use
        //
        struct vcache_entry *FNext;    // free list
    };

    //
    // store head of collison chain for removal since thash will only work if
    // current RID is same as when element was added to chain.
    //
    struct vhpt_lf_entry *CCHead;

    unsigned long virtual_address;

    unsigned int CChainCnt;
    unsigned int Signature;
};


//
// VHPT Long Format Entry (as recognized by hw)
//
struct vhpt_lf_entry {
    unsigned long page_flags;
    unsigned long itir;
    unsigned long ti_tag;
    struct vcache_entry *CChain;
};

#define INVALID_TI_TAG 0x8000000000000000L

extern void vhpt_init (void);
extern void zero_vhpt_stats(void);
extern int dump_vhpt_stats(char *buf);
extern void vhpt_flush_address(unsigned long vadr, unsigned long addr_range);
extern void vhpt_multiple_insert(unsigned long vaddr, unsigned long pte,
				 unsigned long logps);
extern void vhpt_insert (unsigned long vadr, unsigned long ptr,
			 unsigned logps);
extern void vhpt_flush(void);

/* Currently the VHPT is allocated per CPU.  */
DECLARE_PER_CPU (unsigned long, vhpt_paddr);
DECLARE_PER_CPU (unsigned long, vhpt_pend);

#endif /* !__ASSEMBLY */

#if !VHPT_ENABLED
#define VHPT_CCHAIN_LOOKUP(Name, i_or_d)
#else
#if 0 /* One VHPT per cpu! def CONFIG_SMP */
#warning "FIXME SMP: VHPT_CCHAIN_LOOKUP needs a semaphore on the VHPT!"
#endif

// VHPT_CCHAIN_LOOKUP is intended to run with psr.i+ic off
#define VHPT_CCHAIN_LOOKUP(Name, i_or_d) 			\
								\
CC_##Name:;							\
	mov r31 = pr;						\
	mov r16 = cr.ifa;					\
	movl r30 = int_counts;					\
	;;							\
	extr.u r17=r16,59,5					\
	;;							\
	cmp.eq p6,p0=0x1e,r17;					\
(p6)	br.cond.spnt	.Alt_##Name				\
	;;							\
	cmp.eq p6,p0=0x1d,r17;					\
(p6)	br.cond.spnt	.Alt_##Name				\
	;;							\
	thash r28 = r16;					\
	adds  r30 = CAUSE_VHPT_CC_HANDLED << 3, r30;		\
	;;							\
	ttag r19 = r16;						\
ld8 r27 = [r30];					\
adds r17 = VLE_CCHAIN_OFFSET, r28;			\
	;;							\
	ld8 r17 = [r17];					\
	;;							\
	cmp.eq p6,p0 = 0, r17;					\
	mov r21 = r17;						\
	adds r22 = VCE_CCNEXT_OFFSET, r17;			\
	adds r28 = VLE_ITIR_OFFSET, r28;			\
(p6)	br .Out_##Name;						\
	;;							\
								\
.loop_##Name:;							\
	ld8 r20 = [r21];					\
	ld8 r18 = [r22];					\
	adds r23 = VCE_PGFLAGS_OFFSET, r21;			\
	adds r24 = VCE_ITIR_OFFSET, r21;			\
	cmp.eq p6,p0 = r17, r21;				\
	cmp.eq p7,p0 = r0, r0;					\
	;;							\
	lfetch [r18];						\
	cmp.eq.andcm p6,p7 = r19, r20;				\
	mov r21 = r18;						\
	adds r22 = VCE_CCNEXT_OFFSET, r18;			\
(p6)	br.spnt .Out_##Name;					\
(p7)	br.sptk .loop_##Name;					\
	;;							\
								\
	ld8 r26 = [r23];					\
	ld8 r25 = [r24];					\
	adds r29 = VLE_TITAG_OFFSET - VLE_ITIR_OFFSET, r28;	\
	adds  r27 = 1, r27;					\
	;;							\
	mov cr.itir = r25;					\
	st8 [r28] = r25, VLE_PGFLAGS_OFFSET - VLE_ITIR_OFFSET;	\
	or r26 = 1, r26;					\
	st8 [r30] = r27;					\
	;;							\
	itc.i_or_d r26;						\
	;;							\
	srlz.i_or_d;						\
	;;							\
	st8 [r28] = r26;					\
	mov pr = r31, 0x1ffff;					\
	st8 [r29] = r20;					\
	rfi;							\
	;;							\
								\
.Alt_##Name:;							\
	mov pr = r31, 0x1ffff;					\
	;;							\
	br.cond.sptk late_alt_##Name				\
	;;							\
.Out_##Name:;							\
	mov pr = r31, 0x1ffff;					\
	;;							\
.End_##Name:;

//	 br.cond.sptk.few dorfi;	



#define VHPT_INSERT() \
	{.mmi;\
		thash r17 = r16;\
		or r26 = 1, r26;\
		nop 0;\
		;;\
	};\
	{.mii;\
		ttag r21 = r16;\
		adds r18 = VLE_ITIR_OFFSET, r17;\
		adds r19 = VLE_PGFLAGS_OFFSET, r17;\
		;;\
	};\
	{.mmi;\
\
		st8[r18] = r27;\
		adds r20 = VLE_TITAG_OFFSET, r17;\
		nop 0;\
		;;\
	};\
	{.mmb;\
		st8[r19] = r26;\
		st8[r20] = r21;\
		nop 0;\
		;;\
	};\
















#define VHPT_INSERT1() \
VCacheInsert:;\
		mov r18 = 1;\
		extr.u r17 = r27, 2, 6;\
		;;\
\
\
		shl r17 = r18, r17;\
		;;\
\
\
		add r30 = r16, r17;\
		;;\
\
.MainLoop:;\
		thash r18 = r16;\
		;;\
\
		ttag  r24 = r16;\
		adds r29 = VLE_CCHAIN_OFFSET, r18;\
		;;\
\
\
		ld8 r21 = [r29];\
		;;\
\
		adds r19 = VCE_CCNEXT_OFFSET, r21;\
		adds r20 = VCE_TITAG_OFFSET, r21;\
		mov r28 = r21;\
\
		cmp.eq p11, p4 = r0, r21;\
(p11)    br FindOne;\
		;;\
\
\
.find_loop:;\
\
		ld8 r17 = [r19];\
		ld8 r18 = [r20];\
		;;\
\
		adds r19 = VCE_CCNEXT_OFFSET, r17;\
		adds r20 = VCE_TITAG_OFFSET, r17;\
		cmp.eq.unc p10, p8 = r18, r24;\
\
\
\
		cmp.eq.unc p1, p2 = r17, r21;\
\
\
(p10)      br .FillVce;\
		;;\
\
\
(p8)   mov r28 = r17;\
\
		lfetch [r19];\
\
(p2)   br .find_loop;\
		;;\
\
FindOne:;\
\
\
\
		movl r22 = G_VCacheRpl;\
		;;\
\
\
		ld8 r23 = [r22];\
		;;\
\
\
		mov r28 = r23;\
\
\
		adds r17 = VCE_FNEXT_OFFSET, r23;\
\
\
		cmp.eq p14, p3 = r0, r23;\
		;;\
\
(p3)  ld8 r23 = [r17];\
		;;\
\
\
(p3)  st8 [r22] = r23;\
(p3)  br .AddChain;\
		;;\
\
\
\
\
		movl r24 = VHPT_CACHE_MASK;\
\
\
		adds r25 = 8, r22;\
		;;\
\
\
		ld8 r23 = [r25];\
		;;\
\
\
		adds r23 = VHPT_CACHE_ENTRY_SIZE, r23;\
		;;\
\
\
		and r23 = r23, r24;\
\
\
		movl r17 = VHPT_ADDR;\
		;;\
\
\
		st8 [r25] = r23;\
\
\
		add r28 = r17, r23;\
		;;\
\
\
		adds r22 = VCE_CCHEAD_OFFSET, r28;\
		;;\
\
		ld8 r17 = [r22], VLE_PGFLAGS_OFFSET - VLE_CCHAIN_OFFSET;\
\
		adds r19 = VCE_CCNEXT_OFFSET, r28;\
		adds r20 = VCE_CCPREV_OFFSET, r28;\
		;;\
\
		ld8 r20 = [r20];\
		ld8 r19 = [r19];\
\
		adds r21 = VLE_CCHAIN_OFFSET, r17;\
		;;\
\
		ld8 r18 = [r21];\
\
\
		cmp.eq.unc p9, p7 = r19, r28;\
\
\
		adds r23 = VLE_TITAG_OFFSET + 7, r17;\
\
\
		mov r17 = 0x80;\
		;;\
\
\
(p9)       st8 [r21] = r0;\
\
\
(p9)       st1 [r23] = r17;\
\
		adds r24 = VCE_CCPREV_OFFSET, r19;\
		adds r25 = VCE_CCNEXT_OFFSET, r20;\
\
\
(p7)    cmp.eq.unc p13, p6 = r18, r28;\
		;;\
\
(p7)    st8 [r24] = r20;\
(p7)    st8 [r25] = r19;\
\
		adds r17 = VCE_PGFLAGS_OFFSET, r28;\
		;;\
\
(p13)     st8 [r21] = r19;\
(p13)     ld8 r18 = [r17], VCE_ITIR_OFFSET - VCE_PGFLAGS_OFFSET;\
		;;\
(p13)     st8 [r22] = r18, VLE_ITIR_OFFSET - VLE_PGFLAGS_OFFSET;\
\
		;;\
(p13)     ld8 r18 = [r17], VCE_TITAG_OFFSET - VCE_ITIR_OFFSET;\
		;;\
\
(p13)     st8 [r22] = r18, VLE_TITAG_OFFSET - VLE_ITIR_OFFSET;\
		;;\
\
.AddChain:;\
\
\
		ld8 r24 = [r29];\
		;;\
\
\
		st8 [r29] = r28, 0 - VLE_CCHAIN_OFFSET;\
\
		adds r25 = VCE_CCNEXT_OFFSET, r28;\
		adds r19 = VCE_CCPREV_OFFSET, r28;\
		adds r20 = VCE_CCHEAD_OFFSET, r28;\
		;;\
\
\
		st8 [r20] = r29;\
\
		cmp.eq p12, p5 = r0, r24;\
\
		adds r23 = VCE_CCPREV_OFFSET, r24;\
		;;\
\
(p12)   st8 [r25] = r28;\
(p12)   st8 [r19] = r28;\
\
(p5)ld8 r21 = [r23];\
		adds r29 = VLE_CCHAIN_OFFSET, r29;\
		;;\
\
(p5)st8 [r25] = r24;\
(p5)st8 [r19] = r21;\
\
		adds r22 = VCE_CCNEXT_OFFSET, r21;\
		;;\
\
(p5)st8 [r22] = r28;\
(p5)st8 [r23] = r28;\
		;;\
\
.FillVce:;\
		ttag r24 = r16;\
\
\
		adds r29 = 0 - VLE_CCHAIN_OFFSET, r29;\
		adds r17 = VCE_PGFLAGS_OFFSET, r28;\
		movl r19 = PAGE_SIZE_OFFSET;\
		;;\
\
		st8 [r29] = r26, VLE_ITIR_OFFSET - VLE_PGFLAGS_OFFSET;\
		st8 [r17] = r26, VCE_ITIR_OFFSET - VCE_PGFLAGS_OFFSET;\
		add r16 = r16, r19;\
		;;\
\
		st8 [r29] = r27, VLE_TITAG_OFFSET - VLE_ITIR_OFFSET;\
		st8 [r17] = r27, VCE_TITAG_OFFSET - VCE_ITIR_OFFSET;\
		;;\
\
		st8 [r29] = r24;\
		st8 [r17] = r24;\
\
		cmp.lt p15, p0 = r16, r30;\
(p15)     br  .MainLoop;\
		;;\




#endif	/* VHPT_ENABLED */
#endif
