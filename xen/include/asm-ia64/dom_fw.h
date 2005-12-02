/*
 * Xen domain firmware emulation
 *
 * Copyright (C) 2004 Hewlett-Packard Co
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 */

extern unsigned long dom_pa(unsigned long);
extern unsigned long dom_fw_setup(struct domain *, char *, int);

#ifndef MB
#define MB (1024*1024)
#endif

/* This is used to determined the portion of a domain's metaphysical memory
   space reserved for the hypercall patch table. */
//FIXME: experiment with smaller sizes
#define HYPERCALL_START	1*MB
#define HYPERCALL_END	2*MB

#define FW_HYPERCALL_BASE_PADDR HYPERCALL_START
#define	FW_HYPERCALL_END_PADDR HYPERCALL_END
#define	FW_HYPERCALL_PADDR(index) (FW_HYPERCALL_BASE_PADDR + (16UL * index))

/*
 * PAL can be called in physical or virtual mode simply by
 * branching to pal_entry_point, which is found in one of the
 * SAL system table entrypoint descriptors (type=0).  Parameters
 * may be passed in r28-r31 (static) or r32-r35 (stacked); which
 * convention is used depends on which procedure is being called.
 * r28 contains the PAL index, the indicator of which PAL procedure
 * is to be called: Index=0 is reserved, 1-255 indicates static
 * parameters, 256-511 indicates stacked parameters.  512-1023
 * are implementation-specific and 1024+ are reserved.
 * rp=b0 indicates the return point.
 *
 * A single hypercall is used for all PAL calls.
 * The hypercall stub is pal_call_stub (xenasm.S).  Its size is 2 bundles.
 */

#define FW_HYPERCALL_PAL_CALL_INDEX	0x80UL
#define FW_HYPERCALL_PAL_CALL_PADDR	FW_HYPERCALL_PADDR(FW_HYPERCALL_PAL_CALL_INDEX)
#define FW_HYPERCALL_PAL_CALL		0x1000UL

/*
 * SAL consists of a table of descriptors, one of which (type=0)
 * contains a sal_entry_point which provides access to a number of
 * functions.  Parameters are passed in r33-r39; r32 contains the
 * index of the SAL function being called. At entry, r1=gp contains
 * a global pointer which may be needed by the function.  rp=b0
 * indicates the return point.  SAL may not be re-entrant; an
 * OS must ensure it is called by one processor at a time.
 *
 * A single hypercall is used for all SAL calls.
 */

#define FW_HYPERCALL_SAL_CALL_INDEX	0x82UL
#define FW_HYPERCALL_SAL_CALL_PADDR	FW_HYPERCALL_PADDR(FW_HYPERCALL_SAL_CALL_INDEX)
#define FW_HYPERCALL_SAL_CALL		0x1001UL

/*
 * EFI is accessed via the EFI system table, which contains:
 * - a header which contains version info
 * - console information (stdin,stdout,stderr)
 * as well as pointers to:
 * - the EFI configuration table, which contains GUID/pointer pairs,
 *   one of which is a pointer to the SAL system table; another is
 *   a pointer to the ACPI table
 * - the runtime services table, which contains a header followed by
 *   a list of (11) unique "runtime" entry points.  EFI runtime entry
 *   points are real function descriptors so contain both a (physical)
 *   address and a global pointer.  They are entered (at first) in
 *   physical mode, though it is possible (optionally... requests can
 *   be ignored and calls still must be OK) to call one entry point
 *   which switches the others so they are capable of being called in
 *   virtual mode.  Parameters are passed in stacked registers, and
 *   rp=b0 indicates the return point.
 * - the boot services table, which contains bootloader-related
 *   entry points (ADD MORE HERE LATER)
 *
 * Each runtime (and boot) entry point requires a unique hypercall.
 */

/* these are indexes into the runtime services table */
#define	FW_HYPERCALL_EFI_BASE
#define FW_HYPERCALL_EFI_GET_TIME_INDEX			0UL
#define FW_HYPERCALL_EFI_SET_TIME_INDEX			1UL
#define FW_HYPERCALL_EFI_GET_WAKEUP_TIME_INDEX		2UL
#define FW_HYPERCALL_EFI_SET_WAKEUP_TIME_INDEX		3UL
#define FW_HYPERCALL_EFI_SET_VIRTUAL_ADDRESS_MAP_INDEX	4UL
#define FW_HYPERCALL_EFI_GET_VARIABLE_INDEX		5UL
#define FW_HYPERCALL_EFI_GET_NEXT_VARIABLE_INDEX	6UL
#define FW_HYPERCALL_EFI_SET_VARIABLE_INDEX		7UL
#define FW_HYPERCALL_EFI_GET_NEXT_HIGH_MONO_COUNT_INDEX	8UL
#define FW_HYPERCALL_EFI_RESET_SYSTEM_INDEX		9UL

/* these are hypercall numbers */
#define FW_HYPERCALL_EFI_GET_TIME			0x300UL
#define FW_HYPERCALL_EFI_SET_TIME			0x301UL
#define FW_HYPERCALL_EFI_GET_WAKEUP_TIME		0x302UL
#define FW_HYPERCALL_EFI_SET_WAKEUP_TIME		0x303UL
#define FW_HYPERCALL_EFI_SET_VIRTUAL_ADDRESS_MAP	0x304UL
#define FW_HYPERCALL_EFI_GET_VARIABLE			0x305UL
#define FW_HYPERCALL_EFI_GET_NEXT_VARIABLE		0x306UL
#define FW_HYPERCALL_EFI_SET_VARIABLE			0x307UL
#define FW_HYPERCALL_EFI_GET_NEXT_HIGH_MONO_COUNT	0x308UL
#define FW_HYPERCALL_EFI_RESET_SYSTEM			0x309UL

/* these are the physical addresses of the pseudo-entry points that
 * contain the hypercalls */
#define FW_HYPERCALL_EFI_GET_TIME_PADDR			FW_HYPERCALL_PADDR(FW_HYPERCALL_EFI_GET_TIME_INDEX)
#define FW_HYPERCALL_EFI_SET_TIME_PADDR			FW_HYPERCALL_PADDR(FW_HYPERCALL_EFI_SET_TIME_INDEX)
#define FW_HYPERCALL_EFI_GET_WAKEUP_TIME_PADDR		FW_HYPERCALL_PADDR(FW_HYPERCALL_EFI_GET_WAKEUP_TIME_INDEX)
#define FW_HYPERCALL_EFI_SET_WAKEUP_TIME_PADDR		FW_HYPERCALL_PADDR(FW_HYPERCALL_EFI_SET_WAKEUP_TIME_INDEX)
#define FW_HYPERCALL_EFI_SET_VIRTUAL_ADDRESS_MAP_PADDR	FW_HYPERCALL_PADDR(FW_HYPERCALL_EFI_SET_VIRTUAL_ADDRESS_MAP_INDEX)
#define FW_HYPERCALL_EFI_GET_VARIABLE_PADDR		FW_HYPERCALL_PADDR(FW_HYPERCALL_EFI_GET_VARIABLE_INDEX)
#define FW_HYPERCALL_EFI_GET_NEXT_VARIABLE_PADDR	FW_HYPERCALL_PADDR(FW_HYPERCALL_EFI_GET_NEXT_VARIABLE_INDEX)
#define FW_HYPERCALL_EFI_SET_VARIABLE_PADDR		FW_HYPERCALL_PADDR(FW_HYPERCALL_EFI_SET_VARIABLE_INDEX)
#define FW_HYPERCALL_EFI_GET_NEXT_HIGH_MONO_COUNT_PADDR	FW_HYPERCALL_PADDR(FW_HYPERCALL_EFI_GET_NEXT_HIGH_MONO_COUNT_INDEX)
#define FW_HYPERCALL_EFI_RESET_SYSTEM_PADDR		FW_HYPERCALL_PADDR(FW_HYPERCALL_EFI_RESET_SYSTEM_INDEX)

extern struct ia64_pal_retval xen_pal_emulator(UINT64,UINT64,UINT64,UINT64);
extern struct sal_ret_values sal_emulator (long index, unsigned long in1, unsigned long in2, unsigned long in3, unsigned long in4, unsigned long in5, unsigned long in6, unsigned long in7);
extern struct ia64_pal_retval pal_emulator_static (unsigned long);

extern void build_pal_hypercall_bundles(unsigned long *imva, unsigned long brkimm, unsigned long hypnum);
extern void build_hypercall_bundle(UINT64 *imva, UINT64 brkimm, UINT64 hypnum, UINT64 ret);


