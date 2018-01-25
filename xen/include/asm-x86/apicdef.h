#ifndef __ASM_APICDEF_H
#define __ASM_APICDEF_H

/*
 * Constants for various Intel APICs. (local APIC, IOAPIC, etc.)
 *
 * Alan Cox <Alan.Cox@linux.org>, 1995.
 * Ingo Molnar <mingo@redhat.com>, 1999, 2000
 */

#define		APIC_DEFAULT_PHYS_BASE	0xfee00000
 
#define		APIC_ID		0x20
#define			APIC_ID_MASK		(0xFFu<<24)
#define			GET_xAPIC_ID(x)		(((x)>>24)&0xFFu)
#define			SET_xAPIC_ID(x)		(((x)<<24))
#define		APIC_LVR	0x30
#define			APIC_LVR_MASK		0xFF00FF
#define			APIC_LVR_DIRECTED_EOI	(1 << 24)
#define			GET_APIC_VERSION(x)	((x)&0xFF)
#define			GET_APIC_MAXLVT(x)	(((x)>>16)&0xFF)
#define			APIC_XAPIC(x)		((x) >= 0x14)
#define		APIC_TASKPRI	0x80
#define			APIC_TPRI_MASK		0xFF
#define		APIC_ARBPRI	0x90
#define			APIC_ARBPRI_MASK	0xFF
#define		APIC_PROCPRI	0xA0
#define		APIC_EOI	0xB0
#define			APIC_EIO_ACK		0x0		/* Write this to the EOI register */
#define		APIC_RRR	0xC0
#define		APIC_LDR	0xD0
#define			APIC_LDR_MASK		(0xFFu<<24)
#define			GET_xAPIC_LOGICAL_ID(x)	(((x)>>24)&0xFF)
#define			SET_xAPIC_LOGICAL_ID(x)	(((x)<<24))
#define			APIC_ALL_CPUS		0xFF
#define		APIC_DFR	0xE0
#define			APIC_DFR_CLUSTER		0x0FFFFFFFul
#define			APIC_DFR_FLAT			0xFFFFFFFFul
#define		APIC_SPIV	0xF0
#define			APIC_SPIV_FOCUS_DISABLED	(1<<9)
#define			APIC_SPIV_APIC_ENABLED		(1<<8)
#define			APIC_SPIV_DIRECTED_EOI		(1<<12)
#define		APIC_ISR	0x100
#define         APIC_ISR_NR     0x8     /* Number of 32 bit ISR registers. */
#define		APIC_TMR	0x180
#define 	APIC_IRR	0x200
#define 	APIC_ESR	0x280
#define			APIC_ESR_SEND_CS	0x00001
#define			APIC_ESR_RECV_CS	0x00002
#define			APIC_ESR_SEND_ACC	0x00004
#define			APIC_ESR_RECV_ACC	0x00008
#define			APIC_ESR_SENDILL	0x00020
#define			APIC_ESR_RECVILL	0x00040
#define			APIC_ESR_ILLREGA	0x00080
#define		APIC_ICR	0x300
#define			APIC_DEST_NOSHORT	0x00000
#define			APIC_DEST_SELF		0x40000
#define			APIC_DEST_ALLINC	0x80000
#define			APIC_DEST_ALLBUT	0xC0000
#define			APIC_SHORT_MASK		0xC0000
#define			APIC_ICR_RR_MASK	0x30000
#define			APIC_ICR_RR_INVALID	0x00000
#define			APIC_ICR_RR_INPROG	0x10000
#define			APIC_ICR_RR_VALID	0x20000
#define			APIC_INT_LEVELTRIG	0x08000
#define			APIC_INT_ASSERT		0x04000
#define			APIC_ICR_BUSY		0x01000
#define			APIC_DEST_MASK		0x00800
#define			APIC_DEST_LOGICAL	0x00800
#define			APIC_DEST_PHYSICAL	0x00000
#define			APIC_DM_FIXED		0x00000
#define			APIC_DM_LOWEST		0x00100
#define			APIC_DM_SMI		0x00200
#define			APIC_DM_REMRD		0x00300
#define			APIC_DM_NMI		0x00400
#define			APIC_DM_INIT		0x00500
#define			APIC_DM_STARTUP		0x00600
#define			APIC_DM_EXTINT		0x00700
#define			APIC_VECTOR_MASK	0x000FF
#define		APIC_ICR2	0x310
#define			GET_xAPIC_DEST_FIELD(x)	(((x)>>24)&0xFF)
#define			SET_xAPIC_DEST_FIELD(x)	((x)<<24)
#define		APIC_LVTT	0x320
#define		APIC_LVTTHMR	0x330
#define		APIC_LVTPC	0x340
#define		APIC_LVT0	0x350
#define		APIC_CMCI	0x2F0

#define			APIC_TIMER_MODE_MASK		(0x3<<17)
#define			APIC_TIMER_MODE_ONESHOT		(0x0<<17)
#define			APIC_TIMER_MODE_PERIODIC	(0x1<<17)
#define			APIC_TIMER_MODE_TSC_DEADLINE	(0x2<<17)
#define			APIC_LVT_MASKED			(1<<16)
#define			APIC_LVT_LEVEL_TRIGGER		(1<<15)
#define			APIC_LVT_REMOTE_IRR		(1<<14)
#define			APIC_INPUT_POLARITY		(1<<13)
#define			APIC_SEND_PENDING		(1<<12)
#define			APIC_MODE_MASK			0x700
#define			GET_APIC_DELIVERY_MODE(x)	(((x)>>8)&0x7)
#define			SET_APIC_DELIVERY_MODE(x,y)	(((x)&~0x700)|((y)<<8))
#define				APIC_MODE_FIXED		0x0
#define				APIC_MODE_NMI		0x4
#define				APIC_MODE_EXTINT	0x7
#define 	APIC_LVT1	0x360
#define		APIC_LVTERR	0x370
#define		APIC_TMICT	0x380
#define		APIC_TMCCT	0x390
#define		APIC_TDCR	0x3E0
#define			APIC_TDR_DIV_TMBASE	(1<<2)
#define			APIC_TDR_DIV_1		0xB
#define			APIC_TDR_DIV_2		0x0
#define			APIC_TDR_DIV_4		0x1
#define			APIC_TDR_DIV_8		0x2
#define			APIC_TDR_DIV_16		0x3
#define			APIC_TDR_DIV_32		0x8
#define			APIC_TDR_DIV_64		0x9
#define			APIC_TDR_DIV_128	0xA

/* Only available in x2APIC mode */
#define		APIC_SELF_IPI	0x3F0

#define APIC_BASE __fix_to_virt(FIX_APIC_BASE)

/* It's only used in x2APIC mode of an x2APIC unit. */
#define APIC_MSR_BASE 0x800

#define MAX_IO_APICS 128

#endif
