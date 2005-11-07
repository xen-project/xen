#ifndef _VMX_VLAPIC_H
#define _VMX_VLAPIC_H

/*
   We extended one bit for PIC type
 */
#define VLAPIC_DELIV_MODE_FIXED          0x0
#define VLAPIC_DELIV_MODE_LPRI           0x1
#define VLAPIC_DELIV_MODE_SMI            0x2
#define VLAPIC_DELIV_MODE_NMI            0x4
#define VLAPIC_DELIV_MODE_INIT           0x5
#define VLAPIC_DELIV_MODE_STARTUP        0x6
#define VLAPIC_DELIV_MODE_EXT            0x7
#define VLAPIC_DELIV_MODE_MASK            0x8

#define VLAPIC_MSG_LEVEL                4

#define INTR_EXT   0
#define INTR_APIC   1
#define INTR_LAPIC  2

#define VL_STATE_EOI    1
#define VL_STATE_EXT_LOCK   2
#define VL_STATE_MSG_LOCK   3
#define VL_STATE_EOI_LOCK   3

#define VLOCAL_APIC_MAX_INTS             256
#define VLAPIC_INT_COUNT                (VLOCAL_APIC_MAX_INTS/(BITS_PER_BYTE * sizeof(uint64_t)))
#define VLAPIC_INT_COUNT_32             (VLOCAL_APIC_MAX_INTS/(BITS_PER_BYTE * sizeof(uint32_t)))

typedef struct {
    /* interrupt for PIC and ext type IOAPIC interrupt */
    uint64_t   vl_ext_intr[VLAPIC_INT_COUNT];
    uint64_t   vl_ext_intr_mask[VLAPIC_INT_COUNT];
    uint64_t   vl_apic_intr[VLAPIC_INT_COUNT];
    uint64_t   vl_apic_tmr[VLAPIC_INT_COUNT];
    uint64_t   vl_eoi[VLAPIC_INT_COUNT];
    uint32_t   vl_lapic_id;
    uint32_t   direct_intr;
    uint32_t   vl_apr;
    uint32_t   vl_logical_dest;
    uint32_t   vl_dest_format;
    uint32_t   vl_arb_id;
    uint32_t   vl_state;
    uint32_t   apic_msg_count;
} vlapic_info;

#endif /* _VMX_VLAPIC_H_ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
