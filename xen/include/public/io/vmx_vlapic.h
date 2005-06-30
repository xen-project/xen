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
#define VLAPIC_INT_COUNT                (VLOCAL_APIC_MAX_INTS/(BITS_PER_BYTE * sizeof(u64)))
#define VLAPIC_INT_COUNT_32             (VLOCAL_APIC_MAX_INTS/(BITS_PER_BYTE * sizeof(u32)))

struct vapic_bus_message{
   u8   deliv_mode:4;   /* deliver mode, including fixed, LPRI, etc */
   u8   level:1;        /* level or edge */
   u8   trig_mod:1;    /* assert or disassert */
   u8   reserved:2;
   u8   vector;
};

typedef struct {
    /* interrupt for PIC and ext type IOAPIC interrupt */
    u64   vl_ext_intr[VLAPIC_INT_COUNT];
    u64   vl_ext_intr_mask[VLAPIC_INT_COUNT];
    u64   vl_apic_intr[VLAPIC_INT_COUNT];
    u64   vl_apic_tmr[VLAPIC_INT_COUNT];
    u64   vl_eoi[VLAPIC_INT_COUNT];
    u32   vl_lapic_id;
    u32   direct_intr;
    u32   vl_apr;
    u32   vl_logical_dest;
    u32   vl_dest_format;
    u32   vl_arb_id;
    u32   vl_state;
    u32   apic_msg_count;
    struct vapic_bus_message  vl_apic_msg[24];
} vlapic_info;

#endif /* _VMX_VLAPIC_H_ */
