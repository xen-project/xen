#ifndef _VMX_VLAPIC_H
#define _VMX_VLAPIC_H

#define VLAPIC_DELIV_MODE_FIXED          0x0
#define VLAPIC_DELIV_MODE_LPRI           0x1
#define VLAPIC_DELIV_MODE_SMI            0x2
#define VLAPIC_DELIV_MODE_PMI            0x2
#define VLAPIC_DELIV_MODE_NMI            0x4
#define VLAPIC_DELIV_MODE_INIT           0x5
#define VLAPIC_DELIV_MODE_STARTUP        0x6
#define VLAPIC_DELIV_MODE_EXT            0x7
#define VLAPIC_DELIV_MODE_MASK            0x8

#define MAX_VECTOR    256
#define BITS_PER_BYTE   8
#define INTR_LEN        (MAX_VECTOR/(BITS_PER_BYTE * sizeof(u64)))
#define INTR_LEN_32        (MAX_VECTOR/(BITS_PER_BYTE * sizeof(u32)))

typedef struct {
    u32   vl_lapic_id;
    u32   vl_apr;
    u32   vl_logical_dest;
    u32   vl_dest_format;
    u32   vl_arb_id;
    u64   irr[INTR_LEN];
    u64   tmr[INTR_LEN];
}vl_apic_info;

#endif /* _VMX_VLAPIC_H_ */
