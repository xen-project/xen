/* This file is intended to be included multiple times. */
/*
 * Generator for IDT entries.
 *
 * Caller to provide GEN(vector, symbol, dpl, autogen) macro
 *
 * Symbols are 'entry_0xYY' if there is no better name available.  Regular
 * handlers set autogen=1, while manual (autogen=0) require the symbol to be
 * implemented somewhere else.
 */

#define DPL0 0
#define DPL1 1
#define DPL3 3

#define manual 0
#define autogen 1

#define GEN16(i) \
    GEN(0x ## i ## 0, entry_0x ## i ## 0, DPL0, autogen); \
    GEN(0x ## i ## 1, entry_0x ## i ## 1, DPL0, autogen); \
    GEN(0x ## i ## 2, entry_0x ## i ## 2, DPL0, autogen); \
    GEN(0x ## i ## 3, entry_0x ## i ## 3, DPL0, autogen); \
    GEN(0x ## i ## 4, entry_0x ## i ## 4, DPL0, autogen); \
    GEN(0x ## i ## 5, entry_0x ## i ## 5, DPL0, autogen); \
    GEN(0x ## i ## 6, entry_0x ## i ## 6, DPL0, autogen); \
    GEN(0x ## i ## 7, entry_0x ## i ## 7, DPL0, autogen); \
    GEN(0x ## i ## 8, entry_0x ## i ## 8, DPL0, autogen); \
    GEN(0x ## i ## 9, entry_0x ## i ## 9, DPL0, autogen); \
    GEN(0x ## i ## a, entry_0x ## i ## a, DPL0, autogen); \
    GEN(0x ## i ## b, entry_0x ## i ## b, DPL0, autogen); \
    GEN(0x ## i ## c, entry_0x ## i ## c, DPL0, autogen); \
    GEN(0x ## i ## d, entry_0x ## i ## d, DPL0, autogen); \
    GEN(0x ## i ## e, entry_0x ## i ## e, DPL0, autogen); \
    GEN(0x ## i ## f, entry_0x ## i ## f, DPL0, autogen)


GEN(0x00, entry_DE,         DPL0, manual);
GEN(0x01, entry_DB,         DPL0, manual);
GEN(0x02, entry_NMI,        DPL0, manual);
GEN(0x03, entry_BP,         DPL3, manual);
GEN(0x04, entry_OF,         DPL3, manual);
GEN(0x05, entry_BR,         DPL0, manual);
GEN(0x06, entry_UD,         DPL0, manual);
GEN(0x07, entry_NM,         DPL0, manual);
GEN(0x08, entry_DF,         DPL0, manual);
GEN(0x09, entry_0x09,       DPL0, autogen); /* Coprocessor Segment Overrun */
GEN(0x0a, entry_TS,         DPL0, manual);
GEN(0x0b, entry_NP,         DPL0, manual);
GEN(0x0c, entry_SS,         DPL0, manual);
GEN(0x0d, entry_GP,         DPL0, manual);
GEN(0x0e, early_page_fault, DPL0, manual);
GEN(0x0f, entry_0x0f,       DPL0, autogen); /* PIC Spurious Interrupt Vector */

GEN(0x10, entry_MF,         DPL0, manual);
GEN(0x11, entry_AC,         DPL0, manual);
GEN(0x12, entry_MC,         DPL0, manual);
GEN(0x13, entry_XM,         DPL0, manual);
GEN(0x14, entry_VE,         DPL0, autogen);
GEN(0x15, entry_CP,         DPL0, manual);
GEN(0x16, entry_0x16,       DPL0, autogen);
GEN(0x17, entry_0x17,       DPL0, autogen);
GEN(0x18, entry_0x18,       DPL0, autogen);
GEN(0x19, entry_0x19,       DPL0, autogen);
GEN(0x1a, entry_0x1a,       DPL0, autogen);
GEN(0x1b, entry_0x1b,       DPL0, autogen);
GEN(0x1c, entry_HV,         DPL0, autogen);
GEN(0x1d, entry_VC,         DPL0, autogen);
GEN(0x1e, entry_SX,         DPL0, autogen);
GEN(0x1f, entry_0x1f,       DPL0, autogen);

GEN16(2);
GEN16(3);
GEN16(4);
GEN16(5);
GEN16(6);
GEN16(7);

#ifdef CONFIG_PV
GEN(0x80, entry_int80,      DPL3, manual);
#else
GEN(0x80, entry_0x80,       DPL0, autogen);
#endif

GEN(0x81, entry_0x81,       DPL0, autogen);

#ifdef CONFIG_PV32
GEN(0x82, entry_int82,      DPL1, manual);
#else
GEN(0x82, entry_0x82,       DPL0, autogen);
#endif

GEN(0x83, entry_0x83,       DPL0, autogen);
GEN(0x84, entry_0x84,       DPL0, autogen);
GEN(0x85, entry_0x85,       DPL0, autogen);
GEN(0x86, entry_0x86,       DPL0, autogen);
GEN(0x87, entry_0x87,       DPL0, autogen);
GEN(0x88, entry_0x88,       DPL0, autogen);
GEN(0x89, entry_0x89,       DPL0, autogen);
GEN(0x8a, entry_0x8a,       DPL0, autogen);
GEN(0x8b, entry_0x8b,       DPL0, autogen);
GEN(0x8c, entry_0x8c,       DPL0, autogen);
GEN(0x8d, entry_0x8d,       DPL0, autogen);
GEN(0x8e, entry_0x8e,       DPL0, autogen);
GEN(0x8f, entry_0x8f,       DPL0, autogen);

GEN16(9);
GEN16(a);
GEN16(b);
GEN16(c);
GEN16(d);
GEN16(e);
GEN16(f);

#undef autogen
#undef manual

#undef DPL3
#undef DPL1
#undef DPL0

#undef GEN16
