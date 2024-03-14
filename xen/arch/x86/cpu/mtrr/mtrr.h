/*
 * local mtrr defines.
 */
#ifndef X86_CPU_MTRR_MTRR_H
#define X86_CPU_MTRR_MTRR_H

#define MTRR_CHANGE_MASK_FIXED     0x01
#define MTRR_CHANGE_MASK_VARIABLE  0x02
#define MTRR_CHANGE_MASK_DEFTYPE   0x04

void mtrr_get(
    unsigned int reg, unsigned long *base, unsigned long *size,
    mtrr_type *type);
void mtrr_set(
    unsigned int reg, unsigned long base, unsigned long size, mtrr_type type);
void mtrr_set_all(void);
int mtrr_get_free_region(
    unsigned long base, unsigned long size, int replace_reg);
int mtrr_validate_add_page(
    unsigned long base, unsigned long size, unsigned int type);
bool mtrr_have_wrcomb(void);

void get_mtrr_state(void);

extern u64 size_or_mask, size_and_mask;

extern unsigned int num_var_ranges;

void mtrr_state_warn(void);

#endif /* X86_CPU_MTRR_MTRR_H */
