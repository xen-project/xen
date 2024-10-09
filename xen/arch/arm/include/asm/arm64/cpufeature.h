#ifndef __ASM_ARM_ARM64_CPUFEATURES_H
#define __ASM_ARM_ARM64_CPUFEATURES_H

#include <xen/linux-compat.h>

/*
 * CPU feature register tracking
 *
 * The safe value of a CPUID feature field is dependent on the implications
 * of the values assigned to it by the architecture. Based on the relationship
 * between the values, the features are classified into 3 types - LOWER_SAFE,
 * HIGHER_SAFE and EXACT.
 *
 * The lowest value of all the CPUs is chosen for LOWER_SAFE and highest
 * for HIGHER_SAFE. It is expected that all CPUs have the same value for
 * a field when EXACT is specified, failing which, the safe value specified
 * in the table is chosen.
 */

enum ftr_type {
	FTR_EXACT,			/* Use a predefined safe value */
	FTR_LOWER_SAFE,			/* Smaller value is safe */
	FTR_HIGHER_SAFE,		/* Bigger value is safe */
	FTR_HIGHER_OR_ZERO_SAFE,	/* Bigger value is safe, but 0 is biggest */
};

#define FTR_STRICT	true	/* SANITY check strict matching required */
#define FTR_NONSTRICT	false	/* SANITY check ignored */

#define FTR_SIGNED	true	/* Value should be treated as signed */
#define FTR_UNSIGNED	false	/* Value should be treated as unsigned */

#define FTR_VISIBLE	true	/* Feature visible to the user space */
#define FTR_HIDDEN	false	/* Feature is hidden from the user */

#define FTR_VISIBLE_IF_IS_ENABLED(config)		\
	(IS_ENABLED(config) ? FTR_VISIBLE : FTR_HIDDEN)

struct arm64_ftr_bits {
	bool		sign;	/* Value is signed ? */
	bool		visible;
	bool		strict;	/* CPU Sanity check: strict matching required ? */
	enum ftr_type	type;
	u8		shift;
	u8		width;
	s64		safe_val; /* safe value for FTR_EXACT features */
};

static inline int attr_const
cpuid_feature_extract_signed_field_width(u64 features, int field, int width)
{
	return (s64)(features << (64 - width - field)) >> (64 - width);
}

static inline int attr_const
cpuid_feature_extract_signed_field(u64 features, int field)
{
	return cpuid_feature_extract_signed_field_width(features, field, 4);
}

static inline unsigned int attr_const
cpuid_feature_extract_unsigned_field_width(u64 features, int field, int width)
{
	return (u64)(features << (64 - width - field)) >> (64 - width);
}

static inline unsigned int attr_const
cpuid_feature_extract_unsigned_field(u64 features, int field)
{
	return cpuid_feature_extract_unsigned_field_width(features, field, 4);
}

static inline u64 arm64_ftr_mask(const struct arm64_ftr_bits *ftrp)
{
	return (u64)GENMASK(ftrp->shift + ftrp->width - 1, ftrp->shift);
}

static inline int attr_const
cpuid_feature_extract_field_width(u64 features, int field, int width, bool sign)
{
	return (sign) ?
		cpuid_feature_extract_signed_field_width(features, field, width) :
		cpuid_feature_extract_unsigned_field_width(features, field, width);
}

static inline int attr_const
cpuid_feature_extract_field(u64 features, int field, bool sign)
{
	return cpuid_feature_extract_field_width(features, field, 4, sign);
}

static inline s64 arm64_ftr_value(const struct arm64_ftr_bits *ftrp, u64 val)
{
	return (s64)cpuid_feature_extract_field_width(val, ftrp->shift, ftrp->width, ftrp->sign);
}

#endif /* _ASM_ARM_ARM64_CPUFEATURES_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
