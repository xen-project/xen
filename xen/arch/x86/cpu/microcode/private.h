#ifndef ASM_X86_MICROCODE_PRIVATE_H
#define ASM_X86_MICROCODE_PRIVATE_H

#include <asm/microcode.h>

extern bool opt_ucode_allow_same;

enum microcode_match_result {
    OLD_UCODE, /* signature matched, but revision id is older */
    SAME_UCODE, /* signature matched, but revision id is the same */
    NEW_UCODE, /* signature matched, but revision id is newer */
    MIS_UCODE, /* signature mismatched */
};

/* Opaque.  Internals are vendor-specific. */
struct microcode_patch;

struct microcode_ops {
    /*
     * Parse a microcode container.  Format is vendor-specific.
     *
     * Search within the container for the patch, suitable for the current
     * CPU, which has the highest revision.  (Note: May be a patch which is
     * older that what is running in the CPU.  This is a feature, to better
     * cope with corner cases from buggy firmware.)
     *
     * If one is found, behaviour depends on the make_copy argument:
     *
     *     true: allocate and return a struct microcode_patch encapsulating
     *           the appropriate microcode patch.  Does not alias the original
     *           buffer.  Must be suitable to be freed with a single xfree().
     *
     *    false: return a pointer to the patch within the original buffer.
     *           This is useful for early microcode loading when xmalloc might
     *           not be available yet.
     *
     * If one is not found, (nothing matches the current CPU), return NULL.
     * Also may return ERR_PTR(-err), e.g. bad container, out of memory.
     */
    struct microcode_patch *(*cpu_request_microcode)(
        const void *buf, size_t size, bool make_copy);

    /*
     * Obtain microcode-relevant details for the current CPU.  Results in
     * per_cpu(cpu_sig).
     */
    void (*collect_cpu_info)(void);

    /*
     * Attempt to load the provided patch into the CPU.  Returns an error if
     * anything didn't go as expected.
     */
    int (*apply_microcode)(const struct microcode_patch *patch);

    /*
     * Given two patches, are they both applicable to the current CPU, and is
     * new a higher revision than old?
     */
    enum microcode_match_result (*compare_patch)(
        const struct microcode_patch *new, const struct microcode_patch *old);
};

extern bool opt_digest_check;

/**
 * Checks whether we can perform microcode updates on this Intel system
 *
 * @return True iff the microcode update facilities are enabled
 */
bool intel_can_load_microcode(void);

void amd_check_entrysign(void);

extern const struct microcode_ops amd_ucode_ops, intel_ucode_ops;

#endif /* ASM_X86_MICROCODE_PRIVATE_H */
