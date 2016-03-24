#include <xen/init.h>
#include <xen/lib.h>
#include <asm/cpuid.h>

const uint32_t known_features[] = INIT_KNOWN_FEATURES;

static void __init __maybe_unused build_assertions(void)
{
    BUILD_BUG_ON(ARRAY_SIZE(known_features) != FSCAPINTS);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
