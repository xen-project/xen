/* Hook to call BIOS initialisation function */

#define ARCH_SETUP machine_specific_arch_setup();

static inline void __init machine_specific_arch_setup(void);
