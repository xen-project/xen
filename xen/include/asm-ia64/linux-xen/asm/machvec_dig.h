#ifndef _ASM_IA64_MACHVEC_DIG_h
#define _ASM_IA64_MACHVEC_DIG_h

extern ia64_mv_setup_t dig_setup;

/*
 * This stuff has dual use!
 *
 * For a generic kernel, the macros are used to initialize the
 * platform's machvec structure.  When compiling a non-generic kernel,
 * the macros are used directly.
 */
#define platform_name		"dig"
#ifdef XEN
/*
 * All the World is a PC .... yay! yay! yay!
 */
extern ia64_mv_setup_t hpsim_setup;
#define platform_setup				hpsim_setup

#define platform_dma_init			machvec_noop
#define platform_dma_alloc_coherent		machvec_noop
#define platform_dma_free_coherent		machvec_noop
#define platform_dma_map_single			machvec_noop
#define platform_dma_unmap_single		machvec_noop
#define platform_dma_map_sg			machvec_noop
#define platform_dma_unmap_sg			machvec_noop
#define platform_dma_sync_single_for_cpu	machvec_noop
#define platform_dma_sync_sg_for_cpu		machvec_noop
#define platform_dma_sync_single_for_device	machvec_noop
#define platform_dma_sync_sg_for_device		machvec_noop
#define platform_dma_mapping_error		machvec_noop
#define platform_dma_supported			machvec_noop

#define platform_pci_get_legacy_mem		machvec_noop
#define platform_pci_legacy_read		machvec_noop
#define platform_pci_legacy_write		machvec_noop
#else
#define platform_setup		dig_setup
#endif

#endif /* _ASM_IA64_MACHVEC_DIG_h */
