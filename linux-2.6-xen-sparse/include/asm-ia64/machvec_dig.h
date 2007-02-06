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
#define platform_setup		dig_setup

#ifdef CONFIG_XEN
# define platform_dma_map_sg		dma_map_sg
# define platform_dma_unmap_sg		dma_unmap_sg
# define platform_dma_mapping_error	dma_mapping_error
# define platform_dma_supported		dma_supported
# define platform_dma_alloc_coherent	dma_alloc_coherent
# define platform_dma_free_coherent	dma_free_coherent
# define platform_dma_map_single	dma_map_single
# define platform_dma_unmap_single	dma_unmap_single
# define platform_dma_sync_single_for_cpu \
					dma_sync_single_for_cpu
# define platform_dma_sync_single_for_device \
					dma_sync_single_for_device
#endif

#endif /* _ASM_IA64_MACHVEC_DIG_h */
