#ifndef _ASM_IA64_MACHVEC_XEN_h
#define _ASM_IA64_MACHVEC_XEN_h

extern ia64_mv_setup_t			dig_setup;
extern ia64_mv_dma_alloc_coherent	xen_alloc_coherent;
extern ia64_mv_dma_free_coherent	xen_free_coherent;
extern ia64_mv_dma_map_single		xen_map_single;
extern ia64_mv_dma_unmap_single		xen_unmap_single;
extern ia64_mv_dma_map_sg		xen_map_sg;
extern ia64_mv_dma_unmap_sg		xen_unmap_sg;
extern ia64_mv_dma_supported		xen_dma_supported;
extern ia64_mv_dma_mapping_error	xen_dma_mapping_error;

/*
 * This stuff has dual use!
 *
 * For a generic kernel, the macros are used to initialize the
 * platform's machvec structure.  When compiling a non-generic kernel,
 * the macros are used directly.
 */
#define platform_name				"xen"
#define platform_setup				dig_setup
#define platform_dma_init			machvec_noop
#define platform_dma_alloc_coherent		xen_alloc_coherent
#define platform_dma_free_coherent		xen_free_coherent
#define platform_dma_map_single			xen_map_single
#define platform_dma_unmap_single		xen_unmap_single
#define platform_dma_map_sg			xen_map_sg
#define platform_dma_unmap_sg			xen_unmap_sg
#define platform_dma_sync_single_for_cpu	machvec_dma_sync_single
#define platform_dma_sync_sg_for_cpu		machvec_dma_sync_sg
#define platform_dma_sync_single_for_device	machvec_dma_sync_single
#define platform_dma_sync_sg_for_device		machvec_dma_sync_sg
#define platform_dma_supported			xen_dma_supported
#define platform_dma_mapping_error		xen_dma_mapping_error

#endif /* _ASM_IA64_MACHVEC_XEN_h */
