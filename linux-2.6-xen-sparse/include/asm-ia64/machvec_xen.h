#ifndef _ASM_IA64_MACHVEC_XEN_h
#define _ASM_IA64_MACHVEC_XEN_h

extern ia64_mv_setup_t			xen_setup;
extern ia64_mv_cpu_init_t		xen_cpu_init;
extern ia64_mv_irq_init_t		xen_irq_init;
extern ia64_mv_send_ipi_t		xen_platform_send_ipi;
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
#define platform_setup				xen_setup
#define platform_cpu_init			xen_cpu_init
#define platform_irq_init			xen_irq_init
#define platform_send_ipi			xen_platform_send_ipi
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
