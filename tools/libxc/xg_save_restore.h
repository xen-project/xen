/*
** xg_save_restore.h
** 
** Defintions and utilities for save / restore. 
*/

#define DEBUG    1
#define PROGRESS 0

#define ERR(_f, _a...) do {                     \
    fprintf(stderr, _f "\n" , ## _a);           \
    fflush(stderr); }                           \
while (0)

#if DEBUG
#define DPRINTF(_f, _a...) fprintf(stderr, _f , ## _a)
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif


#if PROGRESS
#define PPRINTF(_f, _a...) fprintf(stderr, _f , ## _a)
#else
#define PPRINTF(_f, _a...)
#endif


/*
** We process save/restore/migrate in batches of pages; the below 
** determines how many pages we (at maximum) deal with in each batch. 
*/
#define MAX_BATCH_SIZE 1024   /* up to 1024 pages (4MB) at a time */

/* When pinning page tables at the end of restore, we also use batching. */
#define MAX_PIN_BATCH  1024



/*
** Determine various platform information required for save/restore, in 
** particular: 
**
**    - the maximum MFN on this machine, used to compute the size of 
**      the M2P table; 
** 
**    - the starting virtual address of the the hypervisor; we use this 
**      to determine which parts of guest address space(s) do and don't 
**      require canonicalization during save/restore; and 
** 
**    - the number of page-table levels for save/ restore. This should 
**      be a property of the domain, but for the moment we just read it 
**      from the hypervisor.
**
** Returns 1 on success, 0 on failure. 
*/
static int get_platform_info(int xc_handle, uint32_t dom, 
                             /* OUT */ uint32_t *max_mfn,  
                             /* OUT */ uint32_t *hvirt_start, 
                             /* OUT */ uint32_t *pt_levels)
    
{ 
    xen_capabilities_info_t xen_caps = "";
    xen_platform_parameters_t xen_params;
    xc_physinfo_t physinfo;
    
    if (xc_physinfo(xc_handle, &physinfo) != 0) 
        return 0;
    
    if (xc_version(xc_handle, XENVER_platform_parameters, &xen_params) != 0)
        return 0;
    
    if (xc_version(xc_handle, XENVER_capabilities, &xen_caps) != 0)
        return 0;

    *max_mfn =     physinfo.total_pages;
    *hvirt_start = xen_params.virt_start;

    if (strstr(xen_caps, "xen-3.0-x86_64"))
        *pt_levels = 4;
    else if (strstr(xen_caps, "xen-3.0-x86_32p"))
        *pt_levels = 3; 
    else if (strstr(xen_caps, "xen-3.0-x86_32"))
        *pt_levels = 2; 
    else 
        return 0; 
    
    return 1;
} 


/* 
** Save/restore deal with the mfn_to_pfn (M2P) and pfn_to_mfn (P2M) tables. 
** The M2P simply holds the corresponding PFN, while the top bit of a P2M
** entry tell us whether or not the the PFN is currently mapped.
*/

#define PFN_TO_KB(_pfn) ((_pfn) * PAGE_SIZE / 1024)
#define ROUNDUP(_x,_w) (((unsigned long)(_x)+(1UL<<(_w))-1) & ~((1UL<<(_w))-1))

/* Size in bytes of the M2P and P2M (both rounded up to nearest PAGE_SIZE) */
#define M2P_SIZE ROUNDUP((max_mfn * sizeof(unsigned long)), PAGE_SHIFT) 
#define P2M_SIZE ROUNDUP((max_pfn * sizeof(unsigned long)), PAGE_SHIFT) 


/* Number of unsigned longs in a page */
#define ulpp            (PAGE_SIZE/sizeof(unsigned long))

/* Number of entries in the pfn_to_mfn_frame_list */
#define P2M_FL_ENTRIES  (((max_pfn)+ulpp-1)/ulpp)

/* Size in bytes of the pfn_to_mfn_frame_list     */
#define P2M_FL_SIZE     ((P2M_FL_ENTRIES)*sizeof(unsigned long))

/* Number of entries in the pfn_to_mfn_frame_list_list */
#define P2M_FLL_ENTRIES (((max_pfn)+(ulpp*ulpp)-1)/(ulpp*ulpp))

/* Returns TRUE if the PFN is currently mapped */
#define is_mapped(pfn_type) (!((pfn_type) & 0x80000000UL))

#define INVALID_P2M_ENTRY   (~0UL) 



