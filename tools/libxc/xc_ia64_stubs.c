#include "xg_private.h"
#include "xenguest.h"
#include "xc_private.h"
#include "xc_elf.h"
#include <stdlib.h>
#include <zlib.h>
#include "xen/arch-ia64.h"
#include <xen/io/ioreq.h>

int xc_linux_save(int xc_handle, int io_fd, uint32_t dom, uint32_t max_iters, 
                  uint32_t max_factor, uint32_t flags)
{
    PERROR("xc_linux_save not implemented\n");
    return -1;
}

int xc_linux_restore(int xc_handle, int io_fd, uint32_t dom, unsigned long nr_pfns,
                     unsigned int store_evtchn, unsigned long *store_mfn,
                     unsigned int console_evtchn, unsigned long *console_mfn)
{
    PERROR("xc_linux_restore not implemented\n");
    return -1;
}

int
xc_plan9_build(int xc_handle,
               uint32_t domid,
               const char *image_name,
               const char *cmdline,
               unsigned int control_evtchn, unsigned long flags)
{
    PERROR("xc_plan9_build not implemented\n");
    return -1;
}

int xc_ia64_get_pfn_list(int xc_handle,
                         uint32_t domid, 
                         unsigned long *pfn_buf, 
                         unsigned int start_page,
                         unsigned int nr_pages)
{
    dom0_op_t op;
    int ret;
    unsigned long max_pfns = ((unsigned long)start_page << 32) | nr_pages;

    op.cmd = DOM0_GETMEMLIST;
    op.u.getmemlist.domain   = (domid_t)domid;
    op.u.getmemlist.max_pfns = max_pfns;
    op.u.getmemlist.buffer   = pfn_buf;

    if ( (max_pfns != -1UL)
		&& mlock(pfn_buf, nr_pages * sizeof(unsigned long)) != 0 )
    {
        PERROR("Could not lock pfn list buffer");
        return -1;
    }    

    ret = do_dom0_op(xc_handle, &op);

    if (max_pfns != -1UL)
    	(void)munlock(pfn_buf, nr_pages * sizeof(unsigned long));

    return (ret < 0) ? -1 : op.u.getmemlist.num_pfns;
}

long xc_get_max_pages(int xc_handle, uint32_t domid)
{
    dom0_op_t op;
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)domid;
    return (do_dom0_op(xc_handle, &op) < 0) ? 
        -1 : op.u.getdomaininfo.max_pages;
}

int xc_ia64_copy_to_domain_pages(int xc_handle, uint32_t domid,
        void* src_page, unsigned long dst_pfn, int nr_pages)
{
    // N.B. gva should be page aligned
    
    unsigned long *page_array=NULL;
    int i;

    if ( (page_array = malloc(nr_pages * sizeof(unsigned long))) == NULL ){
        PERROR("Could not allocate memory");
        goto error_out;
    }
    if ( xc_ia64_get_pfn_list(xc_handle, domid, page_array,
                dst_pfn>>PAGE_SHIFT, nr_pages) != nr_pages ){
        PERROR("Could not get the page frame list");
        goto error_out;
    }

    for ( i=0; i< nr_pages; i++ ){
	if (xc_copy_to_domain_page(xc_handle, domid, page_array[i],
			src_page + (i << PAGE_SHIFT)))
	    goto error_out;
    }
    free(page_array);
    return 0;
    
error_out:
    if (page_array)
        free(page_array);
    return -1;
}


#define HOB_SIGNATURE 0x3436474953424f48 // "HOBSIG64"
#define GFW_HOB_START    ((4UL<<30)-(14UL<<20))    //4G -14M
#define GFW_HOB_SIZE     (1UL<<20)              //1M
#define MEM_G   (1UL << 30) 
#define MEM_M   (1UL << 20) 

typedef struct {
    unsigned long signature;
    unsigned int  type;
    unsigned int  length;
} HOB_GENERIC_HEADER;

/*
 * INFO HOB is the first data data in one HOB list
 * it contains the control information of the HOB list
 */
typedef struct { 
    HOB_GENERIC_HEADER  header;
    unsigned long       length;    // current length of hob
    unsigned long       cur_pos;   // current poisiton of hob
    unsigned long       buf_size;  // size of hob buffer
}HOB_INFO;

typedef struct{
    unsigned long start;
    unsigned long size;
}hob_mem_t;

typedef enum {
    HOB_TYPE_INFO=0,
    HOB_TYPE_TERMINAL,
    HOB_TYPE_MEM,
    HOB_TYPE_PAL_BUS_GET_FEATURES_DATA,
    HOB_TYPE_PAL_CACHE_SUMMARY,
    HOB_TYPE_PAL_MEM_ATTRIB,
    HOB_TYPE_PAL_CACHE_INFO,
    HOB_TYPE_PAL_CACHE_PROT_INFO,
    HOB_TYPE_PAL_DEBUG_INFO,
    HOB_TYPE_PAL_FIXED_ADDR,
    HOB_TYPE_PAL_FREQ_BASE,
    HOB_TYPE_PAL_FREQ_RATIOS,
    HOB_TYPE_PAL_HALT_INFO,
    HOB_TYPE_PAL_PERF_MON_INFO,
    HOB_TYPE_PAL_PROC_GET_FEATURES,
    HOB_TYPE_PAL_PTCE_INFO,
    HOB_TYPE_PAL_REGISTER_INFO,
    HOB_TYPE_PAL_RSE_INFO,
    HOB_TYPE_PAL_TEST_INFO,
    HOB_TYPE_PAL_VM_SUMMARY,
    HOB_TYPE_PAL_VM_INFO,
    HOB_TYPE_PAL_VM_PAGE_SIZE,
    HOB_TYPE_MAX
}hob_type_t;

static int hob_init( void  *buffer ,unsigned long buf_size);
static int add_pal_hob(void* hob_buf);
static int add_mem_hob(void* hob_buf, unsigned long dom_mem_size);
static int build_hob (void* hob_buf, unsigned long hob_buf_size,
                  unsigned long dom_mem_size);
static int load_hob(int xc_handle,uint32_t dom, void *hob_buf);

int xc_ia64_build_hob(int xc_handle, uint32_t dom, unsigned long memsize){

    char   hob_buf[GFW_HOB_SIZE];

    if ( build_hob( hob_buf, GFW_HOB_SIZE, memsize<<20) < 0){
        PERROR("Could not build hob");
        return -1;
    }

    if ( load_hob( xc_handle, dom, hob_buf) <0){
        PERROR("Could not load hob");
       return -1;
    }

    return 0;

}
static int
hob_init( void  *buffer ,unsigned long buf_size)
{
    HOB_INFO *phit;
    HOB_GENERIC_HEADER     *terminal;

    if (sizeof(HOB_INFO) + sizeof(HOB_GENERIC_HEADER) > buf_size){
        // buffer too small
        return -1;
    }
    
    phit = (HOB_INFO*)buffer;
    phit->header.signature = HOB_SIGNATURE;
    phit->header.type = HOB_TYPE_INFO;
    phit->header.length = sizeof(HOB_INFO);
    phit->length = sizeof(HOB_INFO) + sizeof(HOB_GENERIC_HEADER);
    phit->cur_pos = 0;
    phit->buf_size = buf_size;
    
    terminal = (HOB_GENERIC_HEADER*) (buffer + sizeof(HOB_INFO));
    terminal->signature= HOB_SIGNATURE;
    terminal->type = HOB_TYPE_TERMINAL;
    terminal->length = sizeof(HOB_GENERIC_HEADER);

    return 0;
}

/*
 *  Add a new HOB to the HOB List.
 *       
 *  hob_start  -  start address of hob buffer
 *  type       -  type of the hob to be added
 *  data       -  data of the hob to be added
 *  data_size  -  size of the data
 */
static int
hob_add(
     void*  hob_start,
     int    type,
     void*  data,
     int    data_size
)
{
    HOB_INFO *phit;
    HOB_GENERIC_HEADER     *newhob,*tail;   
    
    phit = (HOB_INFO*)hob_start;

    if (phit->length + data_size > phit->buf_size){
        // no space for new hob
        return -1;
    }

    //append new HOB 
    newhob = (HOB_GENERIC_HEADER*)
        (hob_start + phit->length - sizeof(HOB_GENERIC_HEADER));
    newhob->signature = HOB_SIGNATURE;
    newhob->type = type;
    newhob->length = data_size + sizeof(HOB_GENERIC_HEADER);
    memcpy((void*)newhob + sizeof(HOB_GENERIC_HEADER), data, data_size);

    // append terminal HOB  
    tail = (HOB_GENERIC_HEADER*) ( hob_start + phit->length + data_size);
    tail->signature = HOB_SIGNATURE;
    tail->type = HOB_TYPE_TERMINAL;
    tail->length = sizeof(HOB_GENERIC_HEADER);

    // adjust HOB list length
    phit->length += sizeof(HOB_GENERIC_HEADER)+ data_size;

    return 0;

}

int get_hob_size(void* hob_buf){
    
    HOB_INFO *phit = (HOB_INFO*)hob_buf;
    
    if (phit->header.signature != HOB_SIGNATURE){
        PERROR("xc_get_hob_size:Incorrect signature");
        return -1;
    }
    return phit->length;
}

int build_hob (void* hob_buf, unsigned long hob_buf_size,
                  unsigned long dom_mem_size)
{   
    //Init HOB List 
    if (hob_init (hob_buf, hob_buf_size)<0){
        PERROR("buffer too small");
        goto err_out;
    }
    
    if ( add_mem_hob( hob_buf,dom_mem_size) < 0){
        PERROR("Add memory hob failed, buffer too small");
        goto err_out;
    }
    
    if ( add_pal_hob( hob_buf ) < 0 ){
        PERROR("Add PAL hob failed, buffer too small");
        goto err_out;
    }
    
    return 0;

err_out:
    return -1;  
}

static int 
load_hob(int xc_handle, uint32_t dom, void *hob_buf)
{
    // hob_buf should be page aligned
    int hob_size;
    int nr_pages;

    if ((hob_size = get_hob_size(hob_buf)) < 0){
        PERROR("Invalid hob data");
        return -1;
    }

    if (hob_size > GFW_HOB_SIZE){
        PERROR("No enough memory for hob data");
        return -1;
    }

    nr_pages = (hob_size + PAGE_SIZE -1) >> PAGE_SHIFT;
    
    return xc_ia64_copy_to_domain_pages(xc_handle, dom,
            hob_buf, GFW_HOB_START, nr_pages );
}

#define MIN(x, y) ((x) < (y)) ? (x) : (y)
static int 
add_mem_hob(void* hob_buf, unsigned long dom_mem_size){
    hob_mem_t memhob;

    // less than 3G
    memhob.start = 0;
    memhob.size = MIN(dom_mem_size, 0xC0000000);
    
    if (hob_add(hob_buf, HOB_TYPE_MEM, &memhob, sizeof(memhob)) < 0){
	return -1;
    }

    if (dom_mem_size > 0xC0000000) {
        // 4G ~ 4G+remain
        memhob.start = 0x100000000; //4G
        memhob.size = dom_mem_size - 0xC0000000;
        if (hob_add(hob_buf, HOB_TYPE_MEM, &memhob, sizeof(memhob)) < 0)
            return -1;
    }
    return 0;
}

unsigned char config_pal_bus_get_features_data[24] = {
    0, 0, 0, 32, 0, 0, 240, 189, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
unsigned char config_pal_cache_summary[16] = {
    3, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0};
unsigned char config_pal_mem_attrib[8] =    {
    241, 0, 0, 0, 0, 0, 0, 0
};
unsigned char config_pal_cache_info[152] = {
    3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    6, 4, 6, 7, 255, 1, 0, 1, 0, 64, 0, 0, 12, 12, 
    49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 6, 7, 0, 1,
    0, 1, 0, 64, 0, 0, 12, 12, 49, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 6, 8, 7, 7, 255, 7, 0, 11, 0, 0, 16, 0, 
    12, 17, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 8, 7, 
    7, 7, 5, 9, 11, 0, 0, 4, 0, 12, 15, 49, 0, 254, 255,
    255, 255, 255, 255, 255, 255, 2, 8, 7, 7, 7, 5, 9, 
    11, 0, 0, 4, 0, 12, 15, 49, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 3, 12, 7, 7, 7, 14, 1, 3, 0, 0, 192, 0, 12, 20, 49, 0
};
unsigned char config_pal_cache_prot_info[200] = {
    3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    45, 0, 16, 8, 0, 76, 12, 64, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    8, 0, 16, 4, 0, 76, 44, 68, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 
    0, 16, 8, 0, 81, 44, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0,
    112, 12, 0, 79, 124, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 254, 255, 255, 255, 255, 255, 255, 255, 
    32, 0, 112, 12, 0, 79, 124, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 160, 
    12, 0, 84, 124, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0
};
unsigned char config_pal_debug_info[16] = {
    2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0
};
unsigned char config_pal_fixed_addr[8] = {
    0, 0, 0, 0, 0, 0, 0, 0
};
unsigned char config_pal_freq_base[8] = {
    109, 219, 182, 13, 0, 0, 0, 0
};
unsigned char config_pal_freq_ratios[24] = {
    11, 1, 0, 0, 77, 7, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 4, 
    0, 0, 0, 7, 0, 0, 0
};
unsigned char config_pal_halt_info[64] = {
    0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
unsigned char config_pal_perf_mon_info[136] = {
    12, 47, 18, 8, 0, 0, 0, 0, 241, 255, 0, 0, 255, 7, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 241, 255, 0, 0, 223, 0, 255, 255, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 240, 255, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 240, 255, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0
};
unsigned char config_pal_proc_get_features[104] = {
    3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 64, 6, 64, 49, 0, 0, 0, 0, 64, 6, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 
    231, 0, 0, 0, 0, 0, 0, 0, 228, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 
    63, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};
unsigned char config_pal_ptce_info[24] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0
};
unsigned char config_pal_register_info[64] = {
    255, 0, 47, 127, 17, 17, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0,
    255, 208, 128, 238, 238, 0, 0, 248, 255, 255, 255, 255, 255, 0, 0, 7, 3,
    251, 3, 0, 0, 0, 0, 255, 7, 3, 0, 0, 0, 0, 0, 248, 252, 4,
    252, 255, 255, 255, 255, 2, 248, 252, 255, 255, 255, 255, 255
};
unsigned char config_pal_rse_info[16] = {
    96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
unsigned char config_pal_test_info[48] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
unsigned char config_pal_vm_summary[16] = {
    101, 18, 15, 2, 7, 7, 4, 2, 59, 18, 0, 0, 0, 0, 0, 0
};
unsigned char config_pal_vm_info[104] = {
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    32, 32, 0, 0, 0, 0, 0, 0, 112, 85, 21, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 1, 32, 32, 0, 0, 0, 0, 0, 0, 112, 85,
    21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 128, 128, 0,
    4, 0, 0, 0, 0, 112, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 1, 128, 128, 0, 4, 0, 0, 0, 0, 112, 85, 0, 0, 0, 0, 0
};
unsigned char config_pal_vm_page_size[16] = {
    0, 112, 85, 21, 0, 0, 0, 0, 0, 112, 85, 21, 0, 0, 0, 0
};

typedef struct{
    hob_type_t type;
    void* data;
    unsigned long size;     
}hob_batch_t;

hob_batch_t hob_batch[]={
    {  HOB_TYPE_PAL_BUS_GET_FEATURES_DATA,
        &config_pal_bus_get_features_data,
        sizeof(config_pal_bus_get_features_data)
    },
    {  HOB_TYPE_PAL_CACHE_SUMMARY,
        &config_pal_cache_summary,
        sizeof(config_pal_cache_summary)
    },
    {  HOB_TYPE_PAL_MEM_ATTRIB,
        &config_pal_mem_attrib,
        sizeof(config_pal_mem_attrib)
    },
    {  HOB_TYPE_PAL_CACHE_INFO,
        &config_pal_cache_info,
        sizeof(config_pal_cache_info)
    },
    {  HOB_TYPE_PAL_CACHE_PROT_INFO,
        &config_pal_cache_prot_info,
        sizeof(config_pal_cache_prot_info)
    },
    {  HOB_TYPE_PAL_DEBUG_INFO,
        &config_pal_debug_info,
        sizeof(config_pal_debug_info)
    },
    {  HOB_TYPE_PAL_FIXED_ADDR,
        &config_pal_fixed_addr,
        sizeof(config_pal_fixed_addr)
    },
    {  HOB_TYPE_PAL_FREQ_BASE,
        &config_pal_freq_base,
        sizeof(config_pal_freq_base)
    },
    {  HOB_TYPE_PAL_FREQ_RATIOS,
        &config_pal_freq_ratios,
        sizeof(config_pal_freq_ratios)
    },
    {  HOB_TYPE_PAL_HALT_INFO,
        &config_pal_halt_info,
        sizeof(config_pal_halt_info)
    },
    {  HOB_TYPE_PAL_PERF_MON_INFO,
        &config_pal_perf_mon_info,
        sizeof(config_pal_perf_mon_info)
    },
    {  HOB_TYPE_PAL_PROC_GET_FEATURES,
        &config_pal_proc_get_features,
        sizeof(config_pal_proc_get_features)
    },
    {  HOB_TYPE_PAL_PTCE_INFO,
        &config_pal_ptce_info,
        sizeof(config_pal_ptce_info)
    },
    {  HOB_TYPE_PAL_REGISTER_INFO,
        &config_pal_register_info,
        sizeof(config_pal_register_info)
    },
    {  HOB_TYPE_PAL_RSE_INFO,
        &config_pal_rse_info,
        sizeof(config_pal_rse_info)
    },
    {  HOB_TYPE_PAL_TEST_INFO,
        &config_pal_test_info,
        sizeof(config_pal_test_info)
    },
    {  HOB_TYPE_PAL_VM_SUMMARY,
        &config_pal_vm_summary,
        sizeof(config_pal_vm_summary)
    },
    {  HOB_TYPE_PAL_VM_INFO,
        &config_pal_vm_info,
        sizeof(config_pal_vm_info)
    },
    {  HOB_TYPE_PAL_VM_PAGE_SIZE,
        &config_pal_vm_page_size,
        sizeof(config_pal_vm_page_size)
    },      
};

static int add_pal_hob(void* hob_buf){
    int i;
    for (i=0; i<sizeof(hob_batch)/sizeof(hob_batch_t); i++){
        if (hob_add(hob_buf, hob_batch[i].type, 
                    hob_batch[i].data,
                    hob_batch[i].size)<0)
            return -1;
    }
    return 0;
}

static int setup_guest(  int xc_handle,
                         uint32_t dom, unsigned long memsize,
                         char *image, unsigned long image_size,
                         unsigned int control_evtchn,
                         unsigned int store_evtchn,
                         unsigned long *store_mfn)
{
    unsigned long page_array[2];
    shared_iopage_t *sp;
    // FIXME: initialize pfn list for a temp hack
    if (xc_ia64_get_pfn_list(xc_handle, dom, NULL, -1, -1) == -1) {
	PERROR("Could not allocate continuous memory");
	goto error_out;
    }
    
    if ((image_size > 12 * MEM_M) || (image_size & (PAGE_SIZE - 1))) {
        PERROR("Guest firmware size is incorrect [%ld]?", image_size);
        return -1;
    }

    /* Load guest firmware */
    if( xc_ia64_copy_to_domain_pages( xc_handle, dom, 
            image, 4*MEM_G-image_size, image_size>>PAGE_SHIFT)) {
        PERROR("Could not load guest firmware into domain");
        goto error_out;
    }

    /* Hand-off state passed to guest firmware */
    if (xc_ia64_build_hob(xc_handle, dom, memsize) < 0){
        PERROR("Could not build hob\n");
       goto error_out;
    }

    /* Retrieve special pages like io, xenstore, etc. */
    if ( xc_ia64_get_pfn_list(xc_handle, dom, page_array, IO_PAGE_START>>PAGE_SHIFT, 2) != 2 )
    {
        PERROR("Could not get the page frame list");
        goto error_out;
    }

    *store_mfn = page_array[1];
    if ((sp = (shared_iopage_t *) xc_map_foreign_range(
		xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
		page_array[0])) == 0)
	goto error_out;
    memset(sp, 0, PAGE_SIZE);
    sp->sp_global.eport = control_evtchn;
    munmap(sp, PAGE_SIZE);

    return 0;

 error_out:
    return -1;
}

int xc_vmx_build(int xc_handle,
                 uint32_t domid,
                 int memsize,
                 const char *image_name,
                 unsigned int control_evtchn,
		 unsigned int lapic,
                 unsigned int vcpus,
                 unsigned int store_evtchn,
                 unsigned long *store_mfn)
{
    dom0_op_t launch_op, op;
    int rc ;
    vcpu_guest_context_t st_ctxt, *ctxt = &st_ctxt;
    char         *image = NULL;
    unsigned long image_size;
    unsigned long nr_pages;

    if ( (nr_pages = xc_get_max_pages(xc_handle, domid)) < 0 )
    {
        PERROR("Could not find total pages for domain");
        goto error_out;
    }

    if ( (image = xc_read_kernel_image(image_name, &image_size)) == NULL ){
        PERROR("Could not read guest firmware image %s",image_name);
        goto error_out;
    }

    image_size = (image_size + PAGE_SIZE - 1) & PAGE_MASK;

    if ( mlock(&st_ctxt, sizeof(st_ctxt) ) ){   
        PERROR("Unable to mlock ctxt");
        return 1;
    }

    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)domid;
    if ( (do_dom0_op(xc_handle, &op) < 0) || 
         ((uint16_t)op.u.getdomaininfo.domain != domid) ) {
        PERROR("Could not get info on domain");
        goto error_out;
    }

    if ( xc_domain_get_vcpu_context(xc_handle, domid, 0, ctxt) ){
        PERROR("Could not get vcpu context");
        goto error_out;
    }

    if ( !(op.u.getdomaininfo.flags & DOMFLAGS_PAUSED) ) {
        ERROR("Domain is already constructed");
        goto error_out;
    }

    if ( setup_guest(xc_handle, domid, (unsigned long)memsize, image, image_size, 
                       control_evtchn, store_evtchn, store_mfn ) < 0 ){
        ERROR("Error constructing guest OS");
        goto error_out;
    }

    if ( image != NULL )
        free(image);

    ctxt->flags = VGCF_VMX_GUEST;
    ctxt->regs.cr_iip = 0x80000000ffffffb0UL;
    ctxt->vcpu.privregs = 0;

    memset( &launch_op, 0, sizeof(launch_op) );

    launch_op.u.setdomaininfo.domain = (domid_t)domid;
    launch_op.u.setdomaininfo.vcpu   = 0;
    launch_op.u.setdomaininfo.ctxt   = ctxt;

    launch_op.cmd = DOM0_SETDOMAININFO;
    rc = do_dom0_op(xc_handle, &launch_op);
    return rc;

 error_out:
    if ( image != NULL )
        free(image);

    return -1;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
