/******************************************************************************
 * kexec.h
 * 
 * Based heavily on machine_kexec.c and kexec.h from Linux 2.6.19-rc1
 *
 */

#ifndef __X86_64_KEXEC_H__
#define __X86_64_KEXEC_H__
  
#include <xen/types.h>
#include <xen/kexec.h>

typedef void (*relocate_new_kernel_t)(
                unsigned long indirection_page,
                unsigned long page_list,
                unsigned long start_address);

static inline void machine_kexec(xen_kexec_image_t *image)
{
    relocate_new_kernel_t rnk;

    rnk = (relocate_new_kernel_t) image->page_list[1];
    (*rnk)(image->indirection_page, (unsigned long)image->page_list, 
           image->start_address);
}

#endif /* __X86_64_KEXEC_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
