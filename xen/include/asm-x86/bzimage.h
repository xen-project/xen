#ifndef __X86_BZIMAGE_H__
#define __X86_BZIMAGE_H__

#include <xen/init.h>

unsigned long bzimage_headroom(void *image_start, unsigned long image_length);

int bzimage_parse(void *image_base, void **image_start,
                  unsigned long *image_len);

#endif /* __X86_BZIMAGE_H__ */
