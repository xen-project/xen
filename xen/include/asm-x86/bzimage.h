#ifndef __X86_BZIMAGE_H__
#define __X86_BZIMAGE_H__

#include <xen/config.h>
#include <xen/init.h>

unsigned long bzimage_headroom(char *image_start, unsigned long image_length);

int bzimage_parse(char *image_base, char **image_start,
                  unsigned long *image_len);

#endif /* __X86_BZIMAGE_H__ */
