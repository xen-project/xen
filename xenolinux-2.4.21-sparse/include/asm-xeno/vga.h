/*
 *	Access to VGA videoram
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 */

#ifndef _LINUX_ASM_VGA_H_
#define _LINUX_ASM_VGA_H_

#include <asm/io.h>

extern unsigned char *vgacon_mmap;

static unsigned long VGA_MAP_MEM(unsigned long x)
{
    if( vgacon_mmap == NULL )
    {
        /* This is our first time in this function. This whole thing
           is a rather grim hack. We know we're going to get asked 
           to map a 32KB region between 0xb0000 and 0xb8000 because
           that's what VGAs are. We used the boot time permanent 
           fixed map region, and map it to machine pages.
        */
        if( x != 0xb8000 )
            panic("Argghh! VGA Console is weird. 1:%08lx\n",x);

        vgacon_mmap = (unsigned char*) bt_ioremap( 0xa0000, 128*1024 );
        return (unsigned long) (vgacon_mmap+x-0xa0000);
    }
    else
    {
        if( x != 0xc0000 && x != 0xa0000 ) /* vidmem_end or charmap fonts */
            panic("Argghh! VGA Console is weird. 2:%08lx\n",x);  
	return (unsigned long) (vgacon_mmap+x-0xa0000);
    }
    return 0;
}

static inline unsigned char vga_readb(unsigned char * x) { return (*(x)); }
static inline void vga_writeb(unsigned char x, unsigned char *y) { *(y) = (x); }

#endif
