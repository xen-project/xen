/*
 * xeno_major.h
 *
 * shared definitions for block IO.
 */

/*
 * this belongs in xenolinux/include/linux/major.h except that
 * xen also needs access...
 */


#ifndef __XENO_MAJOR_H__
#define __XENO_MAJOR_H__


#define XLBLK_MAJOR	123                   /* XenoLinux Block Device: xhd */
#define XHDA_MAJOR      123
#define XHDB_MAJOR      124
#define XHDC_MAJOR      125
#define XHDD_MAJOR      126
#define XLSEG_MAJOR     234                 /* XenoLinux Segment Device: vhd */
#define VHDA_MAJOR      234
#define VHDB_MAJOR      235
#define VHDC_MAJOR      236
#define VHDD_MAJOR      237


/*
 * XenoLinux Block Device Tests
 */
#define IS_XHD_MAJOR(M) ( (M) == XHDA_MAJOR || (M) == XHDB_MAJOR || \
                          (M) == XHDC_MAJOR || (M) == XHDD_MAJOR ? 1 : 0)
#define IS_VHD_MAJOR(M) ( (M) == VHDA_MAJOR || (M) == VHDB_MAJOR || \
                          (M) == VHDC_MAJOR || (M) == VHDD_MAJOR ? 1 : 0)

#endif
