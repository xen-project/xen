#ifndef __HYP_IFS_SEGMENT_H__
#define __HYP_IFS_SEGMENT_H__

#define XEN_MAX_SEGMENTS 100     /* total number of segments across all doms */

#define XEN_SEGMENT_UNUSED 0          /* bzero default */
#define XEN_SEGMENT_RO XEN_DISK_READ_ONLY
#define XEN_SEGMENT_RW XEN_DISK_READ_WRITE

typedef struct xen_segment_info
{
    int count;
    struct {
        unsigned domain;
        unsigned seg_nr;
        char key[XEN_SEGMENT_KEYSIZE];
        unsigned short mode;             /* UNUSED, RO, or RW. */
    } segments[XEN_MAX_SEGMENTS];
} xen_segment_info_t;

#endif /* __HYP_IFS_SEGMENT_H__ */
