#ifndef __HYP_IFS_SEGMENT_H__
#define __HYP_IFS_SEGMENT_H__

#define XEN_MAX_SEGMENTS 100     /* total number of segments across all doms */

typedef struct xen_segment_info
{
  int count;
  struct {
    unsigned domain;
    unsigned seg_nr;
    char key[XEN_SEGMENT_KEYSIZE];
    unsigned short device;
  } segments[XEN_MAX_SEGMENTS];
} xen_segment_info_t;

#endif /* __HYP_IFS_SEGMENT_H__ */
