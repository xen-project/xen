/******************************************************************************
 * suspend.h
 * 
 * NB. This file is part of the Xenolinux interface with Xenoserver control 
 * software. It can be included in such software without invoking the GPL.
 * 
 * Copyright (c) 2003, K A Fraser
 */

#ifndef __ASM_XEN_SUSPEND_H__
#define __ASM_XEN_SUSPEND_H__

typedef struct suspend_record_st {
    /* To be filled in before resume. */
    extended_start_info_t resume_info;
    /*
     * The number of a machine frame containing, in sequence, the number of
     * each machine frame that contains PFN -> MFN translation table data.
     */
    unsigned long pfn_to_mfn_frame_list;
    /* Number of entries in the PFN -> MFN translation table. */
    unsigned long nr_pfns;
} suspend_record_t;

#endif /* __ASM_XEN_SUSPEND_H__ */
