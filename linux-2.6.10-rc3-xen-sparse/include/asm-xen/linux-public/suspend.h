/******************************************************************************
 * suspend.h
 * 
 * Copyright (c) 2003-2004, K A Fraser
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __ASM_XEN_SUSPEND_H__
#define __ASM_XEN_SUSPEND_H__

typedef struct suspend_record_st {
    /* To be filled in before resume. */
    start_info_t resume_info;
    /*
     * The number of a machine frame containing, in sequence, the number of
     * each machine frame that contains PFN -> MFN translation table data.
     */
    unsigned long pfn_to_mfn_frame_list;
    /* Number of entries in the PFN -> MFN translation table. */
    unsigned long nr_pfns;
} suspend_record_t;

#endif /* __ASM_XEN_SUSPEND_H__ */
