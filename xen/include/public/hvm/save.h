/* 
 * hvm/save.h
 *
 * Structure definitions for HVM state that is held by Xen and must
 * be saved along with the domain's memory and device-model state.
 *
 * 
 * Copyright (c) 2007 XenSource Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef __XEN_PUBLIC_HVM_SAVE_H__
#define __XEN_PUBLIC_HVM_SAVE_H__

/*
 * Structures in this header *must* have the same layout in 32bit 
 * and 64bit environments: this means that all fields must be explicitly 
 * sized types and aligned to their sizes.
 *
 * Only the state necessary for saving and restoring (i.e. fields 
 * that are analogous to actual hardware state) should go in this file. 
 * Internal mechanisms should be kept in Xen-private headers.
 */



/*
 * Processor
 */
#define HVM_SAVE_TYPE_CPU  1
struct hvm_hw_cpu {
    uint64_t eip;
    uint64_t esp;
    uint64_t eflags;
    uint64_t cr0;
    uint64_t cr3;
    uint64_t cr4;

    uint32_t cs_sel;
    uint32_t ds_sel;
    uint32_t es_sel;
    uint32_t fs_sel;
    uint32_t gs_sel;
    uint32_t ss_sel;
    uint32_t tr_sel;
    uint32_t ldtr_sel;

    uint32_t cs_limit;
    uint32_t ds_limit;
    uint32_t es_limit;
    uint32_t fs_limit;
    uint32_t gs_limit;
    uint32_t ss_limit;
    uint32_t tr_limit;
    uint32_t ldtr_limit;
    uint32_t idtr_limit;
    uint32_t gdtr_limit;

    uint64_t cs_base;
    uint64_t ds_base;
    uint64_t es_base;
    uint64_t fs_base;
    uint64_t gs_base;
    uint64_t ss_base;
    uint64_t tr_base;
    uint64_t ldtr_base;
    uint64_t idtr_base;
    uint64_t gdtr_base;


    uint32_t cs_arbytes;
    uint32_t ds_arbytes;
    uint32_t es_arbytes;
    uint32_t fs_arbytes;
    uint32_t gs_arbytes;
    uint32_t ss_arbytes;
    uint32_t tr_arbytes;
    uint32_t ldtr_arbytes;

    uint32_t sysenter_cs;
    uint32_t padding0;

    uint64_t sysenter_esp;
    uint64_t sysenter_eip;

    /* msr for em64t */
    uint64_t shadow_gs;
    uint64_t flags;

    /* same size as VMX_MSR_COUNT */
    uint64_t msr_items[6];
    uint64_t vmxassist_enabled;

    /* guest's idea of what rdtsc() would return */
    uint64_t tsc;
};


/* 
 *  PIT
 */
#define HVM_SAVE_TYPE_PIT 2
struct hvm_hw_pit {
    struct hvm_hw_pit_channel {
        int64_t count_load_time;
        uint32_t count; /* can be 65536 */
        uint16_t latched_count;
        uint8_t count_latched;
        uint8_t status_latched;
        uint8_t status;
        uint8_t read_state;
        uint8_t write_state;
        uint8_t write_latch;
        uint8_t rw_mode;
        uint8_t mode;
        uint8_t bcd; /* not supported */
        uint8_t gate; /* timer start */
    } channels[3];  /* 3 x 24 bytes */
    uint32_t speaker_data_on;
};



#endif /* __XEN_PUBLIC_HVM_SAVE_H__ */
