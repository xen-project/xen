/******************************************************************************
 * xenguest.h
 * 
 * A library for guest domain management in Xen.
 * 
 * Copyright (c) 2003-2004, K A Fraser.
 */

#ifndef XENBUILD_H
#define XENBUILD_H

#define XCFLAGS_VERBOSE   1
#define XCFLAGS_LIVE      2
#define XCFLAGS_DEBUG     4
#define XCFLAGS_CONFIGURE 8

/**
 * This function will save a domain running Linux.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm fd the file descriptor to save a domain to
 * @parm dom the id of the domain
 * @return 0 on success, -1 on failure
 */
int xc_linux_save(int xc_handle, int fd, uint32_t dom);

/**
 * This function will restore a saved domain running Linux.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm fd the file descriptor to restore a domain from
 * @parm dom the id of the domain
 * @parm nr_pfns the number of pages
 * @parm store_evtchn the store event channel for this domain to use
 * @parm store_mfn returned with the mfn of the store page
 * @return 0 on success, -1 on failure
 */
int xc_linux_restore(int xc_handle, int io_fd, uint32_t dom, unsigned long nr_pfns,
		     unsigned int store_evtchn, unsigned long *store_mfn);

int xc_linux_build(int xc_handle,
                   uint32_t domid,
                   const char *image_name,
                   const char *ramdisk_name,
                   const char *cmdline,
                   unsigned int control_evtchn,
                   unsigned long flags,
                   unsigned int vcpus,
                   unsigned int store_evtchn,
                   unsigned long *store_mfn);

struct mem_map;
int xc_vmx_build(int xc_handle,
                 uint32_t domid,
                 int memsize,
                 const char *image_name,
                 struct mem_map *memmap,
                 const char *ramdisk_name,
                 const char *cmdline,
                 unsigned int control_evtchn,
                 unsigned long flags,
                 unsigned int vcpus,
                 unsigned int store_evtchn,
                 unsigned long *store_mfn);

#endif
