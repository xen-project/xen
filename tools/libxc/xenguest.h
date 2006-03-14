/******************************************************************************
 * xenguest.h
 * 
 * A library for guest domain management in Xen.
 * 
 * Copyright (c) 2003-2004, K A Fraser.
 */

#ifndef XENGUEST_H
#define XENGUEST_H

#define XCFLAGS_LIVE      1
#define XCFLAGS_DEBUG     2


/**
 * This function will save a domain running Linux.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm fd the file descriptor to save a domain to
 * @parm dom the id of the domain
 * @return 0 on success, -1 on failure
 */
int xc_linux_save(int xc_handle, int io_fd, uint32_t dom, uint32_t max_iters, 
                  uint32_t max_factor, uint32_t flags /* XCFLAGS_xxx */,
                  int (*suspend)(int domid));


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
int xc_linux_restore(int xc_handle, int io_fd, uint32_t dom, 
                     unsigned long nr_pfns, unsigned int store_evtchn, 
                     unsigned long *store_mfn, unsigned int console_evtchn,
                     unsigned long *console_mfn);

/**
 * This function will create a domain for a paravirtualized Linux
 * using file names pointing to kernel and ramdisk
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm domid the id of the domain
 * @param image_name name of the kernel image file
 * @param ramdisk_name name of the ramdisk image file
 * @parm cmdline command line string
 * @parm flags domain creation flags
 * @parm store_evtchn the store event channel for this domain to use
 * @parm store_mfn returned with the mfn of the store page
 * @parm console_evtchn the console event channel for this domain to use
 * @parm conole_mfn returned with the mfn of the console page
 * @return 0 on success, -1 on failure
 */
int xc_linux_build(int xc_handle,
                   uint32_t domid,
                   const char *image_name,
                   const char *ramdisk_name,
                   const char *cmdline,
                   const char *features,
                   unsigned long flags,
                   unsigned int store_evtchn,
                   unsigned long *store_mfn,
                   unsigned int console_evtchn,
                   unsigned long *console_mfn);

/**
 * This function will create a domain for a paravirtualized Linux
 * using buffers for kernel and initrd
 *
 * @param xc_handle a handle to an open hypervisor interface
 * @param domid the id of the domain
 * @param image_buffer buffer containing kernel image
 * @param image_size size of the kernel image buffer
 * @param initrd_buffer name of the ramdisk image file
 * @param initrd_size size of the ramdisk buffer
 * @param cmdline command line string
 * @param flags domain creation flags
 * @param store_evtchn the store event channel for this domain to use
 * @param store_mfn returned with the mfn of the store page
 * @param console_evtchn the console event channel for this domain to use
 * @param conole_mfn returned with the mfn of the console page
 * @return 0 on success, -1 on failure
 */
int xc_linux_build_mem(int xc_handle,
                       uint32_t domid,
                       const char *image_buffer,
                       unsigned long image_size,
                       const char *initrd_buffer,
                       unsigned long initrd_size,
                       const char *cmdline,
                       const char *features,
                       unsigned long flags,
                       unsigned int store_evtchn,
                       unsigned long *store_mfn,
                       unsigned int console_evtchn,
                       unsigned long *console_mfn);

int xc_hvm_build(int xc_handle,
                 uint32_t domid,
                 int memsize,
                 const char *image_name,
                 unsigned int vcpus,
                 unsigned int pae,
                 unsigned int acpi,
                 unsigned int apic,
                 unsigned int store_evtchn,
                 unsigned long *store_mfn);

int xc_hvm_build_mem(int xc_handle,
                     uint32_t domid,
                     int memsize,
                     const char *image_buffer,
                     unsigned long image_size,
                     unsigned int vcpus,
                     unsigned int pae,
                     unsigned int acpi,
                     unsigned int apic,
                     unsigned int store_evtchn,
                     unsigned long *store_mfn);

#endif /* XENGUEST_H */
