#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Legacy migration stream information.

Documentation and record structures for legacy migration, for both libxc
and libxl.
"""

"""
Libxc:

SAVE/RESTORE/MIGRATE PROTOCOL
=============================

The general form of a stream of chunks is a header followed by a
body consisting of a variable number of chunks (terminated by a
chunk with type 0) followed by a trailer.

For a rolling/checkpoint (e.g. remus) migration then the body and
trailer phases can be repeated until an external event
(e.g. failure) causes the process to terminate and commit to the
most recent complete checkpoint.

HEADER
------

unsigned long        : p2m_size

extended-info (PV-only, optional):

  If first unsigned long == ~0UL then extended info is present,
  otherwise unsigned long is part of p2m. Note that p2m_size above
  does not include the length of the extended info.

  extended-info:

    unsigned long    : signature == ~0UL
    uint32_t	        : number of bytes remaining in extended-info

    1 or more extended-info blocks of form:
    char[4]          : block identifier
    uint32_t         : block data size
    bytes            : block data

    defined extended-info blocks:
    "vcpu"		: VCPU context info containing vcpu_guest_context_t.
                       The precise variant of the context structure
                       (e.g. 32 vs 64 bit) is distinguished by
                       the block size.
    "extv"           : Presence indicates use of extended VCPU context in
                       tail, data size is 0.

p2m (PV-only):

  consists of p2m_size bytes comprising an array of xen_pfn_t sized entries.

BODY PHASE - Format A (for live migration or Remus without compression)
----------

A series of chunks with a common header:
  int              : chunk type

If the chunk type is +ve then chunk contains guest memory data, and the
type contains the number of pages in the batch:

    unsigned long[]  : PFN array, length == number of pages in batch
                       Each entry consists of XEN_DOMCTL_PFINFO_*
                       in bits 31-28 and the PFN number in bits 27-0.
    page data        : PAGE_SIZE bytes for each page marked present in PFN
                       array

If the chunk type is -ve then chunk consists of one of a number of
metadata types.  See definitions of XC_SAVE_ID_* below.

If chunk type is 0 then body phase is complete.


BODY PHASE - Format B (for Remus with compression)
----------

A series of chunks with a common header:
  int              : chunk type

If the chunk type is +ve then chunk contains array of PFNs corresponding
to guest memory and type contains the number of PFNs in the batch:

    unsigned long[]  : PFN array, length == number of pages in batch
                       Each entry consists of XEN_DOMCTL_PFINFO_*
                       in bits 31-28 and the PFN number in bits 27-0.

If the chunk type is -ve then chunk consists of one of a number of
metadata types.  See definitions of XC_SAVE_ID_* below.

If the chunk type is -ve and equals XC_SAVE_ID_COMPRESSED_DATA, then the
chunk consists of compressed page data, in the following format:

    unsigned long        : Size of the compressed chunk to follow
    compressed data :      variable length data of size indicated above.
                           This chunk consists of compressed page data.
                           The number of pages in one chunk depends on
                           the amount of space available in the sender's
                           output buffer.

Format of compressed data:
  compressed_data = <deltas>*
  delta           = <marker, run*>
  marker          = (RUNFLAG|SKIPFLAG) bitwise-or RUNLEN [1 byte marker]
  RUNFLAG         = 0
  SKIPFLAG        = 1 << 7
  RUNLEN          = 7-bit unsigned value indicating number of WORDS in the run
  run             = string of bytes of length sizeof(WORD) * RUNLEN

   If marker contains RUNFLAG, then RUNLEN * sizeof(WORD) bytes of data following
  the marker is copied into the target page at the appropriate offset indicated by
  the offset_ptr
   If marker contains SKIPFLAG, then the offset_ptr is advanced
  by RUNLEN * sizeof(WORD).

If chunk type is 0 then body phase is complete.

There can be one or more chunks with type XC_SAVE_ID_COMPRESSED_DATA,
containing compressed pages. The compressed chunks are collated to form
one single compressed chunk for the entire iteration. The number of pages
present in this final compressed chunk will be equal to the total number
of valid PFNs specified by the +ve chunks.

At the sender side, compressed pages are inserted into the output stream
in the same order as they would have been if compression logic was absent.

Until last iteration, the BODY is sent in Format A, to maintain live
migration compatibility with receivers of older Xen versions.
At the last iteration, if Remus compression was enabled, the sender sends
a trigger, XC_SAVE_ID_ENABLE_COMPRESSION to tell the receiver to parse the
BODY in Format B from the next iteration onwards.

An example sequence of chunks received in Format B:
    +16                              +ve chunk
    unsigned long[16]                PFN array
    +100                             +ve chunk
    unsigned long[100]               PFN array
    +50                              +ve chunk
    unsigned long[50]                PFN array

    XC_SAVE_ID_COMPRESSED_DATA       TAG
      N                              Length of compressed data
      N bytes of DATA                Decompresses to 166 pages

    XC_SAVE_ID_*                     other xc save chunks
    0                                END BODY TAG

Corner case with checkpoint compression:
    At sender side, after pausing the domain, dirty pages are usually
  copied out to a temporary buffer. After the domain is resumed,
  compression is done and the compressed chunk(s) are sent, followed by
  other XC_SAVE_ID_* chunks.
    If the temporary buffer gets full while scanning for dirty pages,
  the sender stops buffering of dirty pages, compresses the temporary
  buffer and sends the compressed data with XC_SAVE_ID_COMPRESSED_DATA.
  The sender then resumes the buffering of dirty pages and continues
  scanning for the dirty pages.
    For e.g., assume that the temporary buffer can hold 4096 pages and
  there are 5000 dirty pages. The following is the sequence of chunks
  that the receiver will see:

    +1024                       +ve chunk
    unsigned long[1024]         PFN array
    +1024                       +ve chunk
    unsigned long[1024]         PFN array
    +1024                       +ve chunk
    unsigned long[1024]         PFN array
    +1024                       +ve chunk
    unsigned long[1024]         PFN array

    XC_SAVE_ID_COMPRESSED_DATA  TAG
     N                          Length of compressed data
     N bytes of DATA            Decompresses to 4096 pages

    +4                          +ve chunk
    unsigned long[4]            PFN array

    XC_SAVE_ID_COMPRESSED_DATA  TAG
     M                          Length of compressed data
     M bytes of DATA            Decompresses to 4 pages

    XC_SAVE_ID_*                other xc save chunks
    0                           END BODY TAG

    In other words, XC_SAVE_ID_COMPRESSED_DATA can be interleaved with
  +ve chunks arbitrarily. But at the receiver end, the following condition
  always holds true until the end of BODY PHASE:
   num(PFN entries +ve chunks) >= num(pages received in compressed form)

TAIL PHASE
----------

Content differs for PV and HVM guests.

HVM TAIL:

 "Magic" pages:
    uint64_t         : I/O req PFN
    uint64_t         : Buffered I/O req PFN
    uint64_t         : Store PFN
 Xen HVM Context:
    uint32_t         : Length of context in bytes
    bytes            : Context data
 Qemu context:
    char[21]         : Signature:
      "QemuDeviceModelRecord" : Read Qemu save data until EOF
      "DeviceModelRecord0002" : uint32_t length field followed by that many
                                bytes of Qemu save data
      "RemusDeviceModelState" : Currently the same as "DeviceModelRecord0002".

PV TAIL:

 Unmapped PFN list   : list of all the PFNs that were not in map at the close
    unsigned int     : Number of unmapped pages
    unsigned long[]  : PFNs of unmapped pages

 VCPU context data   : A series of VCPU records, one per present VCPU
                       Maximum and present map supplied in XC_SAVE_ID_VCPUINFO
    bytes:           : VCPU context structure. Size is determined by size
                       provided in extended-info header
    bytes[128]       : Extended VCPU context (present IFF "extv" block
                       present in extended-info header)

 Shared Info Page    : 4096 bytes of shared info page
"""

CHUNK_end                       = 0
CHUNK_enable_verify_mode        = -1
CHUNK_vcpu_info                 = -2
CHUNK_hvm_ident_pt              = -3
CHUNK_hvm_vm86_tss              = -4
CHUNK_tmem                      = -5
CHUNK_tmem_extra                = -6
CHUNK_tsc_info                  = -7
CHUNK_hvm_console_pfn           = -8
CHUNK_last_checkpoint           = -9
CHUNK_hvm_acpi_ioports_location = -10
CHUNK_hvm_viridian              = -11
CHUNK_compressed_data           = -12
CHUNK_enable_compression        = -13
CHUNK_hvm_generation_id_addr    = -14
CHUNK_hvm_paging_ring_pfn       = -15
CHUNK_hvm_monitor_ring_pfn      = -16
CHUNK_hvm_sharing_ring_pfn      = -17
CHUNK_toolstack                 = -18
CHUNK_hvm_ioreq_server_pfn      = -19
CHUNK_hvm_nr_ioreq_server_pages = -20

chunk_type_to_str = {
    CHUNK_end                       : "end",
    CHUNK_enable_verify_mode        : "enable_verify_mode",
    CHUNK_vcpu_info                 : "vcpu_info",
    CHUNK_hvm_ident_pt              : "hvm_ident_pt",
    CHUNK_hvm_vm86_tss              : "hvm_vm86_tss",
    CHUNK_tmem                      : "tmem",
    CHUNK_tmem_extra                : "tmem_extra",
    CHUNK_tsc_info                  : "tsc_info",
    CHUNK_hvm_console_pfn           : "hvm_console_pfn",
    CHUNK_last_checkpoint           : "last_checkpoint",
    CHUNK_hvm_acpi_ioports_location : "hvm_acpi_ioports_location",
    CHUNK_hvm_viridian              : "hvm_viridian",
    CHUNK_compressed_data           : "compressed_data",
    CHUNK_enable_compression        : "enable_compression",
    CHUNK_hvm_generation_id_addr    : "hvm_generation_id_addr",
    CHUNK_hvm_paging_ring_pfn       : "hvm_paging_ring_pfn",
    CHUNK_hvm_monitor_ring_pfn      : "hvm_monitor_ring_pfn",
    CHUNK_hvm_sharing_ring_pfn      : "hvm_sharing_ring_pfn",
    CHUNK_toolstack                 : "toolstack",
    CHUNK_hvm_ioreq_server_pfn      : "hvm_ioreq_server_pfn",
    CHUNK_hvm_nr_ioreq_server_pages : "hvm_nr_ioreq_server_pages",
}

# Up to 1024 pages (4MB) at a time
MAX_BATCH = 1024

# Maximum #VCPUs currently supported for save/restore
MAX_VCPU_ID = 4095


"""
Libxl:

Legacy "toolstack" record layout:

Version 1:
  uint32_t version
  QEMU physmap data:
    uint32_t count
    libxl__physmap_info * count

The problem is that libxl__physmap_info was declared as:

struct libxl__physmap_info {
    uint64_t phys_offset;
    uint64_t start_addr;
    uint64_t size;
    uint32_t namelen;
    char name[];
};

Which has 4 bytes of padding at the end in a 64bit build, thus not the
same between 32 and 64bit builds.

Because of the pointer arithmatic used to construct the record, the 'name' was
shifted up to start at the padding, leaving the erronious 4 bytes at the end
of the name string, after the NUL terminator.

Instead, the information described here has been changed to fit in a new
EMULATOR_XENSTORE_DATA record made of NUL terminated strings.
"""
