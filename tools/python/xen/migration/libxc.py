#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Libxc Migration v2 streams

Record structures as per docs/specs/libxc-migration-stream.pandoc, and
verification routines.
"""

import sys

from struct import calcsize, unpack

from xen.migration.verify import StreamError, RecordError, VerifyBase

# Image Header
IHDR_FORMAT = "!QIIHHI"

IHDR_MARKER  = 0xffffffffffffffff
IHDR_IDENT   = 0x58454E46 # "XENF" in ASCII

IHDR_OPT_BIT_ENDIAN = 0
IHDR_OPT_LE = (0 << IHDR_OPT_BIT_ENDIAN)
IHDR_OPT_BE = (1 << IHDR_OPT_BIT_ENDIAN)

IHDR_OPT_RESZ_MASK = 0xfffe

# Domain Header
DHDR_FORMAT = "IHHII"

DHDR_TYPE_x86_pv  = 0x00000001
DHDR_TYPE_x86_hvm = 0x00000002

dhdr_type_to_str = {
    DHDR_TYPE_x86_pv  : "x86 PV",
    DHDR_TYPE_x86_hvm : "x86 HVM",
}

# Records
RH_FORMAT = "II"

REC_TYPE_end                        = 0x00000000
REC_TYPE_page_data                  = 0x00000001
REC_TYPE_x86_pv_info                = 0x00000002
REC_TYPE_x86_pv_p2m_frames          = 0x00000003
REC_TYPE_x86_pv_vcpu_basic          = 0x00000004
REC_TYPE_x86_pv_vcpu_extended       = 0x00000005
REC_TYPE_x86_pv_vcpu_xsave          = 0x00000006
REC_TYPE_shared_info                = 0x00000007
REC_TYPE_tsc_info                   = 0x00000008
REC_TYPE_hvm_context                = 0x00000009
REC_TYPE_hvm_params                 = 0x0000000a
REC_TYPE_toolstack                  = 0x0000000b
REC_TYPE_x86_pv_vcpu_msrs           = 0x0000000c
REC_TYPE_verify                     = 0x0000000d
REC_TYPE_checkpoint                 = 0x0000000e
REC_TYPE_checkpoint_dirty_pfn_list  = 0x0000000f

rec_type_to_str = {
    REC_TYPE_end                        : "End",
    REC_TYPE_page_data                  : "Page data",
    REC_TYPE_x86_pv_info                : "x86 PV info",
    REC_TYPE_x86_pv_p2m_frames          : "x86 PV P2M frames",
    REC_TYPE_x86_pv_vcpu_basic          : "x86 PV vcpu basic",
    REC_TYPE_x86_pv_vcpu_extended       : "x86 PV vcpu extended",
    REC_TYPE_x86_pv_vcpu_xsave          : "x86 PV vcpu xsave",
    REC_TYPE_shared_info                : "Shared info",
    REC_TYPE_tsc_info                   : "TSC info",
    REC_TYPE_hvm_context                : "HVM context",
    REC_TYPE_hvm_params                 : "HVM params",
    REC_TYPE_toolstack                  : "Toolstack",
    REC_TYPE_x86_pv_vcpu_msrs           : "x86 PV vcpu msrs",
    REC_TYPE_verify                     : "Verify",
    REC_TYPE_checkpoint                 : "Checkpoint",
    REC_TYPE_checkpoint_dirty_pfn_list  : "Checkpoint dirty pfn list",
}

# page_data
PAGE_DATA_FORMAT             = "II"
PAGE_DATA_PFN_MASK           = (1 << 52) - 1
PAGE_DATA_PFN_RESZ_MASK      = ((1 << 60) - 1) & ~((1 << 52) - 1)

# flags from xen/public/domctl.h: XEN_DOMCTL_PFINFO_* shifted by 32 bits
PAGE_DATA_TYPE_SHIFT         = 60
PAGE_DATA_TYPE_LTABTYPE_MASK = (0x7 << PAGE_DATA_TYPE_SHIFT)
PAGE_DATA_TYPE_LTAB_MASK     = (0xf << PAGE_DATA_TYPE_SHIFT)
PAGE_DATA_TYPE_LPINTAB       = (0x8 << PAGE_DATA_TYPE_SHIFT) # Pinned pagetable

PAGE_DATA_TYPE_NOTAB         = (0x0 << PAGE_DATA_TYPE_SHIFT) # Regular page
PAGE_DATA_TYPE_L1TAB         = (0x1 << PAGE_DATA_TYPE_SHIFT) # L1 pagetable
PAGE_DATA_TYPE_L2TAB         = (0x2 << PAGE_DATA_TYPE_SHIFT) # L2 pagetable
PAGE_DATA_TYPE_L3TAB         = (0x3 << PAGE_DATA_TYPE_SHIFT) # L3 pagetable
PAGE_DATA_TYPE_L4TAB         = (0x4 << PAGE_DATA_TYPE_SHIFT) # L4 pagetable
PAGE_DATA_TYPE_BROKEN        = (0xd << PAGE_DATA_TYPE_SHIFT) # Broken
PAGE_DATA_TYPE_XALLOC        = (0xe << PAGE_DATA_TYPE_SHIFT) # Allocate-only
PAGE_DATA_TYPE_XTAB          = (0xf << PAGE_DATA_TYPE_SHIFT) # Invalid

# x86_pv_info
X86_PV_INFO_FORMAT        = "BBHI"

X86_PV_P2M_FRAMES_FORMAT  = "II"

# x86_pv_vcpu_{basic,extended,xsave,msrs}
X86_PV_VCPU_HDR_FORMAT    = "II"

# x86_tsc_info
X86_TSC_INFO_FORMAT       = "IIQII"

# hvm_params
HVM_PARAMS_ENTRY_FORMAT   = "QQ"
HVM_PARAMS_FORMAT         = "II"

class VerifyLibxc(VerifyBase):
    """ Verify a Libxc v2 (or later) stream """

    def __init__(self, info, read):
        VerifyBase.__init__(self, info, read)

        self.squashed_pagedata_records = 0


    def verify(self):
        """ Verity a libxc stream """

        self.verify_ihdr()
        self.verify_dhdr()

        while self.verify_record() != REC_TYPE_end:
            pass


    def verify_ihdr(self):
        """ Verify an Image Header """
        marker, ident, version, options, res1, res2 = \
            self.unpack_exact(IHDR_FORMAT)

        if marker != IHDR_MARKER:
            raise StreamError("Bad image marker: Expected 0x%x, got 0x%x" %
                              (IHDR_MARKER, marker))

        if ident != IHDR_IDENT:
            raise StreamError("Bad image id: Expected 0x%x, got 0x%x" %
                              (IHDR_IDENT, ident))

        if version != 2:
            raise StreamError("Unknown image version: Expected 2, got %d" %
                              (version, ))

        if options & IHDR_OPT_RESZ_MASK:
            raise StreamError("Reserved bits set in image options field: 0x%x" %
                              (options & IHDR_OPT_RESZ_MASK))

        if res1 != 0 or res2 != 0:
            raise StreamError(
                "Reserved bits set in image header: 0x%04x:0x%08x" %
                (res1, res2))

        if ( (sys.byteorder == "little") and
             ((options & IHDR_OPT_BIT_ENDIAN) != IHDR_OPT_LE) ):
            raise StreamError(
                "Stream is not native endianess - unable to validate")

        endian = ["little", "big"][options & IHDR_OPT_LE]
        self.info("Libxc Image Header: %s endian" % (endian, ))


    def verify_dhdr(self):
        """ Verify a domain header """

        gtype, page_shift, res1, major, minor = \
            self.unpack_exact(DHDR_FORMAT)

        if gtype not in dhdr_type_to_str:
            raise StreamError("Unrecognised domain type 0x%x" % (gtype, ))

        if res1 != 0:
            raise StreamError("Reserved bits set in domain header 0x%04x" %
                              (res1, ))

        if page_shift != 12:
            raise StreamError("Page shift expected to be 12.  Got %d" %
                              (page_shift, ))

        if major == 0:
            self.info("Domain Header: legacy converted %s" %
                      (dhdr_type_to_str[gtype], ))
        else:
            self.info("Domain Header: %s from Xen %d.%d" %
                      (dhdr_type_to_str[gtype], major, minor))


    def verify_record(self):
        """ Verify an individual record """

        rtype, length = self.unpack_exact(RH_FORMAT)

        if rtype not in rec_type_to_str:
            raise StreamError("Unrecognised record type 0x%x" % (rtype, ))

        contentsz = (length + 7) & ~7
        content = self.rdexact(contentsz)

        if rtype != REC_TYPE_page_data:

            if self.squashed_pagedata_records > 0:
                self.info("Squashed %d Page Data records together" %
                          (self.squashed_pagedata_records, ))
                self.squashed_pagedata_records = 0

            self.info("Libxc Record: %s, length %d" %
                      (rec_type_to_str[rtype], length))

        else:
            self.squashed_pagedata_records += 1

        padding = content[length:]
        if padding != b"\x00" * len(padding):
            raise StreamError("Padding containing non0 bytes found")

        if rtype not in record_verifiers:
            raise RuntimeError(
                "No verification function for libxc record '%s'" %
                rec_type_to_str[rtype])
        else:
            record_verifiers[rtype](self, content[:length])

        return rtype


    def verify_record_end(self, content):
        """ End record """

        if len(content) != 0:
            raise RecordError("End record with non-zero length")


    def verify_record_page_data(self, content):
        """ Page Data record """
        minsz = calcsize(PAGE_DATA_FORMAT)

        if len(content) <= minsz:
            raise RecordError(
                "PAGE_DATA record must be at least %d bytes long" % (minsz, ))

        count, res1 = unpack(PAGE_DATA_FORMAT, content[:minsz])

        if res1 != 0:
            raise StreamError(
                "Reserved bits set in PAGE_DATA record 0x%04x" % (res1, ))

        pfnsz = count * 8
        if (len(content) - minsz) < pfnsz:
            raise RecordError(
                "PAGE_DATA record must contain a pfn record for each count")

        pfns = list(unpack("=%dQ" % (count, ), content[minsz:minsz + pfnsz]))

        nr_pages = 0
        for idx, pfn in enumerate(pfns):

            if pfn & PAGE_DATA_PFN_RESZ_MASK:
                raise RecordError("Reserved bits set in pfn[%d]: 0x%016x" %
                                  (idx, pfn & PAGE_DATA_PFN_RESZ_MASK))

            if pfn >> PAGE_DATA_TYPE_SHIFT in (5, 6, 7, 8):
                raise RecordError("Invalid type value in pfn[%d]: 0x%016x" %
                                  (idx, pfn & PAGE_DATA_TYPE_LTAB_MASK))

            # We expect page data for each normal page or pagetable
            if PAGE_DATA_TYPE_NOTAB <= (pfn & PAGE_DATA_TYPE_LTABTYPE_MASK) \
                    <= PAGE_DATA_TYPE_L4TAB:
                nr_pages += 1

        pagesz = nr_pages * 4096
        if len(content) != minsz + pfnsz + pagesz:
            raise RecordError("Expected %u + %u + %u, got %u" %
                              (minsz, pfnsz, pagesz, len(content)))


    def verify_record_x86_pv_info(self, content):
        """ x86 PV Info record """

        expectedsz = calcsize(X86_PV_INFO_FORMAT)
        if len(content) != expectedsz:
            raise RecordError("x86_pv_info: expected length of %d, got %d" %
                              (expectedsz, len(content)))

        width, levels, res1, res2 = unpack(X86_PV_INFO_FORMAT, content)

        if width not in (4, 8):
            raise RecordError("Expected width of 4 or 8, got %d" % (width, ))

        if levels not in (3, 4):
            raise RecordError("Expected levels of 3 or 4, got %d" % (levels, ))

        if res1 != 0 or res2 != 0:
            raise StreamError(
                "Reserved bits set in X86_PV_INFO: 0x%04x 0x%08x" %
                (res1, res2))

        bitness = {4:32, 8:64}[width]
        self.info("  %sbit guest, %d levels of pagetables" % (bitness, levels))


    def verify_record_x86_pv_p2m_frames(self, content):
        """ x86 PV p2m frames record """

        if len(content) < 8:
            raise RecordError("x86_pv_p2m_frames: record length must be at"
                              " least 8 bytes long")

        if len(content) % 8 != 0:
            raise RecordError("Length expected to be a multiple of 8, not %d" %
                              (len(content), ))

        start, end = unpack("=II", content[:8])
        self.info("  Start pfn 0x%x, End 0x%x" % (start, end))


    def verify_record_x86_pv_vcpu_generic(self, content, name):
        """ Generic for all REC_TYPE_x86_pv_vcpu_{basic,extended,xsave,msrs} """
        minsz = calcsize(X86_PV_VCPU_HDR_FORMAT)

        if len(content) < minsz:
            raise RecordError(
                "X86_PV_VCPU_%s record length must be at least %d bytes long" %
                (name, minsz))

        if len(content) == minsz:
            self.info("Warning: X86_PV_VCPU_%s record with zero content" %
                      (name, ))

        vcpuid, res1 = unpack(X86_PV_VCPU_HDR_FORMAT, content[:minsz])

        if res1 != 0:
            raise StreamError(
                "Reserved bits set in x86_pv_vcpu_%s record 0x%04x" %
                (name, res1))

        self.info("  vcpu%d %s context, %d bytes" %
                  (vcpuid, name, len(content) - minsz))


    def verify_record_shared_info(self, content):
        """ shared info record """

        contentsz = len(content)
        if contentsz != 4096:
            raise RecordError("Length expected to be 4906 bytes, not %d" %
                              (contentsz, ))


    def verify_record_tsc_info(self, content):
        """ tsc info record """

        sz = calcsize(X86_TSC_INFO_FORMAT)

        if len(content) != sz:
            raise RecordError("Length should be %u bytes" % (sz, ))

        mode, khz, nsec, incarn, res1 = unpack(X86_TSC_INFO_FORMAT, content)

        if res1 != 0:
            raise StreamError("Reserved bits set in X86_TSC_INFO: 0x%08x" %
                              (res1, ))

        self.info("  Mode %u, %u kHz, %u ns, incarnation %d" %
                  (mode, khz, nsec, incarn))


    def verify_record_hvm_context(self, content):
        """ hvm context record """

        if len(content) == 0:
            raise RecordError("Zero length HVM context")


    def verify_record_hvm_params(self, content):
        """ hvm params record """

        sz = calcsize(HVM_PARAMS_FORMAT)

        if len(content) < sz:
            raise RecordError("Length should be at least %u bytes" % (sz, ))

        count, rsvd = unpack(HVM_PARAMS_FORMAT, content[:sz])

        if rsvd != 0:
            raise RecordError("Reserved field not zero (0x%04x)" % (rsvd, ))

        if count == 0:
            self.info("Warning: HVM_PARAMS record with zero content")

        sz += count * calcsize(HVM_PARAMS_ENTRY_FORMAT)

        if len(content) != sz:
            raise RecordError("Length should be %u bytes" % (sz, ))


    def verify_record_toolstack(self, _):
        """ toolstack record """
        raise DeprecationWarning("Found Toolstack record in stream")


    def verify_record_verify(self, content):
        """ verify record """

        if len(content) != 0:
            raise RecordError("Verify record with non-zero length")


    def verify_record_checkpoint(self, content):
        """ checkpoint record """

        if len(content) != 0:
            raise RecordError("Checkpoint record with non-zero length")


    def verify_record_checkpoint_dirty_pfn_list(self, content):
        """ checkpoint dirty pfn list """
        raise RecordError("Found checkpoint dirty pfn list record in stream")


record_verifiers = {
    REC_TYPE_end:
        VerifyLibxc.verify_record_end,
    REC_TYPE_page_data:
        VerifyLibxc.verify_record_page_data,

    REC_TYPE_x86_pv_info:
        VerifyLibxc.verify_record_x86_pv_info,
    REC_TYPE_x86_pv_p2m_frames:
        VerifyLibxc.verify_record_x86_pv_p2m_frames,

    REC_TYPE_x86_pv_vcpu_basic:
        lambda s, x:
        VerifyLibxc.verify_record_x86_pv_vcpu_generic(s, x, "basic"),
    REC_TYPE_x86_pv_vcpu_extended:
        lambda s, x:
        VerifyLibxc.verify_record_x86_pv_vcpu_generic(s, x, "extended"),
    REC_TYPE_x86_pv_vcpu_xsave:
        lambda s, x:
        VerifyLibxc.verify_record_x86_pv_vcpu_generic(s, x, "xsave"),
    REC_TYPE_x86_pv_vcpu_msrs:
        lambda s, x:
        VerifyLibxc.verify_record_x86_pv_vcpu_generic(s, x, "msrs"),

    REC_TYPE_shared_info:
        VerifyLibxc.verify_record_shared_info,
    REC_TYPE_tsc_info:
        VerifyLibxc.verify_record_tsc_info,

    REC_TYPE_hvm_context:
        VerifyLibxc.verify_record_hvm_context,
    REC_TYPE_hvm_params:
        VerifyLibxc.verify_record_hvm_params,
    REC_TYPE_toolstack:
        VerifyLibxc.verify_record_toolstack,
    REC_TYPE_verify:
        VerifyLibxc.verify_record_verify,
    REC_TYPE_checkpoint:
        VerifyLibxc.verify_record_checkpoint,
    REC_TYPE_checkpoint_dirty_pfn_list:
        VerifyLibxc.verify_record_checkpoint_dirty_pfn_list,
    }
