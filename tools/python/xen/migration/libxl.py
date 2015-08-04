#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Libxl Migration v2 streams

Record structures as per docs/specs/libxl-migration-stream.pandoc, and
verification routines.
"""

import sys

from struct import calcsize, unpack, unpack_from
from xen.migration.verify import StreamError, RecordError, VerifyBase
from xen.migration.libxc import VerifyLibxc

# Header
HDR_FORMAT = "!QII"

HDR_IDENT = 0x4c6962786c466d74 # "LibxlFmt" in ASCII
HDR_VERSION = 2

HDR_OPT_BIT_ENDIAN = 0
HDR_OPT_BIT_LEGACY = 1

HDR_OPT_LE     = (0 << HDR_OPT_BIT_ENDIAN)
HDR_OPT_BE     = (1 << HDR_OPT_BIT_ENDIAN)
HDR_OPT_LEGACY = (1 << HDR_OPT_BIT_LEGACY)

HDR_OPT_RESZ_MASK = 0xfffc

# Records
RH_FORMAT = "II"

REC_TYPE_end                    = 0x00000000
REC_TYPE_libxc_context          = 0x00000001
REC_TYPE_emulator_xenstore_data = 0x00000002
REC_TYPE_emulator_context       = 0x00000003
REC_TYPE_checkpoint_end         = 0x00000004

rec_type_to_str = {
    REC_TYPE_end                    : "End",
    REC_TYPE_libxc_context          : "Libxc context",
    REC_TYPE_emulator_xenstore_data : "Emulator xenstore data",
    REC_TYPE_emulator_context       : "Emulator context",
    REC_TYPE_checkpoint_end         : "Checkpoint end",
}

# emulator_* header
EMULATOR_HEADER_FORMAT = "II"

EMULATOR_ID_unknown       = 0x00000000
EMULATOR_ID_qemu_trad     = 0x00000001
EMULATOR_ID_qemu_upstream = 0x00000002

emulator_id_to_str = {
    EMULATOR_ID_unknown       : "Unknown",
    EMULATOR_ID_qemu_trad     : "Qemu Traditional",
    EMULATOR_ID_qemu_upstream : "Qemu Upstream",
}


#
# libxl format
#

LIBXL_QEMU_SIGNATURE = "DeviceModelRecord0002"
LIBXL_QEMU_RECORD_HDR = "=%dsI" % (len(LIBXL_QEMU_SIGNATURE), )

class VerifyLibxl(VerifyBase):
    """ Verify a Libxl v2 stream """

    def __init__(self, info, read):
        VerifyBase.__init__(self, info, read)


    def verify(self):
        """ Verity a libxl stream """

        self.verify_hdr()

        while self.verify_record() != REC_TYPE_end:
            pass


    def verify_hdr(self):
        """ Verify a Header """
        ident, version, options = self.unpack_exact(HDR_FORMAT)

        if ident != HDR_IDENT:
            raise StreamError("Bad image id: Expected 0x%x, got 0x%x"
                              % (HDR_IDENT, ident))

        if version != HDR_VERSION:
            raise StreamError("Unknown image version: Expected %d, got %d"
                              % (HDR_VERSION, version))

        if options & HDR_OPT_RESZ_MASK:
            raise StreamError("Reserved bits set in image options field: 0x%x"
                              % (options & HDR_OPT_RESZ_MASK))

        if ( (sys.byteorder == "little") and
             ((options & HDR_OPT_BIT_ENDIAN) != HDR_OPT_LE) ):
            raise StreamError(
                "Stream is not native endianess - unable to validate")

        endian = ["little", "big"][options & HDR_OPT_LE]

        if options & HDR_OPT_LEGACY:
            self.info("Libxl Header: %s endian, legacy converted" % (endian, ))
        else:
            self.info("Libxl Header: %s endian" % (endian, ))


    def verify_record(self):
        """ Verify an individual record """
        rtype, length = self.unpack_exact(RH_FORMAT)

        if rtype not in rec_type_to_str:
            raise StreamError("Unrecognised record type %x" % (rtype, ))

        self.info("Libxl Record: %s, length %d"
                  % (rec_type_to_str[rtype], length))

        contentsz = (length + 7) & ~7
        content = self.rdexact(contentsz)

        padding = content[length:]
        if padding != "\x00" * len(padding):
            raise StreamError("Padding containing non0 bytes found")

        if rtype not in record_verifiers:
            raise RuntimeError("No verification function for libxl record '%s'"
                               % rec_type_to_str[rtype])
        else:
            record_verifiers[rtype](self, content[:length])

        return rtype


    def verify_record_end(self, content):
        """ End record """

        if len(content) != 0:
            raise RecordError("End record with non-zero length")


    def verify_record_libxc_context(self, content):
        """ Libxc context record """

        if len(content) != 0:
            raise RecordError("Libxc context record with non-zero length")

        # Verify the libxc stream, as we can't seek forwards through it
        VerifyLibxc(self.info, self.read).verify()


    def verify_record_emulator_xenstore_data(self, content):
        """ Emulator Xenstore Data record """
        minsz = calcsize(EMULATOR_HEADER_FORMAT)

        if len(content) < minsz:
            raise RecordError("Length must be at least %d bytes, got %d"
                              % (minsz, len(content)))

        emu_id, emu_idx = unpack(EMULATOR_HEADER_FORMAT, content[:minsz])

        if emu_id not in emulator_id_to_str:
            raise RecordError("Unrecognised emulator id 0x%x" % (emu_id, ))

        self.info("Emulator Xenstore Data (%s, idx %d)"
                  % (emulator_id_to_str[emu_id], emu_idx))

        # Chop off the emulator header
        content = content[minsz:]

        if len(content):

            if content[-1] != '\x00':
                raise RecordError("Data not NUL terminated")

            # Split without the final NUL, to get an even number of parts
            parts = content[:-1].split("\x00")

            if (len(parts) % 2) != 0:
                raise RecordError("Expected an even number of strings, got %d"
                                  % (len(parts), ))

            for key, val in zip(parts[0::2], parts[1::2]):
                self.info("  '%s' = '%s'" % (key, val))


    def verify_record_emulator_context(self, content):
        """ Emulator Context record """
        minsz = calcsize(EMULATOR_HEADER_FORMAT)

        if len(content) < minsz:
            raise RecordError("Length must be at least %d bytes, got %d"
                              % (minsz, len(content)))

        emu_id, emu_idx = unpack(EMULATOR_HEADER_FORMAT, content[:minsz])

        if emu_id not in emulator_id_to_str:
            raise RecordError("Unrecognised emulator id 0x%x" % (emu_id, ))

        self.info("  Index %d, type %s" % (emu_idx, emulator_id_to_str[emu_id]))


    def verify_record_checkpoint_end(self, content):
        """ Checkpoint end record """

        if len(content) != 0:
            raise RecordError("Checkpoint end record with non-zero length")


record_verifiers = {
    REC_TYPE_end:
        VerifyLibxl.verify_record_end,
    REC_TYPE_libxc_context:
        VerifyLibxl.verify_record_libxc_context,
    REC_TYPE_emulator_xenstore_data:
        VerifyLibxl.verify_record_emulator_xenstore_data,
    REC_TYPE_emulator_context:
        VerifyLibxl.verify_record_emulator_context,
    REC_TYPE_checkpoint_end:
        VerifyLibxl.verify_record_checkpoint_end,
}
