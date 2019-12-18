#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Common verification infrastructure for v2 streams
"""

from struct import calcsize, unpack

class StreamError(Exception):
    """Error with the stream"""
    pass

class RecordError(Exception):
    """Error with a record in the stream"""
    pass


class VerifyBase(object):

    def __init__(self, info, read):

        self.info = info
        self.read = read

    def rdexact(self, nr_bytes):
        """Read exactly nr_bytes from the stream"""
        _ = self.read(nr_bytes)
        if len(_) != nr_bytes:
            raise IOError("Stream truncated")
        return _

    def unpack_exact(self, fmt):
        """Unpack a struct format string from the stream"""
        sz = calcsize(fmt)
        return unpack(fmt, self.rdexact(sz))

