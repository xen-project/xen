#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2009 flonatel GmbH & Co. KG
#============================================================================

import logging
import os
import base64
import tempfile
import stat
from xen.xend.XendLogging import log
from xen.util import mkdir
# The following are needed for unit-testing only
import unittest

#
# This functions and classes can be used where a filename is expected -
# especially in the xenapi.VM.create() for PV_kernel and PV_ramdisk.
#
# The functions have a backward compatibility mode, i.e. when there is
# no appropriate scheme detected, the data is seens as a path to a
# (local) file.
#

class scheme_error(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

# Data scheme (as defined in RFC 2397):
#  data:application/octet-stream;base64,<base64 encoded data>
# It looks that there is currently no general purpose implementation
# available (in python) for this URL scheme - so the very basic is
# done here.
#
# Limitations
# o Only base64 is currently supported
class scheme_data:

    def encode(data, mediatype = 'application/octet-stream', 
               encoding = 'base64'):
        # XXX Limit this to base64 for current implementation
        if encoding!='base64':
            raise scheme_error("invalid encoding")
        return 'data:' + mediatype + ";" + encoding \
            + "," + base64.b64encode(data)
    encode = staticmethod(encode)

    # Private method: parse encoded data
    def parse(encoded_data):
        if not isinstance(encoded_data, str):
            raise scheme_error("encoded data has wrong type")
        if not encoded_data.startswith('data:'):
            raise scheme_error("'data:' scheme declaration missing")
        comma = encoded_data.find(',', 5)
        if comma == -1:
            raise scheme_error("data separator (comma) is missing")
        # Cut off the media type and encoding
        mtenc = encoded_data[5:comma]
        if len(mtenc)==0:
            raise scheme_error("encoding is empty")
        # XXX Limit to base64 encoding
        if not mtenc.endswith(';base64'):
            raise scheme_error("encoding is not base64")
        mediatype = mtenc[:-7]
        return (mediatype, 'base64', comma+1)
    parse = staticmethod(parse)

    # Stores the data in a local file and returns the filename
    # and a flag if this file in temporary only and must be deleted
    # after starting the VM.
    def decode(encoded_data):
        mkdir.parents("/var/run/xend/boot/", stat.S_IRWXU)
        mediatype, encoding, data_start = scheme_data.parse(encoded_data)
        fd, filename = tempfile.mkstemp(
            prefix="data_uri_file.", dir="/var/run/xend/boot")
        os.write(fd, base64.b64decode(encoded_data[data_start:]))
        os.close(fd)
        return filename, True
    decode = staticmethod(decode)

    # Utility function which reads in the given (local) file and
    # creates a data scheme from this.
    def create_from_file(filename):
        try:
            f = open(filename, "r")
            d = f.read()
            f.close()
            return scheme_data.encode(d)
        except IOError:
            raise scheme_error("file does not exists")
    create_from_file = staticmethod(create_from_file)

class scheme_data_unit_tests(unittest.TestCase):

    def check_basic_encoding(self):
        "scheme_data - basic encoding"
        sd = scheme_data.encode('Hello!')
        self.assertEqual(sd, 'data:application/octet-stream;base64,SGVsbG8h')

    def check_encoding_with_given_mediatype(self):
        "scheme_data - encoding with given media name"
        sd = scheme_data.encode('Hello!', 'application/x-my-linux-kernel')
        self.assertEqual(sd,
              'data:application/x-my-linux-kernel;base64,SGVsbG8h')

    def check_parse_01(self):
        "scheme_data - parsing of None"
        self.assertRaises(scheme_error, scheme_data.parse, None)

    def check_parse_02(self):
        "scheme_data - parsing of empty string"
        self.assertRaises(scheme_error, scheme_data.parse, "")

    def check_parse_03(self):
        "scheme_data - parsing of unstructured data"
        self.assertRaises(scheme_error, scheme_data.parse, "akskdjdfhezezu")

    def check_parse_04(self):
        "scheme_data - data: is not at the first place"
        self.assertRaises(scheme_error, scheme_data.parse, 'ggdata:sossm')

    def check_parse_05(self):
        "scheme_data - no comma in data"
        self.assertRaises(scheme_error, scheme_data.parse, 'data:sossm')

    def check_parse_06(self):
        "scheme_data - encoding is empty"
        self.assertRaises(scheme_error, scheme_data.parse, 'data:,')

    def check_parse_07(self):
        "scheme_data - unknown encoding"
        self.assertRaises(scheme_error, scheme_data.parse,
                          'data:somemediatype;unknown,')

    def check_parse_08(self):
        "scheme_data - parse ok - empty data"
        mediatype, encoding, data_start = scheme_data.parse(
            'data:somemedia;base64,')
        self.assertEqual(mediatype, 'somemedia')
        self.assertEqual(encoding, 'base64')
        self.assertEqual(data_start, 22)

    def check_parse_09(self):
        "scheme_data - parse ok - some data"
        mediatype, encoding, data_start = scheme_data.parse(
            'data:somemedia;base64,HereComesTheSun')
        self.assertEqual(mediatype, 'somemedia')
        self.assertEqual(encoding, 'base64')
        self.assertEqual(data_start, 22)

    def check_cff_file_does_not_exist(self):
        "scheme_data - create from file - non existent file"
        self.assertRaises(scheme_error, scheme_data.create_from_file,
                          "/there/is/hopefully/no/file/like/this")

    def check_cff_ok(self):
        "scheme_data - create from file - ok"
        tmppath = "/tmp/scheme_data_check_cff_ok"
        f = open(tmppath, "w")
        f.write("huhuhu")
        f.close()
        d = scheme_data.create_from_file(tmppath)
        os.unlink(tmppath)
        self.assertEqual(d, "data:application/octet-stream;base64,aHVodWh1")

# File Scheme
# This class supports absolut paths only.
class scheme_file:

    def encode(filename):
        if len(filename) == 0:
            raise scheme_error("filename is empty")
        if filename[0] != '/':
            raise scheme_error("filename is not absolut")
        return 'file://' + filename
    encode = staticmethod(encode)

    def decode(encoded_data):
        if not encoded_data.startswith("file://"):
            raise scheme_error("no file:// scheme found")
        path = encoded_data[7:]
        if len(path)==0:
            raise scheme_error("path is empty")
        if path[0]!='/':
            raise scheme_error("path is not absolute")
        return path, False
    decode = staticmethod(decode)

class scheme_file_unit_tests(unittest.TestCase):

    def check_encode_empty_filename(self):
        "scheme_file - encode empty filename"
        self.assertRaises(scheme_error, scheme_file.encode, "")

    def check_encode_relative_filename(self):
        "scheme_file - encode relative filename"
        self.assertRaises(scheme_error, scheme_file.encode, "../there")

    def check_encode_absolut_filename(self):
        "scheme_file - encode absolut filename"
        self.assertEqual(
            scheme_file.encode("/here/and/there/again"),
            'file:///here/and/there/again')

    def check_decode_01(self):
        "scheme_file - decode empty data"
        self.assertRaises(scheme_error, scheme_file.decode, "")

    def check_decode_02(self):
        "scheme_file - decode data with no file:// at the beginning (1)"
        self.assertRaises(scheme_error, scheme_file.decode,
                          "phonehome://bbbb")

    def check_decode_03(self):
        "scheme_file - decode data with no file:// at the beginning (2)"
        self.assertRaises(scheme_error, scheme_file.decode,
                          "file:/bbbb")

    def check_decode_04(self):
        "scheme_file - decode empty path"
        self.assertRaises(scheme_error, scheme_file.decode,
                          "file://")

    def check_decode_05(self):
        "scheme_file - decode empty relative path"
        self.assertRaises(scheme_error, scheme_file.decode,
                          "file://somewhere")

    def check_decode_06(self):
        "scheme_file - decode ok"
        path, tmp_file = scheme_file.decode("file:///boot/vmlinuz")
        self.assertEqual(path, "/boot/vmlinuz")
        self.assertEqual(tmp_file, False)

class scheme_set:

    def __init__(self):
        self.schemes = [scheme_data, scheme_file]

    def decode(self, uri):
        for scheme in self.schemes:
            try:
                # If this passes, it is the correct scheme
                return scheme.decode(uri)
            except scheme_error, se:
                log.debug("Decode throws an error: '%s'" % se)
        return uri, False
        
schemes = scheme_set()


def suite():
    return unittest.TestSuite(
        [unittest.makeSuite(scheme_data_unit_tests, 'check_'),
         unittest.makeSuite(scheme_file_unit_tests, 'check_'),])

if __name__ == "__main__":
    testresult = unittest.TextTestRunner(verbosity=3).run(suite())

