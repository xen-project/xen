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

import os
import unittest

from xen.util.fileuri import scheme_error
from xen.util.fileuri import scheme_data
from xen.util.fileuri import scheme_file
from xen.util.fileuri import schemes

class scheme_data_unit_tests(unittest.TestCase):

    def check_basic_encoding(self):
        "util.fileuri.scheme_data - basic encoding"
        sd = scheme_data.encode('Hello!')
        self.assertEqual(sd, 'data:application/octet-stream;base64,SGVsbG8h')

    def check_encoding_with_given_mediatype(self):
        "util.fileuri.scheme_data - encoding with given media name"
        sd = scheme_data.encode('Hello!', 'application/x-my-linux-kernel')
        self.assertEqual(sd,
              'data:application/x-my-linux-kernel;base64,SGVsbG8h')

    def check_parse_01(self):
        "util.fileuri.scheme_data - parsing of None"
        self.assertRaises(scheme_error, scheme_data.parse, None)

    def check_parse_02(self):
        "util.fileuri.scheme_data - parsing of empty string"
        self.assertRaises(scheme_error, scheme_data.parse, "")

    def check_parse_03(self):
        "util.fileuri.scheme_data - parsing of unstructured data"
        self.assertRaises(scheme_error, scheme_data.parse, "akskdjdfhezezu")

    def check_parse_04(self):
        "util.fileuri.scheme_data - data: is not at the first place"
        self.assertRaises(scheme_error, scheme_data.parse, 'ggdata:sossm')

    def check_parse_05(self):
        "util.fileuri.scheme_data - no comma in data"
        self.assertRaises(scheme_error, scheme_data.parse, 'data:sossm')

    def check_parse_06(self):
        "util.fileuri.scheme_data - encoding is empty"
        self.assertRaises(scheme_error, scheme_data.parse, 'data:,')

    def check_parse_07(self):
        "util.fileuri.scheme_data - unknown encoding"
        self.assertRaises(scheme_error, scheme_data.parse,
                          'data:somemediatype;unknown,')

    def check_parse_08(self):
        "util.fileuri.scheme_data - parse ok - empty data"
        mediatype, encoding, data_start = scheme_data.parse(
            'data:somemedia;base64,')
        self.assertEqual(mediatype, 'somemedia')
        self.assertEqual(encoding, 'base64')
        self.assertEqual(data_start, 22)

    def check_parse_09(self):
        "util.fileuri.scheme_data - parse ok - some data"
        mediatype, encoding, data_start = scheme_data.parse(
            'data:somemedia;base64,HereComesTheSun')
        self.assertEqual(mediatype, 'somemedia')
        self.assertEqual(encoding, 'base64')
        self.assertEqual(data_start, 22)

    def check_parse_10(self):
        "util.fileuri.scheme_data - header ok - data error"
        self.assertRaises(scheme_error, scheme_data.decode,
               'data:application/octet-stream;base64,H!$ere"Co<mesT>heS_.un')

    def check_cff_file_does_not_exist(self):
        "util.fileuri.scheme_data - create from file - non existent file"
        self.assertRaises(scheme_error, scheme_data.create_from_file,
                          "/there/is/hopefully/no/file/like/this")

    def check_cff_ok(self):
        "util.fileuri.scheme_data - create from file - ok"
        tmppath = "/tmp/scheme_data_check_cff_ok"
        f = open(tmppath, "w")
        f.write("huhuhu")
        f.close()
        d = scheme_data.create_from_file(tmppath)
        os.unlink(tmppath)
        self.assertEqual(d, "data:application/octet-stream;base64,aHVodWh1")


class scheme_file_unit_tests(unittest.TestCase):

    def check_encode_empty_filename(self):
        "util.fileuri.scheme_file - encode empty filename"
        self.assertRaises(scheme_error, scheme_file.encode, "")

    def check_encode_relative_filename(self):
        "util.fileuri.scheme_file - encode relative filename"
        self.assertRaises(scheme_error, scheme_file.encode, "../there")

    def check_encode_absolut_filename(self):
        "util.fileuri.scheme_file - encode absolut filename"
        self.assertEqual(
            scheme_file.encode("/here/and/there/again"),
            'file:///here/and/there/again')

    def check_decode_01(self):
        "util.fileuri.scheme_file - decode empty data"
        self.assertRaises(scheme_error, scheme_file.decode, "")

    def check_decode_02(self):
        "util.fileuri.scheme_file - decode data with no file:// at the beginning (1)"
        self.assertRaises(scheme_error, scheme_file.decode,
                          "phonehome://bbbb")

    def check_decode_03(self):
        "util.fileuri.scheme_file - decode data with no file:// at the beginning (2)"
        self.assertRaises(scheme_error, scheme_file.decode,
                          "file:/bbbb")

    def check_decode_04(self):
        "util.fileuri.scheme_file - decode empty path"
        self.assertRaises(scheme_error, scheme_file.decode,
                          "file://")

    def check_decode_05(self):
        "util.fileuri.scheme_file - decode empty relative path"
        self.assertRaises(scheme_error, scheme_file.decode,
                          "file://somewhere")

    def check_decode_06(self):
        "util.fileuri.scheme_file - decode ok"
        path, tmp_file = scheme_file.decode("file:///boot/vmlinuz")
        self.assertEqual(path, "/boot/vmlinuz")
        self.assertEqual(tmp_file, False)

class scheme_set_unit_tests(unittest.TestCase):

    def check_data_01(self):
        "util.fileuri.scheme_set - data with error in media type"

        u = "data:something_wrong,base64:swer"
        uri, tmp_file = schemes.decode(u)
        self.assertEqual(uri, u)
        self.assertEqual(tmp_file, False)

    def check_data_02(self):
        "util.fileuri.scheme_set - data with error in base64 data"

        u = "data:application/octet-stream;base64,S!VsbG8h"
        uri, tmp_file = schemes.decode(u)
        self.assertEqual(uri, u)
        self.assertEqual(tmp_file, False)
 
    def check_data_03(self):
        "util.fileuri.scheme_set - data ok"

        u = "data:application/octet-stream;base64,SGVsbG8h"
        uri, tmp_file = schemes.decode(u)

        # Read file contents
        f = open(uri, "r")
        d = f.read()
        f.close()
        os.unlink(uri)

        self.assertEqual(d, "Hello!")
        self.assertEqual(tmp_file, True)
       
    def check_file_01(self):
        "util.fileuri.scheme_set - file ok"

        f = "/The/Path/To/The/File.txt"
        uri, tmp_file = schemes.decode("file://" + f)
        self.assertEqual(uri, f)
        self.assertEqual(tmp_file, False)

    def check_without_scheme_01(self):
        "util.fileuri.scheme_set - without scheme"

        f = "/The/Path/To/The/File.txt"
        uri, tmp_file = schemes.decode(f)
        self.assertEqual(uri, f)
        self.assertEqual(tmp_file, False)


def suite():
    return unittest.TestSuite(
        [unittest.makeSuite(scheme_data_unit_tests, 'check_'),
         unittest.makeSuite(scheme_file_unit_tests, 'check_'),
         unittest.makeSuite(scheme_set_unit_tests, 'check_'),])

if __name__ == "__main__":
    testresult = unittest.TextTestRunner(verbosity=3).run(suite())

