#!/usr/bin/python
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
#
# This file contains test cases for checking the data URI
# functionality:
# kernel and ramdisk are both checked with original uri,
# file uri and data uri (in every constallation)
#

import copy

from xen.util.fileuri import schemes, scheme_data, scheme_file

from XmTestLib import *
from XmTestLib.network_utils import *
from XmTestLib.XenAPIDomain import XmTestAPIDomain

kernel_orig_uri = arch.configDefaults['kernel']
ramdisk_orig_uri = arch.configDefaults['ramdisk']
kernel_data_uri = scheme_data.create_from_file(kernel_orig_uri)
ramdisk_data_uri = scheme_data.create_from_file(ramdisk_orig_uri)
kernel_file_uri = scheme_file.encode(kernel_orig_uri)
ramdisk_file_uri = scheme_file.encode(ramdisk_orig_uri)

config = copy.copy(arch.configDefaults)

for kernel in (kernel_orig_uri, kernel_data_uri, kernel_file_uri):
    for ramdisk in (ramdisk_orig_uri, ramdisk_data_uri, ramdisk_file_uri):
        config['kernel'] = kernel
        config['ramdisk'] = ramdisk
        print("Using kernel='%s' ramdisk='%s'" % (kernel[:100], ramdisk[:100]))
        try:
            guest = XmTestAPIDomain(baseConfig = config)
            console = guest.start()
        except DomainError, e:
            if verbose:
                print("Failed to create test domain because: %s" % e.extra)
            FAIL(str(e))

        try:
            run = console.runCmd("ls /")
            if run['return'] > 0:
                FAIL("Could not start host")
        except ConsoleError, e:
            saveLog(console.getHistory())
            FAIL(str(e))
            
        guest.closeConsole()
        guest.stop()

