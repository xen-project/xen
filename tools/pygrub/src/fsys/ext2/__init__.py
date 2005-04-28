# Copyright 2005 Red Hat, Inc.
# Jeremy Katz <katzj@redhat.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

from grub.fsys import register_fstype, FileSystemType
from _pyext2 import *

import os, struct

class Ext2FileSystemType(FileSystemType):
    def __init__(self):
        FileSystemType.__init__(self)
        self.name = "ext2"

    def sniff_magic(self, fn, offset = 0):
        fd = os.open(fn, os.O_RDONLY)
        os.lseek(fd, offset, 0)
        buf = os.read(fd, 2048)
        
        if len(buf) > 1082 and \
               struct.unpack("<H", buf[1080:1082]) == (0xef53,):
            return True
        return False

    def open_fs(self, fn, offset = 0):
        if not self.sniff_magic(fn, offset):
            raise ValueError, "Not an ext2 filesystem"
        return Ext2Fs(fn)

register_fstype(Ext2FileSystemType())

