# 
# Copyright (C) 2005 Nguyen Anh Quynh <aquynh@gmail.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

from grub.fsys import register_fstype, FileSystemType
from _pyreiser import *

import os

FSMAGIC2 = 'ReIsEr2'
FSMAGIC3 = 'ReIsEr3'

class ReiserFileSystemType(FileSystemType):
    def __init__(self):
        FileSystemType.__init__(self)
        self.name = "reiser"

    def sniff_magic(self, fn, offset = 0):
        fd = os.open(fn, os.O_RDONLY)
        os.lseek(fd, 0x10000, 0)
        buf = os.read(fd, 0x40)
        os.close(fd)
        if len(buf) == 0x40 and (buf[0x34:0x3B] in [FSMAGIC2, FSMAGIC3]) :
            return True
        return False

    def open_fs(self, fn, offset = 0):
        if not self.sniff_magic(fn, offset):
            raise ValueError, "Not a reiserfs filesystem"
        return ReiserFs(fn)

register_fstype(ReiserFileSystemType())

